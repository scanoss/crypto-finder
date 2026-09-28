// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

const (
	nodeCallExpression        = "call_expression"
	nodeMemberExpression      = "member_expression"
	nodeVariableDeclarator    = "variable_declarator"
	nodeFunctionDeclaration   = "function_declaration"
	nodeGeneratorDeclaration  = "generator_function_declaration"
	nodeArrowFunction         = "arrow_function"
	nodeFunctionExpression    = "function_expression"
	nodeMethodDefinition      = "method_definition"
	nodeReturnStatement       = "return_statement"
	nodeNewExpression         = "new_expression"
	nodeClassExpression       = "class"
	nodeObjectLiteral         = "object"
	nodeFieldDefinition       = "field_definition"
	nodePublicFieldDefinition = "public_field_definition"
	nodeAssignmentExpression  = "assignment_expression"
)

// NodeParser extracts JavaScript and TypeScript imports, declarations, and calls.
type NodeParser struct {
	javascript   *sitter.Parser
	typescript   *sitter.Parser
	tsx          *sitter.Parser
	includeTests bool
}

// NewNodeParser creates a parser for JavaScript, TypeScript, and TSX source files.
func NewNodeParser(opts ...ParserOption) *NodeParser {
	cfg := newParserConfig(opts)
	return &NodeParser{
		javascript:   newTreeSitterParser(javascript.GetLanguage()),
		typescript:   newTreeSitterParser(typescript.GetLanguage()),
		tsx:          newTreeSitterParser(tsx.GetLanguage()),
		includeTests: cfg.includeTests,
	}
}

func newTreeSitterParser(language *sitter.Language) *sitter.Parser {
	parser := sitter.NewParser()
	parser.SetLanguage(language)
	return parser
}

// CloneParser returns an independent parser for parallel directory parsing.
func (p *NodeParser) CloneParser() Parser {
	return NewNodeParser(WithIncludeTests(p.includeTests))
}

// SubPackagePath constructs a child module path.
func (p *NodeParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "/" + dirName
}

// PackageSeparator returns the npm package-path separator.
func (p *NodeParser) PackageSeparator() string { return "/" }

// ParseDirectory parses supported JavaScript and TypeScript files in dir.
func (p *NodeParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node parser: read directory %s: %w", dir, err)
	}

	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !p.supportsFile(entry.Name()) || (!p.includeTests && isNodeTestFile(entry.Name())) {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		analysis, parseErr := p.ParseFile(filePath, packagePath)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("file", filePath).Str("package", packagePath).Msg("failed to parse file")
			continue
		}
		analyses = append(analyses, analysis)
	}
	return analyses, nil
}

func (p *NodeParser) supportsFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return true
	default:
		return false
	}
}

func isNodeTestFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") || strings.HasPrefix(lower, "test_")
}

// nodeModulePath scopes a function identity to the FILE rather than to its
// directory, because in Node a file IS a module: `src/alpha.js` and
// `src/beta.js` are different modules however they name their exports.
//
// Keying on the directory alone puts two same-named functions on one identity,
// and only one of them survives: `index.js` beside `utils.js`, each exporting a
// `hash()`, is ordinary Node layout.
//
// The extension is dropped so that `a.js`, `a.ts` and `a.tsx` are one module —
// which is what a Node resolver does — and the separator is "/" so the key
// reads as the path it is. A file directly in the package root yields the
// package path unchanged, which keeps single-file packages stable.
func nodeModulePath(packagePath, filePath string) string {
	base := filepath.Base(filePath)
	// A dotfile whose whole name is its extension (".js") keeps that name:
	// trimming it empties the base, and an empty base falls back to the package
	// path, which is the key its parent directory's `b.js` already holds.
	if ext := filepath.Ext(base); ext != "" && ext != base {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		return packagePath
	}
	if packagePath == "" {
		return base
	}
	return packagePath + "/" + base
}

// ParseFile parses one JavaScript or TypeScript source file.
func (p *NodeParser) ParseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node parser: read %s: %w", filePath, err)
	}
	parser := p.parserForFile(filePath)
	if parser == nil {
		return nil, fmt.Errorf("callgraph: node parser: unsupported source file %s", filePath)
	}
	tree, err := parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: node parser: parse %s: %w", filePath, err)
	}
	defer tree.Close()

	analysis := &FileAnalysis{
		FilePath:    filePath,
		PackageName: filepath.Base(packagePath),
		PackagePath: packagePath,
		Imports:     make(map[string]string),
	}
	root := tree.RootNode()
	bindings := make(nodeBindings)
	extractNodeImports(root, src, bindings)
	resolveNodeRelativeImports(bindings, filePath, packagePath)
	for name, binding := range bindings {
		analysis.Imports[name] = binding.module
	}
	for name := range collectNodeLocalNames(nil, root, src) {
		if _, imported := bindings[name]; !imported {
			bindings[name] = nodeBinding{}
		}
	}
	// Identities and same-file call targets are scoped to the module, not the
	// package: see nodeModulePath. analysis.PackagePath keeps the package so the
	// import map and the package name are unaffected.
	modulePath := nodeModulePath(packagePath, filePath)
	p.extractDeclarations(root, src, filePath, modulePath, bindings, analysis)
	if decl := p.moduleInitDecl(root, src, filePath, modulePath, bindings); decl != nil {
		analysis.Functions = append(analysis.Functions, *decl)
	}
	return analysis, nil
}

func (p *NodeParser) parserForFile(path string) *sitter.Parser {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".mts", ".cts":
		return p.typescript
	case ".tsx":
		return p.tsx
	case ".js", ".jsx", ".mjs", ".cjs":
		return p.javascript
	default:
		return nil
	}
}

// nodeBinding is what a module-level name refers to: the module it was
// imported from and the dotted path of the export it names inside that module.
// An empty member is the module itself. `const EC = require('elliptic').ec`,
// `import { ec as EC } from 'elliptic'` and `const { ec: EC } =
// require('elliptic')` all bind EC to {elliptic, ec}, so `new EC(..)` is
// elliptic.ec.<init> however the consumer spelled the import. An empty module
// is a variable the module declares itself, such as
// `const ec = new EC('secp256k1')`.
type nodeBinding struct {
	module string
	member string
}

type nodeBindings map[string]nodeBinding

// lookup returns the import that name refers to unless a local declaration
// shadows it.
func (b nodeBindings) lookup(locals map[string]bool, name string) (nodeBinding, bool) {
	if locals[name] {
		return nodeBinding{}, false
	}
	binding, ok := b[name]
	return binding, ok && binding.module != ""
}

// withModuleVariables returns a function's locals plus the variables the
// module declares, so a call on a module variable records its receiver. That
// is how a variable the module binds once, as elliptic consumers do with their
// curve context, reaches the functions that use it.
func (b nodeBindings) withModuleVariables(own map[string]bool) map[string]bool {
	locals := make(map[string]bool, len(own))
	for name := range own {
		locals[name] = true
	}
	for name, binding := range b {
		if binding.module == "" {
			locals[name] = true
		}
	}
	return locals
}

// moduleReceivers lists, sorted, the module variables that calls use as their
// receiver and that the function does not declare itself.
func (b nodeBindings) moduleReceivers(calls []FunctionCall, own map[string]bool) []string {
	seen := make(map[string]bool)
	for i := range calls {
		name := calls[i].ReceiverVar
		if binding, ok := b[name]; ok && binding.module == "" && !own[name] {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// qualify appends a dotted access path to the binding and splits the result
// into the package path that owns the last segment and that segment. A
// leading `default` is dropped: the default export of a CommonJS module is the
// module itself, which is how the contracts spell it, and it is what tsc's
// __importDefault and an ESM default import both reach.
func (b nodeBinding) qualify(path ...string) (pkg, last string) {
	var segments []string
	for _, part := range append([]string{b.member}, path...) {
		if part != "" {
			segments = append(segments, strings.Split(part, ".")...)
		}
	}
	if len(segments) > 0 && segments[0] == "default" {
		segments = segments[1:]
	}
	if len(segments) == 0 {
		return b.module, ""
	}
	pkg = b.module
	if len(segments) > 1 {
		pkg += "." + strings.Join(segments[:len(segments)-1], ".")
	}
	return pkg, segments[len(segments)-1]
}

func extractNodeImports(node *sitter.Node, src []byte, bindings nodeBindings) {
	if node == nil {
		return
	}
	switch node.Type() {
	case "import_statement":
		extractNodeESImport(node, src, bindings)
		return
	case nodeVariableDeclarator:
		extractNodeRequireImport(node, src, bindings)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		extractNodeImports(node.Child(i), src, bindings)
	}
}

func extractNodeESImport(node *sitter.Node, src []byte, bindings nodeBindings) {
	source := node.ChildByFieldName("source")
	if source == nil {
		return
	}
	module := unquoteNodeString(source.Content(src))
	if module == "" {
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "import_clause" {
			recordNodeImportAliases(child, src, module, bindings)
		}
	}
}

func recordNodeImportAliases(node *sitter.Node, src []byte, module string, bindings nodeBindings) {
	if node == nil {
		return
	}
	switch node.Type() {
	case goNodeIdentifier:
		bindings[node.Content(src)] = nodeBinding{module: module}
		return
	case "import_specifier":
		name := node.ChildByFieldName("name")
		if name == nil {
			return
		}
		local := name
		if alias := node.ChildByFieldName("alias"); alias != nil {
			local = alias
		}
		bindings[local.Content(src)] = nodeBinding{module: module, member: unquoteNodeString(name.Content(src))}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		recordNodeImportAliases(node.Child(i), src, module, bindings)
	}
}

func extractNodeRequireImport(node *sitter.Node, src []byte, bindings nodeBindings) {
	name := node.ChildByFieldName("name")
	binding, ok := nodeRequireBinding(node.ChildByFieldName("value"), src)
	if !ok || name == nil {
		return
	}
	switch name.Type() {
	case goNodeIdentifier:
		bindings[name.Content(src)] = binding
	case "object_pattern":
		for i := 0; i < int(name.NamedChildCount()); i++ {
			item := name.NamedChild(i)
			switch item.Type() {
			case "shorthand_property_identifier_pattern":
				bindings[item.Content(src)] = nodeBinding{module: binding.module, member: joinNodeMember(binding.member, item.Content(src))}
			case "pair_pattern":
				key := item.ChildByFieldName("key")
				alias := item.ChildByFieldName("value")
				if key != nil && alias != nil && alias.Type() == goNodeIdentifier {
					bindings[alias.Content(src)] = nodeBinding{module: binding.module, member: joinNodeMember(binding.member, unquoteNodeString(key.Content(src)))}
				}
			}
		}
	}
}

func joinNodeMember(member, name string) string {
	if member == "" {
		return name
	}
	return member + "." + name
}

// nodeRequireBinding reads the value of a require-style declarator:
// `require('m')`, a member of it such as `require('m').a.b`, or either wrapped
// in the interop helper a compiler emits for an import, as in tsc's
// `__importStar(require('m'))` and `tslib_1.__importDefault(require('m'))` or
// Babel's `_interopRequireWildcard(require('m'))`.
func nodeRequireBinding(node *sitter.Node, src []byte) (nodeBinding, bool) {
	if node == nil {
		return nodeBinding{}, false
	}
	switch node.Type() {
	case nodeMemberExpression:
		object := node.ChildByFieldName("object")
		property := node.ChildByFieldName("property")
		binding, ok := nodeRequireBinding(object, src)
		if !ok || property == nil {
			return nodeBinding{}, false
		}
		binding.member = joinNodeMember(binding.member, property.Content(src))
		return binding, true
	case nodeCallExpression:
		function := node.ChildByFieldName("function")
		arguments := node.ChildByFieldName("arguments")
		if function == nil || arguments == nil || arguments.NamedChildCount() != 1 {
			return nodeBinding{}, false
		}
		arg := arguments.NamedChild(0)
		if isNodeImportInteropHelper(function, src) {
			return nodeRequireBinding(arg, src)
		}
		if function.Type() != goNodeIdentifier || function.Content(src) != "require" || arg.Type() != "string" {
			return nodeBinding{}, false
		}
		module := unquoteNodeString(arg.Content(src))
		return nodeBinding{module: module}, module != ""
	}
	return nodeBinding{}, false
}

func isNodeImportInteropHelper(function *sitter.Node, src []byte) bool {
	name := function
	if function.Type() == nodeMemberExpression {
		name = function.ChildByFieldName("property")
	}
	if name == nil {
		return false
	}
	switch name.Content(src) {
	case "__importStar", "__importDefault", "_interopRequireWildcard", "_interopRequireDefault":
		return true
	}
	return false
}

func unquoteNodeString(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"'`")
}

func (p *NodeParser) extractDeclarations(node *sitter.Node, src []byte, filePath, packagePath string, bindings nodeBindings, analysis *FileAnalysis) {
	if node == nil {
		return
	}
	switch node.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration:
		if decl := p.parseNodeFunction(node, src, filePath, packagePath, "", "", bindings); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		p.extractDeclarations(node.ChildByFieldName("body"), src, filePath, packagePath, bindings, analysis)
		return
	case "lexical_declaration", "variable_declaration":
		p.extractAssignedFunctions(node, src, filePath, packagePath, bindings, analysis)
		return
	case javaNodeClassDeclaration:
		p.extractClassMethods(node, src, filePath, packagePath, "", bindings, analysis)
		return
	case nodeObjectLiteral:
		p.extractObjectMethods(node, src, filePath, packagePath, "", bindings, analysis)
		return
	case nodeArrowFunction, nodeFunctionExpression:
		// Every function the other cases do not declare, such as a callback or
		// a route handler, is a function of its own: it runs later, on its own
		// variables, so its calls must not join those around it.
		p.declareNodeFunction(node, src, filePath, packagePath, nodeAnonymousName(node), "", bindings, analysis)
		return
	case nodeAssignmentExpression:
		if fn := nodeAssignedFunction(node); fn != nil {
			if name, owner := nodeAssignmentTarget(node.ChildByFieldName("left"), src); name != "" {
				p.declareNodeFunction(fn, src, filePath, packagePath, name, owner, bindings, analysis)
				return
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.extractDeclarations(node.Child(i), src, filePath, packagePath, bindings, analysis)
	}
}

// nodeAssignedFunction returns the function an assignment stores, looking
// through a chain such as `var sign = exports.sign = function (..) {..}`.
func nodeAssignedFunction(node *sitter.Node) *sitter.Node {
	for node != nil && node.Type() == nodeAssignmentExpression {
		node = node.ChildByFieldName("right")
	}
	if node == nil || (node.Type() != nodeArrowFunction && node.Type() != nodeFunctionExpression) {
		return nil
	}
	return node
}

// nodeAssignmentTarget names the function a CommonJS module declares by
// assignment: `exports.sign = function` and `module.exports.sign = function`
// declare sign, and `EC.prototype.sign = function` declares the sign method
// of EC. It returns no name for a target it cannot name, such as `a[i]`.
func nodeAssignmentTarget(left *sitter.Node, src []byte) (name, owner string) {
	if left == nil {
		return "", ""
	}
	switch left.Type() {
	case goNodeIdentifier:
		return left.Content(src), ""
	case nodeMemberExpression:
		object := left.ChildByFieldName("object")
		property := left.ChildByFieldName("property")
		if object == nil || property == nil {
			return "", ""
		}
		if class, ok := strings.CutSuffix(object.Content(src), ".prototype"); ok {
			owner = class[strings.LastIndex(class, ".")+1:]
		}
		return property.Content(src), owner
	}
	return "", ""
}

// moduleInitDecl collects the calls a module makes when it loads, its
// top-level statements, under the synthetic <module> declaration the Python
// parser also emits. A module that makes no such call gets none.
func (p *NodeParser) moduleInitDecl(root *sitter.Node, src []byte, filePath, modulePath string, bindings nodeBindings) *FunctionDecl {
	locals := bindings.withModuleVariables(nil)
	calls := p.extractCalls(root, src, filePath, modulePath, "", bindings, locals)
	if len(calls) == 0 {
		return nil
	}
	return &FunctionDecl{
		ID:           FunctionID{Package: modulePath, Name: moduleInitMethodName},
		FilePath:     filePath,
		StartLine:    int(root.StartPoint().Row) + 1,
		EndLine:      int(root.EndPoint().Row) + 1,
		OwnerType:    "module",
		OwnerName:    modulePath,
		FunctionType: functionTypeModuleInit,
		Calls:        calls,
	}
}

func (p *NodeParser) extractAssignedFunctions(node *sitter.Node, src []byte, filePath, packagePath string, bindings nodeBindings, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		declarator := node.NamedChild(i)
		if declarator.Type() != nodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName("name")
		value := declarator.ChildByFieldName("value")
		if name == nil || name.Type() != goNodeIdentifier || value == nil {
			continue
		}
		bound := name.Content(src)

		// A class or an object literal bound to a name carries methods written
		// exactly as a class declaration's are — `const H = class { run() {} }` and
		// `const o = { run() {} }`. The binding supplies the owner that the shape
		// itself does not name.
		switch value.Type() {
		case nodeClassExpression, javaNodeClassDeclaration:
			p.extractClassMethods(value, src, filePath, packagePath, bound, bindings, analysis)
			continue
		case nodeObjectLiteral:
			p.extractObjectMethods(value, src, filePath, packagePath, bound, bindings, analysis)
			continue
		}

		if fn := nodeAssignedFunction(value); fn != nil {
			p.declareNodeFunction(fn, src, filePath, packagePath, bound, "", bindings, analysis)
			continue
		}
		p.extractDeclarations(value, src, filePath, packagePath, bindings, analysis)
	}
}

// declareNodeFunction records a function expression under name, then the
// functions declared inside it.
func (p *NodeParser) declareNodeFunction(fn *sitter.Node, src []byte, filePath, packagePath, name, owner string, bindings nodeBindings, analysis *FileAnalysis) {
	if decl := p.parseNodeFunction(fn, src, filePath, packagePath, name, owner, bindings); decl != nil {
		analysis.Functions = append(analysis.Functions, *decl)
	}
	p.extractDeclarations(fn.ChildByFieldName("body"), src, filePath, packagePath, bindings, analysis)
}

// nodeAnonymousName names a function expression that nothing names by where
// it starts, as <anonymous>@12:5, which is unique within its module.
func nodeAnonymousName(fn *sitter.Node) string {
	return fmt.Sprintf("<anonymous>@%d:%d", fn.StartPoint().Row+1, fn.StartPoint().Column+1)
}

// extractObjectMethods declares the methods of an object literal: shorthand
// methods, which tree-sitter parses as the `method_definition` a class body
// uses, and properties whose value is a function, as in
// `module.exports = { sign: function (..) {..} }`. owner is the name the
// object is bound to, or empty for an object nothing names. Other property
// values are searched for declarations of their own.
func (p *NodeParser) extractObjectMethods(node *sitter.Node, src []byte, filePath, packagePath, owner string, bindings nodeBindings, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		member := node.NamedChild(i)
		switch member.Type() {
		case nodeMethodDefinition:
			p.declareNodeFunction(member, src, filePath, packagePath, "", owner, bindings, analysis)
		case "pair":
			key := member.ChildByFieldName("key")
			value := member.ChildByFieldName("value")
			if fn := nodeAssignedFunction(value); fn != nil && key != nil && key.Type() != "computed_property_name" {
				p.declareNodeFunction(fn, src, filePath, packagePath, unquoteNodeString(key.Content(src)), owner, bindings, analysis)
				continue
			}
			p.extractDeclarations(value, src, filePath, packagePath, bindings, analysis)
		default:
			p.extractDeclarations(member, src, filePath, packagePath, bindings, analysis)
		}
	}
}

// extractClassMethods walks a class body. fallbackOwner names a class that has
// no name of its own: `const Hasher = class { ... }` is a class_expression, so
// the owner comes from the binding, which is what a reader calls the type
// anyway.
func (p *NodeParser) extractClassMethods(node *sitter.Node, src []byte, filePath, packagePath, fallbackOwner string, bindings nodeBindings, analysis *FileAnalysis) {
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	owner := fallbackOwner
	if name := node.ChildByFieldName("name"); name != nil {
		owner = name.Content(src)
	}
	if owner == "" {
		return
	}
	var fieldInit []*sitter.Node
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		switch member.Type() {
		case nodeMethodDefinition:
			if decl := p.parseNodeFunction(member, src, filePath, packagePath, "", owner, bindings); decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case nodeFieldDefinition, nodePublicFieldDefinition:
			if value := member.ChildByFieldName("value"); value != nil {
				fieldInit = append(fieldInit, value)
			}
		}
	}
	p.appendClassInit(body, fieldInit, src, filePath, packagePath, owner, bindings, analysis)
}

// appendClassInit emits ONE synthetic `<clinit>` for a class whose body holds a
// field with an initialiser, following the Java parser's precedent for the same
// problem: an initialiser runs during construction and belongs to no method the
// reader wrote, so it has no other function to be attributed to.
//
// The decl spans the whole class body deliberately: ContainingFunction picks the
// tightest span for a line, so every real method still wins and only calls that
// sit directly in initialiser position fall through to `<clinit>`.
//
// Calls are collected from the initialiser expressions ONLY, never from method
// bodies, which own their own.
func (p *NodeParser) appendClassInit(body *sitter.Node, inits []*sitter.Node, src []byte, filePath, packagePath, owner string, bindings nodeBindings, analysis *FileAnalysis) {
	if len(inits) == 0 {
		return
	}
	decl := &FunctionDecl{
		ID:           FunctionID{Package: packagePath, Type: owner, Name: clinitMethodName},
		FilePath:     filePath,
		StartLine:    int(body.StartPoint().Row) + 1,
		EndLine:      int(body.EndPoint().Row) + 1,
		OwnerType:    ownerTypeClass,
		OwnerName:    owner,
		FunctionType: javaFunctionTypeMethod,
	}
	own := make(map[string]bool)
	for _, init := range inits {
		collectNodeBindingNames(init, src, own)
	}
	locals := bindings.withModuleVariables(own)
	for _, init := range inits {
		decl.Calls = append(decl.Calls, p.extractCalls(init, src, filePath, packagePath, owner, bindings, locals)...)
	}
	decl.ModuleVars = bindings.moduleReceivers(decl.Calls, own)
	analysis.Functions = append(analysis.Functions, *decl)
}

func (p *NodeParser) parseNodeFunction(node *sitter.Node, src []byte, filePath, packagePath, fallbackName, owner string, imports nodeBindings) *FunctionDecl {
	name := fallbackName
	if nameNode := node.ChildByFieldName("name"); nameNode != nil {
		name = nameNode.Content(src)
	}
	if name == "" {
		return nil
	}
	params := node.ChildByFieldName("parameters")
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	decl := &FunctionDecl{
		ID:           FunctionID{Package: packagePath, Type: owner, Name: name},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "module",
		OwnerName:    packagePath,
		FunctionType: "function",
		Parameters:   nodeParameters(params, src),
	}
	if owner != "" {
		decl.OwnerType = ownerTypeClass
		decl.OwnerName = owner
		decl.FunctionType = javaFunctionTypeMethod
	}
	own := collectNodeLocalNames(params, body, src)
	locals := imports.withModuleVariables(own)
	decl.Calls = p.extractCalls(body, src, filePath, packagePath, owner, imports, locals)
	decl.ModuleVars = imports.moduleReceivers(decl.Calls, own)
	decl.ReturnSources = p.extractReturnSources(body, src, filePath, packagePath, owner, imports, locals)
	return decl
}

func (p *NodeParser) extractReturnSources(body *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool) []SourceNode {
	if body.Type() != "statement_block" {
		if source, ok := p.nodeReturnSource(body, src, filePath, packagePath, owner, imports, locals); ok {
			return []SourceNode{source}
		}
		return nil
	}
	var sources []SourceNode
	p.walkNodeReturnSources(body, src, filePath, packagePath, owner, imports, locals, &sources)
	return sources
}

func (p *NodeParser) walkNodeReturnSources(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool, sources *[]SourceNode) {
	if node == nil {
		return
	}
	if isNodeNestedScope(node.Type()) {
		return
	}
	if node.Type() == nodeReturnStatement {
		if node.NamedChildCount() > 0 {
			if source, ok := p.nodeReturnSource(node.NamedChild(0), src, filePath, packagePath, owner, imports, locals); ok {
				*sources = append(*sources, source)
			}
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkNodeReturnSources(node.Child(i), src, filePath, packagePath, owner, imports, locals, sources)
	}
}

func (p *NodeParser) nodeReturnSource(expr *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool) (SourceNode, bool) {
	location := &SourceLocation{FilePath: filePath, Line: int(expr.StartPoint().Row) + 1}
	switch expr.Type() {
	case nodeCallExpression:
		call := p.parseNodeCall(expr, src, filePath, packagePath, owner, imports, locals)
		if call == nil {
			return SourceNode{}, false
		}
		callee := call.Callee
		callee.Name = fmt.Sprintf("%s#%d", callee.Name, len(call.Arguments))
		return SourceNode{Type: sourceNodeCallResult, CallTarget: &callee, Location: location}, true
	case nodeNewExpression:
		pkg, typeName, _, ok := nodeConstructorType(expr.ChildByFieldName("constructor"), src, packagePath, imports, locals)
		if !ok {
			return SourceNode{}, false
		}
		target := FunctionID{Package: pkg, Type: typeName, Name: fmt.Sprintf("%s#%d", constructorMethodName, len(nodeCallArguments(expr, src)))}
		return SourceNode{Type: sourceNodeCallResult, DeclaredType: qualifiedType(pkg, typeName), CallTarget: &target, Location: location}, true
	case goNodeIdentifier:
		return SourceNode{Type: sourceNodeVariable, Name: expr.Content(src), Location: location}, true
	case "string", "number", javaNodeBoolLiteralTrue, javaNodeBoolLiteralFalse, "null":
		return SourceNode{Type: sourceNodeValue, Value: expr.Content(src), Location: location}, true
	}
	return SourceNode{}, false
}

func nodeParameters(node *sitter.Node, src []byte) []FunctionParameter {
	if node == nil {
		return nil
	}
	params := make([]FunctionParameter, 0, node.NamedChildCount())
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		nameNode := child
		typeNode := (*sitter.Node)(nil)
		if child.Type() == "required_parameter" || child.Type() == "optional_parameter" {
			nameNode = child.ChildByFieldName("pattern")
			typeNode = child.ChildByFieldName("type")
		}
		if nameNode == nil {
			continue
		}
		param := FunctionParameter{Name: strings.TrimPrefix(nameNode.Content(src), "...")}
		if typeNode != nil {
			param.Type = strings.TrimPrefix(strings.TrimSpace(typeNode.Content(src)), ":")
		}
		params = append(params, param)
	}
	return params
}

func collectNodeLocalNames(params, body *sitter.Node, src []byte) map[string]bool {
	locals := make(map[string]bool)
	collectNodeBindingNames(params, src, locals)
	collectNodeBindingNames(body, src, locals)
	return locals
}

func collectNodeBindingNames(node *sitter.Node, src []byte, locals map[string]bool) {
	if node == nil {
		return
	}
	if collectNodeNestedBinding(node, src, locals) {
		return
	}
	if node.Type() == nodeVariableDeclarator {
		name := node.ChildByFieldName("name")
		if name != nil && name.Type() == goNodeIdentifier {
			locals[name.Content(src)] = true
		}
	}
	if node.Type() == goNodeIdentifier && node.Parent() != nil && node.Parent().Type() == "formal_parameters" {
		locals[node.Content(src)] = true
	}
	if node.Type() == "required_parameter" || node.Type() == "optional_parameter" {
		pattern := node.ChildByFieldName("pattern")
		if pattern != nil && pattern.Type() == goNodeIdentifier {
			locals[pattern.Content(src)] = true
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectNodeBindingNames(node.Child(i), src, locals)
	}
}

func collectNodeNestedBinding(node *sitter.Node, src []byte, locals map[string]bool) bool {
	if !isNodeNestedScope(node.Type()) {
		return false
	}
	switch node.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, javaNodeClassDeclaration:
		if name := node.ChildByFieldName("name"); name != nil {
			locals[name.Content(src)] = true
		}
		return true
	}
	return true
}

func isNodeNestedScope(nodeType string) bool {
	switch nodeType {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeArrowFunction, nodeFunctionExpression, nodeMethodDefinition, javaNodeClassDeclaration, nodeClassExpression:
		return true
	default:
		return false
	}
}

func (p *NodeParser) extractCalls(body *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool) []FunctionCall {
	var calls []FunctionCall
	p.walkNodeCalls(body, src, filePath, packagePath, owner, imports, locals, &calls)
	return calls
}

func (p *NodeParser) walkNodeCalls(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool, calls *[]FunctionCall) {
	if node == nil {
		return
	}
	if isNodeNestedScope(node.Type()) {
		return
	}
	var call *FunctionCall
	switch node.Type() {
	case nodeCallExpression:
		call = p.parseNodeCall(node, src, filePath, packagePath, owner, imports, locals)
	case nodeNewExpression:
		call = parseNodeNew(node, src, filePath, imports, locals)
	}
	if call != nil {
		setFunctionCallASTAnchor(call, node)
		*calls = append(*calls, *call)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkNodeCalls(node.Child(i), src, filePath, packagePath, owner, imports, locals, calls)
	}
}

func (p *NodeParser) parseNodeCall(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool) *FunctionCall {
	function := node.ChildByFieldName("function")
	if function == nil {
		return nil
	}
	line := int(node.StartPoint().Row) + 1
	call := &FunctionCall{
		Raw:       function.Content(src),
		FilePath:  filePath,
		Line:      line,
		StartCol:  int(node.StartPoint().Column) + 1,
		EndCol:    int(node.EndPoint().Column) + 1,
		Arguments: nodeCallArguments(node, src),
	}
	call.ChainID, call.AssignedVar = nodeCallChainContext(node, src)

	function = unwrapNodeCallee(function)
	switch function.Type() {
	case goNodeIdentifier:
		name := function.Content(src)
		if name == "require" {
			return nil
		}
		call.Callee = FunctionID{Package: packagePath, Name: name}
		if binding, ok := imports.lookup(locals, name); ok {
			pkg, last := binding.qualify()
			if last == "" {
				last = name
			}
			call.Callee = FunctionID{Package: pkg, Name: last}
		}
		return call
	case nodeMemberExpression:
		object := function.ChildByFieldName("object")
		property := function.ChildByFieldName("property")
		if object == nil || property == nil {
			return nil
		}
		name := property.Content(src)
		objectText := object.Content(src)
		call.Callee = FunctionID{Package: packagePath, Name: name}
		first, suffix := splitNodeMemberObject(objectText)
		binding, importedObject := imports.lookup(locals, first)
		switch {
		case object.Type() != nodeCallExpression && importedObject:
			call.Callee.Package, _ = binding.qualify(suffix, name)
		case object.Type() == "this" && owner != "":
			call.Callee.Type = owner
		case object.Type() == goNodeIdentifier && locals[objectText]:
			call.ReceiverVar = objectText
		}
		return call
	default:
		return nil
	}
}

// unwrapNodeCallee sees through the parentheses and comma operator that
// compiled output wraps around a callee: tsc emits `(0, ns.fn)(..)` for a
// call to a named import so that `this` is not bound to the namespace.
func unwrapNodeCallee(function *sitter.Node) *sitter.Node {
	for {
		switch function.Type() {
		case "parenthesized_expression", "sequence_expression":
			if function.NamedChildCount() == 0 {
				return function
			}
			function = function.NamedChild(int(function.NamedChildCount()) - 1)
		default:
			return function
		}
	}
}

// parseNodeNew records `new C(..)` as a call to C's constructor when C is
// reached through an import. That is what lets `const ec = new EC(curve)`
// type ec from the contract for elliptic.ec.<init>. A class of the module's
// own is left out: its constructor is a method named `constructor`, which a
// <init> target would never reach.
func parseNodeNew(node *sitter.Node, src []byte, filePath string, imports nodeBindings, locals map[string]bool) *FunctionCall {
	constructor := node.ChildByFieldName("constructor")
	pkg, typeName, imported, ok := nodeConstructorType(constructor, src, "", imports, locals)
	if !ok || !imported {
		return nil
	}
	call := &FunctionCall{
		Callee:    FunctionID{Package: pkg, Type: typeName, Name: constructorMethodName},
		Raw:       "new " + constructor.Content(src),
		FilePath:  filePath,
		Line:      int(node.StartPoint().Row) + 1,
		StartCol:  int(node.StartPoint().Column) + 1,
		EndCol:    int(node.EndPoint().Column) + 1,
		Arguments: nodeCallArguments(node, src),
	}
	call.ChainID, call.AssignedVar = nodeCallChainContext(node, src)
	return call
}

// nodeConstructorType names the class a `new` expression constructs. A class
// reached through an import is qualified by its module path. A bare name that
// no import binds is a class of packagePath, and imported reports false.
func nodeConstructorType(constructor *sitter.Node, src []byte, packagePath string, imports nodeBindings, locals map[string]bool) (pkg, typeName string, imported, ok bool) {
	if constructor == nil {
		return "", "", false, false
	}
	switch constructor.Type() {
	case goNodeIdentifier:
		name := constructor.Content(src)
		binding, bound := imports.lookup(locals, name)
		if !bound {
			return packagePath, name, false, true
		}
		pkg, typeName = binding.qualify()
		if typeName == "" {
			typeName = name
		}
		return pkg, typeName, true, true
	case nodeMemberExpression:
		object := constructor.ChildByFieldName("object")
		property := constructor.ChildByFieldName("property")
		if object == nil || property == nil {
			return "", "", false, false
		}
		first, suffix := splitNodeMemberObject(object.Content(src))
		binding, bound := imports.lookup(locals, first)
		if !bound {
			return "", "", false, false
		}
		pkg, typeName = binding.qualify(suffix, property.Content(src))
		return pkg, typeName, true, true
	}
	return "", "", false, false
}

func nodeCallArguments(node *sitter.Node, src []byte) []string {
	arguments := node.ChildByFieldName("arguments")
	if arguments == nil {
		return nil
	}
	args := parseArgumentsFromDelimitedContent(arguments.Content(src))
	for i, arg := range args {
		if literal, ok := canonicalNodeStringLiteral(arg); ok {
			args[i] = literal
		}
	}
	return args
}

func splitNodeMemberObject(object string) (first, suffix string) {
	if dot := strings.Index(object, "."); dot > 0 {
		return object[:dot], object[dot+1:]
	}
	return object, ""
}

func nodeCallChainContext(node *sitter.Node, src []byte) (chainID, assignedVar string) {
	root := nodeChainRoot(node)
	if !sameSyntaxNode(root, node) {
		return fmt.Sprintf("%d", root.StartByte()), ""
	}
	function := node.ChildByFieldName("function")
	if function != nil && function.Type() == nodeMemberExpression {
		object := function.ChildByFieldName("object")
		if object != nil && object.Type() == nodeCallExpression {
			chainID = fmt.Sprintf("%d", root.StartByte())
		}
	}
	return chainID, assignedVarFromParent(root, src)
}

func nodeChainRoot(node *sitter.Node) *sitter.Node {
	root := node
	for {
		member := root.Parent()
		if member == nil || member.Type() != nodeMemberExpression || !sameSyntaxNode(member.ChildByFieldName("object"), root) {
			break
		}
		call := member.Parent()
		if call == nil || call.Type() != nodeCallExpression || !sameSyntaxNode(call.ChildByFieldName("function"), member) {
			break
		}
		root = call
	}
	return root
}

func sameSyntaxNode(a, b *sitter.Node) bool {
	return a != nil && b != nil && a.Type() == b.Type() && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}
