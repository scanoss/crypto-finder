// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

const (
	nodeCallExpression       = "call_expression"
	nodeMemberExpression     = "member_expression"
	nodeVariableDeclarator   = "variable_declarator"
	nodeFunctionDeclaration  = "function_declaration"
	nodeGeneratorDeclaration = "generator_function_declaration"
	nodeArrowFunction        = "arrow_function"
	nodeFunctionExpression   = "function_expression"
	nodeMethodDefinition     = "method_definition"
	nodeReturnStatement      = "return_statement"
	nodeNewExpression        = "new_expression"
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

// SkipDirs returns generated, vendored, and optionally test directories.
func (p *NodeParser) SkipDirs() map[string]bool {
	skip := map[string]bool{
		"node_modules": true,
		"dist":         true,
		"build":        true,
		"coverage":     true,
	}
	if !p.includeTests {
		skip["test"] = true
		skip["tests"] = true
		skip["__tests__"] = true
	}
	return skip
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
	p.extractImports(root, src, analysis)
	p.extractDeclarations(root, src, filePath, packagePath, analysis)
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

func (p *NodeParser) extractImports(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	if node == nil {
		return
	}
	switch node.Type() {
	case "import_statement":
		p.extractESImport(node, src, analysis)
		return
	case nodeVariableDeclarator:
		p.extractRequireImport(node, src, analysis)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.extractImports(node.Child(i), src, analysis)
	}
}

func (p *NodeParser) extractESImport(node *sitter.Node, src []byte, analysis *FileAnalysis) {
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
			recordNodeImportAliases(child, src, module, analysis.Imports)
		}
	}
}

func recordNodeImportAliases(node *sitter.Node, src []byte, module string, imports map[string]string) {
	if node == nil {
		return
	}
	switch node.Type() {
	case goNodeIdentifier:
		imports[node.Content(src)] = module
		return
	case "import_specifier":
		name := node.ChildByFieldName("alias")
		if name == nil {
			name = node.ChildByFieldName("name")
		}
		if name != nil {
			imports[name.Content(src)] = module
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		recordNodeImportAliases(node.Child(i), src, module, imports)
	}
}

func (p *NodeParser) extractRequireImport(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	value := node.ChildByFieldName("value")
	name := node.ChildByFieldName("name")
	module, ok := nodeRequireModule(value, src)
	if !ok || name == nil {
		return
	}
	switch name.Type() {
	case goNodeIdentifier:
		analysis.Imports[name.Content(src)] = module
	case "object_pattern":
		for i := 0; i < int(name.NamedChildCount()); i++ {
			item := name.NamedChild(i)
			switch item.Type() {
			case "shorthand_property_identifier_pattern":
				analysis.Imports[item.Content(src)] = module
			case "pair_pattern":
				alias := item.ChildByFieldName("value")
				if alias != nil {
					analysis.Imports[alias.Content(src)] = module
				}
			}
		}
	}
}

func nodeRequireModule(node *sitter.Node, src []byte) (string, bool) {
	if node == nil || node.Type() != nodeCallExpression {
		return "", false
	}
	function := node.ChildByFieldName("function")
	arguments := node.ChildByFieldName("arguments")
	if function == nil || function.Type() != goNodeIdentifier || function.Content(src) != "require" || arguments == nil || arguments.NamedChildCount() != 1 {
		return "", false
	}
	arg := arguments.NamedChild(0)
	if arg.Type() != "string" {
		return "", false
	}
	module := unquoteNodeString(arg.Content(src))
	return module, module != ""
}

func unquoteNodeString(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"'`")
}

func (p *NodeParser) extractDeclarations(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	if node == nil {
		return
	}
	switch node.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration:
		if decl := p.parseNodeFunction(node, src, filePath, packagePath, "", "", analysis.Imports); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		p.extractDeclarations(node.ChildByFieldName("body"), src, filePath, packagePath, analysis)
		return
	case "lexical_declaration", "variable_declaration":
		p.extractAssignedFunctions(node, src, filePath, packagePath, analysis)
		return
	case javaNodeClassDeclaration:
		p.extractClassMethods(node, src, filePath, packagePath, analysis)
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.extractDeclarations(node.Child(i), src, filePath, packagePath, analysis)
	}
}

func (p *NodeParser) extractAssignedFunctions(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		declarator := node.NamedChild(i)
		if declarator.Type() != nodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName("name")
		value := declarator.ChildByFieldName("value")
		if name == nil || name.Type() != goNodeIdentifier || value == nil || (value.Type() != nodeArrowFunction && value.Type() != nodeFunctionExpression) {
			continue
		}
		if decl := p.parseNodeFunction(value, src, filePath, packagePath, name.Content(src), "", analysis.Imports); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		p.extractDeclarations(value.ChildByFieldName("body"), src, filePath, packagePath, analysis)
	}
}

func (p *NodeParser) extractClassMethods(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	name := node.ChildByFieldName("name")
	body := node.ChildByFieldName("body")
	if name == nil || body == nil {
		return
	}
	owner := name.Content(src)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		method := body.NamedChild(i)
		if method.Type() != nodeMethodDefinition {
			continue
		}
		if decl := p.parseNodeFunction(method, src, filePath, packagePath, "", owner, analysis.Imports); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

func (p *NodeParser) parseNodeFunction(node *sitter.Node, src []byte, filePath, packagePath, fallbackName, owner string, imports map[string]string) *FunctionDecl {
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
	locals := collectNodeLocalNames(params, body, src)
	decl.Calls = p.extractCalls(body, src, filePath, packagePath, owner, imports, locals)
	decl.ReturnSources = p.extractReturnSources(body, src, filePath, packagePath, owner, imports, locals)
	return decl
}

func (p *NodeParser) extractReturnSources(body *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool) []SourceNode {
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

func (p *NodeParser) walkNodeReturnSources(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool, sources *[]SourceNode) {
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

func (p *NodeParser) nodeReturnSource(expr *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool) (SourceNode, bool) {
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
		constructor := expr.ChildByFieldName("constructor")
		if constructor == nil {
			return SourceNode{}, false
		}
		var pkg, typeName string
		switch constructor.Type() {
		case goNodeIdentifier:
			typeName = constructor.Content(src)
			pkg = packagePath
			if importedPackage, ok := nodeImportedPackage(imports, locals, typeName); ok {
				pkg = importedPackage
			}
		case nodeMemberExpression:
			object := constructor.ChildByFieldName("object")
			property := constructor.ChildByFieldName("property")
			if object == nil || property == nil {
				return SourceNode{}, false
			}
			first, suffix := splitNodeMemberObject(object.Content(src))
			var ok bool
			pkg, ok = nodeImportedPackage(imports, locals, first)
			if !ok {
				return SourceNode{}, false
			}
			if suffix != "" {
				pkg += "." + suffix
			}
			typeName = property.Content(src)
		default:
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
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeArrowFunction, nodeFunctionExpression, nodeMethodDefinition, javaNodeClassDeclaration:
		return true
	default:
		return false
	}
}

func (p *NodeParser) extractCalls(body *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool) []FunctionCall {
	var calls []FunctionCall
	p.walkNodeCalls(body, src, filePath, packagePath, owner, imports, locals, &calls)
	return calls
}

func (p *NodeParser) walkNodeCalls(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool, calls *[]FunctionCall) {
	if node == nil {
		return
	}
	if isNodeNestedScope(node.Type()) {
		return
	}
	if node.Type() == nodeCallExpression {
		if call := p.parseNodeCall(node, src, filePath, packagePath, owner, imports, locals); call != nil {
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkNodeCalls(node.Child(i), src, filePath, packagePath, owner, imports, locals, calls)
	}
}

func (p *NodeParser) parseNodeCall(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports map[string]string, locals map[string]bool) *FunctionCall {
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

	switch function.Type() {
	case goNodeIdentifier:
		name := function.Content(src)
		if name == "require" {
			return nil
		}
		call.Callee = FunctionID{Package: packagePath, Name: name}
		if importedPackage, ok := nodeImportedPackage(imports, locals, name); ok {
			call.Callee.Package = importedPackage
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
		importedPackage, importedObject := nodeImportedPackage(imports, locals, first)
		switch {
		case object.Type() != nodeCallExpression && importedObject:
			call.Callee.Package = importedPackage
			if suffix != "" {
				call.Callee.Package += "." + suffix
			}
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

func nodeImportedPackage(imports map[string]string, locals map[string]bool, name string) (string, bool) {
	if locals[name] {
		return "", false
	}
	importedPackage, ok := imports[name]
	return importedPackage, ok
}

func nodeCallArguments(node *sitter.Node, src []byte) []string {
	arguments := node.ChildByFieldName("arguments")
	if arguments == nil {
		return nil
	}
	return parseArgumentsFromDelimitedContent(arguments.Content(src))
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
