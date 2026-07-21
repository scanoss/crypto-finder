package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

const (
	rustNodeCallExpression      = "call_expression"
	rustNodeExpressionStatement = "expression_statement"
	rustNodeFieldExpression     = "field_expression"
	rustNodeFunctionItem        = "function_item"
)

// RustParser extracts function declarations, calls, and imports from Rust source files
// using tree-sitter for fast, accurate parsing.
type RustParser struct {
	parser       *sitter.Parser
	includeTests bool
}

// NewRustParser creates a new Rust source parser backed by tree-sitter.
func NewRustParser(opts ...ParserOption) *RustParser {
	cfg := newParserConfig(opts)
	p := sitter.NewParser()
	p.SetLanguage(rust.GetLanguage())
	return &RustParser{parser: p, includeTests: cfg.includeTests}
}

// CloneParser returns an independent RustParser with the same configuration,
// for concurrent use (tree-sitter parsers are not reentrant).
func (p *RustParser) CloneParser() Parser {
	return NewRustParser(WithIncludeTests(p.includeTests))
}

// SkipDirs returns directory names to skip during Rust source traversal.
func (p *RustParser) SkipDirs() map[string]bool {
	skip := map[string]bool{"target": true, "benches": true, "examples": true}
	if !p.includeTests {
		skip["tests"] = true
	}
	return skip
}

// SubPackagePath constructs a child module path using "::" separator.
// In Rust, src/ is the crate root directory and does not correspond to a module —
// it is transparent in the module path. e.g., ring/src/aead/ maps to "ring::aead",
// not "ring::src::aead".
func (p *RustParser) SubPackagePath(parentPath, dirName string) string {
	if dirName == "src" {
		return parentPath
	}
	if parentPath == "" {
		return dirName
	}
	return parentPath + "::" + dirName
}

// PackageSeparator returns "::" — Rust uses double colons in module paths.
func (p *RustParser) PackageSeparator() string {
	return "::"
}

// ParseDirectory parses all .rs files in a directory.
func (p *RustParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rs") {
			continue
		}
		if !p.includeTests && (strings.HasSuffix(name, "_test.rs") || name == "tests.rs") {
			continue
		}

		fullPath := filepath.Join(dir, name)
		analysis, err := p.parseFile(fullPath, packagePath)
		if err != nil {
			continue
		}
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// parseFile extracts declarations, imports, and calls from a single Rust file.
func (p *RustParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filePath, err)
	}
	defer tree.Close()

	root := tree.RootNode()

	analysis := &FileAnalysis{
		FilePath:    filePath,
		PackagePath: packagePath,
		Imports:     make(map[string]string),
	}

	// Extract use declarations (imports)
	p.extractImports(root, src, analysis)

	// Extract function and method declarations with their calls
	p.extractDeclarations(root, src, filePath, packagePath, analysis)

	return analysis, nil
}

// extractImports processes `use` declarations from the root node.
// Handles: `use ring::aead::Aead;` → imports["Aead"] = "ring::aead"
// Handles: `use ring::aead::{Aead, AeadCore};` → imports for each item.
func (p *RustParser) extractImports(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() == "use_declaration" {
			p.processUseDecl(child, src, analysis, "")
		}
	}
}

// processUseDecl recursively processes a use declaration tree.
func (p *RustParser) processUseDecl(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier:
			// e.g., `ring::aead::Aead` — the full path
			fullPath := child.Content(src)
			lastSep := strings.LastIndex(fullPath, "::")
			if lastSep > 0 {
				name := fullPath[lastSep+2:]
				pkg := fullPath[:lastSep]
				analysis.Imports[name] = pkg
			}
		case goNodeIdentifier:
			// Simple import like `use ring;`
			name := child.Content(src)
			if prefix != "" {
				analysis.Imports[name] = prefix
			}
		case "scoped_use_list":
			// e.g., `use ring::aead::{Aead, AeadCore};`
			p.processScopedUseList(child, src, analysis, "")
		case "use_wildcard":
			// e.g., `use ring::aead::*;` — record as wildcard import
			if prefix != "" {
				analysis.WildcardImports = append(analysis.WildcardImports, prefix)
			}
		}
	}
}

// processScopedUseList handles `path::{item1, item2}` patterns.
func (p *RustParser) processScopedUseList(node *sitter.Node, src []byte, analysis *FileAnalysis, prefix string) {
	var basePath string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier, goNodeIdentifier:
			basePath = child.Content(src)
		case "use_list":
			combinedPrefix := combineRustUsePrefix(prefix, basePath)
			p.processRustUseList(child, src, analysis, combinedPrefix)
		}
	}
}

func combineRustUsePrefix(prefix, basePath string) string {
	if prefix == "" {
		return basePath
	}
	if basePath == "" {
		return prefix
	}
	return prefix + "::" + basePath
}

func (p *RustParser) processRustUseList(node *sitter.Node, src []byte, analysis *FileAnalysis, combinedPrefix string) {
	for j := 0; j < int(node.ChildCount()); j++ {
		p.processRustUseListItem(node.Child(j), src, analysis, combinedPrefix)
	}
}

func (p *RustParser) processRustUseListItem(item *sitter.Node, src []byte, analysis *FileAnalysis, combinedPrefix string) {
	switch item.Type() {
	case goNodeIdentifier:
		analysis.Imports[item.Content(src)] = combinedPrefix
	case javaNodeScopedIdentifier:
		p.recordRustScopedImport(item.Content(src), analysis, combinedPrefix)
	case "scoped_use_list":
		p.processScopedUseList(item, src, analysis, combinedPrefix)
	}
}

func (p *RustParser) recordRustScopedImport(fullPath string, analysis *FileAnalysis, combinedPrefix string) {
	lastSep := strings.LastIndex(fullPath, "::")
	if lastSep <= 0 {
		return
	}
	name := fullPath[lastSep+2:]
	importPath := fullPath[:lastSep]
	if combinedPrefix != "" {
		importPath = combinedPrefix + "::" + importPath
	}
	analysis.Imports[name] = importPath
}

// extractDeclarations walks top-level items for functions and impl blocks.
func (p *RustParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case rustNodeFunctionItem:
			decl := p.parseFunctionItem(child, src, filePath, packagePath, "", analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "impl_item":
			p.processImplBlock(child, src, filePath, packagePath, analysis)
		}
	}
}

// parseFunctionItem parses a function_item node into a FunctionDecl.
func (p *RustParser) parseFunctionItem(node *sitter.Node, src []byte, filePath, packagePath, typeName string, analysis *FileAnalysis) *FunctionDecl {
	var name string
	var body *sitter.Node
	var paramsNode *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case "parameters":
			paramsNode = child
		case goNodeBlock:
			body = child
		}
	}

	if name == "" {
		return nil
	}

	parameters, hasSelf := parseRustParameters(paramsNode, src)
	ownerType := "module"
	ownerName := packagePath
	functionType := "function"
	if typeName != "" {
		ownerType = "type"
		ownerName = typeName
		if hasSelf {
			functionType = "method"
		} else {
			functionType = "associated_function"
		}
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Type:    typeName,
			Name:    name,
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    ownerType,
		OwnerName:    ownerName,
		FunctionType: functionType,
		ReturnType:   parseRustReturnType(node.Content(src)),
		Parameters:   parameters,
	}

	if body != nil {
		varTypes := collectRustVarTypes(paramsNode, body, src)
		decl.Calls = p.extractCalls(body, src, filePath, analysis, typeName, varTypes)
		decl.ReturnSources = p.extractReturnSources(body, src, filePath, analysis, typeName, varTypes)
	}

	return decl
}

func (p *RustParser) extractReturnSources(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) []SourceNode {
	var sources []SourceNode
	p.walkForReturnSources(body, src, filePath, analysis, currentReceiverType, varTypes, &sources)
	return append(sources, p.traceRustTailExpression(body, src, filePath, analysis, currentReceiverType, varTypes)...)
}

func (p *RustParser) walkForReturnSources(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string, sources *[]SourceNode) {
	if node == nil {
		return
	}
	if node.Type() == "return_expression" {
		if expr := rustReturnExpressionNode(node); expr != nil {
			*sources = append(*sources, p.traceRustReturnExpression(expr, src, filePath, analysis, currentReceiverType, varTypes)...)
		}
		return
	}
	if node.Type() == rustNodeFunctionItem || node.Type() == "closure_expression" {
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForReturnSources(node.Child(i), src, filePath, analysis, currentReceiverType, varTypes, sources)
	}
}

func rustReturnExpressionNode(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.IsNamed() && child.Type() != "return" {
			return child
		}
	}
	return nil
}

func (p *RustParser) traceRustTailExpression(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) []SourceNode {
	if body == nil || body.Type() != goNodeBlock {
		return nil
	}
	for i := int(body.NamedChildCount()) - 1; i >= 0; i-- {
		child := body.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Type() == rustNodeExpressionStatement && child.NamedChildCount() == 1 && !strings.HasSuffix(strings.TrimSpace(child.Content(src)), ";") {
			return p.traceRustReturnExpression(child.NamedChild(0), src, filePath, analysis, currentReceiverType, varTypes)
		}
		if child.Type() != rustNodeExpressionStatement {
			return p.traceRustReturnExpression(child, src, filePath, analysis, currentReceiverType, varTypes)
		}
		return nil
	}
	return nil
}

func (p *RustParser) traceRustReturnExpression(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) []SourceNode {
	if node == nil {
		return nil
	}
	switch node.Type() {
	case rustNodeCallExpression:
		call := p.parseCallExpr(node, src, filePath, analysis, currentReceiverType, varTypes)
		if call == nil {
			return nil
		}
		return []SourceNode{{
			Type:       "CALL_RESULT",
			Value:      strings.TrimSpace(node.Content(src)),
			CallTarget: &call.Callee,
		}}
	case goNodeIdentifier:
		name := node.Content(src)
		return []SourceNode{{
			Type:         "VARIABLE",
			Name:         name,
			DeclaredType: varTypes[name],
			Location:     &SourceLocation{FilePath: filePath, Line: int(node.StartPoint().Row) + 1},
		}}
	}
	return nil
}

// processImplBlock processes an impl block, extracting the type name
// and all method declarations within it.
func (p *RustParser) processImplBlock(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	var typeName string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeTypeIdentifier, javaNodeGenericType, javaNodeScopedTypeIdentifier:
			if typeName == "" {
				typeName = p.extractTypeName(child, src)
			}
		case "declaration_list":
			body = child
		}
	}

	if typeName == "" || body == nil {
		return
	}

	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		if child.Type() == rustNodeFunctionItem {
			decl := p.parseFunctionItem(child, src, filePath, packagePath, typeName, analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		}
	}
}

// extractTypeName gets the simple type name from various type nodes.
func (p *RustParser) extractTypeName(node *sitter.Node, src []byte) string {
	switch node.Type() {
	case goNodeTypeIdentifier:
		return node.Content(src)
	case javaNodeGenericType:
		// e.g., `MyStruct<T>` — get just "MyStruct"
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == goNodeTypeIdentifier {
				return child.Content(src)
			}
		}
	case javaNodeScopedTypeIdentifier:
		// e.g., `module::Type` — get just the last segment
		content := node.Content(src)
		if idx := strings.LastIndex(content, "::"); idx >= 0 {
			return content[idx+2:]
		}
		return content
	}
	return node.Content(src)
}

// extractCalls walks a function body to find all call expressions.
func (p *RustParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, currentReceiverType, varTypes, &calls)
	return calls
}

func (p *RustParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string, calls *[]FunctionCall) {
	if node.Type() == rustNodeCallExpression {
		if call := p.parseCallExpr(node, src, filePath, analysis, currentReceiverType, varTypes); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, currentReceiverType, varTypes, calls)
	}
}

// parseCallExpr parses a call_expression into a FunctionCall.
func (p *RustParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	raw := funcNode.Content(src)
	args := p.extractRustCallArguments(node, src)

	switch funcNode.Type() {
	case javaNodeScopedIdentifier:
		// e.g., `ring::aead::Aead::new(...)` or `Aead::new(...)`
		return p.parseScopedCall(funcNode, src, filePath, line, args, analysis)
	case goNodeIdentifier:
		// Simple call like `encrypt(...)`
		name := funcNode.Content(src)
		// Check if this identifier was imported
		if pkg, ok := analysis.Imports[name]; ok {
			return &FunctionCall{
				Callee:    FunctionID{Package: pkg, Name: name},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Name: name},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	case rustNodeFieldExpression:
		// Method call like `self.encrypt(...)` or `obj.method(...)`
		return p.parseFieldCall(funcNode, src, filePath, line, args, analysis, currentReceiverType, varTypes)
	}

	return nil
}

// parseScopedCall handles calls like `Type::method()` or `module::func()`.
func (p *RustParser) parseScopedCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis) *FunctionCall {
	content := node.Content(src)
	lastSep := strings.LastIndex(content, "::")
	if lastSep <= 0 {
		return nil
	}

	prefix := content[:lastSep]
	name := content[lastSep+2:]

	// Try to resolve through imports
	// Case 1: prefix is a single identifier that was imported (e.g., `Aead::new`)
	if pkg, ok := analysis.Imports[prefix]; ok {
		return &FunctionCall{
			Callee:    FunctionID{Package: pkg, Type: prefix, Name: name},
			Raw:       content,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Case 2: prefix contains "::" — it's a qualified path (e.g., `ring::aead::new`)
	// Try resolving the first segment
	firstSep := strings.Index(prefix, "::")
	if firstSep > 0 {
		firstSegment := prefix[:firstSep]
		if pkg, ok := analysis.Imports[firstSegment]; ok {
			fullPath := pkg + "::" + prefix[firstSep+2:]
			return &FunctionCall{
				Callee:    FunctionID{Package: fullPath, Name: name},
				Raw:       content,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
	}

	// Fallback: treat the full prefix as the package path
	if lastTypeSep := strings.LastIndex(prefix, "::"); lastTypeSep > 0 {
		typeName := prefix[lastTypeSep+2:]
		if looksLikeRustTypeName(typeName) {
			return &FunctionCall{
				Callee: FunctionID{
					Package: prefix[:lastTypeSep],
					Type:    typeName,
					Name:    name,
				},
				Raw:       content,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}

		return &FunctionCall{
			Callee:    FunctionID{Package: prefix, Name: name},
			Raw:       content,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Fallback: treat the full prefix as the package path
	return &FunctionCall{
		Callee:    FunctionID{Package: prefix, Name: name},
		Raw:       content,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

func looksLikeRustTypeName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}

	for _, r := range name {
		return unicode.IsUpper(r)
	}
	return false
}

// parseFieldCall handles method calls like `obj.method()` or `self.method()`.
func (p *RustParser) parseFieldCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis, currentReceiverType string, varTypes map[string]string) *FunctionCall {
	var object, field string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "identifier", "self":
			if object == "" {
				object = child.Content(src)
			}
		case "field_identifier":
			field = child.Content(src)
		}
	}

	if field == "" {
		return nil
	}

	raw := node.Content(src)

	// "self" calls are local method calls
	if object == "self" {
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Type: currentReceiverType, Name: field},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	if inferredType, ok := varTypes[object]; ok && inferredType != "" {
		if pkg, typ, ok := splitQualifiedRustType(inferredType); ok {
			pkg = resolveRustTypePackage(pkg, analysis)
			return &FunctionCall{
				Callee:    FunctionID{Package: pkg, Type: typ, Name: field},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
		if pkg, ok := analysis.Imports[inferredType]; ok {
			return &FunctionCall{
				Callee:    FunctionID{Package: pkg, Type: inferredType, Name: field},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Type: inferredType, Name: field},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Try to resolve through imports
	if pkg, ok := analysis.Imports[object]; ok {
		return &FunctionCall{
			Callee:    FunctionID{Package: pkg, Type: object, Name: field},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	return &FunctionCall{
		Callee:    FunctionID{Package: analysis.PackagePath, Type: object, Name: field},
		Raw:       raw,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

func (p *RustParser) extractRustCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "arguments" {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

func collectRustVarTypes(paramsNode, body *sitter.Node, src []byte) map[string]string {
	varTypes := collectRustParameterTypes(paramsNode, src)
	collectRustLocalVarTypes(body, src, varTypes)
	return varTypes
}

func collectRustParameterTypes(node *sitter.Node, src []byte) map[string]string {
	if node == nil {
		return map[string]string{}
	}
	content := trimOuterParens(node.Content(src))
	if content == "" {
		return map[string]string{}
	}

	varTypes := make(map[string]string)
	for _, part := range splitTopLevelCommaList(content) {
		name, typ, isSelf := parseRustParameterBinding(part)
		if isSelf || name == "" || typ == "" {
			continue
		}
		varTypes[name] = typ
	}
	return varTypes
}

func parseRustParameterBinding(part string) (name, typ string, isSelf bool) {
	clean := strings.TrimSpace(part)
	if clean == "" {
		return "", "", false
	}
	if strings.Contains(clean, "self") {
		return "", "", true
	}
	idx := strings.Index(clean, ":")
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(clean[:idx])
	name = strings.TrimPrefix(name, "mut ")
	name = strings.TrimPrefix(name, "ref ")
	name = strings.TrimPrefix(name, "&")
	name = strings.TrimSpace(name)
	typ = strings.TrimSpace(clean[idx+1:])
	return name, normalizeRustTypeText(typ), false
}

func collectRustLocalVarTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node == nil {
		return
	}
	if node.Type() == "let_declaration" {
		name, typ := parseRustLetBinding(node.Content(src))
		if name != "" && typ != "" {
			varTypes[name] = typ
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectRustLocalVarTypes(node.Child(i), src, varTypes)
	}
}

func parseRustLetBinding(content string) (name, typ string) {
	clean := strings.TrimSpace(strings.TrimSuffix(content, ";"))
	clean = strings.TrimPrefix(clean, "let ")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return "", ""
	}
	if idx := strings.Index(clean, "="); idx >= 0 {
		left := strings.TrimSpace(clean[:idx])
		right := strings.TrimSpace(clean[idx+1:])
		name, typ = parseRustTypedBinding(left)
		if name != "" && typ != "" {
			return name, typ
		}
		name = sanitizeRustBindingName(left)
		return name, inferRustTypeFromExpr(right)
	}
	name, typ = parseRustTypedBinding(clean)
	return name, typ
}

func parseRustTypedBinding(left string) (name, typ string) {
	idx := strings.Index(left, ":")
	if idx < 0 {
		return "", ""
	}
	name = sanitizeRustBindingName(left[:idx])
	typ = normalizeRustTypeText(left[idx+1:])
	return name, typ
}

func sanitizeRustBindingName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "mut ")
	name = strings.TrimPrefix(name, "ref ")
	name = strings.TrimPrefix(name, "&")
	name = strings.TrimSpace(name)
	return name
}

func inferRustTypeFromExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	if idx := strings.Index(expr, "."); idx >= 0 {
		expr = strings.TrimSpace(expr[:idx])
	}
	if idx := strings.Index(expr, "("); idx >= 0 {
		expr = strings.TrimSpace(expr[:idx])
	}
	lastSep := strings.LastIndex(expr, "::")
	if lastSep <= 0 {
		return ""
	}
	return normalizeRustTypeText(expr[:lastSep])
}

func normalizeRustTypeText(typeText string) string {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return ""
	}
	typeText = strings.TrimPrefix(typeText, "&")
	typeText = strings.TrimPrefix(typeText, "mut ")
	typeText = strings.TrimSpace(typeText)
	if strings.HasPrefix(typeText, "(") && strings.HasSuffix(typeText, ")") {
		typeText = strings.TrimSpace(typeText[1 : len(typeText)-1])
	}
	if idx := strings.Index(typeText, "<"); idx >= 0 {
		typeText = strings.TrimSpace(typeText[:idx])
	}
	return strings.TrimSpace(typeText)
}

func splitQualifiedRustType(typeName string) (pkg, typ string, ok bool) {
	typeName = strings.TrimSpace(typeName)
	lastSep := strings.LastIndex(typeName, "::")
	if lastSep <= 0 || lastSep >= len(typeName)-2 {
		return "", "", false
	}
	return typeName[:lastSep], typeName[lastSep+2:], true
}

func resolveRustTypePackage(pkg string, analysis *FileAnalysis) string {
	if pkg == "" {
		return pkg
	}
	if importedPkg, ok := analysis.Imports[pkg]; ok {
		if strings.Contains(importedPkg, "::") {
			return importedPkg
		}
		return importedPkg + "::" + pkg
	}
	if firstSep := strings.Index(pkg, "::"); firstSep > 0 {
		firstSegment := pkg[:firstSep]
		if importedPkg, ok := analysis.Imports[firstSegment]; ok {
			return importedPkg + "::" + pkg[firstSep+2:]
		}
	}
	return pkg
}

func parseRustParameters(node *sitter.Node, src []byte) ([]FunctionParameter, bool) {
	if node == nil {
		return nil, false
	}
	content := trimOuterParens(node.Content(src))
	if content == "" {
		return nil, false
	}

	parts := splitTopLevelCommaList(content)
	params := make([]FunctionParameter, 0, len(parts))
	hasSelf := false
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" {
			continue
		}
		if strings.Contains(clean, "self") {
			hasSelf = true
		}

		typ := ""
		if idx := strings.Index(clean, ":"); idx >= 0 {
			typ = strings.TrimSpace(clean[idx+1:])
		}
		params = append(params, FunctionParameter{Type: typ})
	}

	return params, hasSelf
}

func parseRustReturnType(funcContent string) string {
	header := funcContent
	if idx := strings.Index(header, "{"); idx >= 0 {
		header = header[:idx]
	}
	if idx := strings.Index(header, "->"); idx >= 0 {
		return strings.TrimSpace(header[idx+2:])
	}
	return ""
}
