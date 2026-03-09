package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

// RustParser extracts function declarations, calls, and imports from Rust source files
// using tree-sitter for fast, accurate parsing.
type RustParser struct {
	parser *sitter.Parser
}

// NewRustParser creates a new Rust source parser backed by tree-sitter.
func NewRustParser() *RustParser {
	p := sitter.NewParser()
	p.SetLanguage(rust.GetLanguage())
	return &RustParser{parser: p}
}

// SkipDirs returns directory names to skip during Rust source traversal.
func (p *RustParser) SkipDirs() map[string]bool {
	return map[string]bool{"target": true, "tests": true, "benches": true, "examples": true}
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

// ParseDirectory parses all .rs files in a directory (excluding test files).
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
		// Skip test files
		if strings.HasSuffix(name, "_test.rs") || name == "tests.rs" {
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
			p.processScopedUseList(child, src, analysis)
		case "use_wildcard":
			// e.g., `use ring::aead::*;` — record as wildcard import
			if prefix != "" {
				analysis.WildcardImports = append(analysis.WildcardImports, prefix)
			}
		}
	}
}

// processScopedUseList handles `path::{item1, item2}` patterns.
func (p *RustParser) processScopedUseList(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	var basePath string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeScopedIdentifier, goNodeIdentifier:
			basePath = child.Content(src)
		case "use_list":
			// Process each item in the list
			for j := 0; j < int(child.ChildCount()); j++ {
				item := child.Child(j)
				switch item.Type() {
				case goNodeIdentifier:
					name := item.Content(src)
					analysis.Imports[name] = basePath
				case javaNodeScopedIdentifier:
					fullPath := item.Content(src)
					lastSep := strings.LastIndex(fullPath, "::")
					if lastSep > 0 {
						name := fullPath[lastSep+2:]
						analysis.Imports[name] = basePath + "::" + fullPath[:lastSep]
					}
				case "scoped_use_list":
					// Nested use list
					p.processScopedUseList(item, src, analysis)
				}
			}
		}
	}
}

// extractDeclarations walks top-level items for functions and impl blocks.
func (p *RustParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case "function_item":
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
		decl.Calls = p.extractCalls(body, src, filePath, analysis)
	}

	return decl
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
		if child.Type() == "function_item" {
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
func (p *RustParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, &calls)
	return calls
}

func (p *RustParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, calls *[]FunctionCall) {
	if node.Type() == "call_expression" {
		if call := p.parseCallExpr(node, src, filePath, analysis); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, calls)
	}
}

// parseCallExpr parses a call_expression into a FunctionCall.
func (p *RustParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) *FunctionCall {
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
	case "field_expression":
		// Method call like `self.encrypt(...)` or `obj.method(...)`
		return p.parseFieldCall(funcNode, src, filePath, line, args, analysis)
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
	return &FunctionCall{
		Callee:    FunctionID{Package: prefix, Name: name},
		Raw:       content,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

// parseFieldCall handles method calls like `obj.method()` or `self.method()`.
func (p *RustParser) parseFieldCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis) *FunctionCall {
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
			Callee:    FunctionID{Package: analysis.PackagePath, Name: field},
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

func parseRustParameters(node *sitter.Node, src []byte) ([]FunctionParameter, bool) {
	if node == nil {
		return nil, false
	}
	content := trimOuterDelimiters(node.Content(src), '(', ')')
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
