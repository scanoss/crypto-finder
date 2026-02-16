package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// GoParser extracts function declarations, calls, and imports from Go source files
// using tree-sitter for fast, accurate parsing.
type GoParser struct {
	parser *sitter.Parser
}

const (
	goNodeIdentifier      = "identifier"
	goNodeBlock           = "block"
	goNodeFieldIdentifier = "field_identifier"
	goNodeTypeIdentifier  = "type_identifier"
)

// NewGoParser creates a new Go source parser backed by tree-sitter.
func NewGoParser() *GoParser {
	parser := sitter.NewParser()
	parser.SetLanguage(golang.GetLanguage())
	return &GoParser{parser: parser}
}

// ParseFile extracts function declarations, imports, and calls from a single Go file.
// packagePath is the Go import path for the package containing this file.
func (p *GoParser) ParseFile(filePath, packagePath string) (*FileAnalysis, error) {
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

	// Extract package name
	analysis.PackageName = p.extractPackageName(root, src)

	// Extract imports
	p.extractImports(root, src, analysis)

	// Extract function and method declarations with their calls
	p.extractFunctions(root, src, filePath, packagePath, analysis)

	return analysis, nil
}

// ParseDirectory parses all .go files in a directory (excluding _test.go files).
func (p *GoParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
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
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		fullPath := filepath.Join(dir, name)
		analysis, err := p.ParseFile(fullPath, packagePath)
		if err != nil {
			// Log and skip files that can't be parsed
			continue
		}
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// SkipDirs returns directory names to skip during Go package traversal.
func (p *GoParser) SkipDirs() map[string]bool {
	return map[string]bool{"vendor": true, "testdata": true}
}

// SubPackagePath constructs a child import path by appending the dir name with "/".
func (p *GoParser) SubPackagePath(parentPath, dirName string) string {
	return parentPath + "/" + dirName
}

// PackageSeparator returns "/" — Go uses forward slashes in import paths.
func (p *GoParser) PackageSeparator() string {
	return "/"
}

func (p *GoParser) extractPackageName(root *sitter.Node, src []byte) string {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() == "package_clause" {
			for j := 0; j < int(child.ChildCount()); j++ {
				nameNode := child.Child(j)
				if nameNode.Type() == "package_identifier" {
					return nameNode.Content(src)
				}
			}
		}
	}
	return ""
}

func (p *GoParser) extractImports(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() != "import_declaration" {
			continue
		}
		p.walkImportNode(child, src, analysis)
	}
}

func (p *GoParser) walkImportNode(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "import_spec":
			p.processImportSpec(child, src, analysis)
		case "import_spec_list":
			for j := 0; j < int(child.ChildCount()); j++ {
				spec := child.Child(j)
				if spec.Type() == "import_spec" {
					p.processImportSpec(spec, src, analysis)
				}
			}
		}
	}
}

func (p *GoParser) processImportSpec(spec *sitter.Node, src []byte, analysis *FileAnalysis) {
	var alias, path string

	for i := 0; i < int(spec.ChildCount()); i++ {
		child := spec.Child(i)
		switch child.Type() {
		case "package_identifier":
			alias = child.Content(src)
		case "interpreted_string_literal":
			// Remove surrounding quotes
			path = strings.Trim(child.Content(src), "\"")
		}
	}

	if path == "" {
		return
	}

	// If no explicit alias, use the last segment of the import path
	if alias == "" {
		parts := strings.Split(path, "/")
		alias = parts[len(parts)-1]
	}

	analysis.Imports[alias] = path
}

func (p *GoParser) extractFunctions(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case "function_declaration":
			decl := p.parseFunctionDecl(child, src, filePath, packagePath, analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "method_declaration":
			decl := p.parseMethodDecl(child, src, filePath, packagePath, analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		}
	}
}

func (p *GoParser) parseFunctionDecl(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) *FunctionDecl {
	var name string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case goNodeBlock:
			body = child
		}
	}

	if name == "" {
		return nil
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Name:    name,
		},
		FilePath:  filePath,
		StartLine: int(node.StartPoint().Row) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
	}

	if body != nil {
		decl.Calls = p.extractCalls(body, src, filePath, analysis)
	}

	return decl
}

func (p *GoParser) parseMethodDecl(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) *FunctionDecl {
	var name, receiver string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeFieldIdentifier:
			name = child.Content(src)
		case "parameter_list":
			// This is the receiver parameter list
			receiver = p.extractReceiverType(child, src)
		case goNodeBlock:
			body = child
		}
	}

	if name == "" {
		return nil
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Type:    receiver,
			Name:    name,
		},
		FilePath:  filePath,
		StartLine: int(node.StartPoint().Row) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
	}

	if body != nil {
		decl.Calls = p.extractCalls(body, src, filePath, analysis)
	}

	return decl
}

func (p *GoParser) extractReceiverType(paramList *sitter.Node, src []byte) string {
	for i := 0; i < int(paramList.ChildCount()); i++ {
		child := paramList.Child(i)
		if child.Type() == "parameter_declaration" {
			// Get the type part of the receiver
			for j := 0; j < int(child.ChildCount()); j++ {
				typeNode := child.Child(j)
				switch typeNode.Type() {
				case "pointer_type", goNodeTypeIdentifier:
					return typeNode.Content(src)
				}
			}
		}
	}
	return ""
}

// extractCalls walks a function body to find all call expressions.
func (p *GoParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, &calls)
	return calls
}

func (p *GoParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, calls *[]FunctionCall) {
	if node.Type() == "call_expression" {
		if call := p.parseCallExpr(node, src, filePath, analysis); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, calls)
	}
}

func (p *GoParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1

	switch funcNode.Type() {
	case "selector_expression":
		return p.parseSelectorCall(funcNode, src, filePath, line, analysis)
	case goNodeIdentifier:
		// Simple call like `doSomething()`
		name := funcNode.Content(src)
		return &FunctionCall{
			Callee: FunctionID{
				Package: analysis.PackagePath,
				Name:    name,
			},
			Raw:      name,
			FilePath: filePath,
			Line:     line,
		}
	}

	return nil
}

func (p *GoParser) parseSelectorCall(node *sitter.Node, src []byte, filePath string, line int, analysis *FileAnalysis) *FunctionCall {
	var operand, field string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			operand = child.Content(src)
		case goNodeFieldIdentifier:
			field = child.Content(src)
		}
	}

	if operand == "" || field == "" {
		return nil
	}

	raw := operand + "." + field

	// Try to resolve the operand as a package import
	if importPath, ok := analysis.Imports[operand]; ok {
		return &FunctionCall{
			Callee: FunctionID{
				Package: importPath,
				Name:    field,
			},
			Raw:      raw,
			FilePath: filePath,
			Line:     line,
		}
	}

	// Otherwise it's a method call on a variable (e.g., cipher.Encrypt())
	// We can't fully resolve the type here, so we record it with the receiver name
	return &FunctionCall{
		Callee: FunctionID{
			Package: analysis.PackagePath,
			Type:    operand,
			Name:    field,
		},
		Raw:      raw,
		FilePath: filePath,
		Line:     line,
	}
}
