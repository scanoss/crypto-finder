package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

// PythonParser extracts function declarations, calls, and imports from Python source files
// using tree-sitter for fast, accurate parsing.
type PythonParser struct {
	parser       *sitter.Parser
	includeTests bool
}

const (
	pythonNodeDottedName         = "dotted_name"
	pythonNodeFunctionDefinition = "function_definition"
	pythonSelfObjectName         = "self"
)

// NewPythonParser creates a new Python source parser backed by tree-sitter.
func NewPythonParser(opts ...ParserOption) *PythonParser {
	cfg := newParserConfig(opts)
	p := sitter.NewParser()
	p.SetLanguage(python.GetLanguage())
	return &PythonParser{parser: p, includeTests: cfg.includeTests}
}

// SkipDirs returns directory names to skip during Python source traversal.
func (p *PythonParser) SkipDirs() map[string]bool {
	skip := map[string]bool{
		"__pycache__": true,
		".venv":       true,
		"venv":        true,
		".tox":        true,
	}
	if !p.includeTests {
		skip["test"] = true
		skip["tests"] = true
	}
	return skip
}

// SubPackagePath constructs a child module path using "." separator.
func (p *PythonParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "." + dirName
}

// PackageSeparator returns "." — Python uses dots in module paths.
func (p *PythonParser) PackageSeparator() string {
	return "."
}

// ParseDirectory parses all .py files in a directory.
func (p *PythonParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
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
		if !strings.HasSuffix(name, ".py") {
			continue
		}
		if !p.includeTests && (strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py")) {
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

// parseFile extracts declarations, imports, and calls from a single Python file.
func (p *PythonParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
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
		FilePath:      filePath,
		PackagePath:   packagePath,
		Imports:       make(map[string]string),
		ImportedTypes: make(map[string]bool),
	}

	// Extract imports
	p.extractImports(root, src, analysis)

	// Extract function and class declarations
	p.extractDeclarations(root, src, filePath, packagePath, analysis)

	return analysis, nil
}

// extractImports processes import statements from the module root.
func (p *PythonParser) extractImports(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case "import_statement":
			// `import hashlib` → imports["hashlib"] = "hashlib"
			p.processImportStatement(child, src, analysis)
		case "import_from_statement":
			// `from cryptography.hazmat.primitives import Cipher` → imports["Cipher"] = "cryptography.hazmat.primitives"
			p.processImportFromStatement(child, src, analysis)
		}
	}
}

// processImportStatement handles `import X` and `import X as Y`.
func (p *PythonParser) processImportStatement(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeDottedName:
			// `import hashlib`
			name := child.Content(src)
			// Use the first component as the alias
			parts := strings.Split(name, ".")
			analysis.Imports[parts[0]] = name
		case "aliased_import":
			// `import hashlib as hl`
			var module, alias string
			for j := 0; j < int(child.ChildCount()); j++ {
				grandchild := child.Child(j)
				switch grandchild.Type() {
				case pythonNodeDottedName:
					module = grandchild.Content(src)
				case goNodeIdentifier:
					alias = grandchild.Content(src)
				}
			}
			if alias != "" && module != "" {
				analysis.Imports[alias] = module
			}
		}
	}
}

// processImportFromStatement handles `from X import Y` and `from X import *`.
func (p *PythonParser) processImportFromStatement(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	var modulePath string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeDottedName:
			if modulePath == "" {
				modulePath = child.Content(src)
			} else {
				// This is a name being imported: `from X import name`
				recordImportedPythonSymbol(analysis, child.Content(src), modulePath)
			}
		case goNodeIdentifier:
			// Single name import: `from X import name`
			name := child.Content(src)
			if name != "import" && name != "from" && modulePath != "" {
				recordImportedPythonSymbol(analysis, name, modulePath)
			}
		case "wildcard_import":
			// `from X import *`
			if modulePath != "" {
				analysis.WildcardImports = append(analysis.WildcardImports, modulePath)
			}
		case "import_prefix":
			// Relative import dots — skip these
			continue
		}
	}
}

func recordImportedPythonSymbol(analysis *FileAnalysis, name, modulePath string) {
	analysis.Imports[name] = modulePath
	if looksLikePythonTypeName(name) {
		analysis.ImportedTypes[name] = true
	}
}

// extractDeclarations walks top-level statements for function and class definitions.
func (p *PythonParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "class_definition":
			p.processClass(child, src, filePath, packagePath, analysis)
		case "decorated_definition":
			// Handle decorated functions and classes
			p.processDecorated(child, src, filePath, packagePath, analysis)
		}
	}
}

// parseFunctionDef parses a function_definition node into a FunctionDecl.
func (p *PythonParser) parseFunctionDef(node *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis) *FunctionDecl {
	var name string
	var body *sitter.Node
	var paramNode *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case "parameters":
			paramNode = child
		case "block":
			body = child
		}
	}

	if name == "" {
		return nil
	}

	// Skip dunder methods except __init__
	if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__") && name != "__init__" {
		return nil
	}

	// Map __init__ to <init> for consistency with Java
	funcName := name
	if name == "__init__" {
		funcName = constructorMethodName
	}

	ownerType := "module"
	ownerName := packagePath
	functionType := "function"
	if className != "" {
		ownerType = "class"
		ownerName = className
		functionType = "method"
	}
	if funcName == constructorMethodName {
		functionType = "constructor"
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Type:    className,
			Name:    funcName,
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    ownerType,
		OwnerName:    ownerName,
		FunctionType: functionType,
		ReturnType:   parsePythonReturnType(node.Content(src)),
		Parameters:   parsePythonParameters(paramNode, src),
	}

	if body != nil {
		decl.Calls = p.extractCalls(body, src, filePath, analysis)
	}

	return decl
}

// processClass processes a class_definition node and extracts its methods.
func (p *PythonParser) processClass(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	var className string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			className = child.Content(src)
		case "block":
			body = child
		}
	}

	if className == "" || body == nil {
		return
	}

	// Walk class body for method definitions.
	p.extractClassMethods(body, src, filePath, packagePath, className, analysis)
}

// extractClassMethods extracts method declarations from a class body node.
func (p *PythonParser) extractClassMethods(body *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis) {
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, className, analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "decorated_definition":
			p.extractDecoratedMethod(child, src, filePath, packagePath, className, analysis)
		}
	}
}

// extractDecoratedMethod extracts a method from a decorated_definition within a class.
func (p *PythonParser) extractDecoratedMethod(node *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis) {
	for j := 0; j < int(node.ChildCount()); j++ {
		inner := node.Child(j)
		if inner.Type() != pythonNodeFunctionDefinition {
			continue
		}
		decl := p.parseFunctionDef(inner, src, filePath, packagePath, className, analysis)
		if decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

// processDecorated handles a decorated_definition which wraps a function or class.
func (p *PythonParser) processDecorated(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "class_definition":
			p.processClass(child, src, filePath, packagePath, analysis)
		}
	}
}

// extractCalls walks a function body to find all call expressions.
func (p *PythonParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, &calls)
	return calls
}

func (p *PythonParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, calls *[]FunctionCall) {
	if node.Type() == "call" {
		if call := p.parseCallExpr(node, src, filePath, analysis); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, calls)
	}
}

// parseCallExpr parses a call expression into a FunctionCall.
func (p *PythonParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	raw := funcNode.Content(src)
	args := p.extractPythonCallArguments(node, src)

	switch funcNode.Type() {
	case goNodeIdentifier:
		// Simple call like `sha256()` or imported class constructor like `Cipher()`
		name := funcNode.Content(src)
		if pkg, ok := analysis.Imports[name]; ok {
			if analysis.ImportedTypes[name] {
				return &FunctionCall{
					Callee:    FunctionID{Package: pkg, Type: name, Name: constructorMethodName},
					Raw:       raw,
					FilePath:  filePath,
					Line:      line,
					Arguments: args,
				}
			}

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
	case "attribute":
		// Method/attribute call like `hashlib.sha256()` or `obj.method()`
		return p.parseAttributeCall(funcNode, src, filePath, line, args, analysis)
	}

	return nil
}

func looksLikePythonTypeName(name string) bool {
	if name == "" {
		return false
	}

	first := rune(name[0])
	return first >= 'A' && first <= 'Z'
}

// parseAttributeCall handles calls on attributes like `module.func()` or `obj.method()`.
func (p *PythonParser) parseAttributeCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis) *FunctionCall {
	var object, method string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			if object == "" {
				object = child.Content(src)
			} else {
				method = child.Content(src)
			}
		case "attribute":
			// Chained attribute: `a.b.c()` — recurse
			object = child.Content(src)
		}
	}

	if method == "" {
		return nil
	}

	raw := node.Content(src)

	// "self" calls are local method calls
	if object == pythonSelfObjectName {
		return &FunctionCall{
			Callee:    FunctionID{Package: analysis.PackagePath, Name: method},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Try to resolve the object through imports
	if pkg, ok := analysis.Imports[object]; ok {
		return &FunctionCall{
			Callee:    FunctionID{Package: pkg, Name: method},
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Handle chained attribute access like `cryptography.hazmat.primitives.hashes.SHA256()`
	// Try to resolve by splitting off the first segment
	if dotIdx := strings.Index(object, "."); dotIdx > 0 {
		firstSegment := object[:dotIdx]
		if pkg, ok := analysis.Imports[firstSegment]; ok {
			fullPath := pkg + "." + object[dotIdx+1:]
			return &FunctionCall{
				Callee:    FunctionID{Package: fullPath, Name: method},
				Raw:       raw,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
		}
	}

	// Fallback: assume same package
	return &FunctionCall{
		Callee:    FunctionID{Package: analysis.PackagePath, Type: object, Name: method},
		Raw:       raw,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

func (p *PythonParser) extractPythonCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "argument_list" {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

func parsePythonParameters(node *sitter.Node, src []byte) []FunctionParameter {
	if node == nil {
		return nil
	}

	content := trimOuterParens(node.Content(src))
	if content == "" {
		return nil
	}

	parts := splitTopLevelCommaList(content)
	params := make([]FunctionParameter, 0, len(parts))
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" || clean == "/" || clean == "*" {
			continue
		}
		clean = strings.TrimPrefix(clean, "*")
		clean = strings.TrimPrefix(clean, "*")

		if eq := strings.Index(clean, "="); eq >= 0 {
			clean = strings.TrimSpace(clean[:eq])
		}

		paramType := ""
		if colon := strings.Index(clean, ":"); colon >= 0 {
			paramType = strings.TrimSpace(clean[colon+1:])
		}
		params = append(params, FunctionParameter{Type: paramType})
	}

	return params
}

func parsePythonReturnType(defContent string) string {
	header := defContent
	if idx := strings.Index(header, "\n"); idx >= 0 {
		header = header[:idx]
	}
	if idx := strings.LastIndex(header, ":"); idx >= 0 {
		header = header[:idx]
	}
	if idx := strings.LastIndex(header, "->"); idx >= 0 {
		return strings.TrimSpace(header[idx+2:])
	}
	return ""
}
