package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
)

// JavaParser extracts function declarations, calls, and imports from Java source files
// using tree-sitter for fast, accurate parsing.
type JavaParser struct {
	parser *sitter.Parser
}

const (
	javaNodeIdentifier           = "identifier"
	javaNodeScopedIdentifier     = "scoped_identifier"
	javaNodeGenericType          = "generic_type"
	javaNodeScopedTypeIdentifier = "scoped_type_identifier"
)

// NewJavaParser creates a new Java source parser backed by tree-sitter.
func NewJavaParser() *JavaParser {
	p := sitter.NewParser()
	p.SetLanguage(java.GetLanguage())
	return &JavaParser{parser: p}
}

// SkipDirs returns directory names to skip during Java source traversal.
func (p *JavaParser) SkipDirs() map[string]bool {
	return map[string]bool{"test": true, "tests": true, "META-INF": true, "target": true}
}

// SubPackagePath constructs a child package path using "." separator.
func (p *JavaParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "." + dirName
}

// PackageSeparator returns "." — Java uses dots in package paths.
func (p *JavaParser) PackageSeparator() string {
	return "."
}

// ParseDirectory parses all .java files in a directory (excluding test files).
func (p *JavaParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
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
		if !strings.HasSuffix(name, ".java") {
			continue
		}
		// Skip test files
		if strings.HasSuffix(name, "Test.java") || strings.HasSuffix(name, "Tests.java") {
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

// parseFile extracts declarations, imports, and calls from a single Java file.
func (p *JavaParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
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

	// Extract package declaration
	analysis.PackageName = p.extractPackageName(root, src)
	// Use the declared package if available, otherwise use the provided path
	if analysis.PackageName != "" {
		analysis.PackagePath = analysis.PackageName
	}

	// Extract imports
	p.extractImports(root, src, analysis)

	// Extract class declarations with their methods
	p.extractClasses(root, src, filePath, analysis)

	return analysis, nil
}

// extractPackageName extracts the package name from a package_declaration node.
func (p *JavaParser) extractPackageName(root *sitter.Node, src []byte) string {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() == "package_declaration" {
			// Find the scoped_identifier or identifier child
			for j := 0; j < int(child.ChildCount()); j++ {
				nameNode := child.Child(j)
				if nameNode.Type() == javaNodeScopedIdentifier || nameNode.Type() == javaNodeIdentifier {
					return nameNode.Content(src)
				}
			}
		}
	}
	return ""
}

// extractImports processes import declarations.
func (p *JavaParser) extractImports(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() != "import_declaration" {
			continue
		}

		importText := child.Content(src)
		// Remove "import " prefix and ";" suffix
		importText = strings.TrimPrefix(importText, "import ")
		importText = strings.TrimPrefix(importText, "static ")
		importText = strings.TrimSuffix(importText, ";")
		importText = strings.TrimSpace(importText)

		if strings.HasSuffix(importText, ".*") {
			// Wildcard import: import java.security.*
			prefix := strings.TrimSuffix(importText, ".*")
			analysis.WildcardImports = append(analysis.WildcardImports, prefix)
		} else {
			// Explicit import: import javax.crypto.Cipher → imports["Cipher"] = "javax.crypto"
			lastDot := strings.LastIndex(importText, ".")
			if lastDot > 0 {
				className := importText[lastDot+1:]
				pkg := importText[:lastDot]
				analysis.Imports[className] = pkg
			}
		}
	}
}

// extractClasses walks top-level class declarations.
func (p *JavaParser) extractClasses(root *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() == "class_declaration" {
			p.processClass(child, src, filePath, analysis, "")
		}
	}
}

// processClass processes a class declaration and its methods.
func (p *JavaParser) processClass(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, outerClass string) {
	var className string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeIdentifier:
			className = child.Content(src)
		case "class_body":
			body = child
		}
	}

	if className == "" || body == nil {
		return
	}

	// For inner classes, use OuterClass.InnerClass format
	fullClassName := className
	if outerClass != "" {
		fullClassName = outerClass + "." + className
	}

	// Collect field-level variable types (e.g., "private final SecretKey key;")
	fieldTypes := make(map[string]string)
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		if child.Type() == "field_declaration" {
			p.collectVarTypes(child, src, fieldTypes)
		}
	}

	// Walk class body for methods, constructors, and inner classes
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case "method_declaration":
			decl := p.parseMethodDecl(child, src, filePath, analysis, fullClassName, fieldTypes)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "constructor_declaration":
			decl := p.parseConstructorDecl(child, src, filePath, analysis, fullClassName, fieldTypes)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "class_declaration":
			p.processClass(child, src, filePath, analysis, fullClassName)
		}
	}
}

// parseMethodDecl parses a Java method declaration.
func (p *JavaParser) parseMethodDecl(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, className string, fieldTypes map[string]string) *FunctionDecl {
	var name string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeIdentifier:
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
			Package: analysis.PackagePath,
			Type:    className,
			Name:    name,
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "class",
		OwnerName:    className,
		FunctionType: "method",
		ReturnType:   p.extractMethodReturnType(node, src),
		Parameters:   p.extractJavaParameterTypes(node, src),
	}

	if body != nil {
		decl.Calls = p.extractCallsWithFieldTypes(body, src, filePath, analysis, fieldTypes)
	}

	return decl
}

// parseConstructorDecl parses a Java constructor declaration.
func (p *JavaParser) parseConstructorDecl(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, className string, fieldTypes map[string]string) *FunctionDecl {
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "constructor_body" || child.Type() == goNodeBlock {
			body = child
		}
	}

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: analysis.PackagePath,
			Type:    className,
			Name:    constructorMethodName,
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "class",
		OwnerName:    className,
		FunctionType: "constructor",
		ReturnType:   className,
		Parameters:   p.extractJavaParameterTypes(node, src),
	}

	if body != nil {
		decl.Calls = p.extractCallsWithFieldTypes(body, src, filePath, analysis, fieldTypes)
	}

	return decl
}

// extractCallsWithFieldTypes walks a method body to find all call expressions,
// using both class field types and local variable types for resolution.
func (p *JavaParser) extractCallsWithFieldTypes(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, fieldTypes map[string]string) []FunctionCall {
	// Merge field types with local variable types (locals take precedence)
	varTypes := make(map[string]string, len(fieldTypes))
	for k, v := range fieldTypes {
		varTypes[k] = v
	}
	p.collectVarTypes(body, src, varTypes)

	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, varTypes, &calls)
	return calls
}

// collectVarTypes scans a block for local variable declarations and records
// variable name → declared type name (e.g., "service" → "CryptoService").
//
//nolint:gocognit,nestif // Variable/type collection traverses deeply nested Java declaration nodes.
func (p *JavaParser) collectVarTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node.Type() == "local_variable_declaration" || node.Type() == "field_declaration" {
		typeName := p.extractDeclTypeName(node, src)
		if typeName != "" {
			// Extract variable names from declarators
			for i := 0; i < int(node.ChildCount()); i++ {
				child := node.Child(i)
				if child.Type() == "variable_declarator" {
					for j := 0; j < int(child.ChildCount()); j++ {
						nameNode := child.Child(j)
						if nameNode.Type() == javaNodeIdentifier {
							varTypes[nameNode.Content(src)] = typeName
							break
						}
					}
				}
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectVarTypes(node.Child(i), src, varTypes)
	}
}

// extractDeclTypeName extracts the type name from a variable/field declaration node.
func (p *JavaParser) extractDeclTypeName(node *sitter.Node, src []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeTypeIdentifier:
			return child.Content(src)
		case javaNodeGenericType:
			// e.g., List<String> → "List"
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc.Type() == goNodeTypeIdentifier {
					return gc.Content(src)
				}
			}
		case javaNodeScopedTypeIdentifier:
			// e.g., java.util.Map → use last segment
			content := child.Content(src)
			if dot := strings.LastIndex(content, "."); dot >= 0 {
				return content[dot+1:]
			}
			return content
		}
	}
	return ""
}

func (p *JavaParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varTypes map[string]string, calls *[]FunctionCall) {
	switch node.Type() {
	case "method_invocation":
		if call := p.parseMethodInvocation(node, src, filePath, analysis, varTypes); call != nil {
			*calls = append(*calls, *call)
		}
	case "object_creation_expression":
		if call := p.parseObjectCreation(node, src, filePath, analysis); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, varTypes, calls)
	}
}

// parseMethodInvocation handles method calls like:
//   - Cipher.getInstance("AES")           → static call on class
//   - cipher.doFinal(data)                → instance method call
//   - doSomething()                       → local method call
func (p *JavaParser) parseMethodInvocation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varTypes map[string]string) *FunctionCall {
	var object, method string
	line := int(node.StartPoint().Row) + 1

	// Re-parse more carefully using the full node structure
	// method_invocation children: [object, ".", identifier, argument_list]
	// or: [identifier, argument_list] for simple calls
	object = ""
	method = ""
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeIdentifier:
			if method == "" {
				method = child.Content(src)
			} else {
				// Previous "method" was actually the object
				object = method
				method = child.Content(src)
			}
		case "field_access":
			object = child.Content(src)
		case "method_invocation":
			// Chained call: foo.bar().baz() — the inner call is the object
			object = child.Content(src)
		}
	}

	if method == "" {
		return nil
	}

	raw := method
	if object != "" {
		raw = object + "." + method
	}

	callee := p.resolveCallee(object, method, analysis, varTypes)
	args := p.extractJavaCallArguments(node, src)

	return &FunctionCall{
		Callee:    callee,
		Raw:       raw,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

// parseObjectCreation handles `new ClassName(...)` expressions.
func (p *JavaParser) parseObjectCreation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) *FunctionCall {
	line := int(node.StartPoint().Row) + 1
	var typeName string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeTypeIdentifier:
			typeName = child.Content(src)
		case javaNodeScopedTypeIdentifier:
			typeName = child.Content(src)
		case javaNodeGenericType:
			// e.g., ArrayList<String> — get the base type
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc.Type() == goNodeTypeIdentifier {
					typeName = gc.Content(src)
					break
				}
			}
		}
	}

	if typeName == "" {
		return nil
	}

	callee := p.resolveCallee(typeName, constructorMethodName, analysis, nil)
	args := p.extractJavaCallArguments(node, src)

	return &FunctionCall{
		Callee:    callee,
		Raw:       "new " + typeName,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}

func (p *JavaParser) extractJavaCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "argument_list" {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

func (p *JavaParser) extractJavaParameterTypes(node *sitter.Node, src []byte) []FunctionParameter {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "formal_parameters" {
			continue
		}
		return parseJavaParameterTypesFromList(child.Content(src))
	}
	return nil
}

func parseJavaParameterTypesFromList(listContent string) []FunctionParameter {
	inner := trimOuterDelimiters(listContent, '(', ')')
	if inner == "" {
		return nil
	}

	parts := splitTopLevelCommaList(inner)
	params := make([]FunctionParameter, 0, len(parts))
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" {
			continue
		}

		// Strip common modifiers.
		clean = strings.TrimSpace(strings.ReplaceAll(clean, "final ", ""))
		if strings.HasPrefix(clean, "@") {
			segments := strings.Fields(clean)
			if len(segments) > 1 {
				clean = strings.Join(segments[1:], " ")
			}
		}

		typeText := clean
		if idx := strings.LastIndex(clean, " "); idx > 0 {
			typeText = strings.TrimSpace(clean[:idx])
		}
		params = append(params, FunctionParameter{Type: typeText})
	}

	return params
}

func (p *JavaParser) extractMethodReturnType(node *sitter.Node, src []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeTypeIdentifier,
			javaNodeGenericType,
			javaNodeScopedTypeIdentifier,
			javaNodeScopedIdentifier,
			"integral_type",
			"floating_point_type",
			"boolean_type",
			"void_type",
			"array_type":
			return strings.TrimSpace(child.Content(src))
		}
	}
	return ""
}

// resolveCallee resolves a class/method pair against imports and local variable types.
func (p *JavaParser) resolveCallee(object, method string, analysis *FileAnalysis, varTypes map[string]string) FunctionID {
	if object == "" {
		// Simple local call like `doSomething()`
		return FunctionID{
			Package: analysis.PackagePath,
			Name:    method,
		}
	}

	// Extract the simple class name (handle dotted objects like "System.out")
	simpleClass := object
	if dot := strings.LastIndex(object, "."); dot >= 0 {
		simpleClass = object[dot+1:]
	}

	// 1. Check explicit imports: imports["Cipher"] → "javax.crypto"
	if pkg, ok := analysis.Imports[simpleClass]; ok {
		return FunctionID{
			Package: pkg,
			Type:    simpleClass,
			Name:    method,
		}
	}

	// Also check the full object name for imports (e.g., the object itself was imported)
	if pkg, ok := analysis.Imports[object]; ok {
		return FunctionID{
			Package: pkg,
			Type:    object,
			Name:    method,
		}
	}

	// 2. Check local variable types: service → CryptoService → resolve via imports
	if typeName, ok := varTypes[object]; ok {
		if pkg, ok := analysis.Imports[typeName]; ok {
			return FunctionID{
				Package: pkg,
				Type:    typeName,
				Name:    method,
			}
		}
		// Type is from the same package (no import needed)
		return FunctionID{
			Package: analysis.PackagePath,
			Type:    typeName,
			Name:    method,
		}
	}

	// 3. Check wildcard imports — try each prefix
	for _, prefix := range analysis.WildcardImports {
		// Best-effort: assume the class comes from this wildcard import
		// For crypto detection, this works well since crypto classes are typically
		// imported via wildcards (import java.security.*)
		return FunctionID{
			Package: prefix,
			Type:    simpleClass,
			Name:    method,
		}
	}

	// 4. Fallback: assume same package (unresolved variable method call)
	return FunctionID{
		Package: analysis.PackagePath,
		Type:    object,
		Name:    method,
	}
}
