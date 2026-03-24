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

// extractClasses walks top-level class and interface declarations.
func (p *JavaParser) extractClasses(root *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case "class_declaration":
			p.processClass(child, src, filePath, analysis, "")
		case "interface_declaration":
			p.processInterface(child, src, filePath, analysis, "")
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

	// First pass: scan constructors for field assignments (this.field = param)
	fieldAssignments := make(map[string]fieldAssignment)
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		if child.Type() == "constructor_declaration" {
			var ctorBody *sitter.Node
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc.Type() == "constructor_body" || gc.Type() == goNodeBlock {
					ctorBody = gc
				}
			}
			for k, v := range p.extractFieldAssignments(child, ctorBody, src, fieldTypes) {
				fieldAssignments[k] = v
			}
		}
	}

	// Second pass: walk class body for methods, constructors, and inner classes
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case "method_declaration":
			decl := p.parseMethodDecl(child, src, filePath, analysis, fullClassName, "class", fieldTypes, fieldAssignments)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "constructor_declaration":
			decl := p.parseConstructorDecl(child, src, filePath, analysis, fullClassName, fieldTypes, fieldAssignments)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "class_declaration":
			p.processClass(child, src, filePath, analysis, fullClassName)
		case "interface_declaration":
			p.processInterface(child, src, filePath, analysis, fullClassName)
		}
	}
}

// processInterface processes an interface declaration and its methods.
func (p *JavaParser) processInterface(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, outerType string) {
	var interfaceName string
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeIdentifier:
			interfaceName = child.Content(src)
		case "interface_body":
			body = child
		}
	}

	if interfaceName == "" || body == nil {
		return
	}

	fullInterfaceName := interfaceName
	if outerType != "" {
		fullInterfaceName = outerType + "." + interfaceName
	}

	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case "method_declaration":
			decl := p.parseMethodDecl(child, src, filePath, analysis, fullInterfaceName, "interface", nil, nil)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "class_declaration":
			p.processClass(child, src, filePath, analysis, fullInterfaceName)
		case "interface_declaration":
			p.processInterface(child, src, filePath, analysis, fullInterfaceName)
		}
	}
}

// parseMethodDecl parses a Java method declaration.
func (p *JavaParser) parseMethodDecl(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	ownerName string,
	ownerType string,
	fieldTypes map[string]string,
	fieldAssignments map[string]fieldAssignment,
) *FunctionDecl {
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

	params := p.extractJavaParameterTypes(node, src)

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: analysis.PackagePath,
			Type:    ownerName,
			Name:    javaMethodWithArity(name, len(params)),
		},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    ownerType,
		OwnerName:    ownerName,
		FunctionType: "method",
		ReturnType:   p.extractMethodReturnType(node, src),
		Parameters:   params,
	}

	if body != nil {
		decl.Calls = p.extractCallsWithFieldTypes(node, body, src, filePath, analysis, fieldTypes, fieldAssignments)
	}

	return decl
}

// parseConstructorDecl parses a Java constructor declaration.
func (p *JavaParser) parseConstructorDecl(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, className string, fieldTypes map[string]string, fieldAssignments map[string]fieldAssignment) *FunctionDecl {
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
		decl.Calls = p.extractCallsWithFieldTypes(node, body, src, filePath, analysis, fieldTypes, fieldAssignments)
	}

	return decl
}

// extractCallsWithFieldTypes walks a method body to find all call expressions,
// using class fields, method parameters, and local variable types for resolution.
func (p *JavaParser) extractCallsWithFieldTypes(
	methodNode *sitter.Node,
	body *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	fieldTypes map[string]string,
	fieldAssignments map[string]fieldAssignment,
) []FunctionCall {
	// Merge field types with local variable types (locals take precedence)
	varTypes := make(map[string]string, len(fieldTypes))
	for k, v := range fieldTypes {
		varTypes[k] = v
	}
	p.collectParameterTypes(methodNode, src, varTypes)
	p.collectVarTypes(body, src, varTypes)

	// Build variable origin map for data flow tracing
	varOrigins := make(map[string]varOrigin)
	// Add field origins with constructor parameter tracing
	for k, v := range fieldTypes {
		origin := varOrigin{typeName: v, kind: "field", paramIndex: -1}
		if fa, ok := fieldAssignments[k]; ok {
			origin.constructorParam = &fa
		}
		varOrigins[k] = origin
	}
	p.collectParameterOrigins(methodNode, src, varOrigins)
	p.collectVarOrigins(body, src, varOrigins, false)

	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, varTypes, varOrigins, &calls)
	return calls
}

// fieldAssignment records that a class field was assigned from a constructor parameter.
type fieldAssignment struct {
	paramName  string // constructor parameter name
	paramIndex int    // parameter index (0-based)
	paramType  string // parameter type
	line       int    // assignment line
}

// varOrigin tracks where a variable's value comes from.
type varOrigin struct {
	typeName        string           // declared type (e.g., "Cipher")
	kind            string           // "parameter", "field", "local_variable"
	initializer     string           // raw initializer expression (e.g., "Cipher.getInstance(\"AES\")")
	line            int              // declaration line
	paramIndex      int              // for parameters: which param (0-based), -1 otherwise
	constructorParam *fieldAssignment // for fields: which constructor param assigned this field
}

// extractFieldAssignments scans a constructor body for `this.field = param` patterns
// and returns a map of field name → constructor parameter source.
func (p *JavaParser) extractFieldAssignments(
	constructorNode *sitter.Node,
	body *sitter.Node,
	src []byte,
	fieldTypes map[string]string,
) map[string]fieldAssignment {
	if body == nil {
		return nil
	}

	// Build param name → (index, type) map from constructor parameters
	paramMap := make(map[string]int)    // name → index
	paramTypes := make(map[string]string) // name → type
	idx := 0
	for i := 0; i < int(constructorNode.ChildCount()); i++ {
		child := constructorNode.Child(i)
		if child.Type() != "formal_parameters" {
			continue
		}
		for name, typ := range parseJavaParameterMapFromList(child.Content(src)) {
			if name != "" {
				paramMap[name] = idx
				paramTypes[name] = typ
				idx++
			}
		}
	}
	if len(paramMap) == 0 {
		return nil
	}

	result := make(map[string]fieldAssignment)
	p.walkForFieldAssignments(body, src, fieldTypes, paramMap, paramTypes, result)
	return result
}

// walkForFieldAssignments recursively walks an AST looking for `this.field = param` assignments.
func (p *JavaParser) walkForFieldAssignments(
	node *sitter.Node,
	src []byte,
	fieldTypes map[string]string,
	paramMap map[string]int,
	paramTypes map[string]string,
	result map[string]fieldAssignment,
) {
	if node.Type() == "assignment_expression" {
		// Check: left side is a field access (this.fieldName) or a known field name
		// and right side is a constructor parameter
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")

		if left != nil && right != nil {
			fieldName := ""
			line := int(node.StartPoint().Row) + 1

			// Check for this.fieldName pattern
			if left.Type() == "field_access" {
				obj := left.ChildByFieldName("object")
				field := left.ChildByFieldName("field")
				if obj != nil && field != nil && obj.Content(src) == "this" {
					fieldName = field.Content(src)
				}
			}
			// Also check simple identifier that matches a known field
			if fieldName == "" && left.Type() == javaNodeIdentifier {
				name := left.Content(src)
				if _, isField := fieldTypes[name]; isField {
					fieldName = name
				}
			}

			if fieldName != "" {
				// Check if right side is a constructor parameter
				rightExpr := strings.TrimSpace(right.Content(src))
				if paramIdx, ok := paramMap[rightExpr]; ok {
					result[fieldName] = fieldAssignment{
						paramName:  rightExpr,
						paramIndex: paramIdx,
						paramType:  paramTypes[rightExpr],
						line:       line,
					}
				}
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForFieldAssignments(node.Child(i), src, fieldTypes, paramMap, paramTypes, result)
	}
}

// collectParameterTypes records method parameter name -> normalized type mappings.
func (p *JavaParser) collectParameterTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if varTypes == nil || node == nil {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "formal_parameters" {
			continue
		}

		for name, typ := range parseJavaParameterMapFromList(child.Content(src)) {
			if name == "" || typ == "" {
				continue
			}
			varTypes[name] = typ
		}
		return
	}
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

// collectParameterOrigins records method parameter origins for data flow tracing.
func (p *JavaParser) collectParameterOrigins(node *sitter.Node, src []byte, origins map[string]varOrigin) {
	if origins == nil || node == nil {
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "formal_parameters" {
			continue
		}
		paramMap := parseJavaParameterMapFromList(child.Content(src))
		paramIdx := 0
		for name, typ := range paramMap {
			if name == "" || typ == "" {
				continue
			}
			origins[name] = varOrigin{
				typeName:   typ,
				kind:       "parameter",
				line:       int(node.StartPoint().Row) + 1,
				paramIndex: paramIdx,
			}
			paramIdx++
		}
		return
	}
}

// collectVarOrigins scans a block for variable declarations and records
// variable name → origin info including initializer expressions.
//
//nolint:gocognit,nestif // Variable/type collection traverses deeply nested Java declaration nodes.
func (p *JavaParser) collectVarOrigins(node *sitter.Node, src []byte, origins map[string]varOrigin, isField bool) {
	nodeType := node.Type()
	if nodeType == "local_variable_declaration" || nodeType == "field_declaration" {
		typeName := p.extractDeclTypeName(node, src)
		if typeName != "" {
			kind := "local_variable"
			if isField || nodeType == "field_declaration" {
				kind = "field"
			}
			for i := 0; i < int(node.ChildCount()); i++ {
				child := node.Child(i)
				if child.Type() == "variable_declarator" {
					varName := ""
					initializer := ""
					for j := 0; j < int(child.ChildCount()); j++ {
						gc := child.Child(j)
						if gc.Type() == javaNodeIdentifier && varName == "" {
							varName = gc.Content(src)
						}
						if gc.Type() == "=" {
							// Next sibling is the initializer value
							if j+1 < int(child.ChildCount()) {
								initializer = strings.TrimSpace(child.Child(j + 1).Content(src))
							}
						}
					}
					if varName != "" {
						origins[varName] = varOrigin{
							typeName:    typeName,
							kind:        kind,
							initializer: initializer,
							line:        int(child.StartPoint().Row) + 1,
							paramIndex:  -1,
						}
					}
				}
			}
		}
	}

	fieldChild := isField || nodeType == "field_declaration"
	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectVarOrigins(node.Child(i), src, origins, fieldChild)
	}
}

// resolveArgumentSources traces where each argument value comes from.
func resolveArgumentSources(args []string, origins map[string]varOrigin) [][]SourceNode {
	if len(args) == 0 {
		return nil
	}
	sources := make([][]SourceNode, len(args))
	for i, arg := range args {
		sources[i] = traceExpression(strings.TrimSpace(arg), origins, 0)
	}
	return sources
}

const maxTraceDepth = 5

// traceExpression resolves a single expression to its source nodes.
func traceExpression(expr string, origins map[string]varOrigin, depth int) []SourceNode {
	if depth > maxTraceDepth || expr == "" {
		return nil
	}

	// String literal
	if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
		return []SourceNode{{Type: "VALUE", Value: expr}}
	}
	// Numeric literal
	if isNumericLiteral(expr) {
		return []SourceNode{{Type: "VALUE", Value: expr}}
	}
	// Boolean/null literals
	if expr == "true" || expr == "false" || expr == "null" {
		return []SourceNode{{Type: "VALUE", Value: expr}}
	}

	// Known variable/parameter/field
	if info, ok := origins[expr]; ok {
		node := SourceNode{
			Type:         kindToSourceType(info.kind),
			Name:         expr,
			DeclaredType: info.typeName,
			Location:     &SourceLocation{Line: info.line},
		}
		if info.kind == "parameter" {
			node.ParameterIndex = info.paramIndex
		}
		// For fields assigned from constructor parameters, trace deeper
		if info.kind == "field" && info.constructorParam != nil {
			fa := info.constructorParam
			node.SourceNodes = []SourceNode{{
				Type:           "PARAMETER",
				Name:           fa.paramName,
				DeclaredType:   fa.paramType,
				ParameterIndex: fa.paramIndex,
				Location:       &SourceLocation{Line: fa.line},
			}}
		} else if info.initializer != "" {
			// Recurse into initializer if available
			node.SourceNodes = traceExpression(info.initializer, origins, depth+1)
		}
		return []SourceNode{node}
	}

	// Enum/static field access like SignatureAlgorithm.HS256
	if strings.Contains(expr, ".") && !strings.Contains(expr, "(") {
		return []SourceNode{{Type: "VALUE", Name: expr, Value: expr}}
	}

	// Method call (contains parentheses)
	if strings.Contains(expr, "(") {
		return []SourceNode{{Type: "CALL_RESULT", Value: expr}}
	}

	// Unknown expression (operator, cast, etc.)
	return []SourceNode{{Type: "EXPRESSION", Value: expr}}
}

func isNumericLiteral(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if i == 0 && c == '-' {
			continue
		}
		if c == '.' || c == 'L' || c == 'f' || c == 'd' || c == 'F' || c == 'D' {
			continue
		}
		if c == 'x' || c == 'X' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue // hex
		}
		return false
	}
	return true
}

func kindToSourceType(kind string) string {
	switch kind {
	case "parameter":
		return "PARAMETER"
	case "field":
		return "FIELD"
	case "local_variable":
		return "VARIABLE"
	default:
		return "VARIABLE"
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
		case "array_type":
			// e.g., byte[] → "byte[]", String[] → "String[]"
			return child.Content(src)
		case "integral_type", "floating_point_type", "boolean_type", "void_type":
			// Primitive types: int, long, float, double, boolean, void
			return child.Content(src)
		}
	}
	return ""
}

func (p *JavaParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varTypes map[string]string, varOrigins map[string]varOrigin, calls *[]FunctionCall) {
	switch node.Type() {
	case "method_invocation":
		if call := p.parseMethodInvocation(node, src, filePath, analysis, varTypes, varOrigins); call != nil {
			*calls = append(*calls, *call)
		}
	case "object_creation_expression":
		if call := p.parseObjectCreation(node, src, filePath, analysis, varOrigins); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, varTypes, varOrigins, calls)
	}
}

// parseMethodInvocation handles method calls like:
//   - Cipher.getInstance("AES")           → static call on class
//   - cipher.doFinal(data)                → instance method call
//   - doSomething()                       → local method call
func (p *JavaParser) parseMethodInvocation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varTypes map[string]string, varOrigins map[string]varOrigin) *FunctionCall {
	var object, method string
	line := int(node.StartPoint().Row) + 1

	if objectNode := node.ChildByFieldName("object"); objectNode != nil {
		object = strings.TrimSpace(objectNode.Content(src))
	}
	if nameNode := node.ChildByFieldName("name"); nameNode != nil {
		method = strings.TrimSpace(nameNode.Content(src))
	}

	// Fallback for older grammar variants where field names may be absent.
	if method == "" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == javaNodeIdentifier {
				method = strings.TrimSpace(child.Content(src))
			}
		}
	}

	if method == "" {
		return nil
	}

	raw := method
	if object != "" {
		raw = object + "." + method
	}

	args := p.extractJavaCallArguments(node, src)
	callee := p.resolveCallee(object, javaMethodWithArity(method, len(args)), analysis, varTypes)
	if method == "newInstance" {
		if target, ok := parseReflectionTargetFromArgs(args); ok {
			callee = target
		}
	}

	return &FunctionCall{
		Callee:          callee,
		Raw:             raw,
		FilePath:        filePath,
		Line:            line,
		Arguments:       args,
		ArgumentSources: resolveArgumentSources(args, varOrigins),
	}
}

// parseObjectCreation handles `new ClassName(...)` expressions.
func (p *JavaParser) parseObjectCreation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varOrigins map[string]varOrigin) *FunctionCall {
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
		Callee:          callee,
		Raw:             "new " + typeName,
		FilePath:        filePath,
		Line:            line,
		Arguments:       args,
		ArgumentSources: resolveArgumentSources(args, varOrigins),
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

func parseJavaParameterMapFromList(listContent string) map[string]string {
	inner := trimOuterDelimiters(listContent, '(', ')')
	if inner == "" {
		return nil
	}

	parts := splitTopLevelCommaList(inner)
	params := make(map[string]string, len(parts))
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean == "" {
			continue
		}

		clean = strings.TrimSpace(strings.ReplaceAll(clean, "final ", ""))
		tokens := strings.Fields(clean)
		if len(tokens) < 2 {
			continue
		}

		filtered := make([]string, 0, len(tokens))
		for _, token := range tokens {
			if strings.HasPrefix(token, "@") {
				continue
			}
			filtered = append(filtered, token)
		}
		if len(filtered) < 2 {
			continue
		}

		name := strings.TrimSpace(filtered[len(filtered)-1])
		typeText := strings.TrimSpace(strings.Join(filtered[:len(filtered)-1], " "))
		if strings.HasPrefix(name, "...") {
			name = strings.TrimPrefix(name, "...")
		}
		normalizedType := normalizeJavaTypeName(typeText)
		if name == "" || normalizedType == "" {
			continue
		}
		params[name] = normalizedType
	}

	if len(params) == 0 {
		return nil
	}
	return params
}

func normalizeJavaTypeName(typeText string) string {
	normalized := strings.TrimSpace(typeText)
	normalized = strings.TrimSuffix(normalized, "...")
	for strings.HasSuffix(normalized, "[]") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "[]"))
	}
	if idx := strings.Index(normalized, "<"); idx > 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	if dot := strings.LastIndex(normalized, "."); dot >= 0 {
		normalized = normalized[dot+1:]
	}
	return strings.TrimSpace(normalized)
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

func parseReflectionTargetFromArgs(args []string) (FunctionID, bool) {
	if len(args) == 0 {
		return FunctionID{}, false
	}
	className, ok := parseJavaStringLiteral(args[0])
	if !ok {
		return FunctionID{}, false
	}
	return functionIDFromQualifiedClass(className)
}

func parseJavaStringLiteral(value string) (string, bool) {
	clean := strings.TrimSpace(value)
	if len(clean) < 2 || clean[0] != '"' || clean[len(clean)-1] != '"' {
		return "", false
	}
	unquoted := strings.Trim(clean, "\"")
	unquoted = strings.TrimSpace(unquoted)
	if unquoted == "" {
		return "", false
	}
	return unquoted, true
}

func functionIDFromQualifiedClass(className string) (FunctionID, bool) {
	lastDot := strings.LastIndex(className, ".")
	if lastDot <= 0 || lastDot >= len(className)-1 {
		return FunctionID{}, false
	}

	return FunctionID{
		Package: className[:lastDot],
		Type:    className[lastDot+1:],
		Name:    constructorMethodName,
	}, true
}

func javaMethodWithArity(name string, arity int) string {
	if name == "" || name == constructorMethodName {
		return name
	}
	return fmt.Sprintf("%s#%d", name, arity)
}
