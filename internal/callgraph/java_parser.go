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
	parser       *sitter.Parser
	includeTests bool
}

const (
	javaNodeIdentifier           = "identifier"
	javaNodeScopedIdentifier     = "scoped_identifier"
	javaNodeGenericType          = "generic_type"
	javaNodeScopedTypeIdentifier = "scoped_type_identifier"
	javaNodeClassDeclaration     = "class_declaration"
	javaNodeInterfaceDeclaration = "interface_declaration"
	javaNodeFieldDeclaration     = "field_declaration"
	javaNodeMethodDeclaration    = "method_declaration"
	javaNodeFormalParameters     = "formal_parameters"
	javaNodeArgumentList         = "argument_list"
	javaSourceTypeParameter      = "PARAMETER"
	javaVarOriginKindField       = "field"
	javaFunctionTypeMethod       = "method"
	javaFunctionTypeConstructor  = "constructor"
)

// NewJavaParser creates a new Java source parser backed by tree-sitter.
func NewJavaParser(opts ...ParserOption) *JavaParser {
	cfg := newParserConfig(opts)
	p := sitter.NewParser()
	p.SetLanguage(java.GetLanguage())
	return &JavaParser{parser: p, includeTests: cfg.includeTests}
}

// SkipDirs returns directory names to skip during Java source traversal.
func (p *JavaParser) SkipDirs() map[string]bool {
	skip := map[string]bool{"META-INF": true, "target": true}
	if !p.includeTests {
		skip["test"] = true
		skip["tests"] = true
	}
	return skip
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

// ParseDirectory parses all .java files in a directory.
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
		if !p.includeTests && (strings.HasSuffix(name, "Test.java") || strings.HasSuffix(name, "Tests.java")) {
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
		isStatic := strings.HasPrefix(importText, "static ")
		importText = strings.TrimPrefix(importText, "static ")
		importText = strings.TrimSuffix(importText, ";")
		importText = strings.TrimSpace(importText)

		if strings.HasSuffix(importText, ".*") {
			prefix := strings.TrimSuffix(importText, ".*")
			if isStatic {
				analysis.StaticWildcardImports = append(analysis.StaticWildcardImports, prefix)
			} else {
				// Wildcard import: import java.security.*
				analysis.WildcardImports = append(analysis.WildcardImports, prefix)
			}
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
		case javaNodeClassDeclaration:
			p.processClass(child, src, filePath, analysis, "", "")
		case javaNodeInterfaceDeclaration:
			p.processInterface(child, src, filePath, analysis, "", "")
		}
	}
}

// processClass processes a class declaration and its methods.
func (p *JavaParser) processClass(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	outerClass string,
	outerVisibility string,
) {
	className, body := parseJavaClass(node, src)
	if className == "" || body == nil {
		return
	}

	fullClassName := javaNestedTypeName(outerClass, className)
	ownerVisibility := combineJavaOwnerVisibility(outerVisibility, parseJavaDeclaredVisibility(node, src))
	fieldTypes := p.collectJavaFieldTypes(body, src)
	fieldAssignments := p.collectClassFieldAssignments(body, src, filePath, fieldTypes)
	methodDecls, constructorDecls := p.collectJavaClassDecls(body, src, filePath, analysis, fullClassName, ownerVisibility, fieldTypes, fieldAssignments)
	appendJavaDecls(analysis, constructorDecls)
	appendJavaDecls(analysis, methodDecls)
}

func parseJavaClass(node *sitter.Node, src []byte) (string, *sitter.Node) {
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

	return className, body
}

func javaNestedTypeName(outerType, typeName string) string {
	if outerType == "" {
		return typeName
	}
	return outerType + "." + typeName
}

func (p *JavaParser) collectJavaFieldTypes(body *sitter.Node, src []byte) map[string]string {
	fieldTypes := make(map[string]string)
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		if child.Type() == javaNodeFieldDeclaration {
			p.collectVarTypes(child, src, fieldTypes)
		}
	}
	return fieldTypes
}

func (p *JavaParser) collectJavaClassDecls(
	body *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	fullClassName string,
	ownerVisibility string,
	fieldTypes map[string]string,
	fieldAssignments map[string]fieldAssignment,
) ([]*FunctionDecl, []*FunctionDecl) {
	var methodDecls []*FunctionDecl
	var constructorDecls []*FunctionDecl

	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case javaNodeMethodDeclaration:
			if decl := p.parseMethodDecl(child, src, filePath, analysis, fullClassName, "class", ownerVisibility, fieldTypes, fieldAssignments); decl != nil {
				methodDecls = append(methodDecls, decl)
			}
		case "constructor_declaration":
			if decl := p.parseConstructorDecl(child, src, filePath, analysis, fullClassName, ownerVisibility, fieldTypes, fieldAssignments); decl != nil {
				constructorDecls = append(constructorDecls, decl)
			}
		case javaNodeClassDeclaration:
			p.processClass(child, src, filePath, analysis, fullClassName, ownerVisibility)
		case javaNodeInterfaceDeclaration:
			p.processInterface(child, src, filePath, analysis, fullClassName, ownerVisibility)
		}
	}

	disambiguateJavaMethodOverloads(methodDecls)
	disambiguateJavaMethodOverloads(constructorDecls)
	return methodDecls, constructorDecls
}

func appendJavaDecls(analysis *FileAnalysis, decls []*FunctionDecl) {
	for _, decl := range decls {
		analysis.Functions = append(analysis.Functions, *decl)
	}
}

func (p *JavaParser) collectClassFieldAssignments(
	body *sitter.Node,
	src []byte,
	filePath string,
	fieldTypes map[string]string,
) map[string]fieldAssignment {
	assignments := make(map[string]fieldAssignment)
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		if child.Type() != "constructor_declaration" {
			continue
		}
		for key, value := range p.extractFieldAssignments(child, findConstructorBody(child), src, filePath, fieldTypes) {
			assignments[key] = value
		}
	}
	return assignments
}

func findConstructorBody(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "constructor_body" || child.Type() == goNodeBlock {
			return child
		}
	}
	return nil
}

// processInterface processes an interface declaration and its methods.
func (p *JavaParser) processInterface(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	outerType string,
	outerVisibility string,
) {
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
	ownerVisibility := combineJavaOwnerVisibility(outerVisibility, parseJavaDeclaredVisibility(node, src))

	var methodDecls []*FunctionDecl
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case javaNodeMethodDeclaration:
			decl := p.parseMethodDecl(child, src, filePath, analysis, fullInterfaceName, "interface", ownerVisibility, nil, nil)
			if decl != nil {
				methodDecls = append(methodDecls, decl)
			}
		case javaNodeClassDeclaration:
			p.processClass(child, src, filePath, analysis, fullInterfaceName, ownerVisibility)
		case javaNodeInterfaceDeclaration:
			p.processInterface(child, src, filePath, analysis, fullInterfaceName, ownerVisibility)
		}
	}

	disambiguateJavaMethodOverloads(methodDecls)
	for _, decl := range methodDecls {
		analysis.Functions = append(analysis.Functions, *decl)
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
	ownerVisibility string,
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
	returnRaw, returnRef := p.extractMethodReturnTypeRef(node, src)

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: analysis.PackagePath,
			Type:    ownerName,
			Name:    javaMethodWithArity(name, len(params)),
		},
		FilePath:        filePath,
		StartLine:       int(node.StartPoint().Row) + 1,
		EndLine:         int(node.EndPoint().Row) + 1,
		OwnerType:       ownerType,
		OwnerName:       ownerName,
		FunctionType:    javaFunctionTypeMethod,
		ReturnType:      erasedTypeName(returnRaw, returnRef),
		ReturnTypeRef:   returnRef,
		Visibility:      parseJavaMemberVisibility(node, src, ownerType, javaFunctionTypeMethod),
		OwnerVisibility: ownerVisibility,
		Parameters:      params,
	}

	if body != nil {
		decl.Calls = p.extractCallsWithFieldTypes(node, body, src, filePath, analysis, ownerName, fieldTypes, fieldAssignments)
	}

	return decl
}

// parseConstructorDecl parses a Java constructor declaration.
func (p *JavaParser) parseConstructorDecl(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	className string,
	ownerVisibility string,
	fieldTypes map[string]string,
	fieldAssignments map[string]fieldAssignment,
) *FunctionDecl {
	var body *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "constructor_body" || child.Type() == goNodeBlock {
			body = child
		}
	}

	params := p.extractJavaParameterTypes(node, src)

	decl := &FunctionDecl{
		ID: FunctionID{
			Package: analysis.PackagePath,
			Type:    className,
			Name:    javaMethodWithArity(constructorMethodName, len(params)),
		},
		FilePath:        filePath,
		StartLine:       int(node.StartPoint().Row) + 1,
		EndLine:         int(node.EndPoint().Row) + 1,
		OwnerType:       "class",
		OwnerName:       className,
		FunctionType:    javaFunctionTypeConstructor,
		ReturnType:      className,
		Visibility:      parseJavaMemberVisibility(node, src, "class", javaFunctionTypeConstructor),
		OwnerVisibility: ownerVisibility,
		Parameters:      params,
	}

	if body != nil {
		decl.Calls = p.extractCallsWithFieldTypes(node, body, src, filePath, analysis, className, fieldTypes, fieldAssignments)
	}

	return decl
}

func parseJavaDeclaredVisibility(node *sitter.Node, src []byte) string {
	if node == nil {
		return VisibilityPackagePrivate
	}
	modifiers := node.ChildByFieldName("modifiers")
	if visibility, ok := findJavaVisibilityInNode(modifiers, src); ok {
		return visibility
	}
	if visibility, ok := findJavaVisibilityInNode(node, src); ok {
		return visibility
	}
	return VisibilityPackagePrivate
}

func findJavaVisibilityInNode(node *sitter.Node, src []byte) (string, bool) {
	if node == nil {
		return "", false
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		visibility := strings.TrimSpace(node.Child(i).Content(src))
		switch visibility {
		case VisibilityPublic, VisibilityProtected, VisibilityPrivate:
			return visibility, true
		}
	}
	return "", false
}

func parseJavaMemberVisibility(node *sitter.Node, src []byte, ownerType, functionType string) string {
	visibility := parseJavaDeclaredVisibility(node, src)
	if visibility != VisibilityPackagePrivate {
		return visibility
	}
	if ownerType == "interface" && functionType == javaFunctionTypeMethod {
		return VisibilityPublic
	}
	return VisibilityPackagePrivate
}

func combineJavaOwnerVisibility(parentVisibility, declaredVisibility string) string {
	declaredVisibility = normalizeJavaVisibility(declaredVisibility)
	if parentVisibility == "" {
		return declaredVisibility
	}
	parentVisibility = normalizeJavaVisibility(parentVisibility)
	if javaVisibilityRank(parentVisibility) < javaVisibilityRank(declaredVisibility) {
		return parentVisibility
	}
	return declaredVisibility
}

func normalizeJavaVisibility(visibility string) string {
	switch strings.TrimSpace(visibility) {
	case VisibilityPublic:
		return VisibilityPublic
	case VisibilityProtected:
		return VisibilityProtected
	case VisibilityPrivate:
		return VisibilityPrivate
	default:
		return VisibilityPackagePrivate
	}
}

func javaVisibilityRank(visibility string) int {
	switch normalizeJavaVisibility(visibility) {
	case VisibilityPrivate:
		return 0
	case VisibilityPackagePrivate:
		return 1
	case VisibilityProtected:
		return 2
	case VisibilityPublic:
		return 3
	default:
		return 1
	}
}

// extractCallsWithFieldTypes walks a method body to find all call expressions,
// using class fields, method parameters, and local variable types for resolution.
func (p *JavaParser) extractCallsWithFieldTypes(
	methodNode *sitter.Node,
	body *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentClass string,
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
		origin := varOrigin{typeName: v, kind: "field", filePath: filePath, paramIndex: -1}
		if fa, ok := fieldAssignments[k]; ok {
			origin.constructorParam = &fa
		}
		varOrigins[k] = origin
	}
	p.collectParameterOrigins(methodNode, src, filePath, varOrigins)
	p.collectVarOrigins(body, src, filePath, varOrigins, false)

	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, currentClass, varTypes, varOrigins, &calls)
	return calls
}

// fieldAssignment records that a class field was assigned from a constructor parameter.
type fieldAssignment struct {
	paramName  string // constructor parameter name
	paramIndex int    // parameter index (0-based)
	paramType  string // parameter type
	line       int    // assignment line
	filePath   string
}

// varOrigin tracks where a variable's value comes from.
type varOrigin struct {
	typeName         string // declared type (e.g., "Cipher")
	kind             string // "parameter", "field", "local_variable"
	initializer      string // raw initializer expression (e.g., "Cipher.getInstance(\"AES\")")
	line             int    // declaration line
	filePath         string
	paramIndex       int              // for parameters: which param (0-based), -1 otherwise
	constructorParam *fieldAssignment // for fields: which constructor param assigned this field
}

// extractFieldAssignments scans a constructor body for `this.field = param` patterns
// and returns a map of field name → constructor parameter source.
func (p *JavaParser) extractFieldAssignments(
	constructorNode *sitter.Node,
	body *sitter.Node,
	src []byte,
	filePath string,
	fieldTypes map[string]string,
) map[string]fieldAssignment {
	if body == nil {
		return nil
	}

	// Build param name → (index, type) map from constructor parameters
	paramMap := make(map[string]int)      // name → index
	paramTypes := make(map[string]string) // name → type
	idx := 0
	for i := 0; i < int(constructorNode.ChildCount()); i++ {
		child := constructorNode.Child(i)
		if child.Type() != javaNodeFormalParameters {
			continue
		}
		for _, param := range parseJavaParameterList(child.Content(src)) {
			if param.Name != "" {
				paramMap[param.Name] = idx
				paramTypes[param.Name] = param.Type
				idx++
			}
		}
	}
	if len(paramMap) == 0 {
		return nil
	}

	result := make(map[string]fieldAssignment)
	p.walkForFieldAssignments(body, src, filePath, fieldTypes, paramMap, paramTypes, result)
	return result
}

// walkForFieldAssignments recursively walks an AST looking for `this.field = param` assignments.
func (p *JavaParser) walkForFieldAssignments(
	node *sitter.Node,
	src []byte,
	filePath string,
	fieldTypes map[string]string,
	paramMap map[string]int,
	paramTypes map[string]string,
	result map[string]fieldAssignment,
) {
	if assignment := parseFieldAssignmentNode(node, src, filePath, fieldTypes, paramMap, paramTypes); assignment != nil {
		result[assignment.fieldName] = assignment.assignment
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForFieldAssignments(node.Child(i), src, filePath, fieldTypes, paramMap, paramTypes, result)
	}
}

type parsedFieldAssignment struct {
	fieldName  string
	assignment fieldAssignment
}

func parseFieldAssignmentNode(
	node *sitter.Node,
	src []byte,
	filePath string,
	fieldTypes map[string]string,
	paramMap map[string]int,
	paramTypes map[string]string,
) *parsedFieldAssignment {
	if node.Type() != "assignment_expression" {
		return nil
	}
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil || right == nil {
		return nil
	}

	fieldName := assignedFieldName(left, src, fieldTypes)
	if fieldName == "" {
		return nil
	}
	rightExpr := strings.TrimSpace(right.Content(src))
	paramIdx, ok := paramMap[rightExpr]
	if !ok {
		return nil
	}

	return &parsedFieldAssignment{
		fieldName: fieldName,
		assignment: fieldAssignment{
			paramName:  rightExpr,
			paramIndex: paramIdx,
			paramType:  paramTypes[rightExpr],
			line:       int(node.StartPoint().Row) + 1,
			filePath:   filePath,
		},
	}
}

func assignedFieldName(left *sitter.Node, src []byte, fieldTypes map[string]string) string {
	if left.Type() == "field_access" {
		obj := left.ChildByFieldName("object")
		field := left.ChildByFieldName("field")
		if obj != nil && field != nil && obj.Content(src) == "this" {
			return field.Content(src)
		}
	}
	if left.Type() != javaNodeIdentifier {
		return ""
	}
	name := left.Content(src)
	if _, isField := fieldTypes[name]; isField {
		return name
	}
	return ""
}

// collectParameterTypes records method parameter name -> normalized type mappings.
func (p *JavaParser) collectParameterTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if varTypes == nil || node == nil {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != javaNodeFormalParameters {
			continue
		}

		for _, param := range parseJavaParameterList(child.Content(src)) {
			if param.Name == "" || param.Type == "" {
				continue
			}
			varTypes[param.Name] = param.Type
		}
		return
	}
}

// collectVarTypes scans a block for local variable declarations and records
// variable name → declared type name (e.g., "service" → "CryptoService").
//
//nolint:gocognit,nestif // Variable/type collection traverses deeply nested Java declaration nodes.
func (p *JavaParser) collectVarTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node.Type() == javaNodeFormalParameters {
		for _, param := range parseJavaParameterList(node.Content(src)) {
			if param.Name == "" || param.Type == "" {
				continue
			}
			varTypes[param.Name] = param.Type
		}
	}

	if node.Type() == "local_variable_declaration" || node.Type() == javaNodeFieldDeclaration {
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
func (p *JavaParser) collectParameterOrigins(node *sitter.Node, src []byte, filePath string, origins map[string]varOrigin) {
	if origins == nil || node == nil {
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != javaNodeFormalParameters {
			continue
		}
		paramIdx := 0
		for _, param := range parseJavaParameterList(child.Content(src)) {
			if param.Name == "" || param.Type == "" {
				continue
			}
			origins[param.Name] = varOrigin{
				typeName:   param.Type,
				kind:       "parameter",
				line:       int(child.StartPoint().Row) + 1,
				filePath:   filePath,
				paramIndex: paramIdx,
			}
			paramIdx++
		}
		return
	}
}

// collectVarOrigins scans a block for variable declarations and records
// variable name → origin info including initializer expressions.
func (p *JavaParser) collectVarOrigins(node *sitter.Node, src []byte, filePath string, origins map[string]varOrigin, isField bool) {
	nodeType := node.Type()
	if nodeType == "local_variable_declaration" || nodeType == javaNodeFieldDeclaration {
		p.collectDeclarationOrigins(node, src, filePath, origins, isField || nodeType == javaNodeFieldDeclaration)
	}

	fieldChild := isField || nodeType == javaNodeFieldDeclaration
	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectVarOrigins(node.Child(i), src, filePath, origins, fieldChild)
	}
}

func (p *JavaParser) collectDeclarationOrigins(
	node *sitter.Node,
	src []byte,
	filePath string,
	origins map[string]varOrigin,
	isField bool,
) {
	typeName := p.extractDeclTypeName(node, src)
	if typeName == "" {
		return
	}

	kind := "local_variable"
	if isField {
		kind = javaVarOriginKindField
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "variable_declarator" {
			continue
		}
		name, initializer := parseVariableDeclaratorOrigin(child, src)
		if name == "" {
			continue
		}
		origins[name] = varOrigin{
			typeName:    typeName,
			kind:        kind,
			initializer: initializer,
			line:        int(child.StartPoint().Row) + 1,
			filePath:    filePath,
			paramIndex:  -1,
		}
	}
}

func parseVariableDeclaratorOrigin(node *sitter.Node, src []byte) (string, string) {
	name := ""
	initializer := ""
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == javaNodeIdentifier && name == "" {
			name = child.Content(src)
			continue
		}
		if child.Type() == "=" && i+1 < int(node.ChildCount()) {
			initializer = strings.TrimSpace(node.Child(i + 1).Content(src))
		}
	}
	return name, initializer
}

// resolveArgumentSources traces where each argument value comes from.
func (p *JavaParser) resolveArgumentSources(args []string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, origins map[string]varOrigin) [][]SourceNode {
	if len(args) == 0 {
		return nil
	}
	sources := make([][]SourceNode, len(args))
	for i, arg := range args {
		sources[i] = p.traceExpression(strings.TrimSpace(arg), analysis, currentClass, varTypes, origins, 0)
	}
	return sources
}

const maxTraceDepth = 5

// traceExpression resolves a single expression to its source nodes.
func (p *JavaParser) traceExpression(expr string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, origins map[string]varOrigin, depth int) []SourceNode {
	if depth > maxTraceDepth || expr == "" {
		return nil
	}
	if literal := traceLiteralExpression(expr); literal != nil {
		return literal
	}
	if originNodes := p.traceOriginExpression(expr, analysis, currentClass, varTypes, origins, depth); originNodes != nil {
		return originNodes
	}
	if strings.Contains(expr, ".") && !strings.Contains(expr, "(") {
		return []SourceNode{{Type: "VALUE", Name: expr, Value: expr}}
	}
	if constructorNodes := p.traceConstructorExpression(expr, analysis, currentClass); constructorNodes != nil {
		return constructorNodes
	}
	if methodCallNodes := p.traceMethodCallExpression(expr, analysis, currentClass, varTypes, origins, depth); methodCallNodes != nil {
		return methodCallNodes
	}
	return []SourceNode{{Type: "EXPRESSION", Value: expr}}
}

func traceLiteralExpression(expr string) []SourceNode {
	switch {
	case strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\""):
		return []SourceNode{{Type: "VALUE", Value: expr}}
	case isNumericLiteral(expr):
		return []SourceNode{{Type: "VALUE", Value: expr}}
	case expr == "true" || expr == "false" || expr == "null":
		return []SourceNode{{Type: "VALUE", Value: expr}}
	default:
		return nil
	}
}

func (p *JavaParser) traceOriginExpression(
	expr string,
	analysis *FileAnalysis,
	currentClass string,
	varTypes map[string]string,
	origins map[string]varOrigin,
	depth int,
) []SourceNode {
	info, ok := origins[expr]
	if !ok {
		return nil
	}

	node := SourceNode{
		Type:         kindToSourceType(info.kind),
		Name:         expr,
		DeclaredType: info.typeName,
		Location:     &SourceLocation{FilePath: info.filePath, Line: info.line},
	}
	if info.kind == "parameter" {
		node.ParameterIndex = info.paramIndex
	}
	switch {
	case info.kind == javaVarOriginKindField && info.constructorParam != nil:
		node.SourceNodes = fieldConstructorSourceNodes(info.constructorParam)
	case info.initializer != "":
		node.SourceNodes = p.traceExpression(info.initializer, analysis, currentClass, varTypes, origins, depth+1)
	}
	return []SourceNode{node}
}

func fieldConstructorSourceNodes(fa *fieldAssignment) []SourceNode {
	return []SourceNode{{
		Type:           javaSourceTypeParameter,
		Name:           fa.paramName,
		DeclaredType:   fa.paramType,
		ParameterIndex: fa.paramIndex,
		Location:       &SourceLocation{FilePath: fa.filePath, Line: fa.line},
	}}
}

func (p *JavaParser) traceConstructorExpression(expr string, analysis *FileAnalysis, currentClass string) []SourceNode {
	typeName, argc, ok := parseJavaConstructorExpression(expr)
	if !ok {
		return nil
	}
	node := SourceNode{Type: "CALL_RESULT", Value: expr}
	if analysis != nil {
		target := p.resolveCallee(typeName, javaMethodWithArity(constructorMethodName, argc), analysis, currentClass, nil)
		node.CallTarget = &target
	}
	return []SourceNode{node}
}

func (p *JavaParser) traceMethodCallExpression(
	expr string,
	analysis *FileAnalysis,
	currentClass string,
	varTypes map[string]string,
	origins map[string]varOrigin,
	depth int,
) []SourceNode {
	if !strings.Contains(expr, "(") {
		return nil
	}

	node := SourceNode{Type: "CALL_RESULT", Value: expr}
	object, method, argc, ok := parseJavaMethodCallExpression(expr)
	if !ok {
		return []SourceNode{node}
	}
	if receiverSources := p.traceMethodCallReceiverSources(object, analysis, currentClass, varTypes, origins, depth+1); len(receiverSources) > 0 {
		node.SourceNodes = receiverSources
	}
	if analysis != nil {
		target := p.resolveCallee(object, javaMethodWithArity(method, argc), analysis, currentClass, varTypes)
		node.CallTarget = &target
	}
	return []SourceNode{node}
}

func (p *JavaParser) traceMethodCallReceiverSources(
	object string,
	analysis *FileAnalysis,
	currentClass string,
	varTypes map[string]string,
	origins map[string]varOrigin,
	depth int,
) []SourceNode {
	object = strings.TrimSpace(object)
	if object == "" {
		return nil
	}
	if _, ok := origins[object]; ok {
		return p.traceExpression(object, analysis, currentClass, varTypes, origins, depth)
	}
	if strings.HasPrefix(object, "this.") {
		fieldName := strings.TrimSpace(strings.TrimPrefix(object, "this."))
		if _, ok := origins[fieldName]; ok {
			return p.traceExpression(fieldName, analysis, currentClass, varTypes, origins, depth)
		}
	}
	return nil
}

func parseJavaMethodCallExpression(expr string) (object, method string, argc int, ok bool) {
	expr = strings.TrimSpace(expr)
	open := strings.Index(expr, "(")
	closeIdx := strings.LastIndex(expr, ")")
	if open <= 0 || closeIdx <= open {
		return "", "", 0, false
	}
	head := strings.TrimSpace(expr[:open])
	if head == "" {
		return "", "", 0, false
	}
	if dot := strings.LastIndex(head, "."); dot >= 0 {
		object = strings.TrimSpace(head[:dot])
		method = strings.TrimSpace(head[dot+1:])
	} else {
		method = head
	}
	if method == "" {
		return "", "", 0, false
	}
	argc = len(parseArgumentsFromDelimitedContent(expr[open : closeIdx+1]))
	return object, method, argc, true
}

func parseJavaConstructorExpression(expr string) (typeName string, argc int, ok bool) {
	expr = strings.TrimSpace(expr)
	if !strings.HasPrefix(expr, "new ") {
		return "", 0, false
	}
	expr = strings.TrimSpace(strings.TrimPrefix(expr, "new "))
	open := strings.Index(expr, "(")
	closeIdx := strings.LastIndex(expr, ")")
	if open <= 0 || closeIdx <= open {
		return "", 0, false
	}
	typeName = strings.TrimSpace(expr[:open])
	if typeName == "" {
		return "", 0, false
	}
	argc = len(parseArgumentsFromDelimitedContent(expr[open : closeIdx+1]))
	return typeName, argc, true
}

func isNumericLiteral(s string) bool {
	if s == "" {
		return false
	}
	runes := []rune(s)
	start := 0
	if runes[0] == '-' {
		if len(runes) == 1 {
			return false
		}
		start = 1
	}

	if len(runes[start:]) >= 2 && runes[start] == '0' && (runes[start+1] == 'x' || runes[start+1] == 'X') {
		if len(runes[start:]) == 2 {
			return false
		}
		hasDigit := false
		for i := start + 2; i < len(runes); i++ {
			if !isNumericLiteralRune(runes[i], true, false, false) {
				return false
			}
			if runes[i] >= '0' && runes[i] <= '9' {
				hasDigit = true
			}
		}
		return hasDigit
	}

	hasDigit := false
	seenDot := false
	for i := start; i < len(runes); i++ {
		c := runes[i]
		allowDot := !seenDot
		allowSuffix := i == len(runes)-1
		if !isNumericLiteralRune(c, false, allowDot, allowSuffix) {
			return false
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
			continue
		}
		if c == '.' {
			seenDot = true
		}
	}
	return hasDigit
}

func isNumericLiteralRune(c rune, allowHexLetters, allowDot, allowSuffix bool) bool {
	if c >= '0' && c <= '9' {
		return true
	}
	if allowHexLetters && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
		return true
	}
	if allowDot && c == '.' {
		return true
	}
	return allowSuffix && strings.ContainsRune("fFdDlL", c)
}

func kindToSourceType(kind string) string {
	switch kind {
	case "parameter":
		return javaSourceTypeParameter
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
			return child.Content(src)
		case javaNodeScopedTypeIdentifier:
			return child.Content(src)
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

func (p *JavaParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, varOrigins map[string]varOrigin, calls *[]FunctionCall) {
	switch node.Type() {
	case "method_invocation":
		if call := p.parseMethodInvocation(node, src, filePath, analysis, currentClass, varTypes, varOrigins); call != nil {
			*calls = append(*calls, *call)
		}
	case "object_creation_expression":
		if call := p.parseObjectCreation(node, src, filePath, analysis, currentClass, varTypes, varOrigins); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, currentClass, varTypes, varOrigins, calls)
	}
}

// parseMethodInvocation handles method calls like:
//   - Cipher.getInstance("AES")           → static call on class
//   - cipher.doFinal(data)                → instance method call
//   - doSomething()                       → local method call
func (p *JavaParser) parseMethodInvocation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, varOrigins map[string]varOrigin) *FunctionCall {
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
	callee := p.resolveCallee(object, javaMethodWithArity(method, len(args)), analysis, currentClass, varTypes)
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
		ArgumentSources: p.resolveArgumentSources(args, analysis, currentClass, varTypes, varOrigins),
	}
}

// parseObjectCreation handles `new ClassName(...)` expressions.
func (p *JavaParser) parseObjectCreation(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, varOrigins map[string]varOrigin) *FunctionCall {
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

	args := p.extractJavaCallArguments(node, src)
	callee := p.resolveCallee(typeName, javaMethodWithArity(constructorMethodName, len(args)), analysis, currentClass, nil)

	return &FunctionCall{
		Callee:          callee,
		Raw:             "new " + typeName,
		FilePath:        filePath,
		Line:            line,
		Arguments:       args,
		ArgumentSources: p.resolveArgumentSources(args, analysis, currentClass, varTypes, varOrigins),
	}
}

func (p *JavaParser) extractJavaCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == javaNodeArgumentList {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

func (p *JavaParser) extractJavaParameterTypes(node *sitter.Node, src []byte) []FunctionParameter {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != javaNodeFormalParameters {
			continue
		}
		return parseJavaParameterTypesFromList(child.Content(src))
	}
	return nil
}

func parseJavaParameterTypesFromList(listContent string) []FunctionParameter {
	specs := parseJavaParameterList(listContent)
	if len(specs) == 0 {
		return nil
	}
	params := make([]FunctionParameter, 0, len(specs))
	for _, spec := range specs {
		ref := parseSourceTypeRef(spec.RawType)
		params = append(params, FunctionParameter{
			Type:    erasedTypeName(spec.RawType, ref),
			TypeRef: ref,
		})
	}
	return params
}

// erasedTypeName returns the erased simple name for a Java source type. When
// the structured TypeRef carries information (i.e. the parser was able to
// understand the raw text), its Name is preferred since it already reflects
// any generic-argument stripping and short-name reduction. Otherwise the raw
// source string is returned as-is so we never silently lose information.
func erasedTypeName(rawType string, ref TypeRef) string {
	if ref.Name != "" {
		return ref.Name
	}
	return strings.TrimSpace(rawType)
}

type javaParameterSpec struct {
	Name    string
	Type    string
	RawType string
}

func parseJavaParameterList(listContent string) []javaParameterSpec {
	inner := trimOuterParens(listContent)
	if inner == "" {
		return nil
	}

	parts := splitTopLevelCommaList(inner)
	params := make([]javaParameterSpec, 0, len(parts))
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
		name = strings.TrimPrefix(name, "...")
		normalizedType := normalizeJavaReferenceType(typeText)
		if name == "" || normalizedType == "" {
			continue
		}
		params = append(params, javaParameterSpec{
			Name:    name,
			Type:    normalizedType,
			RawType: typeText,
		})
	}

	if len(params) == 0 {
		return nil
	}
	return params
}

func normalizeJavaTypeName(typeText string) string {
	normalized := strings.TrimSpace(typeText)
	arraySuffix := ""
	if strings.HasSuffix(normalized, "...") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "..."))
		arraySuffix = "[]"
	}
	for strings.HasSuffix(normalized, "[]") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "[]"))
		arraySuffix += "[]"
	}
	if idx := strings.Index(normalized, "<"); idx > 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	if dot := strings.LastIndex(normalized, "."); dot >= 0 {
		normalized = normalized[dot+1:]
	}
	return strings.TrimSpace(normalized) + arraySuffix
}

func normalizeJavaReferenceType(typeText string) string {
	normalized := strings.TrimSpace(typeText)
	arraySuffix := ""
	if strings.HasSuffix(normalized, "...") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "..."))
		arraySuffix = "[]"
	}
	for strings.HasSuffix(normalized, "[]") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "[]"))
		arraySuffix += "[]"
	}
	if idx := strings.Index(normalized, "<"); idx > 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return ""
	}
	return normalized + arraySuffix
}

// extractMethodReturnTypeRef returns both the raw text of the return type as
// it appears in the source AST and a structured TypeRef that captures any
// generic parameters declared on it. Callers that only need the raw text can
// use extractMethodReturnType.
func (p *JavaParser) extractMethodReturnTypeRef(node *sitter.Node, src []byte) (string, TypeRef) {
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
			raw := strings.TrimSpace(child.Content(src))
			return raw, parseSourceTypeRef(raw)
		}
	}
	return "", TypeRef{}
}

// parseSourceTypeRef parses a Java source type expression (e.g.
// "Map<String, List<Foo>>", "byte[]", or "java.util.Set<? extends Number>")
// into a structured TypeRef. The Name field is reduced to the simple class
// name; package qualifiers and generic argument syntax are stripped from it
// while generics are surfaced through GenericParameters.
//
// Bounded wildcards drop their bound direction; an unbounded wildcard becomes
// {Name: "?"}.
func parseSourceTypeRef(typeText string) TypeRef {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return TypeRef{}
	}
	if strings.HasSuffix(typeText, "...") {
		return appendArrayDim(parseSourceTypeRef(strings.TrimSpace(strings.TrimSuffix(typeText, "..."))))
	}
	arraySuffix := ""
	for strings.HasSuffix(typeText, "[]") {
		typeText = strings.TrimSpace(strings.TrimSuffix(typeText, "[]"))
		arraySuffix += "[]"
	}
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return TypeRef{Name: arraySuffix}
	}

	if strings.HasPrefix(typeText, "?") {
		return TypeRef{Name: "?" + arraySuffix}
	}

	open := strings.Index(typeText, "<")
	if open < 0 {
		return TypeRef{Name: simpleSourceTypeName(typeText) + arraySuffix}
	}

	base := simpleSourceTypeName(strings.TrimSpace(typeText[:open]))
	closeIdx := findMatchingTypeArgClose(typeText, open)
	if closeIdx < 0 {
		return TypeRef{Name: base + arraySuffix}
	}
	args := splitTopLevelTypeArgs(typeText[open+1 : closeIdx])
	generics := make([]TypeRef, 0, len(args))
	for _, arg := range args {
		generics = append(generics, parseSourceWildcardOrTypeRef(arg))
	}
	return TypeRef{Name: base + arraySuffix, GenericParameters: generics}
}

func parseSourceWildcardOrTypeRef(arg string) TypeRef {
	arg = strings.TrimSpace(arg)
	switch {
	case arg == "?" || arg == "":
		return TypeRef{Name: "?"}
	case strings.HasPrefix(arg, "? extends "):
		return parseSourceTypeRef(strings.TrimSpace(strings.TrimPrefix(arg, "? extends ")))
	case strings.HasPrefix(arg, "? super "):
		return parseSourceTypeRef(strings.TrimSpace(strings.TrimPrefix(arg, "? super ")))
	default:
		return parseSourceTypeRef(arg)
	}
}

func appendArrayDim(ref TypeRef) TypeRef {
	ref.Name += "[]"
	return ref
}

func simpleSourceTypeName(name string) string {
	name = strings.TrimSpace(name)
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	return name
}

func findMatchingTypeArgClose(s string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopLevelTypeArgs(inner string) []string {
	depth := 0
	start := 0
	args := make([]string, 0, 2)
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, strings.TrimSpace(inner[start:]))
	return args
}

// resolveCallee resolves a class/method pair against imports and local variable types.
func (p *JavaParser) resolveCallee(object, method string, analysis *FileAnalysis, currentClass string, varTypes map[string]string) FunctionID {
	if object == "" {
		return resolveJavaLocalCallee(method, analysis, currentClass)
	}

	return resolveJavaObjectCallee(object, method, analysis, varTypes)
}

func resolveJavaLocalCallee(method string, analysis *FileAnalysis, currentClass string) FunctionID {
	if target, ok := resolveImportedJavaLocalCallee(method, analysis); ok {
		return target
	}

	packagePath := javaAnalysisPackagePath(analysis)
	if currentClass != "" {
		return FunctionID{
			Package: packagePath,
			Type:    currentClass,
			Name:    method,
		}
	}

	return FunctionID{
		Package: packagePath,
		Name:    method,
	}
}

func resolveImportedJavaLocalCallee(method string, analysis *FileAnalysis) (FunctionID, bool) {
	if analysis == nil {
		return FunctionID{}, false
	}

	if target, ok := functionIDFromImportedJavaType(analysis.Imports[BaseFunctionName(method)], method, analysis.PackagePath); ok {
		return target, true
	}
	if importedType, ok := resolveJavaStaticWildcardImport(BaseFunctionName(method), analysis.StaticWildcardImports); ok {
		if target, ok := functionIDFromImportedJavaType(importedType, method, analysis.PackagePath); ok {
			return target, true
		}
	}
	return FunctionID{}, false
}

func resolveJavaObjectCallee(object, method string, analysis *FileAnalysis, varTypes map[string]string) FunctionID {
	simpleClass := simpleJavaObjectName(object)

	if target, ok := resolveImportedJavaObjectCallee(object, simpleClass, method, analysis); ok {
		return target
	}
	if target, ok := resolveJavaVariableTypeCallee(object, method, analysis, varTypes); ok {
		return target
	}
	if target, ok := resolveWildcardJavaObjectCallee(simpleClass, method, analysis); ok {
		return target
	}
	if target, ok := functionIDFromQualifiedJavaObject(object, method); ok {
		return target
	}

	return FunctionID{
		Package: javaAnalysisPackagePath(analysis),
		Type:    object,
		Name:    method,
	}
}

func simpleJavaObjectName(object string) string {
	if dot := strings.LastIndex(object, "."); dot >= 0 {
		return object[dot+1:]
	}
	return object
}

func resolveImportedJavaObjectCallee(object, simpleClass, method string, analysis *FileAnalysis) (FunctionID, bool) {
	if analysis == nil {
		return FunctionID{}, false
	}
	if pkg, ok := analysis.Imports[simpleClass]; ok {
		return FunctionID{Package: pkg, Type: simpleClass, Name: method}, true
	}
	if pkg, ok := analysis.Imports[object]; ok {
		return FunctionID{Package: pkg, Type: object, Name: method}, true
	}
	return FunctionID{}, false
}

func resolveJavaVariableTypeCallee(object, method string, analysis *FileAnalysis, varTypes map[string]string) (FunctionID, bool) {
	typeName, ok := varTypes[object]
	if !ok {
		return FunctionID{}, false
	}
	if pkg, typ, ok := splitQualifiedJavaType(typeName); ok {
		return FunctionID{Package: pkg, Type: typ, Name: method}, true
	}
	if analysis != nil {
		if pkg, ok := analysis.Imports[typeName]; ok {
			return FunctionID{Package: pkg, Type: typeName, Name: method}, true
		}
		if pkg, ok := knownWildcardImportPackage(typeName, analysis.WildcardImports); ok {
			return FunctionID{Package: pkg, Type: typeName, Name: method}, true
		}
	}
	return FunctionID{Package: javaAnalysisPackagePath(analysis), Type: typeName, Name: method}, true
}

func resolveWildcardJavaObjectCallee(simpleClass, method string, analysis *FileAnalysis) (FunctionID, bool) {
	if analysis == nil {
		return FunctionID{}, false
	}
	if pkg, ok := preferredWildcardImportPackage(simpleClass, analysis.WildcardImports); ok {
		return FunctionID{Package: pkg, Type: simpleClass, Name: method}, true
	}
	for _, prefix := range analysis.WildcardImports {
		return FunctionID{Package: prefix, Type: simpleClass, Name: method}, true
	}
	return FunctionID{}, false
}

func functionIDFromImportedJavaType(importedType, method, packagePath string) (FunctionID, bool) {
	if importedType == "" {
		return FunctionID{}, false
	}
	if pkg, typ, ok := splitQualifiedJavaType(importedType); ok {
		return FunctionID{Package: pkg, Type: typ, Name: method}, true
	}
	return FunctionID{Package: packagePath, Type: importedType, Name: method}, true
}

func functionIDFromQualifiedJavaObject(object, method string) (FunctionID, bool) {
	if pkg, typ, ok := splitQualifiedJavaType(object); ok {
		return FunctionID{Package: pkg, Type: typ, Name: method}, true
	}
	return FunctionID{}, false
}

func javaAnalysisPackagePath(analysis *FileAnalysis) string {
	if analysis == nil {
		return ""
	}
	return analysis.PackagePath
}

func preferredWildcardImportPackage(simpleClass string, wildcardImports []string) (string, bool) {
	if len(wildcardImports) == 0 || simpleClass == "" {
		return "", false
	}

	if pkg, ok := knownWildcardImportPackage(simpleClass, wildcardImports); ok {
		return pkg, true
	}

	if len(wildcardImports) == 1 {
		return wildcardImports[0], true
	}

	return "", false
}

func knownWildcardImportPackage(simpleClass string, wildcardImports []string) (string, bool) {
	if len(wildcardImports) == 0 || simpleClass == "" {
		return "", false
	}

	if preferred, ok := knownJavaWildcardTypePackages[simpleClass]; ok {
		for _, wildcard := range wildcardImports {
			if wildcard == preferred {
				return wildcard, true
			}
		}
	}

	return "", false
}

var knownJavaWildcardTypePackages = map[string]string{
	"CertificateFactory": "java.security.cert",
	"Cipher":             "javax.crypto",
	"GCMParameterSpec":   "javax.crypto.spec",
	"IvParameterSpec":    "javax.crypto.spec",
	"KeyAgreement":       "javax.crypto",
	"KeyFactory":         "java.security",
	"KeyGenerator":       "javax.crypto",
	"KeyPairGenerator":   "java.security",
	"KeyStore":           "java.security",
	"Mac":                "javax.crypto",
	"MessageDigest":      "java.security",
	"SecretKeyFactory":   "javax.crypto",
	"SecretKeySpec":      "javax.crypto.spec",
	"SecureRandom":       "java.security",
	"Signature":          "java.security",
}

func splitQualifiedJavaType(typeName string) (pkg, typ string, ok bool) {
	typeName = strings.TrimSpace(typeName)
	dot := strings.LastIndex(typeName, ".")
	if dot <= 0 || dot >= len(typeName)-1 {
		return "", "", false
	}
	return typeName[:dot], typeName[dot+1:], true
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
		Name:    javaMethodWithArity(constructorMethodName, 0),
	}, true
}

func javaMethodWithArity(name string, arity int) string {
	if name == "" {
		return name
	}
	return fmt.Sprintf("%s#%d", name, arity)
}

func disambiguateJavaMethodOverloads(decls []*FunctionDecl) {
	groups := make(map[string][]*FunctionDecl)
	for _, decl := range decls {
		if decl == nil {
			continue
		}
		groups[decl.ID.Name] = append(groups[decl.ID.Name], decl)
	}

	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		for _, decl := range group {
			decl.ID.Name = decorateJavaOverloadName(decl.ID.Name, decl.Parameters)
		}
	}
}

func decorateJavaOverloadName(name string, params []FunctionParameter) string {
	if len(params) == 0 {
		return name + "$"
	}

	parts := make([]string, 0, len(params))
	for _, param := range params {
		parts = append(parts, normalizeJavaTypeNameWithPackage(param.Type))
	}
	return name + "$" + strings.Join(parts, ",")
}

func resolveJavaStaticWildcardImport(baseMethod string, wildcardImports []string) (string, bool) {
	if baseMethod == "" {
		return "", false
	}

	for _, importedValue := range wildcardImports {
		if pkg, typ, ok := splitQualifiedJavaType(importedValue); ok && looksLikeJavaTypeName(typ) {
			return pkg + "." + typ, true
		}
	}

	return "", false
}

func looksLikeJavaTypeName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}

	for _, r := range name {
		return r >= 'A' && r <= 'Z'
	}
	return false
}

func normalizeJavaTypeNameWithPackage(typeText string) string {
	normalized := strings.TrimSpace(typeText)
	arraySuffix := ""
	if strings.HasSuffix(normalized, "...") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "..."))
		arraySuffix = "[]"
	}
	for strings.HasSuffix(normalized, "[]") {
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, "[]"))
		arraySuffix += "[]"
	}
	if idx := strings.Index(normalized, "<"); idx > 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	replacer := strings.NewReplacer(".", "_", "$", "_")
	return replacer.Replace(strings.TrimSpace(normalized)) + arraySuffix
}
