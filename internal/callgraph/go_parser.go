package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// GoParser extracts function declarations, calls, and imports from Go source files
// using tree-sitter for fast, accurate parsing.
type GoParser struct {
	parser       *sitter.Parser
	includeTests bool
}

const (
	goNodeIdentifier      = "identifier"
	goNodeBlock           = "block"
	goNodeFieldIdentifier = "field_identifier"
	goNodeTypeIdentifier  = "type_identifier"
	goNodeParameterDecl   = "parameter_declaration"
	goNodeResult          = "result"
	goNodeReturnStatement = "return_statement"
	goNodeExpressionList  = "expression_list"
	goNodeCallExpression  = "call_expression"
)

// NewGoParser creates a new Go source parser backed by tree-sitter.
func NewGoParser(opts ...ParserOption) *GoParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(golang.GetLanguage())
	return &GoParser{parser: parser, includeTests: cfg.includeTests}
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

// ParseDirectory parses all .go files in a directory.
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
		if !strings.HasSuffix(name, ".go") || (!p.includeTests && strings.HasSuffix(name, "_test.go")) {
			continue
		}

		fullPath := filepath.Join(dir, name)
		analysis, err := p.ParseFile(fullPath, packagePath)
		if err != nil {
			log.Error().Err(err).Str("file", fullPath).Str("package", packagePath).Msg("failed to parse file")
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
	var params *sitter.Node
	var result *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case "parameter_list":
			if params == nil {
				params = child
			}
		case goNodeResult:
			result = child
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
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "package",
		OwnerName:    analysis.PackageName,
		FunctionType: "function",
		Parameters:   p.extractParameterTypes(params, src),
	}
	decl.ReturnType = p.extractReturnType(result, src)

	if body != nil {
		varTypes := p.collectGoVarTypes(params, body, src)
		decl.Calls = p.extractCalls(body, src, filePath, analysis, "", "", varTypes)
		decl.ReturnSources = p.extractReturnSources(body, src, filePath, analysis, "", "", varTypes)
	}

	return decl
}

func (p *GoParser) parseMethodDecl(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) *FunctionDecl {
	var name, receiver, receiverVar string
	var body *sitter.Node
	var params *sitter.Node
	var result *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeFieldIdentifier:
			name = child.Content(src)
		case "parameter_list":
			// In method declarations the first parameter_list is the receiver.
			if receiver == "" {
				receiverVar, receiver = p.extractReceiverInfo(child, src)
			} else if params == nil {
				params = child
			}
		case goNodeResult:
			result = child
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
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "type",
		OwnerName:    receiver,
		FunctionType: "method",
		Parameters:   p.extractParameterTypes(params, src),
	}
	decl.ReturnType = p.extractReturnType(result, src)

	if body != nil {
		varTypes := p.collectGoVarTypes(params, body, src)
		decl.Calls = p.extractCalls(body, src, filePath, analysis, receiver, receiverVar, varTypes)
		decl.ReturnSources = p.extractReturnSources(body, src, filePath, analysis, receiver, receiverVar, varTypes)
	}

	return decl
}

func (p *GoParser) extractReturnSources(
	body *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) []SourceNode {
	var sources []SourceNode
	p.walkGoReturnSources(body, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, &sources)
	return sources
}

func (p *GoParser) walkGoReturnSources(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
	sources *[]SourceNode,
) {
	if node.Type() == "func_literal" {
		return
	}
	if node.Type() == goNodeReturnStatement {
		p.appendGoReturnSources(node, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, sources)
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkGoReturnSources(node.Child(i), src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, sources)
	}
}

func (p *GoParser) appendGoReturnSources(
	returnNode *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
	sources *[]SourceNode,
) {
	for i := 0; i < int(returnNode.ChildCount()); i++ {
		child := returnNode.Child(i)
		if child.Type() != goNodeExpressionList {
			continue
		}
		for j := 0; j < int(child.ChildCount()); j++ {
			if source, ok := p.goReturnSource(child.Child(j), src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes); ok {
				*sources = append(*sources, source)
			}
		}
	}
}

func (p *GoParser) goReturnSource(
	expr *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) (SourceNode, bool) {
	location := &SourceLocation{FilePath: filePath, Line: int(expr.StartPoint().Row) + 1}
	switch expr.Type() {
	case goNodeCallExpression:
		call := p.parseCallExpr(expr, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes)
		if call == nil {
			return SourceNode{}, false
		}
		callee := call.Callee
		return SourceNode{Type: "CALL_RESULT", CallTarget: &callee, Location: location}, true
	case goNodeIdentifier:
		return SourceNode{Type: "VARIABLE", Name: expr.Content(src), Location: location}, true
	case "selector_expression":
		return SourceNode{Type: "FIELD", Name: expr.Content(src), Location: location}, true
	case "int_literal", "float_literal", "imaginary_literal", "rune_literal", "raw_string_literal", "interpreted_string_literal", javaNodeBoolLiteralTrue, javaNodeBoolLiteralFalse, "nil":
		return SourceNode{Type: "VALUE", Value: expr.Content(src), Location: location}, true
	}

	return SourceNode{}, false
}

func (p *GoParser) extractReceiverInfo(paramList *sitter.Node, src []byte) (string, string) {
	for i := 0; i < int(paramList.ChildCount()); i++ {
		child := paramList.Child(i)
		if child.Type() == goNodeParameterDecl {
			// Get the type part of the receiver
			var receiverName string
			for j := 0; j < int(child.ChildCount()); j++ {
				typeNode := child.Child(j)
				switch typeNode.Type() {
				case goNodeIdentifier:
					receiverName = typeNode.Content(src)
				case "pointer_type", goNodeTypeIdentifier:
					return receiverName, typeNode.Content(src)
				}
			}
		}
	}
	return "", ""
}

// extractCalls walks a function body to find all call expressions.
func (p *GoParser) extractCalls(
	body *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, &calls)
	return calls
}

func (p *GoParser) walkForCalls(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
	calls *[]FunctionCall,
) {
	if node.Type() == "call_expression" {
		if call := p.parseCallExpr(node, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, calls)
	}
}

func (p *GoParser) parseCallExpr(
	node *sitter.Node,
	src []byte,
	filePath string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	args := p.extractCallArguments(node, src)

	switch funcNode.Type() {
	case "selector_expression":
		return p.parseSelectorCall(funcNode, src, filePath, line, args, analysis, currentReceiverType, currentReceiverVar, varTypes)
	case goNodeIdentifier:
		// Simple call like `doSomething()`
		name := funcNode.Content(src)
		return &FunctionCall{
			Callee: FunctionID{
				Package: analysis.PackagePath,
				Name:    name,
			},
			Raw:       name,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	return nil
}

func (p *GoParser) parseSelectorCall(
	node *sitter.Node,
	src []byte,
	filePath string,
	line int,
	args []string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) *FunctionCall {
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
			Raw:       raw,
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	// Otherwise it's a method call on a variable (e.g., cipher.Encrypt())
	calleePackage, calleeType := p.resolveSelectorReceiverType(operand, analysis, currentReceiverType, currentReceiverVar, varTypes)
	return &FunctionCall{
		Callee: FunctionID{
			Package: calleePackage,
			Type:    calleeType,
			Name:    field,
		},
		ReceiverVar: operand,
		Raw:         raw,
		FilePath:    filePath,
		Line:        line,
		Arguments:   args,
	}
}

func (p *GoParser) collectGoVarTypes(paramsNode, body *sitter.Node, src []byte) map[string]string {
	varTypes := make(map[string]string)
	p.collectGoParameterTypes(paramsNode, src, varTypes)
	p.collectGoLocalVarTypes(body, src, varTypes)
	return varTypes
}

func (p *GoParser) collectGoParameterTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node == nil {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != goNodeParameterDecl {
			continue
		}

		namedCount := int(child.NamedChildCount())
		if namedCount < 2 {
			continue
		}

		typeText := strings.TrimSpace(child.NamedChild(namedCount - 1).Content(src))
		if typeText == "" {
			continue
		}

		for j := 0; j < namedCount-1; j++ {
			nameNode := child.NamedChild(j)
			if nameNode == nil || nameNode.Type() != goNodeIdentifier {
				continue
			}
			varTypes[nameNode.Content(src)] = typeText
		}
	}
}

func (p *GoParser) collectGoLocalVarTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node == nil {
		return
	}

	if node.Type() == "var_spec" {
		text := strings.TrimSpace(node.Content(src))
		if eq := strings.Index(text, "="); eq >= 0 {
			text = strings.TrimSpace(text[:eq])
		}
		fields := strings.Fields(text)
		if len(fields) >= 2 {
			typeText := fields[len(fields)-1]
			namesText := strings.Join(fields[:len(fields)-1], "")
			for _, name := range strings.Split(namesText, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				varTypes[name] = typeText
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectGoLocalVarTypes(node.Child(i), src, varTypes)
	}
}

func (p *GoParser) resolveSelectorReceiverType(
	operand string,
	analysis *FileAnalysis,
	currentReceiverType string,
	currentReceiverVar string,
	varTypes map[string]string,
) (string, string) {
	if operand == currentReceiverVar && currentReceiverType != "" {
		return analysis.PackagePath, currentReceiverType
	}

	typeText, ok := varTypes[operand]
	if !ok || strings.TrimSpace(typeText) == "" {
		return analysis.PackagePath, ""
	}

	trimmed := strings.TrimSpace(typeText)
	pointerPrefix := ""
	for strings.HasPrefix(trimmed, "*") {
		pointerPrefix += "*"
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "*"))
	}

	if dot := strings.Index(trimmed, "."); dot > 0 {
		if importPath, ok := analysis.Imports[trimmed[:dot]]; ok {
			return importPath, pointerPrefix + trimmed[dot+1:]
		}
	}

	return analysis.PackagePath, pointerPrefix + trimmed
}

func (p *GoParser) extractParameterTypes(node *sitter.Node, src []byte) []FunctionParameter {
	if node == nil {
		return nil
	}

	var params []FunctionParameter
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != goNodeParameterDecl {
			continue
		}

		namedCount := int(child.NamedChildCount())
		if namedCount == 0 {
			continue
		}

		typeNode := child.NamedChild(namedCount - 1)
		typeText := strings.TrimSpace(typeNode.Content(src))
		if typeText == "" {
			continue
		}

		paramCount := 1
		if namedCount > 1 {
			paramCount = namedCount - 1
		}
		for j := 0; j < paramCount; j++ {
			params = append(params, FunctionParameter{Type: typeText})
		}
	}

	return params
}

func (p *GoParser) extractReturnType(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.Content(src))
}

func (p *GoParser) extractCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == javaNodeArgumentList {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}
