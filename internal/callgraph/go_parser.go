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
	goNodeReturnStatement = "return_statement"
	goNodeExpressionList  = "expression_list"
	goNodeCallExpression  = "call_expression"
	// Node names verified against tree-sitter-go v0.23.4 node-types.json.
	goNodeShortVarDeclaration = "short_var_declaration"
	goNodeCompositeLiteral    = "composite_literal"
	goNodeTypeConversion      = "type_conversion_expression"
	goNodeUnaryExpression     = "unary_expression"
	goFieldType               = "type"
	goNodeGenericType         = "generic_type"
	goNodePointerType         = "pointer_type"
	goNodeSelectorExpression  = "selector_expression"
	goFieldOperand            = "operand"
	goFieldField              = "field"
	goFieldFunction           = "function"
	goFieldLeft               = "left"
	goFieldRight              = "right"
	goNodeParenExpr           = "parenthesized_expression"
	goNodeAssignmentStmt      = "assignment_statement"
)

// NewGoParser creates a new Go source parser backed by tree-sitter.
func NewGoParser(opts ...ParserOption) *GoParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(golang.GetLanguage())
	return &GoParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent GoParser with the same configuration,
// for concurrent use (tree-sitter parsers are not reentrant).
func (p *GoParser) CloneParser() Parser {
	return NewGoParser(WithIncludeTests(p.includeTests))
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
		if child.Type() == "type_declaration" {
			p.extractInterfaceMethods(child, src, filePath, packagePath, analysis)
			continue
		}
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

// extractInterfaceMethods registers each method of an interface declaration as
// a FunctionDecl with OwnerType "interface". A Go interface method has no body,
// so the walk never produced a declaration for it: a call on an
// interface-typed receiver — `id.Unwrap(...)` with `id age.Identity` — had
// nothing to join, and the builder's generic expandInterfaceDispatch, which
// keys off OwnerType "interface" exactly like Java's interface declarations,
// never fired for Go. Embedded interfaces (type_elem) are not flattened here;
// the dispatch expansion matches by name and arity, which does not need them.
func (p *GoParser) extractInterfaceMethods(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		spec := node.NamedChild(i)
		if spec.Type() != "type_spec" {
			continue
		}
		typeNode := spec.ChildByFieldName(goFieldType)
		nameNode := spec.ChildByFieldName("name")
		if typeNode == nil || nameNode == nil || typeNode.Type() != "interface_type" {
			continue
		}
		ifaceName := strings.TrimSpace(nameNode.Content(src))
		if ifaceName == "" {
			continue
		}
		for j := 0; j < int(typeNode.NamedChildCount()); j++ {
			elem := typeNode.NamedChild(j)
			if elem.Type() != "method_elem" {
				continue
			}
			methodName := ""
			if n := elem.ChildByFieldName("name"); n != nil {
				methodName = strings.TrimSpace(n.Content(src))
			}
			if methodName == "" {
				continue
			}
			decl := &FunctionDecl{
				ID: FunctionID{
					Package: packagePath,
					Type:    ifaceName,
					Name:    methodName,
				},
				FilePath:     filePath,
				StartLine:    int(elem.StartPoint().Row) + 1,
				EndLine:      int(elem.EndPoint().Row) + 1,
				OwnerType:    "interface",
				OwnerName:    ifaceName,
				FunctionType: "method",
				Parameters:   p.extractParameterTypes(elem.ChildByFieldName("parameters"), src),
			}
			decl.ReturnType = p.extractReturnType(elem.ChildByFieldName("result"), src, analysis)
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

func (p *GoParser) parseFunctionDecl(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) *FunctionDecl {
	var name string
	var body *sitter.Node
	var params *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case "parameter_list":
			if params == nil {
				params = child
			}

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
	// "result" is a FIELD of the declaration node, not a node type; the child's
	// own type is pointer_type, type_identifier, or a parameter_list for
	// multi-value returns. Matching a child *typed* "result" never fired, so
	// every Go declaration carried an empty ReturnType and nothing downstream
	// could type a := binding from an in-corpus producer.
	decl.ReturnType = p.extractReturnType(node.ChildByFieldName("result"), src, analysis)

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
		OwnerType:    ownerTypeType,
		OwnerName:    receiver,
		FunctionType: "method",
		Parameters:   p.extractParameterTypes(params, src),
	}
	// "result" is a FIELD of the declaration node, not a node type; the child's
	// own type is pointer_type, type_identifier, or a parameter_list for
	// multi-value returns. Matching a child *typed* "result" never fired, so
	// every Go declaration carried an empty ReturnType and nothing downstream
	// could type a := binding from an in-corpus producer.
	decl.ReturnType = p.extractReturnType(node.ChildByFieldName("result"), src, analysis)

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
				case goNodePointerType, goNodeTypeIdentifier, goNodeGenericType:
					return receiverName, goErasedReceiverType(typeNode, src)
				}
			}
		}
	}
	return "", ""
}

// extractCalls walks a function body to find all call expressions.
// goErasedReceiverType names a method's receiver type with its type arguments
// erased: `Gen[T]` and `*Gen[T]` become `Gen` and `*Gen`.
//
// A generic receiver parses as `generic_type`, which was matched by no case at
// all, so `func (g Gen[T]) Get()` produced a declaration with no owning type —
// orphaned, since no call on a `Gen` value can ever join it. The pointer form
// did match, but kept the `[T]` in the identity, which a call on a `Gen[int]`
// likewise cannot match. Go itself erases type parameters when forming a
// type's method set, so the identity has to erase them too.
func goErasedReceiverType(typeNode *sitter.Node, src []byte) string {
	switch typeNode.Type() {
	case goNodeGenericType:
		if base := typeNode.ChildByFieldName(goFieldType); base != nil {
			return strings.TrimSpace(base.Content(src))
		}
	case goNodePointerType:
		// `*Gen[T]`: the pointed-to type is the sole named child.
		if inner := typeNode.NamedChild(0); inner != nil {
			if erased := goErasedReceiverType(inner, src); erased != "" {
				return "*" + erased
			}
		}
	}
	return strings.TrimSpace(typeNode.Content(src))
}

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
			setFunctionCallASTAnchor(call, node)
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

	var call *FunctionCall
	switch funcNode.Type() {
	case "selector_expression":
		call = p.parseSelectorCall(funcNode, src, filePath, line, args, analysis, currentReceiverType, currentReceiverVar, varTypes)
	case goNodeIdentifier:
		// Simple call like `doSomething()`
		name := funcNode.Content(src)
		if goPredeclaredIdentifiers[name] {
			// A predeclared identifier belongs to no package: it lives in the
			// universe scope (go/types, universe.go), which is the root of the
			// scope tree and exists before any source is read. Emitting it under
			// the caller's package invents a callee — `internal/callgraph.len` —
			// that no declaration can ever match, and `int(x)` is not even a call
			// but a conversion. Neither reaches user code, so neither belongs in
			// a call graph built to answer reachability.
			return nil
		}
		call = &FunctionCall{
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
	if call != nil {
		call.ChainID, call.AssignedVar = goCallChainContext(node, src)
		call.StartCol = int(node.StartPoint().Column) + 1
		call.EndCol = int(node.EndPoint().Column) + 1
	}
	return call
}

// goPredeclaredIdentifiers is Go's universe scope: the predeclared functions,
// types and constants that belong to no package (Go spec, "Predeclared
// identifiers"; go/types builds the same set in universe.go). Types appear here
// because a conversion — `int(x)`, `string(b)` — parses as a call expression.
var goPredeclaredIdentifiers = map[string]bool{
	// functions
	"append": true, "cap": true, "clear": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true, "make": true,
	"max": true, "min": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true,
	// types, reachable as conversions
	"any": true, "bool": true, "byte": true, "comparable": true,
	"complex64": true, "complex128": true, "error": true, "float32": true,
	"float64": true, "int": true, "int8": true, "int16": true, "int32": true,
	"int64": true, "rune": true, "string": true, "uint": true, "uint8": true,
	"uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

// goChainableCallNode unwraps an expression to the call node it denotes, or nil
// when it is not a call: the operand of a chained selector is a call_expression,
// possibly inside parentheses.
func goChainableCallNode(node *sitter.Node) *sitter.Node {
	for node != nil && node.Type() == goNodeParenExpr {
		node = node.NamedChild(0)
	}
	if node != nil && node.Type() == goNodeCallExpression {
		return node
	}
	return nil
}

// goCallChainContext mirrors callChainContext for Go's chain shape, where a
// link is `call_expression → function: selector_expression → operand: <inner
// call>`. Inner links share the root call's start byte as ChainID; the root
// carries the ChainID only when it actually has inner links, plus the variable
// its result is bound to, when any.
func goCallChainContext(node *sitter.Node, src []byte) (chainID, assignedVar string) {
	root := goChainRootNode(node)
	if root != node {
		return fmt.Sprintf("%d", root.StartByte()), ""
	}
	if fn := node.ChildByFieldName(goFieldFunction); fn != nil && fn.Type() == goNodeSelectorExpression {
		if goChainableCallNode(fn.ChildByFieldName(goFieldOperand)) != nil {
			chainID = fmt.Sprintf("%d", root.StartByte())
		}
	}
	return chainID, goAssignedVarFromParent(root, src)
}

// goChainRootNode climbs from a call to the outermost call of its fluent chain:
// the parent selector whose operand is this call, wrapped in the parent call.
func goChainRootNode(node *sitter.Node) *sitter.Node {
	root := node
	for {
		parent := root.Parent()
		for parent != nil && parent.Type() == goNodeParenExpr {
			parent = parent.Parent()
		}
		if parent == nil || parent.Type() != goNodeSelectorExpression {
			break
		}
		grand := parent.Parent()
		if grand == nil || grand.Type() != goNodeCallExpression || grand.ChildByFieldName(goFieldFunction) != parent {
			break
		}
		root = grand
	}
	return root
}

// goAssignedVarFromParent names the variable a call's result is bound to: the
// matching name of a `:=` or `=`, or a `var x = ...` spec. For the multi-valued
// Go idiom `block, err := f(key)` the first non-blank name is the value the
// crypto lifecycle follows; the error is never the crypto object.
func goAssignedVarFromParent(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil || parent.Type() != goNodeExpressionList {
		return ""
	}
	// Only when this call is the sole right-hand expression is the binding
	// unambiguous; `a, b := f(), g()` pairs positionally and is left alone.
	if int(parent.NamedChildCount()) != 1 {
		return ""
	}
	grand := parent.Parent()
	if grand == nil {
		return ""
	}
	switch grand.Type() {
	case goNodeShortVarDeclaration, goNodeAssignmentStmt:
		left := grand.ChildByFieldName(goFieldLeft)
		if left == nil || left == parent {
			return ""
		}
		return goFirstBoundName(left, src)
	case "var_spec":
		// `var h = sha256.New()`: the names sit directly on the spec.
		if name := grand.ChildByFieldName("name"); name != nil {
			return strings.TrimSpace(name.Content(src))
		}
	}
	return ""
}

// goFirstBoundName returns the first non-blank identifier of a binding list:
// for the multi-valued idiom `block, err := f(key)` the first name is the
// value the crypto lifecycle follows; the error is never the crypto object.
func goFirstBoundName(left *sitter.Node, src []byte) string {
	for i := 0; i < int(left.NamedChildCount()); i++ {
		name := left.NamedChild(i)
		if name.Type() != goNodeIdentifier {
			continue
		}
		if text := strings.TrimSpace(name.Content(src)); text != "" && text != "_" {
			return text
		}
	}
	return ""
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
	operandNode := node.ChildByFieldName(goFieldOperand)
	fieldNode := node.ChildByFieldName(goFieldField)
	if operandNode == nil || fieldNode == nil {
		return nil
	}
	field := fieldNode.Content(src)
	if field == "" {
		return nil
	}

	// A selector whose operand is itself a call — `sha256.New().Sum(data)` —
	// is a fluent-chain link. Its receiver type is the inner call's return
	// type, which this per-file pass does not know, so the link is emitted
	// with an empty callee type (the honest form) and its ChainID groups it
	// with the inner call; resolveFluentChainCalleesByContract then seeds the
	// type from the root link's KB contract and rewrites this one. Before
	// this branch existed the link was not emitted at all: the walk only
	// recognized identifier operands, so every chained call vanished from
	// the graph — the crypto idiom `sha256.New().Sum(x)` lost its operation.
	if goChainableCallNode(operandNode) != nil {
		return &FunctionCall{
			Callee:    FunctionID{Name: field},
			Raw:       node.Content(src),
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}

	if operandNode.Type() != goNodeIdentifier {
		return nil
	}
	operand := operandNode.Content(src)
	if operand == "" {
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

	if node.Type() == goNodeShortVarDeclaration {
		p.collectGoShortVarTypes(node, src, varTypes)
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

// collectGoShortVarTypes records the bindings of a short variable declaration
// (`buf := make([]byte, n)`) whose type its right-hand side already states.
//
// Go declares locals with `:=` far more often than with `var x T`, and only the
// latter was read here, so most locals carried no type at all and any method
// call on them fell back to the caller's package. Only the forms that carry
// their type in their own syntax are read: a composite literal, a conversion,
// `make`, `new`, and `&` applied to a composite literal. Binding the result of
// an ordinary call (`c := f()`) needs f's return type, which is not available
// during this per-file pass.
func (p *GoParser) collectGoShortVarTypes(node *sitter.Node, src []byte, varTypes map[string]string) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	count := int(left.NamedChildCount())
	// Differing counts mean one multi-valued call feeds several names
	// (`block, err := aes.NewCipher(key)`); the names cannot be paired here.
	if count == 0 || count != int(right.NamedChildCount()) {
		return
	}
	for i := 0; i < count; i++ {
		nameNode := left.NamedChild(i)
		if nameNode == nil || nameNode.Type() != goNodeIdentifier {
			continue
		}
		name := strings.TrimSpace(nameNode.Content(src))
		if name == "" || name == "_" {
			continue
		}
		if typeText := goSyntacticType(right.NamedChild(i), src); typeText != "" {
			varTypes[name] = typeText
		}
	}
}

// goSyntacticType returns the type an expression states in its own syntax, or
// "" when naming it would require resolving something else first.
func goSyntacticType(expr *sitter.Node, src []byte) string {
	if expr == nil {
		return ""
	}
	switch expr.Type() {
	case goNodeCompositeLiteral, goNodeTypeConversion:
		if t := expr.ChildByFieldName(goFieldType); t != nil {
			return strings.TrimSpace(t.Content(src))
		}
	case goNodeUnaryExpression:
		op := expr.ChildByFieldName("operator")
		if op == nil || strings.TrimSpace(op.Content(src)) != "&" {
			return ""
		}
		if inner := goSyntacticType(expr.ChildByFieldName("operand"), src); inner != "" {
			return "*" + inner
		}
	case goNodeCallExpression:
		fn := expr.ChildByFieldName("function")
		args := expr.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Type() != goNodeIdentifier {
			return ""
		}
		first := args.NamedChild(0)
		if first == nil {
			return ""
		}
		switch strings.TrimSpace(fn.Content(src)) {
		case "make":
			return strings.TrimSpace(first.Content(src))
		case "new":
			return "*" + strings.TrimSpace(first.Content(src))
		}
	}
	return ""
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
		// Unknown receiver: emit no identity at all rather than the caller's
		// package. `cmd.StdoutPipe()` under the caller's package is an identity
		// that LOOKS like a package function — it can coincide with a real
		// same-package name, and, because an edge with no EdgeResolutions entry
		// reads as exact, it presented an unresolved call as resolved proof.
		// The empty form is the honest one the Java parser already emits.
		return "", ""
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

func (p *GoParser) extractReturnType(node *sitter.Node, src []byte, analysis *FileAnalysis) string {
	if node == nil {
		return ""
	}
	return goQualifyReturnType(strings.TrimSpace(node.Content(src)), analysis)
}

// goQualifyReturnType expands the package alias of each component of a
// declared return ("*format.Header" -> "*filippo.io/age/internal/format.Header")
// using the file's imports. The alias only means something inside this file, so
// leaving it in the stored ReturnType made the type unusable anywhere else —
// the builder pass that types := receivers from in-corpus producers had to
// skip every alias-qualified return. An unqualified type is left alone; it is
// qualified with the declaring package where it is consumed.
func goQualifyReturnType(raw string, analysis *FileAnalysis) string {
	if raw == "" || analysis == nil || len(analysis.Imports) == 0 {
		return raw
	}
	if strings.HasPrefix(raw, "(") && strings.HasSuffix(raw, ")") {
		parts := strings.Split(raw[1:len(raw)-1], ",")
		for i := range parts {
			parts[i] = goQualifyReturnType(strings.TrimSpace(parts[i]), analysis)
		}
		return "(" + strings.Join(parts, ", ") + ")"
	}
	core := raw
	prefix := ""
	for strings.HasPrefix(core, "*") {
		prefix += "*"
		core = core[1:]
	}
	dot := strings.Index(core, ".")
	if dot <= 0 {
		return raw
	}
	path, ok := analysis.Imports[core[:dot]]
	if !ok {
		return raw
	}
	return prefix + path + core[dot:]
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
