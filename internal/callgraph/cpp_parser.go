package callgraph

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	treecpp "github.com/smacker/go-tree-sitter/cpp"
)

const cppNodeFunctionDefinition = "function_definition"

// CPPParser extracts C++ function declarations, calls, and include paths.
type CPPParser struct {
	parser       *sitter.Parser
	includeTests bool
	anchors      callAnchors
}

// NewCPPParser creates a C++ source parser backed by tree-sitter.
func NewCPPParser(opts ...ParserOption) *CPPParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(treecpp.GetLanguage())
	return &CPPParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent parser for concurrent use.
func (p *CPPParser) CloneParser() Parser {
	return NewCPPParser(WithIncludeTests(p.includeTests))
}

// ParseDirectory parses C++ source and header files directly under dir.
func (p *CPPParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("callgraph: cpp parser: read directory %s: %w", dir, err)
	}

	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isCPPFile(entry.Name()) || (!p.includeTests && strings.Contains(strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())), "_test")) {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		analysis, err := p.parseFile(filePath, packagePath)
		if err != nil {
			log.Error().Err(err).Str("file", filePath).Str("package", packagePath).Msg("failed to parse file")
			continue
		}
		analyses = append(analyses, analysis)
	}
	return analyses, nil
}

func isCPPFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".cc", ".cp", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++":
		return true
	default:
		return false
	}
}

func (p *CPPParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: cpp parser: read %s: %w", filePath, err)
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: cpp parser: parse %s: %w", filePath, err)
	}
	defer tree.Close()
	defer p.anchors.reset()

	analysis := &FileAnalysis{
		FilePath:      filePath,
		PackageName:   packagePath,
		PackagePath:   packagePath,
		Imports:       make(map[string]string),
		DeclaredTypes: make(map[string]bool),
	}
	staticFunctions := make(map[string]bool)
	collectCPPStaticFunctions(tree.RootNode(), src, staticFunctions)
	collectCPPDeclaredTypes(tree.RootNode(), src, "", analysis.DeclaredTypes)
	p.walkFile(tree.RootNode(), src, filePath, packagePath, "", staticFunctions, analysis.DeclaredTypes, analysis)
	return analysis, nil
}

func (p *CPPParser) walkFile(node *sitter.Node, src []byte, filePath, packagePath, scope string, staticFunctions, localTypes map[string]bool, analysis *FileAnalysis) {
	switch node.Type() {
	case "preproc_include":
		p.extractInclude(node, src, analysis)
	case cppNodeFunctionDefinition:
		if decl := p.parseFunction(node, src, filePath, packagePath, scope, staticFunctions, localTypes); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		return
	}
	scope = cppNestedScope(node, src, scope)
	childScope := scope
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if next, handled := cppMacroScope(child, src, childScope, scope); handled {
			childScope = next
			continue
		}
		p.walkFile(child, src, filePath, packagePath, childScope, staticFunctions, localTypes, analysis)
	}
}

// cppMacroScope tracks namespaces opened by a macro instead of a `namespace`
// block. The macro leaves the declarations as siblings, not children, so the
// scope has to carry forward across them rather than nest. Crypto++'s
// NAMESPACE_BEGIN(CryptoPP) is the case this exists for; without it every type
// in such a library resolves unqualified and no contract or rule anchored on the
// qualified name can match the library's own sources.
func cppMacroScope(node *sitter.Node, src []byte, current, outer string) (string, bool) {
	name, kind := cppNamespaceMacro(node, src)
	switch kind {
	case cppMacroOpen:
		if current == "" {
			return name, true
		}
		return current + "::" + name, true
	case cppMacroClose:
		if idx := strings.LastIndex(current, "::"); idx >= 0 {
			return current[:idx], true
		}
		return outer, true
	}
	return current, false
}

const (
	cppMacroNone = iota
	cppMacroOpen
	cppMacroClose
)

// cppNamespaceMacro recognizes the BEGIN/END namespace macro idiom by shape:
// a bare identifier or a single-identifier-argument call whose name reads as a
// namespace delimiter. Matching on shape rather than a fixed list keeps the
// common spellings (NAMESPACE_BEGIN, BEGIN_NAMESPACE, QT_BEGIN_NAMESPACE)
// working without enumerating every library.
func cppNamespaceMacro(node *sitter.Node, src []byte) (string, int) {
	if node.Type() != rustNodeExpressionStatement || node.ChildCount() == 0 {
		return "", cppMacroNone
	}
	inner := node.Child(0)
	switch inner.Type() {
	case cNodeIdentifier:
		if kind := cppNamespaceMacroKind(inner.Content(src)); kind == cppMacroClose {
			return "", kind
		}
	case "call_expression":
		callee := inner.ChildByFieldName("function")
		args := inner.ChildByFieldName("arguments")
		if callee == nil || callee.Type() != cNodeIdentifier || args == nil {
			return "", cppMacroNone
		}
		kind := cppNamespaceMacroKind(callee.Content(src))
		if kind == cppMacroNone {
			return "", cppMacroNone
		}
		var names []string
		for i := 0; i < int(args.NamedChildCount()); i++ {
			arg := args.NamedChild(i)
			if arg.Type() != cNodeIdentifier {
				return "", cppMacroNone
			}
			names = append(names, arg.Content(src))
		}
		if kind == cppMacroClose {
			return "", kind
		}
		if len(names) != 1 {
			return "", cppMacroNone
		}
		return names[0], cppMacroOpen
	}
	return "", cppMacroNone
}

func cppNamespaceMacroKind(name string) int {
	if !strings.Contains(name, "NAMESPACE") {
		return cppMacroNone
	}
	switch {
	case strings.Contains(name, "BEGIN"):
		return cppMacroOpen
	case strings.Contains(name, "END"):
		return cppMacroClose
	}
	return cppMacroNone
}

func collectCPPDeclaredTypes(node *sitter.Node, src []byte, scope string, result map[string]bool) {
	nextScope := cppNestedScope(node, src, scope)
	if nextScope != scope && (node.Type() == "class_specifier" || node.Type() == "struct_specifier") {
		result[nextScope] = true
	}
	childScope := nextScope
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if next, handled := cppMacroScope(child, src, childScope, nextScope); handled {
			childScope = next
			continue
		}
		collectCPPDeclaredTypes(child, src, childScope, result)
	}
}

func cppNestedScope(node *sitter.Node, src []byte, scope string) string {
	switch node.Type() {
	case "namespace_definition", "class_specifier", "struct_specifier":
		name := node.ChildByFieldName("name")
		if name == nil || name.Content(src) == "" {
			return scope
		}
		if scope == "" {
			return strings.TrimPrefix(name.Content(src), "::")
		}
		return scope + "::" + name.Content(src)
	default:
		return scope
	}
}

func collectCPPStaticFunctions(node *sitter.Node, src []byte, result map[string]bool) {
	if node.Type() == cppNodeFunctionDefinition {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "storage_class_specifier" && child.Content(src) == "static" {
				result[cppDeclaratorName(node.ChildByFieldName("declarator"), src)] = true
				return
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCPPStaticFunctions(node.Child(i), src, result)
	}
}

func (p *CPPParser) extractInclude(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	path := node.ChildByFieldName("path")
	if path == nil {
		return
	}
	header := strings.Trim(strings.TrimSpace(path.Content(src)), "<>\"")
	if header != "" {
		analysis.Imports[header] = header
	}
}

func (p *CPPParser) parseFunction(node *sitter.Node, src []byte, filePath, packagePath, scope string, staticFunctions, localTypes map[string]bool) *FunctionDecl {
	declarator := node.ChildByFieldName("declarator")
	name, typeName := cppDeclaratorIdentity(declarator, src)
	// An out-of-line definition names its type relative to the enclosing scope
	// ("void SHA256::InitState" inside namespace CryptoPP), so the scope has to
	// be prepended for the identity to match a caller's qualified receiver.
	switch {
	case typeName == "":
		typeName = scope
	case scope != "" && typeName != scope && !strings.HasPrefix(typeName, scope+"::"):
		typeName = scope + "::" + typeName
	}
	body := node.ChildByFieldName("body")
	if name == "" || body == nil {
		return nil
	}
	decl := &FunctionDecl{
		ID:           FunctionID{Package: cFunctionPackage(packagePath, filePath, name, staticFunctions), Type: typeName, Name: name},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		StartCol:     int(node.StartPoint().Column) + 1,
		EndCol:       int(node.EndPoint().Column) + 1,
		OwnerType:    "module",
		OwnerName:    packagePath,
		FunctionType: "function",
		Parameters:   cppParameters(declarator, src),
	}
	variableTypes := cppVariableTypes(decl.Parameters)
	p.walkCalls(body, src, filePath, packagePath, staticFunctions, localTypes, variableTypes, &decl.Calls)
	decl.ReturnSources = p.extractReturnSources(body, src, filePath, packagePath, staticFunctions, localTypes, variableTypes)
	return decl
}

const cppNodeQualifiedIdentifier = "qualified_identifier"

func cppVariableTypes(parameters []FunctionParameter) map[string]string {
	types := make(map[string]string)
	for _, parameter := range parameters {
		if parameter.Name != "" && parameter.Type != "" {
			types[parameter.Name] = cppCanonicalType(parameter.Type)
		}
	}
	return types
}

func recordCPPDeclarationTypes(node *sitter.Node, src []byte, types map[string]string) {
	typeNode := node.ChildByFieldName("type")
	if typeNode == nil {
		return
	}
	typeName := cppCanonicalType(typeNode.Content(src))
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if sameSyntaxNode(child, typeNode) {
			continue
		}
		if name := cppBoundVariableName(child, src); name != "" {
			types[name] = typeName
		}
	}
}

// cppBoundVariableName names the variable a declarator binds. Unlike C's
// cDeclaratorName it descends a reference declarator (`const auto& m = f()`),
// which tree-sitter-cpp gives no `declarator` field.
func cppBoundVariableName(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Type() {
	case cNodeIdentifier:
		return node.Content(src)
	case "reference_declarator":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if name := cppBoundVariableName(node.NamedChild(i), src); name != "" {
				return name
			}
		}
		return ""
	}
	return cppBoundVariableName(node.ChildByFieldName("declarator"), src)
}

func cppParameters(declarator *sitter.Node, src []byte) []FunctionParameter {
	result := cParameters(declarator, src)
	parameters := cDescendantByType(declarator, cNodeParameterList)
	if parameters == nil || len(result) == 0 {
		return result
	}

	resultIndex := 0
	for i := 0; i < int(parameters.NamedChildCount()); i++ {
		parameter := parameters.NamedChild(i)
		if parameter.Type() != "parameter_declaration" {
			continue
		}
		if resultIndex >= len(result) {
			break
		}
		result[resultIndex].Type = cppCanonicalType(result[resultIndex].Type)
		if result[resultIndex].Name == "" {
			result[resultIndex].Name = cppVariableDeclaratorName(parameter.ChildByFieldName("declarator"), src)
		}
		resultIndex++
	}
	return result
}

func cppVariableDeclaratorName(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == cNodeIdentifier {
		return node.Content(src)
	}
	if declarator := node.ChildByFieldName("declarator"); declarator != nil {
		return cppVariableDeclaratorName(declarator, src)
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if name := cppVariableDeclaratorName(node.NamedChild(i), src); name != "" {
			return name
		}
	}
	return ""
}

func cppCanonicalType(typeName string) string {
	return strings.TrimPrefix(strings.TrimSpace(typeName), "::")
}

func cppDeclaratorName(node *sitter.Node, src []byte) string {
	name, _ := cppDeclaratorIdentity(node, src)
	return name
}

func cppDeclaratorIdentity(node *sitter.Node, src []byte) (name, typeName string) {
	if node == nil {
		return "", ""
	}
	switch node.Type() {
	case cNodeIdentifier, "field_identifier":
		return node.Content(src), ""
	case cppNodeQualifiedIdentifier:
		parts := strings.Split(strings.TrimPrefix(node.Content(src), "::"), "::")
		return parts[len(parts)-1], strings.Join(parts[:len(parts)-1], "::")
	default:
		return cppDeclaratorIdentity(node.ChildByFieldName("declarator"), src)
	}
}

func (p *CPPParser) walkCalls(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions, localTypes map[string]bool, variableTypes map[string]string, calls *[]FunctionCall) {
	if cppIntroducesVariableScope(node.Type()) {
		variableTypes = maps.Clone(variableTypes)
	}
	if node.Type() == "declaration" {
		recordCPPDeclarationTypes(node, src, variableTypes)
	}
	if node.Type() == cNodeCallExpression {
		if call := p.parseCall(node, src, filePath, packagePath, staticFunctions, localTypes, variableTypes); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, packagePath, staticFunctions, localTypes, variableTypes, calls)
	}
}

func cppIntroducesVariableScope(nodeType string) bool {
	switch nodeType {
	case "compound_statement", "if_statement", "switch_statement", "for_statement", "while_statement", "do_statement", "catch_clause", lambdaExpressionNode:
		return true
	default:
		return false
	}
}

func (p *CPPParser) parseCall(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions, localTypes map[string]bool, variableTypes map[string]string) *FunctionCall {
	function := node.ChildByFieldName("function")
	if function == nil {
		return nil
	}
	chainID, assignedVar := cppCallChainContext(node, src)
	call := &FunctionCall{
		Callee:      FunctionID{Package: packagePath},
		Raw:         function.Content(src),
		FilePath:    filePath,
		Line:        int(node.StartPoint().Row) + 1,
		StartCol:    int(node.StartPoint().Column) + 1,
		EndCol:      int(node.EndPoint().Column) + 1,
		AssignedVar: assignedVar,
		ChainID:     chainID,
		Arguments:   cCallArguments(node, src),
	}
	switch function.Type() {
	case cNodeIdentifier:
		call.Callee.Name = function.Content(src)
		call.Callee.Package = cFunctionPackage(packagePath, filePath, call.Callee.Name, staticFunctions)
	case fieldExpressionNode:
		field, argument := function.ChildByFieldName("field"), function.ChildByFieldName("argument")
		if field == nil {
			return nil
		}
		call.Callee.Name = field.Content(src)
		if argument != nil && argument.Type() == cNodeIdentifier {
			call.ReceiverVar = argument.Content(src)
			call.Callee.Type = variableTypes[call.ReceiverVar]
			if localTypes[call.Callee.Type] {
				call.Callee.Linkage = LinkageInternal
			}
		}
	case "template_function":
		name := cppTemplateFunctionName(function, src, variableTypes)
		if name == "" {
			return nil
		}
		call.Callee.Name = name
		call.Callee.Package = cFunctionPackage(packagePath, filePath, call.Callee.Name, staticFunctions)
	case cppNodeQualifiedIdentifier:
		scope, name := cppQualifiedCallee(function, src)
		if scope == "" || name == "" {
			return nil
		}
		call.Callee.Name = name
		call.Callee.Type = scope
		if localTypes[call.Callee.Type+"::"+call.Callee.Name] {
			call.Callee.Linkage = LinkageInternal
		}
	default:
		// `obj->m<N>(x)` never reaches here: tree-sitter-cpp cannot tell a
		// member template call from `(obj->m < N) > (x)` without knowing m is a
		// template, and parses it as that comparison. It stays unrecorded.
		return nil
	}
	return call
}

// cppTemplateFunctionName names a free templated callee without its template
// arguments: `f<32>(x)` calls f. tree-sitter-cpp reads two things that are
// not calls the same way, and both yield "": the casts (`static_cast<T>(x)`),
// and the comparison `a < b > (c)`, recognized by a being a variable in scope.
func cppTemplateFunctionName(node *sitter.Node, src []byte, variableTypes map[string]string) string {
	name := node.ChildByFieldName("name")
	if name == nil || name.Type() != cNodeIdentifier {
		return ""
	}
	text := name.Content(src)
	switch text {
	case "static_cast", "dynamic_cast", "const_cast", "reinterpret_cast":
		return ""
	}
	if _, isVariable := variableTypes[text]; isVariable {
		return ""
	}
	return text
}

// cppQualifiedCallee splits a qualified callee into its scope and name by
// walking the syntax tree, so a `::` inside template arguments
// (`ns::f<libff::alt_bn128_pp>`) is never taken for a scope separator. A
// templated name loses its argument list: the call is to `ns::f`. Template
// arguments in the scope stay (`Foo<T>::create`), as a declared type keeps them.
func cppQualifiedCallee(node *sitter.Node, src []byte) (scope, name string) {
	var scopes []string
	for node != nil && node.Type() == cppNodeQualifiedIdentifier {
		if s := node.ChildByFieldName("scope"); s != nil {
			scopes = append(scopes, s.Content(src))
		}
		node = node.ChildByFieldName("name")
	}
	if node == nil {
		return "", ""
	}
	name = node.Content(src)
	if node.Type() == "template_function" {
		base := node.ChildByFieldName("name")
		if base == nil {
			return "", ""
		}
		name = base.Content(src)
	}
	return strings.Join(scopes, "::"), name
}

func (p *CPPParser) extractReturnSources(body *sitter.Node, src []byte, filePath, packagePath string, staticFunctions, localTypes map[string]bool, variableTypes map[string]string) []SourceNode {
	var sources []SourceNode
	p.walkReturnSources(body, src, filePath, packagePath, staticFunctions, localTypes, variableTypes, &sources)
	return sources
}

func (p *CPPParser) walkReturnSources(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions, localTypes map[string]bool, variableTypes map[string]string, sources *[]SourceNode) {
	if node.Type() == lambdaExpressionNode {
		return
	}
	if cppIntroducesVariableScope(node.Type()) {
		variableTypes = maps.Clone(variableTypes)
	}
	if node.Type() == "declaration" {
		recordCPPDeclarationTypes(node, src, variableTypes)
	}
	if node.Type() == cNodeReturnStatement {
		if expr := cReturnExpression(node); expr != nil {
			if source, ok := p.returnSource(expr, src, filePath, packagePath, staticFunctions, localTypes, variableTypes); ok {
				*sources = append(*sources, source)
			}
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkReturnSources(node.Child(i), src, filePath, packagePath, staticFunctions, localTypes, variableTypes, sources)
	}
}

func (p *CPPParser) returnSource(expr *sitter.Node, src []byte, filePath, packagePath string, staticFunctions, localTypes map[string]bool, variableTypes map[string]string) (SourceNode, bool) {
	location := &SourceLocation{FilePath: filePath, Line: int(expr.StartPoint().Row) + 1}
	switch expr.Type() {
	case cNodeCallExpression:
		call := p.parseCall(expr, src, filePath, packagePath, staticFunctions, localTypes, variableTypes)
		if call == nil {
			return SourceNode{}, false
		}
		callee := call.Callee
		callee.Name = fmt.Sprintf("%s#%d", callee.Name, len(call.Arguments))
		return SourceNode{Type: sourceNodeCallResult, CallTarget: &callee, Location: location}, true
	case cNodeIdentifier:
		return SourceNode{Type: sourceNodeVariable, Name: expr.Content(src), Location: location}, true
	case fieldExpressionNode:
		return SourceNode{Type: sourceNodeField, Name: expr.Content(src), Location: location}, true
	}
	return SourceNode{}, false
}

func cppCallChainContext(node *sitter.Node, src []byte) (chainID, assignedVar string) {
	root := cppChainRoot(node)
	if !sameSyntaxNode(root, node) {
		return fmt.Sprintf("%d", root.StartByte()), ""
	}
	function := node.ChildByFieldName("function")
	if function != nil && function.Type() == fieldExpressionNode {
		argument := function.ChildByFieldName("argument")
		if argument != nil && argument.Type() == cNodeCallExpression {
			chainID = fmt.Sprintf("%d", root.StartByte())
		}
	}
	return chainID, cppAssignedVar(root, src)
}

// cppAssignedVar names the variable a call's result initializes or is
// assigned to. Beyond C's `T v = f()` and `v = f()` it accepts C++ direct
// initialization, where the call is the only element of the initializer:
// `std::unique_ptr<X> v(f())`, `auto v{f()}`, `X v{f()}`. A multi-argument
// initializer (`X v(f(), n)`) constructs a new object rather than binding the
// call's result, so it binds nothing.
func cppAssignedVar(node *sitter.Node, src []byte) string {
	value := node
	if parent := node.Parent(); parent != nil && (parent.Type() == "argument_list" || parent.Type() == "initializer_list") && parent.NamedChildCount() == 1 {
		value = parent
	}
	parent := value.Parent()
	if parent == nil {
		return ""
	}
	switch parent.Type() {
	case "init_declarator":
		if sameSyntaxNode(parent.ChildByFieldName("value"), value) {
			return cppBoundVariableName(parent.ChildByFieldName("declarator"), src)
		}
	case "assignment_expression":
		if sameSyntaxNode(value, node) {
			return cAssignedVar(node, src)
		}
	}
	return ""
}

func cppChainRoot(node *sitter.Node) *sitter.Node {
	root := node
	for {
		field := root.Parent()
		if field == nil || field.Type() != fieldExpressionNode || !sameSyntaxNode(field.ChildByFieldName("argument"), root) {
			break
		}
		call := field.Parent()
		if call == nil || call.Type() != cNodeCallExpression || !sameSyntaxNode(call.ChildByFieldName("function"), field) {
			break
		}
		root = call
	}
	return root
}

// SubPackagePath constructs a child namespace using path separators.
func (p *CPPParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "/" + dirName
}

// PackageSeparator returns the C++ package-path separator.
func (p *CPPParser) PackageSeparator() string { return "/" }
