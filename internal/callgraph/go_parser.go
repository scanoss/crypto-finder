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
	goNodeVarSpec             = "var_spec"
	goNodeTypeSpec            = "type_spec"
	goOwnerInterface          = "interface"
	goNodeFuncLiteral         = "func_literal"
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

// SkipsDirNamed mirrors the go tool's rule: a directory whose name begins with
// "_" is not part of any build.
func (p *GoParser) SkipsDirNamed(name string) bool {
	return strings.HasPrefix(name, "_")
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
	// Type names first, before any function body is walked: Go imposes no
	// order between declarations, so a conversion may textually precede the
	// type it names.
	for i := 0; i < int(root.ChildCount()); i++ {
		if child := root.Child(i); child.Type() == "type_declaration" {
			p.recordGoDeclaredTypeNames(child, src, analysis)
		}
	}
	embeds := make(map[string][]string)
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() == "type_declaration" {
			p.extractInterfaceMethods(child, src, filePath, packagePath, analysis, embeds)
			continue
		}
		if child.Type() == "var_declaration" {
			p.extractGoFuncVars(child, src, filePath, packagePath, analysis)
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
	if len(embeds) > 0 {
		flattenGoEmbeddedInterfaces(analysis, embeds, packagePath)
	}
	p.extractGoPackageInitCalls(root, src, filePath, packagePath, analysis)
}

// extractGoPackageInitCalls collects the calls made by package-level variable
// initializers — `var errNoMatch = errors.New(...)`, `var b64 = base64.
// RawStdEncoding.Strict()` — into one synthetic <varinit> declaration per file.
// These run at program start, before main; without a containing function the
// walk never visited them and the calls were absent from the graph entirely.
// The Java parser's synthetic <clinit> is the same idea for class initializers.
func (p *GoParser) extractGoPackageInitCalls(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	var calls []FunctionCall
	varTypes := make(map[string]string)
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() != "var_declaration" {
			continue
		}
		p.walkForCalls(child, src, filePath, analysis, "", "", varTypes, &calls)
	}
	if len(calls) == 0 {
		return
	}
	// One synthetic decl per FILE, discriminated in the name: several files of
	// one package would otherwise collide on the same map key in the graph and
	// silently drop each other's initializer calls.
	base := filePath
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".go")
	analysis.Functions = append(analysis.Functions, FunctionDecl{
		ID:           FunctionID{Package: packagePath, Name: "<varinit:" + base + ">"},
		FilePath:     filePath,
		StartLine:    1,
		EndLine:      int(root.EndPoint().Row) + 1,
		OwnerType:    "package",
		FunctionType: "function",
		Calls:        calls,
	})
}

// extractInterfaceMethods registers each method of an interface declaration as
// a FunctionDecl with OwnerType "interface". A Go interface method has no body,
// so the walk never produced a declaration for it: a call on an
// interface-typed receiver — `id.Unwrap(...)` with `id age.Identity` — had
// nothing to join, and the builder's generic expandInterfaceDispatch, which
// keys off OwnerType "interface" exactly like Java's interface declarations,
// never fired for Go. Embedded interfaces (type_elem) are not flattened here;
// the dispatch expansion matches by name and arity, which does not need them.
// flattenGoEmbeddedInterfaces copies the methods of an embedded interface onto
// its embedder, same file only: `type RecipientWithLabels interface {
// Recipient; WrapWithLabels(...) }` also has Wrap, and a call through the
// asserted type had no declaration to join. Runs after every interface in the
// file is extracted, so declaration order does not matter; one level is
// flattened per pass, run to the file's nesting depth.
func flattenGoEmbeddedInterfaces(analysis *FileAnalysis, embeds map[string][]string, packagePath string) {
	byIface := make(map[string][]FunctionDecl)
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.OwnerType == goOwnerInterface && fn.ID.Package == packagePath {
			byIface[fn.ID.Type] = append(byIface[fn.ID.Type], *fn)
		}
	}
	for range 4 {
		added := false
		for outer, inners := range embeds {
			if copyGoEmbeddedMethods(analysis, byIface, outer, inners) {
				added = true
			}
		}
		if !added {
			break
		}
	}
}

// copyGoEmbeddedMethods copies each not-yet-present method of the embedded
// interfaces onto the embedder, reporting whether anything was added.
func copyGoEmbeddedMethods(analysis *FileAnalysis, byIface map[string][]FunctionDecl, outer string, inners []string) bool {
	have := make(map[string]bool)
	for i := range byIface[outer] {
		have[byIface[outer][i].ID.Name] = true
	}
	added := false
	for _, inner := range inners {
		methods := byIface[inner]
		for i := range methods {
			if have[methods[i].ID.Name] {
				continue
			}
			copied := methods[i]
			copied.ID.Type = outer
			copied.OwnerName = outer
			analysis.Functions = append(analysis.Functions, copied)
			byIface[outer] = append(byIface[outer], copied)
			have[copied.ID.Name] = true
			added = true
		}
	}
	return added
}

func (p *GoParser) extractInterfaceMethods(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, embeds map[string][]string) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		spec := node.NamedChild(i)
		if spec.Type() != goNodeTypeSpec {
			continue
		}
		typeNode := spec.ChildByFieldName(goFieldType)
		nameNode := spec.ChildByFieldName("name")
		if typeNode == nil || nameNode == nil {
			continue
		}
		if typeNode.Type() == "struct_type" {
			p.extractGoStructFuncFields(spec, src, filePath, packagePath, analysis)
			continue
		}
		if typeNode.Type() != "interface_type" {
			continue
		}
		ifaceName := strings.TrimSpace(nameNode.Content(src))
		if ifaceName == "" {
			continue
		}
		p.extractGoInterfaceMembers(typeNode, src, filePath, packagePath, analysis, ifaceName, embeds)
	}
}

// extractGoInterfaceMembers walks one interface body: method elements become
// interface-owned declarations, embedded interfaces are recorded for the
// same-file flattening pass.
func (p *GoParser) extractGoInterfaceMembers(typeNode *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, ifaceName string, embeds map[string][]string) {
	for j := 0; j < int(typeNode.NamedChildCount()); j++ {
		elem := typeNode.NamedChild(j)
		if elem.Type() == "type_elem" {
			if embedded := strings.TrimSpace(elem.Content(src)); embedded != "" && !strings.ContainsAny(embedded, ". |~[") {
				embeds[ifaceName] = append(embeds[ifaceName], embedded)
			}
			continue
		}
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
		decl := FunctionDecl{
			ID:           FunctionID{Package: packagePath, Type: ifaceName, Name: methodName},
			FilePath:     filePath,
			StartLine:    int(elem.StartPoint().Row) + 1,
			EndLine:      int(elem.EndPoint().Row) + 1,
			OwnerType:    goOwnerInterface,
			OwnerName:    ifaceName,
			FunctionType: "method",
			Parameters:   p.extractParameterTypes(elem.ChildByFieldName("parameters"), src),
		}
		decl.ReturnType = p.extractReturnType(elem.ChildByFieldName("result"), src, analysis)
		analysis.Functions = append(analysis.Functions, decl)
	}
}

// extractGoStructFuncFields declares each func-typed field of a struct as a
// member of that type. `type ClientUI struct{ DisplayMessage func(...) error }`
// makes `ui.DisplayMessage(...)` a real member call whose identity —
// (*ClientUI).DisplayMessage — is correct; without a declaration behind it the
// call read as claiming a member that does not exist. Which function runs is
// still dynamic; declaring the field only anchors the identity.
func (p *GoParser) extractGoStructFuncFields(spec *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	typeNode := spec.ChildByFieldName(goFieldType)
	nameNode := spec.ChildByFieldName("name")
	if typeNode == nil || nameNode == nil || typeNode.Type() != "struct_type" {
		return
	}
	structName := strings.TrimSpace(nameNode.Content(src))
	if structName == "" {
		return
	}
	body := typeNode.NamedChild(0) // field_declaration_list
	if body == nil {
		return
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		field := body.NamedChild(i)
		if field.Type() != javaNodeFieldDeclaration {
			continue
		}
		ft := field.ChildByFieldName(goFieldType)
		if ft == nil || ft.Type() != "function_type" {
			continue
		}
		p.declareGoFuncField(field, ft, src, filePath, packagePath, analysis, structName)
	}
}

// declareGoFuncField emits the two receiver spellings of one func-typed field.
func (p *GoParser) declareGoFuncField(field, ft *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, structName string) {
	for j := 0; j < int(field.NamedChildCount()); j++ {
		n := field.NamedChild(j)
		if n.Type() != goNodeFieldIdentifier {
			continue
		}
		fieldName := strings.TrimSpace(n.Content(src))
		if fieldName == "" {
			continue
		}
		for _, recv := range []string{structName, "*" + structName} {
			analysis.Functions = append(analysis.Functions, FunctionDecl{
				ID:           FunctionID{Package: packagePath, Type: recv, Name: fieldName},
				FilePath:     filePath,
				StartLine:    int(field.StartPoint().Row) + 1,
				EndLine:      int(field.EndPoint().Row) + 1,
				OwnerType:    "struct-field",
				OwnerName:    structName,
				FunctionType: "method",
				Parameters:   p.extractParameterTypes(ft.ChildByFieldName("parameters"), src),
			})
		}
	}
}

// recordGoDeclaredTypeNames marks each type name this file declares. A bare
// call whose name is a declared type is a CONVERSION (`WriterFunc(fn)`), not a
// call — the same shape `int(x)` takes with a predeclared type.
func (p *GoParser) recordGoDeclaredTypeNames(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	if analysis.DeclaredTypes == nil {
		analysis.DeclaredTypes = make(map[string]bool)
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		spec := node.NamedChild(i)
		if spec.Type() != goNodeTypeSpec && spec.Type() != "type_alias" {
			continue
		}
		if name := spec.ChildByFieldName("name"); name != nil {
			analysis.DeclaredTypes[strings.TrimSpace(name.Content(src))] = true
		}
	}
}

// extractGoFuncVars declares package-level variables that hold functions —
// a func-typed var (`var hook func()`), a closure, or an alias to another
// function (`var EncodeToString = b64.EncodeToString`). These are callable
// package members with a stable identity: age's format.EncodeToString is one,
// and every one of its nine call sites claimed a corpus identity that no
// declaration backed. Ordinary data vars are not declared.
func (p *GoParser) extractGoFuncVars(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		spec := node.NamedChild(i)
		if spec.Type() != goNodeVarSpec {
			continue
		}
		nameNode := spec.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		callable := false
		if t := spec.ChildByFieldName(goFieldType); t != nil && t.Type() == "function_type" {
			callable = true
		}
		if v := spec.ChildByFieldName("value"); v != nil && int(v.NamedChildCount()) == 1 {
			switch v.NamedChild(0).Type() {
			case goNodeFuncLiteral, goNodeSelectorExpression, goNodeIdentifier:
				callable = true
			}
		}
		if !callable {
			continue
		}
		name := strings.TrimSpace(nameNode.Content(src))
		if name == "" || name == "_" {
			continue
		}
		analysis.Functions = append(analysis.Functions, FunctionDecl{
			ID:           FunctionID{Package: packagePath, Name: name},
			FilePath:     filePath,
			StartLine:    int(spec.StartPoint().Row) + 1,
			EndLine:      int(spec.EndPoint().Row) + 1,
			OwnerType:    "package",
			FunctionType: "function",
		})
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

	if name == "init" {
		// Go allows any number of init functions per package and even per
		// file; they all run. One shared key would keep only the last one's
		// calls in the graph — the same silent drop the per-file <varinit>
		// declaration exists to avoid — so each gets a file-discriminated
		// identity. Nothing can call init explicitly, so no call site needs
		// the undiscriminated name.
		base := filePath
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		decl.ID.Name = "<init:" + strings.TrimSuffix(base, ".go") + ">"
	}

	if body != nil {
		varTypes := p.collectGoVarTypes(params, src)
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
		varTypes := p.collectGoVarTypes(params, src)
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
	if node.Type() == goNodeFuncLiteral {
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

	// The pinned tree-sitter-go grammar predates explicit generic
	// instantiation and misparses `Register[*Key](&x{})` as a CONVERSION to
	// the generic type Register[*Key] — no error node, no call_expression, so
	// the call vanished (145 of tink-go's sites, its key-serializer
	// registrations among them; go/types sees every one). Until the grammar
	// pin moves, a conversion whose type is generic and does NOT name a type
	// declared in this file is read back as the call it is.
	if node.Type() == goNodeTypeConversion {
		if call := p.parseGoMisparsedGenericCall(node, src, filePath, analysis, varTypes); call != nil {
			call.StartCol = int(node.StartPoint().Column) + 1
			call.EndCol = int(node.EndPoint().Column) + 1
			setFunctionCallASTAnchor(call, node)
			*calls = append(*calls, *call)
		}
	}

	// Bindings are recorded in textual order, AFTER descending into the node
	// that introduces them: in `pk, ok := pk.(ssh.CryptoPublicKey)` the
	// right-hand pk is the OUTER one (Go's declared-before-use), so the calls
	// inside the right side must resolve against the map as it was before the
	// binding lands. A nested scope gets a copy, so its bindings shadow inward
	// and never leak back out — the position-sensitive lookup go/types does,
	// approximated by walk order.
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if goOpensScope(child.Type()) {
			scoped := make(map[string]string, len(varTypes))
			for k, v := range varTypes {
				scoped[k] = v
			}
			p.walkForCalls(child, src, filePath, analysis, currentReceiverType, currentReceiverVar, scoped, calls)
			continue
		}
		p.walkForCalls(child, src, filePath, analysis, currentReceiverType, currentReceiverVar, varTypes, calls)
		p.collectGoVarTypesAt(child, src, varTypes)
	}
}

// parseGoMisparsedGenericCall recovers an explicitly instantiated generic call
// from the conversion shape the pinned grammar gives it. See walkForCalls.
func (p *GoParser) parseGoMisparsedGenericCall(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, varTypes map[string]string) *FunctionCall {
	typeNode := node.ChildByFieldName(goFieldType)
	if typeNode == nil || typeNode.Type() != goNodeGenericType {
		return nil
	}
	base := typeNode.ChildByFieldName(goFieldType)
	if base == nil {
		return nil
	}
	name := strings.TrimSpace(base.Content(src))
	if name == "" {
		return nil
	}
	line := int(node.StartPoint().Row) + 1
	var args []string
	if operand := node.ChildByFieldName(goFieldOperand); operand != nil {
		args = []string{strings.TrimSpace(operand.Content(src))}
	}
	if dot := strings.Index(name, "."); dot > 0 {
		// qualified: pkg.Register[T](x) — resolve the alias like any selector
		alias, fn := name[:dot], name[dot+1:]
		if _, shadowed := varTypes[alias]; !shadowed {
			if importPath, ok := analysis.Imports[alias]; ok {
				return &FunctionCall{
					Callee:    FunctionID{Package: importPath, Name: fn},
					Raw:       name,
					FilePath:  filePath,
					Line:      line,
					Arguments: args,
				}
			}
		}
		return nil
	}
	if analysis.DeclaredTypes[name] {
		// a REAL conversion to a locally declared generic type
		return nil
	}
	return &FunctionCall{
		Callee:    FunctionID{Package: analysis.PackagePath, Name: name},
		Raw:       name,
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
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

	// An explicitly instantiated generic call — RegisterKeySerializer[*Key](x),
	// or pkg.Register[T](x) — wraps its function in an index_expression. The
	// type arguments are erased everywhere else, so they are unwrapped here
	// too; before this the whole call was dropped (145 of tink-go's call
	// sites, its key-serializer registrations among them).
	for funcNode != nil && funcNode.Type() == "index_expression" {
		funcNode = funcNode.ChildByFieldName(goFieldOperand)
	}
	if funcNode == nil {
		return nil
	}

	var call *FunctionCall
	switch funcNode.Type() {
	case goNodeFuncLiteral:
		// An immediately invoked literal — go func(){...}(), defer func(){...}()
		// — is a real call whose body the walk already visits; the invocation
		// itself carries the honest empty identity (there is nothing to name).
		call = &FunctionCall{
			Callee:    FunctionID{Name: "<func-literal>"},
			Raw:       "func(){...}()",
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	case "selector_expression":
		call = p.parseSelectorCall(funcNode, src, filePath, line, args, analysis, currentReceiverType, currentReceiverVar, varTypes)
	case goNodeIdentifier:
		// Simple call like `doSomething()`
		name := funcNode.Content(src)
		if analysis.DeclaredTypes[name] {
			// `WriterFunc(fn)` where WriterFunc is a type this file declares is
			// a conversion, exactly like `int(x)` with a predeclared type.
			return nil
		}
		if name == currentReceiverVar && currentReceiverVar != "" {
			// A method on a named func type calls its own receiver:
			// `func (f WriterFunc) Write(p []byte) { f(p) }`. Dynamic value,
			// honest empty identity.
			call = &FunctionCall{
				Callee:    FunctionID{Name: name},
				Raw:       name,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
			break
		}
		if _, isLocal := varTypes[name]; isLocal {
			// A bare call through a local variable is a func-value call:
			// `getLine()` where getLine is a closure, `f()` where f arrived as
			// a parameter. Which function runs is genuinely dynamic, so the
			// honest empty identity is emitted rather than the caller's
			// package, which would claim a package function that may not exist.
			call = &FunctionCall{
				Callee:    FunctionID{Name: name},
				Raw:       name,
				FilePath:  filePath,
				Line:      line,
				Arguments: args,
			}
			break
		}
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
	case goNodeVarSpec:
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
		// Any other receiver shape — a field chain (`s.c.XORKeyStream(...)`),
		// an index expression (`hs[i].Sum(...)`), a composite literal — is a
		// real call whose receiver this pass cannot type. Dropping it removed
		// the call from the graph entirely (34 of age's stream.go call sites);
		// it is emitted with the honest empty identity instead.
		return &FunctionCall{
			Callee:    FunctionID{Name: field},
			Raw:       node.Content(src),
			FilePath:  filePath,
			Line:      line,
			Arguments: args,
		}
	}
	operand := operandNode.Content(src)
	if operand == "" {
		return nil
	}

	raw := operand + "." + field

	// A local binding shadows an imported package of the same name (Go's
	// innermost-scope rule): in tink-go, `key.AESKeyBytes()` inside a function
	// that binds a variable `key` is a METHOD call on that variable, yet the
	// import lookup ran first and emitted a call to a package function that
	// does not exist. The binding map holds exactly the names bound up to this
	// position, so consulting it first is the language's own resolution order.
	_, shadowedByLocal := varTypes[operand]
	if operand == currentReceiverVar && currentReceiverVar != "" {
		shadowedByLocal = true
	}

	// Try to resolve the operand as a package import
	if importPath, ok := analysis.Imports[operand]; ok && !shadowedByLocal {
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

// collectGoVarTypes seeds a function's binding map with its parameters; the
// body's bindings are collected in textual order during the call walk.
func (p *GoParser) collectGoVarTypes(paramsNode *sitter.Node, src []byte) map[string]string {
	varTypes := make(map[string]string)
	p.collectGoParameterTypes(paramsNode, src, varTypes)
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

// goOpensScope reports whether a node introduces a new declaration scope. Go
// scopes a local to its block, an if/for/switch initializer binding to that
// statement, and a literal's parameters to the literal (Go spec, "Declarations
// and scope"). One flat map per function loses that: the type assertion in
// `if r, ok := r.(RecipientWithLabels); ok { ... }` rebound r for the WHOLE
// function, so the outer r's calls after the if were typed against the
// asserted interface — a silently wrong receiver, the same defect the Java
// parser had with sibling blocks.
func goOpensScope(nodeType string) bool {
	switch nodeType {
	case goNodeBlock, "if_statement", "for_statement", "expression_switch_statement",
		"type_switch_statement", "select_statement", goNodeFuncLiteral:
		return true
	default:
		return false
	}
}

// collectGoVarTypesAt records only the bindings this one node introduces,
// without descending — the scope-bounded walk controls its own recursion.
// goBindNames records each identifier of a binding list as a local. overwrite
// controls rebinding: a range variable always rebinds; a := keeps an existing
// (possibly typed) entry for a reused name.
func goBindNames(left *sitter.Node, src []byte, varTypes map[string]string, overwrite bool) {
	for i := 0; i < int(left.NamedChildCount()); i++ {
		n := left.NamedChild(i)
		if n == nil || n.Type() != goNodeIdentifier {
			continue
		}
		name := strings.TrimSpace(n.Content(src))
		if name == "" || name == "_" {
			continue
		}
		if _, exists := varTypes[name]; exists && !overwrite {
			continue
		}
		varTypes[name] = ""
	}
}

func (p *GoParser) collectGoVarTypesAt(node *sitter.Node, src []byte, varTypes map[string]string) {
	if node.Type() == goNodeShortVarDeclaration {
		p.collectGoShortVarTypes(node, src, varTypes)
	}

	if node.Type() == "range_clause" {
		// `for k, v := range xs` declares locals too; they shadow imports the
		// same way, with no type this pass can name.
		if l := node.ChildByFieldName("left"); l != nil {
			goBindNames(l, src, varTypes, true)
		}
	}

	if node.Type() == goNodeFuncLiteral {
		// A literal's parameters are visible to the calls inside it, which the
		// walk attributes to the enclosing declaration: `yield` in a
		// range-over-func body, `f` in a callback. The map is function-flat,
		// so a literal parameter shadowing an outer name follows the same
		// last-write rule as every other local here.
		p.collectGoParameterTypes(node.ChildByFieldName("parameters"), src, varTypes)
	}

	if node.Type() == goNodeVarSpec {
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
	// Every name a := binds is a LOCAL from here on, even when its type is
	// unknown: `hash, ok := HashIdToHash(b)` must shadow the imported package
	// `hash` (Go's innermost-scope rule), or `hash.Available()` resolves as a
	// call into the package. An unknown type stays empty — the honest form —
	// and the builder pass may still type it from the producer's return.
	goBindNames(left, src, varTypes, false)
	count := int(left.NamedChildCount())
	// A type assertion states its type in its own syntax even in the
	// two-valued form: `r, ok := x.(RecipientWithLabels)` binds the first
	// name to the asserted type (the second is the bool).
	if count == 2 && int(right.NamedChildCount()) == 1 {
		collectGoAssertionBinding(left, right.NamedChild(0), src, varTypes)
		return
	}
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

// collectGoAssertionBinding records the first name of a two-valued `:=` whose
// right side is a type assertion.
func collectGoAssertionBinding(left, expr *sitter.Node, src []byte, varTypes map[string]string) {
	if expr == nil || expr.Type() != "type_assertion_expression" {
		return
	}
	nameNode := left.NamedChild(0)
	typeNode := expr.ChildByFieldName(goFieldType)
	if nameNode == nil || nameNode.Type() != goNodeIdentifier || typeNode == nil {
		return
	}
	if name := strings.TrimSpace(nameNode.Content(src)); name != "" && name != "_" {
		varTypes[name] = strings.TrimSpace(typeNode.Content(src))
	}
}

// goSyntacticType returns the type an expression states in its own syntax, or
// "" when naming it would require resolving something else first.
func goSyntacticType(expr *sitter.Node, src []byte) string {
	if expr == nil {
		return ""
	}
	switch expr.Type() {
	case "type_assertion_expression":
		if t := expr.ChildByFieldName(goFieldType); t != nil {
			return strings.TrimSpace(t.Content(src))
		}
	case goNodeFuncLiteral:
		// A closure has no nameable type; the marker makes a later bare call
		// through the variable recognizable as a func-value call.
		return "func"
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
		return goMakeNewType(expr, src)
	}
	return ""
}

// goMakeNewType names the type a make() or new() call states in its first
// argument, or "" for any other call.
func goMakeNewType(expr *sitter.Node, src []byte) string {
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
	// Type arguments are erased from every declared identity (a method set is
	// formed on the bare name), so a receiver typed `Reachable[T]` must erase
	// too or it joins nothing.
	if i := strings.Index(trimmed, "["); i > 0 {
		trimmed = trimmed[:i]
	}

	// A predeclared type belongs to the universe scope, not to the caller's
	// package: `err.Error()` with `err error` is interface dispatch on a type
	// no package owns, and "func" is the marker a closure binding records.
	if goPredeclaredIdentifiers[trimmed] || trimmed == "func" || strings.HasPrefix(trimmed, "func(") || strings.HasPrefix(trimmed, "func ") {
		return "", ""
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
