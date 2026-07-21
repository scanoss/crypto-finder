package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	treec "github.com/smacker/go-tree-sitter/c"
)

const (
	cNodeCallExpression     = "call_expression"
	cNodeFunctionDefinition = "function_definition"
	cNodeIdentifier         = "identifier"
	cNodeParameterList      = "parameter_list"
	cNodeReturnStatement    = "return_statement"
)

// CParser extracts C function declarations, calls, and include paths.
type CParser struct {
	parser       *sitter.Parser
	includeTests bool
}

// NewCParser creates a C source parser backed by tree-sitter.
func NewCParser(opts ...ParserOption) *CParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(treec.GetLanguage())
	return &CParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent parser for concurrent use.
func (p *CParser) CloneParser() Parser {
	return NewCParser(WithIncludeTests(p.includeTests))
}

// ParseDirectory parses C source and header files directly under dir.
func (p *CParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("callgraph: c parser: read directory %s: %w", dir, err)
	}

	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if entry.IsDir() || (ext != ".c" && ext != ".h") {
			continue
		}
		if !p.includeTests && strings.HasSuffix(entry.Name(), "_test.c") {
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

func (p *CParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: c parser: read %s: %w", filePath, err)
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: c parser: parse %s: %w", filePath, err)
	}
	defer tree.Close()

	analysis := &FileAnalysis{
		FilePath:    filePath,
		PackageName: packagePath,
		PackagePath: packagePath,
		Imports:     make(map[string]string),
	}
	root := tree.RootNode()
	staticFunctions := make(map[string]bool)
	collectCStaticFunctions(root, src, staticFunctions)
	p.walkFile(root, src, filePath, packagePath, staticFunctions, analysis)
	return analysis, nil
}

func (p *CParser) walkFile(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, analysis *FileAnalysis) {
	switch node.Type() {
	case "preproc_include":
		p.extractInclude(node, src, analysis)
	case cNodeFunctionDefinition:
		if decl := p.parseFunction(node, src, filePath, packagePath, staticFunctions); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkFile(node.Child(i), src, filePath, packagePath, staticFunctions, analysis)
	}
}

func collectCStaticFunctions(node *sitter.Node, src []byte, result map[string]bool) {
	if node.Type() == cNodeFunctionDefinition {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "storage_class_specifier" && child.Content(src) == "static" {
				result[cDeclaratorName(node.ChildByFieldName("declarator"), src)] = true
				return
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCStaticFunctions(node.Child(i), src, result)
	}
}

func (p *CParser) extractInclude(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	path := node.ChildByFieldName("path")
	if path == nil {
		return
	}
	header := strings.Trim(strings.TrimSpace(path.Content(src)), "<>\"")
	if header != "" {
		analysis.Imports[header] = header
	}
}

func (p *CParser) parseFunction(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) *FunctionDecl {
	declarator := node.ChildByFieldName("declarator")
	name := cDeclaratorName(declarator, src)
	body := node.ChildByFieldName("body")
	if name == "" || body == nil {
		return nil
	}

	decl := &FunctionDecl{
		ID:           FunctionID{Package: cFunctionPackage(packagePath, filePath, name, staticFunctions), Name: name},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "module",
		OwnerName:    packagePath,
		FunctionType: "function",
		Parameters:   cParameters(declarator, src),
		ReturnType:   cFunctionReturnType(node, declarator, src),
	}
	p.walkCalls(body, src, filePath, packagePath, staticFunctions, &decl.Calls)
	decl.ReturnSources = p.extractReturnSources(body, src, filePath, packagePath, staticFunctions)
	return decl
}

func cFunctionReturnType(node, declarator *sitter.Node, src []byte) string {
	typeNode := node.ChildByFieldName("type")
	if typeNode == nil {
		return ""
	}
	returnType := strings.TrimSpace(typeNode.Content(src))
	for current := declarator; current != nil; current = current.ChildByFieldName("declarator") {
		if current.Type() == "pointer_declarator" {
			returnType += "*"
		}
	}
	return returnType
}

func cFunctionPackage(packagePath, filePath, name string, staticFunctions map[string]bool) string {
	if staticFunctions[name] {
		if packagePath == "" {
			return filepath.Base(filePath)
		}
		return packagePath + "/" + filepath.Base(filePath)
	}
	return packagePath
}

func cDeclaratorName(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == cNodeIdentifier {
		return node.Content(src)
	}
	if child := node.ChildByFieldName("declarator"); child != nil {
		return cDeclaratorName(child, src)
	}
	return ""
}

func cParameters(declarator *sitter.Node, src []byte) []FunctionParameter {
	parameters := cDescendantByType(declarator, cNodeParameterList)
	if parameters == nil {
		return nil
	}

	var result []FunctionParameter
	for i := 0; i < int(parameters.NamedChildCount()); i++ {
		parameter := parameters.NamedChild(i)
		if parameter.Type() != "parameter_declaration" {
			continue
		}
		typeNode := parameter.ChildByFieldName("type")
		typeName := ""
		if typeNode != nil {
			typeName = strings.TrimSpace(typeNode.Content(src))
		}
		name := cDeclaratorName(parameter.ChildByFieldName("declarator"), src)
		if typeName == "void" && name == "" && parameters.NamedChildCount() == 1 {
			return nil
		}
		result = append(result, FunctionParameter{Type: typeName, Name: name})
	}
	return result
}

func cDescendantByType(node *sitter.Node, nodeType string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == nodeType {
		return node
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if found := cDescendantByType(node.Child(i), nodeType); found != nil {
			return found
		}
	}
	return nil
}

func (p *CParser) walkCalls(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, calls *[]FunctionCall) {
	if node.Type() == cNodeCallExpression {
		if call := p.parseCall(node, src, filePath, packagePath, staticFunctions); call != nil {
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, packagePath, staticFunctions, calls)
	}
}

func (p *CParser) parseCall(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) *FunctionCall {
	function := node.ChildByFieldName("function")
	if function == nil {
		return nil
	}

	call := &FunctionCall{
		Callee:      FunctionID{Package: packagePath},
		Raw:         function.Content(src),
		FilePath:    filePath,
		Line:        int(node.StartPoint().Row) + 1,
		StartCol:    int(node.StartPoint().Column) + 1,
		EndCol:      int(node.EndPoint().Column) + 1,
		AssignedVar: cAssignedVar(node, src),
		Arguments:   cCallArguments(node, src),
	}

	switch function.Type() {
	case cNodeIdentifier:
		call.Callee.Name = function.Content(src)
		call.Callee.Package = cFunctionPackage(packagePath, filePath, call.Callee.Name, staticFunctions)
	case fieldExpressionNode:
		field := function.ChildByFieldName("field")
		argument := function.ChildByFieldName("argument")
		if field == nil {
			return nil
		}
		call.Callee.Name = field.Content(src)
		if argument != nil && argument.Type() == cNodeIdentifier {
			call.ReceiverVar = argument.Content(src)
		}
	default:
		return nil
	}
	return call
}

func cAssignedVar(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil {
		return ""
	}
	switch parent.Type() {
	case "init_declarator":
		if parent.ChildByFieldName("value") == node {
			return cDeclaratorName(parent.ChildByFieldName("declarator"), src)
		}
	case "assignment_expression":
		if parent.ChildByFieldName("right") == node {
			left := parent.ChildByFieldName("left")
			if left != nil && left.Type() == cNodeIdentifier {
				return left.Content(src)
			}
		}
	}
	return ""
}

func cCallArguments(node *sitter.Node, src []byte) []string {
	arguments := node.ChildByFieldName("arguments")
	if arguments == nil {
		return nil
	}
	return parseArgumentsFromDelimitedContent(arguments.Content(src))
}

func (p *CParser) extractReturnSources(body *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) []SourceNode {
	var sources []SourceNode
	p.walkReturnSources(body, src, filePath, packagePath, staticFunctions, &sources)
	return sources
}

func (p *CParser) walkReturnSources(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, sources *[]SourceNode) {
	if node.Type() == cNodeReturnStatement {
		if expr := cReturnExpression(node); expr != nil {
			if source, ok := p.cReturnSource(expr, src, filePath, packagePath, staticFunctions); ok {
				*sources = append(*sources, source)
			}
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkReturnSources(node.Child(i), src, filePath, packagePath, staticFunctions, sources)
	}
}

func cReturnExpression(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.IsNamed() {
			return child
		}
	}
	return nil
}

func (p *CParser) cReturnSource(expr *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) (SourceNode, bool) {
	location := &SourceLocation{FilePath: filePath, Line: int(expr.StartPoint().Row) + 1}
	switch expr.Type() {
	case cNodeCallExpression:
		call := p.parseCall(expr, src, filePath, packagePath, staticFunctions)
		if call == nil {
			return SourceNode{}, false
		}
		callee := call.Callee
		callee.Name = fmt.Sprintf("%s#%d", callee.Name, len(call.Arguments))
		return SourceNode{Type: "CALL_RESULT", CallTarget: &callee, Location: location}, true
	case cNodeIdentifier:
		return SourceNode{Type: "VARIABLE", Name: expr.Content(src), Location: location}, true
	case "field_expression":
		return SourceNode{Type: "FIELD", Name: expr.Content(src), Location: location}, true
	}
	return SourceNode{}, false
}

// SkipDirs returns build and dependency directories excluded from C traversal.
func (p *CParser) SkipDirs() map[string]bool {
	skip := map[string]bool{"build": true, "vendor": true}
	if !p.includeTests {
		skip["test"] = true
		skip["tests"] = true
	}
	return skip
}

// SubPackagePath constructs a child namespace using path separators.
func (p *CParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "/" + dirName
}

// PackageSeparator returns the C package-path separator.
func (p *CParser) PackageSeparator() string { return "/" }
