package callgraph

import (
	"context"
	"fmt"
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

	analysis := &FileAnalysis{FilePath: filePath, PackageName: packagePath, PackagePath: packagePath, Imports: make(map[string]string)}
	staticFunctions := make(map[string]bool)
	collectCPPStaticFunctions(tree.RootNode(), src, staticFunctions)
	p.walkFile(tree.RootNode(), src, filePath, packagePath, staticFunctions, analysis)
	return analysis, nil
}

func (p *CPPParser) walkFile(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, analysis *FileAnalysis) {
	switch node.Type() {
	case "preproc_include":
		p.extractInclude(node, src, analysis)
	case cppNodeFunctionDefinition:
		if decl := p.parseFunction(node, src, filePath, packagePath, staticFunctions); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkFile(node.Child(i), src, filePath, packagePath, staticFunctions, analysis)
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

func (p *CPPParser) parseFunction(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) *FunctionDecl {
	declarator := node.ChildByFieldName("declarator")
	name, typeName := cppDeclaratorIdentity(declarator, src)
	body := node.ChildByFieldName("body")
	if name == "" || body == nil {
		return nil
	}
	decl := &FunctionDecl{
		ID:           FunctionID{Package: cFunctionPackage(packagePath, filePath, name, staticFunctions), Type: typeName, Name: name},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		OwnerType:    "module",
		OwnerName:    packagePath,
		FunctionType: "function",
		Parameters:   cParameters(declarator, src),
	}
	p.walkCalls(body, src, filePath, packagePath, staticFunctions, &decl.Calls)
	decl.ReturnSources = p.extractReturnSources(body, src, filePath, packagePath, staticFunctions)
	return decl
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
	case cNodeIdentifier:
		return node.Content(src), ""
	case "qualified_identifier":
		parts := strings.Split(node.Content(src), "::")
		return parts[len(parts)-1], strings.Join(parts[:len(parts)-1], "::")
	default:
		return cppDeclaratorIdentity(node.ChildByFieldName("declarator"), src)
	}
}

func (p *CPPParser) walkCalls(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, calls *[]FunctionCall) {
	if node.Type() == cNodeCallExpression {
		if call := p.parseCall(node, src, filePath, packagePath, staticFunctions); call != nil {
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, packagePath, staticFunctions, calls)
	}
}

func (p *CPPParser) parseCall(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) *FunctionCall {
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
		}
	case "qualified_identifier":
		parts := strings.Split(function.Content(src), "::")
		if len(parts) < 2 {
			return nil
		}
		call.Callee.Name = parts[len(parts)-1]
		call.Callee.Type = strings.Join(parts[:len(parts)-1], "::")
	default:
		return nil
	}
	return call
}

func (p *CPPParser) extractReturnSources(body *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) []SourceNode {
	var sources []SourceNode
	p.walkReturnSources(body, src, filePath, packagePath, staticFunctions, &sources)
	return sources
}

func (p *CPPParser) walkReturnSources(node *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool, sources *[]SourceNode) {
	if node.Type() == "lambda_expression" {
		return
	}
	if node.Type() == cNodeReturnStatement {
		if expr := cReturnExpression(node); expr != nil {
			if source, ok := p.returnSource(expr, src, filePath, packagePath, staticFunctions); ok {
				*sources = append(*sources, source)
			}
		}
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkReturnSources(node.Child(i), src, filePath, packagePath, staticFunctions, sources)
	}
}

func (p *CPPParser) returnSource(expr *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) (SourceNode, bool) {
	location := &SourceLocation{FilePath: filePath, Line: int(expr.StartPoint().Row) + 1}
	switch expr.Type() {
	case cNodeCallExpression:
		call := p.parseCall(expr, src, filePath, packagePath, staticFunctions)
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
	return chainID, cAssignedVar(root, src)
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

// SkipDirs returns build and dependency directories excluded from C++ traversal.
func (p *CPPParser) SkipDirs() map[string]bool {
	skip := map[string]bool{"build": true, "vendor": true}
	if !p.includeTests {
		skip["test"] = true
		skip["tests"] = true
	}
	return skip
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
