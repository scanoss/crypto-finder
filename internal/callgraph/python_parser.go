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
		FromImports:   make(map[string]bool),
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
	analysis.FromImports[name] = true
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
	var bases []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			className = child.Content(src)
		case "argument_list":
			// class Foo(Base1, Base2): the argument_list holds the superclass names.
			bases = extractPythonBaseClassNames(child, src)
		case "block":
			body = child
		}
	}

	if className == "" || body == nil {
		return
	}

	// Walk class body for method definitions.
	p.extractClassMethods(body, src, filePath, packagePath, className, bases, analysis)
}

// extractPythonBaseClassNames returns the simple identifier names from a
// class_definition argument_list node (the "(Base1, Base2)" part).
// Only direct identifier bases are collected; complex expressions (e.g. generics,
// attribute access like "abc.ABC") are currently included as their full text.
func extractPythonBaseClassNames(argListNode *sitter.Node, src []byte) []string {
	var bases []string
	for i := 0; i < int(argListNode.ChildCount()); i++ {
		child := argListNode.Child(i)
		switch child.Type() {
		case goNodeIdentifier, "attribute":
			name := child.Content(src)
			if name != "" {
				bases = append(bases, name)
			}
		}
	}
	return bases
}

// extractClassMethods extracts method declarations from a class body node.
func (p *PythonParser) extractClassMethods(body *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis) {
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, className, analysis)
			if decl != nil {
				decl.OwnerBases = bases
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "decorated_definition":
			p.extractDecoratedMethod(child, src, filePath, packagePath, className, bases, analysis)
		}
	}
}

// extractDecoratedMethod extracts a method from a decorated_definition within a class.
// bases are the direct superclass names of className, propagated from processClass.
func (p *PythonParser) extractDecoratedMethod(node *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis) {
	for j := 0; j < int(node.ChildCount()); j++ {
		inner := node.Child(j)
		if inner.Type() != pythonNodeFunctionDefinition {
			continue
		}
		decl := p.parseFunctionDef(inner, src, filePath, packagePath, className, analysis)
		if decl != nil {
			decl.OwnerBases = bases
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

// extractCalls walks a function body to find all call expressions, collecting
// local variable assignments first so ReceiverVar can be attributed correctly.
func (p *PythonParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis) []FunctionCall {
	// Build the set of local variable names from assignment statements in this body.
	localVars := collectPythonLocalVars(body, src)

	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, localVars, &calls)
	return calls
}

// collectPythonLocalVars scans a function body for assignment targets to
// populate the set of known local variable names. This is used to distinguish
// receiver variables from module or type names.
func collectPythonLocalVars(body *sitter.Node, src []byte) map[string]bool {
	locals := make(map[string]bool)
	collectPythonLocalVarsInNode(body, src, locals)
	return locals
}

func collectPythonLocalVarsInNode(node *sitter.Node, src []byte, locals map[string]bool) {
	if node == nil {
		return
	}
	if node.Type() == "assignment" {
		left := node.ChildByFieldName("left")
		if left != nil && left.Type() == goNodeIdentifier {
			locals[left.Content(src)] = true
		}
		// Also handle augmented assignments (+=, etc.)
	}
	// Walk all children to catch assignments in nested blocks.
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPythonLocalVarsInNode(node.Child(i), src, locals)
	}
}

func (p *PythonParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, localVars map[string]bool, calls *[]FunctionCall) {
	if node.Type() == "call" {
		if call := p.parseCallExpr(node, src, filePath, analysis, localVars); call != nil {
			*calls = append(*calls, *call)
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, localVars, calls)
	}
}

// parseCallExpr parses a call expression into a FunctionCall.
func (p *PythonParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, localVars map[string]bool) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	raw := funcNode.Content(src)
	args := p.extractPythonCallArguments(node, src)

	chainID, assignedVar := pythonCallChainContext(node, src)

	switch funcNode.Type() {
	case goNodeIdentifier:
		// Simple call like `sha256()` or imported class constructor like `Cipher()`
		name := funcNode.Content(src)
		if pkg, ok := analysis.Imports[name]; ok {
			if analysis.ImportedTypes[name] {
				return &FunctionCall{
					Callee:      FunctionID{Package: pkg, Type: name, Name: constructorMethodName},
					Raw:         raw,
					FilePath:    filePath,
					Line:        line,
					Arguments:   args,
					AssignedVar: assignedVar,
					ChainID:     chainID,
				}
			}

			return &FunctionCall{
				Callee:      FunctionID{Package: pkg, Name: name},
				Raw:         raw,
				FilePath:    filePath,
				Line:        line,
				Arguments:   args,
				AssignedVar: assignedVar,
				ChainID:     chainID,
			}
		}
		return &FunctionCall{
			Callee:      FunctionID{Package: analysis.PackagePath, Name: name},
			Raw:         raw,
			FilePath:    filePath,
			Line:        line,
			Arguments:   args,
			AssignedVar: assignedVar,
			ChainID:     chainID,
		}
	case "attribute":
		// Method/attribute call like `hashlib.sha256()` or `obj.method()`
		return p.parseAttributeCall(funcNode, src, filePath, line, args, analysis, localVars, chainID, assignedVar)
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

// parseAttributeCall handles calls on attributes like `module.func()`, `obj.method()`,
// or chained calls like `Cipher(a,b).encryptor().update(data)`.
func (p *PythonParser) parseAttributeCall(node *sitter.Node, src []byte, filePath string, line int, args []string, analysis *FileAnalysis, localVars map[string]bool, chainID, assignedVar string) *FunctionCall {
	var object, method string
	objectIsCall := false

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
			// Chained attribute: `a.b.c()` — recurse to get text
			object = child.Content(src)
		case "call":
			// Chained call: `Cipher(a,b).encryptor()` — object is a call result.
			// Use the raw text as a placeholder identifier; the ReceiverVar logic
			// will not fire (it only fires for simple identifier locals).
			object = child.Content(src)
			objectIsCall = true
		}
	}

	if method == "" {
		return nil
	}

	raw := node.Content(src)

	// "self" calls are local method calls
	if object == pythonSelfObjectName {
		return &FunctionCall{
			Callee:      FunctionID{Package: analysis.PackagePath, Name: method},
			Raw:         raw,
			FilePath:    filePath,
			Line:        line,
			Arguments:   args,
			ChainID:     chainID,
			AssignedVar: assignedVar,
		}
	}

	// Determine ReceiverVar: only when object is a simple local variable (not a
	// module import, not a type name, and not itself a call expression result).
	receiverVar := pythonReceiverVarName(object, objectIsCall, analysis, localVars)

	// Try to resolve the object through imports (module-qualified calls).
	if !objectIsCall {
		if pkg, ok := analysis.Imports[object]; ok {
			// When the symbol was introduced via `from X import Y`, the real
			// module path for the call is X.Y, not X. For example:
			//   from Crypto.Cipher import AES; AES.new(key, mode)
			// must emit Package="Crypto.Cipher.AES", Name="new" so the KB join
			// hits `Crypto.Cipher.AES.new` (not `Crypto.Cipher.new`).
			// Plain `import hashlib; hashlib.sha256()` is NOT a from-import, so
			// Package="hashlib" is preserved unchanged.
			// Note: in the attribute-call path we always use the full X.Y form for
			// from-imports regardless of capitalisation, because AES.new(...) is a
			// module-level function call, not a constructor — constructors go through
			// the direct-call path (parseCallExpr's identifier branch).
			resolvedPkg := pkg
			if analysis.FromImports[object] {
				resolvedPkg = pkg + "." + object
			}
			return &FunctionCall{
				Callee:      FunctionID{Package: resolvedPkg, Name: method},
				Raw:         raw,
				FilePath:    filePath,
				Line:        line,
				Arguments:   args,
				ReceiverVar: receiverVar,
				ChainID:     chainID,
				AssignedVar: assignedVar,
			}
		}

		// Handle chained attribute access like `cryptography.hazmat.primitives.hashes.SHA256()`
		// Try to resolve by splitting off the first segment.
		if dotIdx := strings.Index(object, "."); dotIdx > 0 {
			firstSegment := object[:dotIdx]
			if pkg, ok := analysis.Imports[firstSegment]; ok {
				fullPath := pkg + "." + object[dotIdx+1:]
				return &FunctionCall{
					Callee:      FunctionID{Package: fullPath, Name: method},
					Raw:         raw,
					FilePath:    filePath,
					Line:        line,
					Arguments:   args,
					ReceiverVar: receiverVar,
					ChainID:     chainID,
					AssignedVar: assignedVar,
				}
			}
		}
	}

	// Fallback: assume same package (local object or unresolved chain result).
	return &FunctionCall{
		Callee:      FunctionID{Package: analysis.PackagePath, Type: object, Name: method},
		Raw:         raw,
		FilePath:    filePath,
		Line:        line,
		Arguments:   args,
		ReceiverVar: receiverVar,
		ChainID:     chainID,
		AssignedVar: assignedVar,
	}
}

// pythonReceiverVarName returns the receiver variable name when the object of a
// method call is a known local variable. Returns "" for module imports, type
// names (CapitalCase), or call expression results.
func pythonReceiverVarName(object string, objectIsCall bool, analysis *FileAnalysis, localVars map[string]bool) string {
	if objectIsCall || object == "" || object == pythonSelfObjectName {
		return ""
	}
	// Module import — not a receiver variable.
	if _, isImport := analysis.Imports[object]; isImport {
		return ""
	}
	// Type name (CapitalCase) — not a receiver variable.
	if looksLikePythonTypeName(object) {
		return ""
	}
	// Must be a known local variable.
	if localVars[object] {
		return object
	}
	return ""
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

// pythonCallChainContext derives, for a Python call node, the fluent-chain
// grouping ID and the variable name that this call's result is assigned to.
//
// ChainID is non-empty only when the call participates in a multi-link fluent
// chain such as `Cipher(a, m).encryptor().update(x)`. All links of the chain
// share the chain root's StartByte as a decimal string — exactly mirroring the
// Java callChainContext derivation.
//
// AssignedVar is populated only on the chain root (the outermost call) when
// that root is the right-hand side of an assignment statement, e.g.
// `result = Cipher(a,m).encryptor()` → AssignedVar "result" on `encryptor()`.
func pythonCallChainContext(node *sitter.Node, src []byte) (chainID, assignedVar string) {
	root := pythonChainRootNode(node)
	if root != node {
		// Inner link: shares the root's byte offset, no assignment on this link.
		return fmt.Sprintf("%d", root.StartByte()), ""
	}
	// Chain root: check whether it has inner links below it.
	if isPythonCallNode(node.Child(0)) || isPythonAttributeCallNode(node) {
		// Only set ChainID when there's actually a chain (the call's function is an
		// attribute whose object is itself a call).
		funcChild := node.Child(0)
		if funcChild != nil && funcChild.Type() == "attribute" {
			obj := funcChild.ChildByFieldName("object")
			if obj != nil && obj.Type() == "call" {
				chainID = fmt.Sprintf("%d", root.StartByte())
			}
		}
	}
	return chainID, pythonAssignedVarFromParent(root, src)
}

// pythonChainRootNode walks UP through enclosing Python call→attribute nodes
// whose object is the current node, returning the outermost call of the fluent
// chain. Mirrors Java's chainRootNode.
//
// Python chain structure: `a().b().c()` AST:
//
//	call[c()] → attribute[a().b().c] → call[b()] → attribute[a().b] → call[a()]
//
// Walking from `a()`:
//
//	parent = attribute (a().b), parent.object == a() → continue
//	parent of that attribute = call (b()), i.e. that call's function == attribute → continue upward
func pythonChainRootNode(node *sitter.Node) *sitter.Node {
	root := node
	for {
		// node's parent is an "attribute" node whose "object" field is this node
		attrParent := root.Parent()
		if attrParent == nil || attrParent.Type() != "attribute" {
			break
		}
		obj := attrParent.ChildByFieldName("object")
		if obj != root {
			break
		}
		// attrParent.parent should be a call node whose first child (function) is attrParent
		callParent := attrParent.Parent()
		if callParent == nil || callParent.Type() != "call" {
			break
		}
		if callParent.Child(0) != attrParent {
			break
		}
		root = callParent
	}
	return root
}

// isPythonCallNode reports whether node is a call expression.
func isPythonCallNode(node *sitter.Node) bool {
	return node != nil && node.Type() == "call"
}

// isPythonAttributeCallNode reports whether the call node's function child is
// an attribute whose object is itself a call (i.e., a chained call).
func isPythonAttributeCallNode(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	fn := node.Child(0)
	if fn == nil || fn.Type() != "attribute" {
		return false
	}
	obj := fn.ChildByFieldName("object")
	return obj != nil && obj.Type() == "call"
}

// pythonAssignedVarFromParent returns the variable name a Python call result is
// bound to when the call is on the right-hand side of an assignment statement.
// Returns "" for unassigned calls. Mirrors Java's assignedVarFromParent.
//
// Handles:
//   - `cipher = Cipher(a, m)` — expression_statement → assignment
//   - direct assignment in a block
func pythonAssignedVarFromParent(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil {
		return ""
	}
	if parent.Type() == "assignment" {
		left := parent.ChildByFieldName("left")
		if left != nil && left.Type() == goNodeIdentifier {
			return left.Content(src)
		}
		return ""
	}
	// expression_statement wrapping an assignment
	if parent.Type() == "expression_statement" {
		gp := parent.Parent()
		if gp != nil && gp.Type() == "assignment" {
			left := gp.ChildByFieldName("left")
			if left != nil && left.Type() == goNodeIdentifier {
				return left.Content(src)
			}
		}
	}
	return ""
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
