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
	// visits, when non-nil, counts every node visited by this parser
	// instance's recursive walkers (D4, python-parser-parity-2). Always nil
	// in production — set only by TestPythonParser_NodeVisitBudget via
	// direct same-package field access. A PythonParser is never shared
	// across goroutines (CloneParser returns an independent instance per
	// worker), so an instance field is race-free without synchronization.
	// Production cost is a single nil-pointer compare per node.
	visits *int
}

// countVisit increments p.visits when the visit-budget test hook is active
// (D4). Called once per node by every top-level recursive walker so the
// hook's cost never depends on how many walkers happen to visit a node.
func (p *PythonParser) countVisit() {
	if p.visits != nil {
		*p.visits++
	}
}

// pythonVisitBudgetPerCall bounds the extra node-visit allowance
// TestPythonParser_NodeVisitBudget grants per call node, on top of the
// file's total node count, to account for deferred per-scope call
// resolution (D1): a call is collected once during the single descent and
// revisited once more when its scope resolves pending calls.
const pythonVisitBudgetPerCall = 8

const (
	pythonNodeDottedName         = "dotted_name"
	pythonNodeFunctionDefinition = "function_definition"
	pythonNodeAttribute          = "attribute"
	pythonNodeAssignment         = "assignment"
	pythonNodeCall               = "call"
	pythonNodeArgumentList       = "argument_list"
	pythonNodeAliasedImport      = "aliased_import"
	pythonNodeClassDefinition    = "class_definition"
	pythonNodeListSplatPattern   = "list_splat_pattern"
	pythonNodeDictSplatPattern   = "dictionary_splat_pattern"
	pythonNodeParameters         = "parameters"
	// pythonOwnerTypeModule is both the FunctionDecl.OwnerType value for a
	// module-scoped function AND (not coincidentally — CPython's grammar
	// names its root node the same way) the tree-sitter root node's own
	// Type(), reused as such in ast_anchor.go's isFunctionContainer.
	pythonOwnerTypeModule = "module"
	pythonSelfObjectName  = "self"
	pythonClsObjectName   = "cls"
	pythonInitMethodName  = "__init__"
	// pythonInitPyFileName is the Python package-init filename. A file with
	// this basename is the only place `__init__.py` re-export collection
	// (collectPythonReExports) runs.
	pythonInitPyFileName = "__init__.py"
	// pythonNodeRelativeImport is the tree-sitter node type for a relative
	// `from` import's dot-prefixed module reference (e.g. `.mod`, `..pkg`).
	pythonNodeRelativeImport = "relative_import"
)

// pythonSymbolTable caches tree-sitter grammar symbol IDs for the node types
// compared in hot per-node dispatch loops (the recursive tree walkers, which
// visit every node in a file — potentially several times per file).
// Node.Symbol() is a single cheap cgo call returning a small integer;
// Node.Type() additionally calls C.GoString on every invocation, allocating
// a fresh Go string from the C buffer each time. Resolving the symbols ONCE
// (via resolvePythonSymbols, at package init) and comparing sitter.Symbol
// values directly in the walkers removes that per-node cgo string
// allocation from the hottest code paths in the parser.
type pythonSymbolTable struct {
	assignment              sitter.Symbol
	augmentedAssignment     sitter.Symbol
	asPattern               sitter.Symbol
	forStatement            sitter.Symbol
	namedExpression         sitter.Symbol
	call                    sitter.Symbol
	functionDefinition      sitter.Symbol
	classDefinition         sitter.Symbol
	decoratedDefinition     sitter.Symbol
	lambda                  sitter.Symbol
	listComprehension       sitter.Symbol
	setComprehension        sitter.Symbol
	dictionaryComprehension sitter.Symbol
	generatorExpression     sitter.Symbol
	importStatement         sitter.Symbol
	importFromStatement     sitter.Symbol
	identifier              sitter.Symbol
	forInClause             sitter.Symbol

	// Added by design §3.3 (python-parser-parity-2, A1) to extend
	// symbol-id dispatch across the single-descent walker and its readers.
	block                 sitter.Symbol
	parameters            sitter.Symbol
	attribute             sitter.Symbol
	argumentList          sitter.Symbol
	dottedName            sitter.Symbol
	aliasedImport         sitter.Symbol
	wildcardImport        sitter.Symbol
	relativeImport        sitter.Symbol
	importPrefix          sitter.Symbol
	typedParameter        sitter.Symbol
	defaultParameter      sitter.Symbol
	typedDefaultParameter sitter.Symbol
	patternList           sitter.Symbol
	tuplePattern          sitter.Symbol
	listPattern           sitter.Symbol
	listSplatPattern      sitter.Symbol
	dictSplatPattern      sitter.Symbol
	expressionStatement   sitter.Symbol
	keywordArgument       sitter.Symbol
	integer               sitter.Symbol
	string                sitter.Symbol
	stringContent         sitter.Symbol
	typeNode              sitter.Symbol
	genericType           sitter.Symbol
	typeParameter         sitter.Symbol
	binaryOperator        sitter.Symbol
	none                  sitter.Symbol
	decorator             sitter.Symbol
	await                 sitter.Symbol
	lambdaParameters      sitter.Symbol
}

// pythonSyms is resolved ONCE at package init against the Python grammar
// tree-sitter is compiled with (the same grammar every PythonParser/
// CloneParser instance uses), so no per-parser-instance resolution is
// needed.
var pythonSyms = resolvePythonSymbols(python.GetLanguage())

// resolvePythonSymbols iterates the language's full symbol table exactly
// once, matching each entry's grammar-rule name against the node type
// strings this parser cares about. A handful of cgo calls at package init
// time, trading a one-time cost for the elimination of repeated Type()
// string comparisons (and their per-call allocations) from every node visit
// during every file parse.
func resolvePythonSymbols(lang *sitter.Language) pythonSymbolTable {
	var t pythonSymbolTable
	dst := map[string]*sitter.Symbol{
		pythonNodeAssignment:         &t.assignment,
		"augmented_assignment":       &t.augmentedAssignment,
		"as_pattern":                 &t.asPattern,
		"for_statement":              &t.forStatement,
		"named_expression":           &t.namedExpression,
		pythonNodeCall:               &t.call,
		pythonNodeFunctionDefinition: &t.functionDefinition,
		pythonNodeClassDefinition:    &t.classDefinition,
		"decorated_definition":       &t.decoratedDefinition,
		"lambda":                     &t.lambda,
		"list_comprehension":         &t.listComprehension,
		"set_comprehension":          &t.setComprehension,
		"dictionary_comprehension":   &t.dictionaryComprehension,
		"generator_expression":       &t.generatorExpression,
		"import_statement":           &t.importStatement,
		"import_from_statement":      &t.importFromStatement,
		goNodeIdentifier:             &t.identifier,
		"for_in_clause":              &t.forInClause,

		goNodeBlock:                 &t.block,
		pythonNodeParameters:        &t.parameters,
		pythonNodeAttribute:         &t.attribute,
		pythonNodeArgumentList:      &t.argumentList,
		pythonNodeDottedName:        &t.dottedName,
		pythonNodeAliasedImport:     &t.aliasedImport,
		"wildcard_import":           &t.wildcardImport,
		pythonNodeRelativeImport:    &t.relativeImport,
		"import_prefix":             &t.importPrefix,
		"typed_parameter":           &t.typedParameter,
		"default_parameter":         &t.defaultParameter,
		"typed_default_parameter":   &t.typedDefaultParameter,
		"pattern_list":              &t.patternList,
		"tuple_pattern":             &t.tuplePattern,
		"list_pattern":              &t.listPattern,
		pythonNodeListSplatPattern:  &t.listSplatPattern,
		pythonNodeDictSplatPattern:  &t.dictSplatPattern,
		rustNodeExpressionStatement: &t.expressionStatement,
		"keyword_argument":          &t.keywordArgument,
		"integer":                   &t.integer,
		"string":                    &t.string,
		"string_content":            &t.stringContent,
		"type":                      &t.typeNode,
		"generic_type":              &t.genericType,
		"type_parameter":            &t.typeParameter,
		"binary_operator":           &t.binaryOperator,
		"none":                      &t.none,
		"decorator":                 &t.decorator,
		"await":                     &t.await,
		"lambda_parameters":         &t.lambdaParameters,
	}
	count := lang.SymbolCount()
	for i := uint32(0); i < count; i++ {
		sym := sitter.Symbol(i)
		if field, ok := dst[lang.SymbolName(sym)]; ok {
			*field = sym
		}
	}
	return t
}

// NewPythonParser creates a new Python source parser backed by tree-sitter.
func NewPythonParser(opts ...ParserOption) *PythonParser {
	cfg := newParserConfig(opts)
	p := sitter.NewParser()
	p.SetLanguage(python.GetLanguage())
	return &PythonParser{parser: p, includeTests: cfg.includeTests}
}

// CloneParser returns an independent PythonParser with the same configuration,
// for concurrent use (tree-sitter parsers are not reentrant).
func (p *PythonParser) CloneParser() Parser {
	return NewPythonParser(WithIncludeTests(p.includeTests))
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
		if !strings.HasSuffix(name, ".py") && !strings.HasSuffix(name, ".pyi") {
			continue
		}
		if !p.includeTests && (strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || strings.HasSuffix(name, "_test.pyi")) {
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

	// ONE full-file descent (D1, python-parser-parity-2 A1) replaces the
	// former three-walk pipeline (import prepass + per-function
	// walkForCalls + pruned walkPrunedForCalls): import/re-export
	// discovery, every scope's binding table, and every pending call node
	// are all collected in a single pythonWalk pass. Call resolution itself
	// is DEFERRED — pythonWalk only records pending call node references;
	// extractDeclarations resolves them per scope afterwards, once every
	// scope's binding layer is fully populated (see pythonWalk's doc
	// comment for the full scope-stack contract).
	isInitPy := filepath.Base(filePath) == pythonInitPyFileName
	fw := &pythonFileWalk{
		moduleScope: &pythonScope{locals: &pythonBindingLayer{}},
		funcScopes:  make(map[uint32]*pythonScope),
		classInfo:   make(map[uint32]*pythonClassInfo),
		classDirect: make(map[uint32]*pythonScope),
	}
	p.pythonWalk(root, src, analysis, isInitPy, fw, fw.moduleScope.locals, nil, nil, nil, true)

	// Extract function and class declarations, resolving each scope's
	// pending calls (fw) against its now-complete binding layer.
	p.extractDeclarations(root, src, filePath, packagePath, analysis, fw)

	return analysis, nil
}

func (p *PythonParser) recordPythonReExportsFromStatement(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	moduleNameNode := node.ChildByFieldName("module_name")
	if moduleNameNode == nil || moduleNameNode.Type() != pythonNodeRelativeImport {
		// Only an explicit relative import re-exports; absolute imports in
		// __init__.py are left alone (design: gated on in-graph evidence,
		// not inferred).
		return
	}
	modulePath, ok := pythonImportFromModulePath(moduleNameNode, src, analysis.PackagePath)
	if !ok {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		if node.FieldNameForChild(i) != "name" {
			continue
		}
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeDottedName:
			recordPythonReExport(analysis, child.Content(src), modulePath)
		case pythonNodeAliasedImport:
			aliasNode := child.ChildByFieldName("alias")
			if aliasNode != nil {
				recordPythonReExport(analysis, aliasNode.Content(src), modulePath)
			}
		}
		// wildcard_import carries no "name" field and is intentionally
		// ignored — `from .mod import *` never re-exports a known symbol.
	}
}

func recordPythonReExport(analysis *FileAnalysis, symbol, modulePath string) {
	if analysis.PythonReExports == nil {
		analysis.PythonReExports = make(map[string]string)
	}
	if _, exists := analysis.PythonReExports[symbol]; exists {
		return
	}
	analysis.PythonReExports[symbol] = modulePath
}

// pythonBindingLayer is a chain-of-maps lexical binding scope (D2, A1): a
// map of names bound directly at THIS layer, plus a parent layer for names
// bound in an enclosing scope. Ordinary binders (assignment, with/for/
// except-as, walrus) bind into a scope's single ROOT layer in place;
// comprehensions are the only construct that pushes a fresh CHILD layer for
// their own subtree (pythonWalk), replacing the former cloned-map-per-
// comprehension approach with an O(1) push instead of an O(n) copy.
type pythonBindingLayer struct {
	parent *pythonBindingLayer
	names  map[string]bool
}

// has reports whether name is bound in this layer or any enclosing layer.
func (l *pythonBindingLayer) has(name string) bool {
	for cur := l; cur != nil; cur = cur.parent {
		if cur.names[name] {
			return true
		}
	}
	return false
}

// bind records name as bound directly in this layer.
func (l *pythonBindingLayer) bind(name string) {
	if l.names == nil {
		l.names = make(map[string]bool)
	}
	l.names[name] = true
}

// pythonPendingCall is a call node collected during pythonWalk's single
// descent together with the binding layer active at its position, resolved
// later (D1) once its enclosing scope's ENTIRE body has been walked — so a
// call that textually precedes its binder (e.g. a body-top call before a
// body-bottom `with ... as name:`) still resolves correctly, without a
// separate prepass.
type pythonPendingCall struct {
	node  *sitter.Node
	layer *pythonBindingLayer
}

// pythonScope is one scope's accumulated state: its root binding layer,
// its pending (unresolved) calls in visitation/document order (D3), and —
// for a method's function scope — the enclosing class's attrs (nil
// otherwise). Used for the module scope, each class's own "direct" body
// scope (the synthetic <clinit> source), and each outermost function/method
// scope.
type pythonScope struct {
	locals  *pythonBindingLayer
	attrs   map[string]bool // class-scoped self/cls attribute names; nil outside a class
	pending []pythonPendingCall
}

// pythonClassInfo accumulates one class's self/cls attribute set, collected
// across the FULL depth of the class body — self.attr=... may appear inside
// any method — active for the class's ENTIRE subtree (never pruned at a
// nested function/class/decorated-definition/lambda boundary), unlike
// pythonFileWalk.classDirect, which tracks only the class body's OWN direct
// statements for the synthetic <clinit> entry point.
type pythonClassInfo struct {
	attrs map[string]bool
}

// pythonFileWalk is the accumulated output of pythonWalk's single
// traversal: the module-level synthetic <module> entry point's scope, one
// pythonClassInfo (self/cls attrs) and one pythonScope (direct-body pending
// calls/locals, for <clinit>) per class_definition node, and one pythonScope
// per OUTERMOST function_definition node (a top-level function or a
// method), each keyed by that node's StartByte (a cheap,
// collision-free-within-one-parse-tree node identity — two distinct nodes
// never start at the same byte offset). analysis.Imports/FromImports/
// ImportedTypes/WildcardImports/PythonReExports are populated as a side
// effect of the same traversal, not returned here.
type pythonFileWalk struct {
	moduleScope *pythonScope
	funcScopes  map[uint32]*pythonScope
	classInfo   map[uint32]*pythonClassInfo
	classDirect map[uint32]*pythonScope
}

// pythonWalk performs ONE full-file descent, visiting every node exactly
// once, that replaces the former three-walk pipeline: import/from-import
// discovery (recursing into the WHOLE file — `try`/`except`, `if`
// TYPE_CHECKING guards, and function bodies are all in scope, since Python
// permits imports anywhere a statement is valid), __init__.py re-export
// discovery, every scope's binding layer, and every pending call node (see
// pythonPendingCall — resolution is DEFERRED to extractDeclarations, once
// this whole descent finishes and every scope's layer is complete).
//
// Import/re-export discovery is intentionally UNPRUNED — the descent always
// continues into every child regardless of scope. moduleDirect and each
// class's own direct-scope tracking (classDirect) are independently PRUNED
// at function/class/decorated-definition/lambda boundaries
// (isPythonPrunedDefinitionSymbol) so a name — or a pending call — bound
// only inside a nested scope never leaks into an enclosing synthetic entry
// point, while a class's attrs tracking (activeClassInfo) is NEVER pruned
// within that class's own subtree (it must see inside every method).
// Entering a NESTED class_definition (e.g. a class declared inside another
// class's body) starts a BRAND NEW, independent pythonClassInfo/classDirect
// pair (pythonWalkClass) — a self.attr assignment inside the nested class's
// own methods attributes to the nested class, never the enclosing one; no
// test in this codebase exercises a class nested directly inside another
// class's body, and processClass is never invoked recursively for one
// either way, so the nested scope's own entry is simply unused.
//
// activeFunc mirrors activeClassInfo but for function scope: entering a
// function_definition while activeFunc is nil starts a BRAND NEW pythonScope
// for it (pythonWalkEnterFunction), with its OWN independent root layer
// (never chained to the enclosing scope — a function's locals never inherit
// module/class-level names); entering one while activeFunc is ALREADY
// non-nil (a closure nested inside another function) does NOT start a new
// scope — its binders and pending calls keep flowing into the SAME
// enclosing scope, matching the FunctionDecl this closure's calls end up
// attributed to (a nested closure never gets its own FunctionDecl; see
// extractDeclarations/extractClassMethods, which only ever visit top-level
// or class-body-level function_definition nodes). Unlike classDirect,
// function-scope collection is NEVER pruned within an active function — a
// class or lambda nested inside a function still contributes its calls/
// locals to that SAME enclosing function scope.
func (p *PythonParser) pythonWalk(node *sitter.Node, src []byte, analysis *FileAnalysis, isInitPy bool, fw *pythonFileWalk, layer *pythonBindingLayer, activeFunc *pythonScope, activeClassInfo *pythonClassInfo, activeClassDirect *pythonScope, moduleDirect bool) {
	p.countVisit()
	// node.Symbol() is a cgo call: read it ONCE per node (sym) rather than
	// re-invoking it once per switch case — visited-node count dominates
	// this walk's cost (every node in the file goes through this
	// dispatch), so a repeated per-case cgo call here would multiply that
	// cost several-fold across the whole traversal.
	sym := node.Symbol()

	switch sym {
	case pythonSyms.importStatement:
		p.processImportStatement(node, src, analysis)
	case pythonSyms.importFromStatement:
		p.processImportFromStatement(node, src, analysis)
		if isInitPy {
			p.recordPythonReExportsFromStatement(node, src, analysis)
		}
	case pythonSyms.classDefinition:
		p.pythonWalkClass(node, src, analysis, isInitPy, fw, activeFunc)
		return
	case pythonSyms.call:
		recordPythonPendingCall(node, layer, fw, activeFunc, activeClassDirect, moduleDirect)
	}

	enteringFunc := sym == pythonSyms.functionDefinition && activeFunc == nil
	if enteringFunc {
		activeFunc = p.pythonWalkEnterFunction(node, src, fw, activeClassInfo)
	}

	recordPythonWalkBinder(node, sym, src, layer, activeClassInfo)

	childLayer := layer
	switch {
	case enteringFunc:
		childLayer = activeFunc.locals
	case isPythonComprehensionSymbol(sym):
		childLayer = &pythonBindingLayer{parent: layer}
	}

	// NamedChildCount()/NamedChild() (not ChildCount()/Child()) — every
	// dispatch case above (and in recordPythonWalkBinder,
	// isPythonPrunedDefinitionSymbol, isPythonComprehensionSymbol) matches
	// only NAMED grammar rules (assignment, call, function_definition, ...),
	// never an anonymous literal token (punctuation, keywords like "def"/
	// "class"/"return"). go-tree-sitter's binding allocates and caches a Go
	// *Node wrapper (Tree.cachedNode) for EVERY node surfaced via Child(),
	// named or not; skipping anonymous tokens here removes a large fraction
	// of wrapper allocations across a full-file descent for free, since this
	// switch's own dispatch behavior is unaffected — see
	// TestPythonParser_NodeVisitBudget, which counts only named nodes to
	// match. Also cache the count once per node rather than re-invoking it
	// on every loop condition check.
	childCount := int(node.NamedChildCount())
	for i := 0; i < childCount; i++ {
		child := node.NamedChild(i)
		pruned := isPythonPrunedDefinitionSymbol(child.Symbol())
		nextClassDirect := activeClassDirect
		if pruned {
			nextClassDirect = nil
		}
		p.pythonWalk(child, src, analysis, isInitPy, fw, childLayer, activeFunc, activeClassInfo, nextClassDirect, moduleDirect && !pruned)
	}
}

// pythonWalkClass handles pythonWalk's class_definition case: register a
// brand new pythonClassInfo (attrs) and pythonScope (classDirect, for
// <clinit>) for node, keyed by StartByte, and recurse into its children
// with that fresh pair active. A class boundary always prunes the enclosing
// module's direct scope, regardless of the moduleDirect value node itself
// inherited. activeFunc is threaded through unchanged: a class defined
// INSIDE a function body (rare) has its methods' calls/locals swept into
// the SAME enclosing function's scope, matching pythonWalk's fully-unpruned
// treatment of an active function (processClass is never invoked for such a
// class, so its own methods are never separately extracted either).
func (p *PythonParser) pythonWalkClass(node *sitter.Node, src []byte, analysis *FileAnalysis, isInitPy bool, fw *pythonFileWalk, activeFunc *pythonScope) {
	info := &pythonClassInfo{attrs: make(map[string]bool)}
	fw.classInfo[node.StartByte()] = info
	direct := &pythonScope{locals: &pythonBindingLayer{}, attrs: info.attrs}
	fw.classDirect[node.StartByte()] = direct

	childCount := int(node.NamedChildCount())
	for i := 0; i < childCount; i++ {
		p.pythonWalk(node.NamedChild(i), src, analysis, isInitPy, fw, direct.locals, activeFunc, info, direct, false)
	}
}

// pythonWalkEnterFunction handles pythonWalk's function_definition case for
// the OUTERMOST active function scope: register a brand new pythonScope for
// node (keyed by StartByte), pre-populate its root layer with node's own
// declared parameter names, attach the enclosing class's attrs (nil outside
// a class), and return it so the caller's recursive descent threads it
// through as the active function scope.
func (p *PythonParser) pythonWalkEnterFunction(node *sitter.Node, src []byte, fw *pythonFileWalk, activeClassInfo *pythonClassInfo) *pythonScope {
	root := &pythonBindingLayer{}
	for i := 0; i < int(node.ChildCount()); i++ {
		if child := node.Child(i); child.Type() == pythonNodeParameters {
			for _, name := range pythonParameterNames(child, src) {
				root.bind(name)
			}
			break
		}
	}
	var attrs map[string]bool
	if activeClassInfo != nil {
		attrs = activeClassInfo.attrs
	}
	scope := &pythonScope{locals: root, attrs: attrs}
	fw.funcScopes[node.StartByte()] = scope
	return scope
}

// recordPythonPendingCall attributes a call node to whichever scope's
// pending list will actually be resolved: the innermost active function
// (regardless of class nesting — a method's or closure's calls always
// belong to it), else the active class's own direct-body scope (<clinit>),
// else the module scope when still module-direct. A call reachable through
// none of these (e.g. inside a lambda or nested class whose own direct
// scope has already been pruned, with no active function) is silently
// dropped — this exactly mirrors the former walkPrunedForCalls's pruning of
// such positions for the <module>/<clinit> synthetic entry points.
func recordPythonPendingCall(node *sitter.Node, layer *pythonBindingLayer, fw *pythonFileWalk, activeFunc, activeClassDirect *pythonScope, moduleDirect bool) {
	pc := pythonPendingCall{node: node, layer: layer}
	switch {
	case activeFunc != nil:
		activeFunc.pending = append(activeFunc.pending, pc)
	case activeClassDirect != nil:
		activeClassDirect.pending = append(activeClassDirect.pending, pc)
	case moduleDirect:
		fw.moduleScope.pending = append(fw.moduleScope.pending, pc)
	}
}

// recordPythonWalkBinder applies pythonWalk's binder detection for one
// node: an ordinary binder (assignment/augmented_assignment, with/except
// `as`, `for`, walrus) binds into the CURRENT layer (which is already
// scoped to the right function/class-direct/module root, or a nested
// comprehension child layer — see pythonWalk), and — when inside a class,
// at any depth — a plain (non-augmented) self/cls attribute assignment adds
// to that class's attrs. sym is node.Symbol(), precomputed once by the
// caller's switch dispatch and threaded through here so this node's symbol
// is never re-fetched via another cgo call.
func recordPythonWalkBinder(node *sitter.Node, sym sitter.Symbol, src []byte, layer *pythonBindingLayer, activeClassInfo *pythonClassInfo) {
	switch sym {
	case pythonSyms.assignment, pythonSyms.augmentedAssignment:
		collectPythonAssignmentTargetsLayer(node.ChildByFieldName("left"), src, layer)
		if sym == pythonSyms.assignment && activeClassInfo != nil {
			if attr, ok := pythonSelfOrClsAttrTarget(node.ChildByFieldName("left"), src); ok {
				activeClassInfo.attrs[attr] = true
			}
		}
	case pythonSyms.asPattern:
		if aliasTarget := node.ChildByFieldName("alias"); aliasTarget != nil {
			if ident := firstIdentifierChild(aliasTarget); ident != nil {
				layer.bind(ident.Content(src))
			}
		}
	case pythonSyms.forStatement:
		collectPythonAssignmentTargetsLayer(node.ChildByFieldName("left"), src, layer)
	case pythonSyms.forInClause:
		// for_in_clause is comprehension/generator-expression-specific (an
		// ordinary for loop uses for_statement, above); its target is
		// bound into the CURRENT layer, which is already the fresh child
		// layer pythonWalk pushed for the enclosing comprehension — see
		// isPythonComprehensionSymbol.
		collectPythonAssignmentTargetsLayer(node.ChildByFieldName("left"), src, layer)
	case pythonSyms.namedExpression:
		if name := node.ChildByFieldName("name"); name != nil && name.Symbol() == pythonSyms.identifier {
			layer.bind(name.Content(src))
		}
	}
}

// collectPythonAssignmentTargetsLayer records every identifier bound by an
// assignment-style target into layer: a plain identifier, or a
// pattern_list/tuple_pattern/list_pattern of nested targets (arbitrarily
// deep, e.g. `a, (b, *rest) = ...`), or a list_splat_pattern/
// dictionary_splat_pattern (`*rest`, `**extra`). An attribute target
// (`self.attr = ...`) is deliberately NOT recorded here — it is a
// class-scoped attribute binding, handled separately by
// recordPythonWalkBinder.
func collectPythonAssignmentTargetsLayer(target *sitter.Node, src []byte, layer *pythonBindingLayer) {
	if target == nil {
		return
	}
	switch target.Type() {
	case goNodeIdentifier:
		layer.bind(target.Content(src))
	case "pattern_list", "tuple_pattern", "list_pattern":
		for i := 0; i < int(target.ChildCount()); i++ {
			collectPythonAssignmentTargetsLayer(target.Child(i), src, layer)
		}
	case pythonNodeListSplatPattern, pythonNodeDictSplatPattern:
		if ident := firstIdentifierChild(target); ident != nil {
			layer.bind(ident.Content(src))
		}
	}
}

// resolvePythonPendingCalls resolves every pending call collected for one
// scope (the module <module>, a class's <clinit>, or an ordinary
// function/method body) into a []FunctionCall, in the SAME order the calls
// were encountered during pythonWalk's single descent — document order
// (D3), the invariant internal/scan/supporting_calls.go's
// lifecycleSelector.selectDescendants depends on for positional self.attr
// rebinding splits.
func (p *PythonParser) resolvePythonPendingCalls(pending []pythonPendingCall, attrs map[string]bool, src []byte, filePath string, analysis *FileAnalysis) []FunctionCall {
	if len(pending) == 0 {
		return nil
	}
	calls := make([]FunctionCall, 0, len(pending))
	for _, pc := range pending {
		bindings := pythonBindings{layer: pc.layer, attrs: attrs}
		if call := p.parseCallExpr(pc.node, src, filePath, analysis, bindings); call != nil {
			setFunctionCallASTAnchor(call, pc.node)
			calls = append(calls, *call)
		}
	}
	return calls
}

// processImportStatement handles `import X` and `import X as Y`.
func (p *PythonParser) processImportStatement(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeDottedName:
			// `import hashlib` -> Imports["hashlib"] = "hashlib".
			// `import a.b.c` -> Imports["a"] = "a" (the bound top-level
			// name, NOT the full dotted path "a.b.c"). Real Python binds
			// only the top-level module name "a" into scope; recording the
			// full path here would make resolveImportedCall's
			// chained-attribute path double-append the dotted suffix
			// ("a.b.c.b.c.foo" instead of "a.b.c.foo") for a later
			// `a.b.c.foo()` call, and would also let this binding silently
			// shadow a later distinct `import a.d` under the same "a" key
			// (see TestPythonParser_Import_DottedPlainImport,
			// TestPythonParser_Import_DottedPlainImport_MultipleTopLevelSiblings).
			name := child.Content(src)
			parts := strings.Split(name, ".")
			recordPythonImportOnce(analysis, parts[0], parts[0])
		case pythonNodeAliasedImport:
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
				recordPythonImportOnce(analysis, alias, module)
			}
		}
	}
}

// processImportFromStatement handles `from X import Y`, `from X import *`,
// `from X import Y as Z`, and relative forms (`from . import x`,
// `from ..pkg import y`). Reads the "module_name" field directly — its
// child is either a dotted_name (absolute import) or a relative_import
// (wrapping import_prefix + an optional dotted_name) — rather than
// scanning direct children for the first dotted_name, which mis-binds
// `from .foo import Bar` (the first dotted_name met that way is "Bar", not
// "foo", since "foo" is nested inside relative_import). See T0 finding 3.
func (p *PythonParser) processImportFromStatement(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	modulePath, ok := pythonImportFromModulePath(node.ChildByFieldName("module_name"), src, analysis.PackagePath)
	if !ok {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		if node.FieldNameForChild(i) != "name" {
			continue
		}
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeDottedName:
			// `from X import name`
			recordImportedPythonSymbol(analysis, child.Content(src), modulePath)
		case pythonNodeAliasedImport:
			// `from X import name as alias`
			nameNode := child.ChildByFieldName("name")
			aliasNode := child.ChildByFieldName("alias")
			if nameNode != nil && aliasNode != nil {
				recordImportedPythonSymbol(analysis, aliasNode.Content(src), modulePath)
			}
		}
	}

	// `from X import *` — wildcard_import carries no "name" field, so it is
	// handled separately from the loop above.
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == "wildcard_import" {
			analysis.WildcardImports = append(analysis.WildcardImports, modulePath)
		}
	}
}

// pythonImportFromModulePath resolves an import_from_statement's
// "module_name" field to a module path: verbatim for an absolute
// dotted_name, or via pythonRelativeModulePath for a relative_import.
// Returns ok=false when the module_name field is nil or the relative import
// walks above the current package root (nothing sensible to resolve to).
func pythonImportFromModulePath(moduleNameNode *sitter.Node, src []byte, packagePath string) (string, bool) {
	if moduleNameNode == nil {
		return "", false
	}
	switch moduleNameNode.Type() {
	case pythonNodeDottedName:
		return moduleNameNode.Content(src), true
	case pythonNodeRelativeImport:
		var prefix, dotted string
		for i := 0; i < int(moduleNameNode.ChildCount()); i++ {
			switch c := moduleNameNode.Child(i); c.Type() {
			case "import_prefix":
				prefix = c.Content(src)
			case pythonNodeDottedName:
				dotted = c.Content(src)
			}
		}
		return pythonRelativeModulePath(packagePath, prefix, dotted)
	default:
		return "", false
	}
}

// pythonRelativeModulePath resolves a relative import's dot-prefix against
// the current file's packagePath. A single dot (prefix ".") means the
// CURRENT package (0 levels up); each additional dot means one more level
// up. dotted is the dotted module name after the dots, or "" for a bare
// `from . import x` / `from .. import x` form.
func pythonRelativeModulePath(packagePath, prefix, dotted string) (string, bool) {
	levelsUp := len(prefix) - 1
	if levelsUp < 0 {
		levelsUp = 0
	}
	var segments []string
	if packagePath != "" {
		segments = strings.Split(packagePath, ".")
	}
	if levelsUp > len(segments) {
		return "", false
	}
	base := strings.Join(segments[:len(segments)-levelsUp], ".")
	switch {
	case base == "" && dotted == "":
		return "", false
	case base == "":
		return dotted, true
	case dotted == "":
		return base, true
	default:
		return base + "." + dotted, true
	}
}

// recordPythonImportOnce records a plain `import X [as Y]` binding, but only
// when the name is not already bound — first binding in document order
// wins (e.g. `try: import fastcrypto as crypto / except ImportError: import
// crypto` keeps the primary `crypto -> fastcrypto` binding).
func recordPythonImportOnce(analysis *FileAnalysis, name, modulePath string) {
	if _, exists := analysis.Imports[name]; exists {
		return
	}
	analysis.Imports[name] = modulePath
}

func recordImportedPythonSymbol(analysis *FileAnalysis, name, modulePath string) {
	if _, exists := analysis.Imports[name]; exists {
		// First binding in document order wins — see recordPythonImportOnce.
		return
	}
	analysis.Imports[name] = modulePath
	analysis.FromImports[name] = true
	if looksLikePythonTypeName(name) {
		analysis.ImportedTypes[name] = true
	}
}

// extractDeclarations walks top-level statements for function and class
// definitions, consuming prepass's precomputed locals/attrs tables (built by
// ONE earlier collectPythonFilePrepass traversal over this same file) so
// neither buildModuleInitDecl nor processClass need to re-walk the tree to
// build them.
func (p *PythonParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, fw *pythonFileWalk) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis, nil, fw)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case pythonNodeClassDefinition:
			p.processClass(child, src, filePath, packagePath, analysis, fw)
		case "decorated_definition":
			// Handle decorated functions and classes
			p.processDecorated(child, src, filePath, packagePath, analysis, fw)
		}
	}

	if moduleDecl := p.buildModuleInitDecl(root, src, filePath, packagePath, analysis, fw); moduleDecl != nil {
		analysis.Functions = append(analysis.Functions, *moduleDecl)
	}
}

// buildModuleInitDecl builds the synthetic `<module>` FunctionDecl for a
// file's direct module-level calls (pruned at any nested
// function/class/decorated-definition/lambda boundary). Returns nil when the
// module body has no such calls — no decl is emitted for a call-free module,
// which is what keeps TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis at zero.
// fw.moduleScope is populated once per file by pythonWalk, already scoped to
// ONLY module-level direct-statement binders and pending calls.
func (p *PythonParser) buildModuleInitDecl(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, fw *pythonFileWalk) *FunctionDecl {
	calls := p.resolvePythonPendingCalls(fw.moduleScope.pending, nil, src, filePath, analysis)
	if len(calls) == 0 {
		return nil
	}
	return &FunctionDecl{
		ID: FunctionID{
			Package: pythonModuleDottedPath(filePath, packagePath),
			Name:    moduleInitMethodName,
		},
		FilePath:     filePath,
		StartLine:    int(root.StartPoint().Row) + 1,
		EndLine:      int(root.EndPoint().Row) + 1,
		OwnerType:    pythonOwnerTypeModule,
		OwnerName:    packagePath,
		FunctionType: functionTypeModuleInit,
		Calls:        calls,
	}
}

// pythonModuleDottedPath returns the module's own dotted path: packagePath
// + "." + the file's stem (e.g. "pkg.a" for "pkg/a.py"), bare packagePath
// for "__init__.py"/"__init__.pyi" (whose module name IS the package), or
// the bare stem when packagePath is empty (a root-level module has no
// package prefix to join with — joining would otherwise produce a
// leading-dot path like ".a").
func pythonModuleDottedPath(filePath, packagePath string) string {
	stem := pythonModuleDottedPathStem(filePath)
	switch {
	case stem == "":
		return packagePath
	case packagePath == "":
		return stem
	default:
		return packagePath + "." + stem
	}
}

// pythonModuleDottedPathStem returns filePath's module stem for
// pythonModuleDottedPath. Unlike pythonModuleFileStem (builder.go — used to
// gate stub-vs-source collision handling and intentionally returns "" for
// any non-".py" extension), this handles BOTH ".py" and ".pyi": a type-stub
// module still needs its own distinct stem so its synthetic <module> decl
// does not collapse onto the bare package path and collide with an
// unrelated __init__.py's <module> decl in the same package. "" is returned
// only for __init__.py/__init__.pyi (whose module name IS the bare package
// path).
func pythonModuleDottedPathStem(filePath string) string {
	ext := filepath.Ext(filePath)
	if ext != ".py" && ext != ".pyi" {
		return ""
	}
	stem := strings.TrimSuffix(filepath.Base(filePath), ext)
	if stem == "" || stem == "__init__" {
		return ""
	}
	return stem
}

// parseFunctionDef parses a function_definition node into a FunctionDecl.
// attrs is the enclosing class's attribute set (nil outside a class). fw is
// the whole-file walk output; node's own scope (parameters plus every
// binder and pending call found anywhere in its body, including nested
// closures — see pythonWalkEnterFunction) was already computed by
// pythonWalk in the SAME earlier traversal that also found this node, and
// is looked up here by node identity (StartByte), not recomputed.
func (p *PythonParser) parseFunctionDef(node *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis, attrs map[string]bool, fw *pythonFileWalk) *FunctionDecl {
	var name string
	var body *sitter.Node
	var paramNode *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			name = child.Content(src)
		case pythonNodeParameters:
			paramNode = child
		case goNodeBlock:
			body = child
		}
	}

	if name == "" {
		return nil
	}

	// Skip dunder methods except __init__
	if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__") && name != pythonInitMethodName {
		return nil
	}

	// Map __init__ to <init> for consistency with Java
	funcName := name
	if name == pythonInitMethodName {
		funcName = constructorMethodName
	}

	ownerType := pythonOwnerTypeModule
	ownerName := packagePath
	functionType := "function"
	if className != "" {
		ownerType = ownerTypeClass
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
		ReturnType:   pythonReturnTypeOf(node, src),
		Parameters:   parsePythonParameters(paramNode, src),
	}

	if body != nil {
		scope := fw.funcScopes[node.StartByte()]
		var pending []pythonPendingCall
		if scope != nil {
			pending = scope.pending
		}
		decl.Calls = p.resolvePythonPendingCalls(pending, attrs, src, filePath, analysis)
	}

	return decl
}

// processClass processes a class_definition node and extracts its methods.
// fw is the whole-file walk output; this class's own scope (attrs +
// direct-body pending calls) was already computed by pythonWalk in a single
// earlier traversal and is looked up here by node identity (StartByte), not
// recomputed.
func (p *PythonParser) processClass(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, fw *pythonFileWalk) {
	var className string
	var body *sitter.Node
	var bases []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case goNodeIdentifier:
			className = child.Content(src)
		case pythonNodeArgumentList:
			// class Foo(Base1, Base2): the argument_list holds the superclass names.
			bases = extractPythonBaseClassNames(child, src)
		case goNodeBlock:
			body = child
		}
	}

	if className == "" || body == nil {
		return
	}

	info := fw.classInfo[node.StartByte()]
	direct := fw.classDirect[node.StartByte()]
	attrs := make(map[string]bool)
	if info != nil {
		// Every class_definition node extractDeclarations/processDecorated
		// visits was also visited by the earlier pythonWalk traversal over
		// this SAME tree, so info/direct are always non-nil in practice;
		// the fresh empty map above is a defensive fallback only, never
		// exercised by a real parse.
		attrs = info.attrs
	}

	// Walk class body for method definitions.
	p.extractClassMethods(body, src, filePath, packagePath, className, bases, analysis, attrs, fw)

	if clinit := p.buildClassInitDecl(body, src, filePath, packagePath, className, analysis, attrs, direct); clinit != nil {
		analysis.Functions = append(analysis.Functions, *clinit)
	}
}

// buildClassInitDecl builds the synthetic `<clinit>` FunctionDecl for a
// class's direct class-body calls (outside any method), pruned at any nested
// function/class/decorated-definition/lambda boundary. Returns nil when the
// class body has no such calls. direct is precomputed once per class by
// pythonWalk, already scoped to ONLY class-body direct-statement pending
// calls.
func (p *PythonParser) buildClassInitDecl(classBody *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis, attrs map[string]bool, direct *pythonScope) *FunctionDecl {
	var pending []pythonPendingCall
	if direct != nil {
		pending = direct.pending
	}
	calls := p.resolvePythonPendingCalls(pending, attrs, src, filePath, analysis)
	if len(calls) == 0 {
		return nil
	}
	return &FunctionDecl{
		ID: FunctionID{
			Package: packagePath,
			Type:    className,
			Name:    clinitMethodName,
		},
		FilePath:     filePath,
		StartLine:    int(classBody.StartPoint().Row) + 1,
		EndLine:      int(classBody.EndPoint().Row) + 1,
		OwnerType:    ownerTypeClass,
		OwnerName:    className,
		FunctionType: functionTypeClassInit,
		Calls:        calls,
	}
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
		case goNodeIdentifier, pythonNodeAttribute:
			name := child.Content(src)
			if name != "" {
				bases = append(bases, name)
			}
		}
	}
	return bases
}

// extractClassMethods extracts method declarations from a class body node.
// attrs is the class's shared self/cls attribute set, collected once by processClass.
func (p *PythonParser) extractClassMethods(body *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis, attrs map[string]bool, fw *pythonFileWalk) {
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, className, analysis, attrs, fw)
			if decl != nil {
				decl.OwnerBases = bases
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "decorated_definition":
			p.extractDecoratedMethod(child, src, filePath, packagePath, className, bases, analysis, attrs, fw)
		}
	}
}

// extractDecoratedMethod extracts a method from a decorated_definition within a class.
// bases are the direct superclass names of className, propagated from processClass.
// attrs is the class's shared self/cls attribute set.
func (p *PythonParser) extractDecoratedMethod(node *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis, attrs map[string]bool, fw *pythonFileWalk) {
	for j := 0; j < int(node.ChildCount()); j++ {
		inner := node.Child(j)
		if inner.Type() != pythonNodeFunctionDefinition {
			continue
		}
		decl := p.parseFunctionDef(inner, src, filePath, packagePath, className, analysis, attrs, fw)
		if decl != nil {
			decl.OwnerBases = bases
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

// processDecorated handles a decorated_definition which wraps a function or class.
func (p *PythonParser) processDecorated(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, fw *pythonFileWalk) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis, nil, fw)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case pythonNodeClassDefinition:
			p.processClass(child, src, filePath, packagePath, analysis, fw)
		}
	}
}

// pythonSelfOrClsAttrTarget reports the attribute name when target is a
// `self.attr` or `cls.attr` attribute node, i.e. an assignment left-hand
// side of the shape `attribute { object: identifier(self|cls), attribute: identifier }`.
func pythonSelfOrClsAttrTarget(target *sitter.Node, src []byte) (attr string, ok bool) {
	if target == nil || target.Type() != pythonNodeAttribute {
		return "", false
	}
	object := target.ChildByFieldName("object")
	attrNode := target.ChildByFieldName("attribute")
	if object == nil || attrNode == nil {
		return "", false
	}
	switch object.Content(src) {
	case pythonSelfObjectName, pythonClsObjectName:
		return attrNode.Content(src), true
	default:
		return "", false
	}
}

// pythonBindings is the per-call answer to "can this receiver text be an
// object identity?". It combines every syntactic binder visible at THIS
// call's position (layer: parameters, assignment targets, with/for/
// except-as targets, walrus, unpacking, comprehension targets — see
// pythonBindingLayer) with the enclosing class's attribute set (attrs:
// literal `self.<attr>`/`cls.<attr>` names assigned anywhere in the class
// body), so receiverIdentity can answer for both plain-name and self/
// cls-attribute receivers. Built once per pending call at resolution time
// (resolvePythonPendingCalls) — see D1/D2 in design.md §2.
type pythonBindings struct {
	layer *pythonBindingLayer // this call's captured binding layer (D1/D2)
	attrs map[string]bool     // class-scoped attribute names (canonical, no prefix)
}

// receiverIdentity resolves the receiver text of an attribute call to a
// stable object identity, or "" when it is not an object (a module, a type
// constructor, or a call-expression result). Check order is load-bearing:
// objectIsCall -> import -> self/cls bare -> attribute set -> locals.
// Imports must stay ahead of locals so an import-name receiver is never
// masked by a same-named parameter (TestPythonParser_ModuleCall_NoReceiverVar).
// A known local binding is authoritative and is checked LAST only because it
// is the least specific positive signal — it does NOT defer to a
// CapitalCase-looking spelling: an UPPER_CASE local (e.g. `HASHER`) still
// resolves as a receiver (TestPythonParser_ReceiverVar_UpperCaseLocal). A
// bare name that is neither an import, self/cls, a class attribute, nor a
// known local (e.g. an unresolved `Cipher` type reference used directly,
// never bound to a variable) falls through to "".
func (b pythonBindings) receiverIdentity(object string, objectIsCall bool, analysis *FileAnalysis) string {
	if objectIsCall || object == "" {
		return ""
	}
	if _, isImport := analysis.Imports[object]; isImport {
		return ""
	}
	if object == pythonSelfObjectName || object == pythonClsObjectName {
		// A bare self/cls receiver names the enclosing instance/class itself,
		// never a crypto object.
		return ""
	}
	if attr, ok := pythonSelfOrClsAttr(object); ok && b.attrs[attr] {
		return pythonSelfObjectName + "." + attr
	}
	// A known local binding always wins over the CapitalCase-type-name
	// heuristic below: an UPPER_CASE constant-style local (e.g. `HASHER`)
	// satisfies `looksLikePythonTypeName` just as a class reference (e.g.
	// `Cipher`) does, but a real local binder is authoritative evidence that
	// this identifier is an instance, not a type reference. The heuristic
	// below only disqualifies names that were never bound as a local at all.
	if b.layer.has(object) {
		return object
	}
	return ""
}

// pythonSelfOrClsAttr splits a receiver text of the shape "self.attr" or
// "cls.attr" into its attribute name. Returns ok=false for any other shape
// (bare names, multi-level chains, module-qualified paths).
func pythonSelfOrClsAttr(object string) (attr string, ok bool) {
	for _, prefix := range [...]string{pythonSelfObjectName + ".", pythonClsObjectName + "."} {
		if strings.HasPrefix(object, prefix) {
			rest := object[len(prefix):]
			if rest != "" && !strings.Contains(rest, ".") {
				return rest, true
			}
		}
	}
	return "", false
}

// pythonParameterNames returns every bound parameter name declared in a
// function/method "parameters" node: plain identifiers, typed parameters
// (`b: int`), default parameters (`c=1`), typed-default parameters
// (`d: int = 2`), and star/kwarg splat parameters (`*args`, `**kwargs`). The
// bare `/` and `*` positional/keyword-only separators carry no identifier and
// are skipped. self/cls ARE recorded here (they are still legitimate local
// names): pythonBindings.receiverIdentity is what refuses to ever return them
// as a receiver identity, via its self/cls bare-name check.
func pythonParameterNames(params *sitter.Node, src []byte) []string {
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < int(params.ChildCount()); i++ {
		child := params.Child(i)
		var identNode *sitter.Node
		switch child.Type() {
		case goNodeIdentifier:
			identNode = child
		case "typed_parameter", "default_parameter", "typed_default_parameter",
			pythonNodeListSplatPattern, pythonNodeDictSplatPattern:
			identNode = firstIdentifierChild(child)
		default:
			// "/" and "*" separator tokens, punctuation — no identifier to bind.
			continue
		}
		if identNode == nil {
			continue
		}
		names = append(names, identNode.Content(src))
	}
	return names
}

// firstIdentifierChild returns the first direct child of node whose type is
// "identifier". Splat parameters (*args, **kwargs) carry their star token(s)
// as an earlier anonymous child, so this looks past them rather than
// assuming index 0.
func firstIdentifierChild(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		if child := node.Child(i); child.Type() == goNodeIdentifier {
			return child
		}
	}
	return nil
}

// isPythonComprehensionSymbol reports whether sym is one of the tree-sitter
// symbols that introduce their own binding scope for a `for ... in ...`
// clause: the comprehension's loop target is visible only inside the
// comprehension, never in the enclosing function scope (unlike an ordinary
// for_statement, whose target leaks to the rest of the function per real
// Python semantics). Symbol() is a single cheap cgo call returning a small
// integer with no allocation, resolved once at package init via
// resolvePythonSymbols — cheaper than a per-node Type() string compare (an
// additional cgo call plus a Go string allocation from the C buffer) in
// these hot recursive walkers.
func isPythonComprehensionSymbol(sym sitter.Symbol) bool {
	switch sym {
	case pythonSyms.listComprehension, pythonSyms.setComprehension,
		pythonSyms.dictionaryComprehension, pythonSyms.generatorExpression:
		return true
	default:
		return false
	}
}

// isPythonPrunedDefinitionSymbol reports whether sym is one of the symbols
// whose subtree calls must NOT be attributed to a `<module>`/`<clinit>`
// synthetic entry point (function definition, class definition, decorated
// definition, or lambda): they run at invocation time (a function/method
// call, a lambda call, or a nested class's own methods), not at
// module-load/class-body execution time. Also used by
// pythonWalk to prune module/class-direct-scope locals and
// pending-call collection at the same boundary (see F3).
func isPythonPrunedDefinitionSymbol(sym sitter.Symbol) bool {
	switch sym {
	case pythonSyms.functionDefinition, pythonSyms.classDefinition,
		pythonSyms.decoratedDefinition, pythonSyms.lambda:
		return true
	default:
		return false
	}
}

// parseCallExpr parses a call expression into a FunctionCall.
func (p *PythonParser) parseCallExpr(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings) *FunctionCall {
	if node.ChildCount() == 0 {
		return nil
	}

	funcNode := node.Child(0)
	line := int(node.StartPoint().Row) + 1
	raw := funcNode.Content(src)
	args := p.extractPythonCallArguments(node, src)

	chainID, assignedVar := pythonCallChainContext(node, src)

	// Convert tree-sitter 0-based byte columns to the internal 1-based convention.
	// StartCol is inclusive; EndCol is exclusive (one past last byte of the call
	// expression node). Mirrors the opengrep convention used by the Java parser.
	startCol := int(node.StartPoint().Column) + 1
	endCol := int(node.EndPoint().Column) + 1

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
					StartCol:    startCol,
					EndCol:      endCol,
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
				StartCol:    startCol,
				EndCol:      endCol,
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
			StartCol:    startCol,
			EndCol:      endCol,
			Arguments:   args,
			AssignedVar: assignedVar,
			ChainID:     chainID,
		}
	case pythonNodeAttribute:
		// Method/attribute call like `hashlib.sha256()` or `obj.method()`
		return p.parseAttributeCall(funcNode, src, filePath, line, startCol, endCol, args, analysis, bindings, chainID, assignedVar)
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
// startCol and endCol are the 1-based column span of the FULL call expression node
// (not just the attribute node), matching the Java parser's convention.
func (p *PythonParser) parseAttributeCall(node *sitter.Node, src []byte, filePath string, line, startCol, endCol int, args []string, analysis *FileAnalysis, bindings pythonBindings, chainID, assignedVar string) *FunctionCall {
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
		case pythonNodeAttribute:
			// Chained attribute: `a.b.c()` — recurse to get text
			object = child.Content(src)
		case pythonNodeCall:
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
			StartCol:    startCol,
			EndCol:      endCol,
			Arguments:   args,
			ChainID:     chainID,
			AssignedVar: assignedVar,
		}
	}

	// Determine ReceiverVar: only when object resolves to a known object
	// identity (a local/parameter, or a self/cls-attribute), never a module
	// import, a type name, or a call expression result.
	receiverVar := bindings.receiverIdentity(object, objectIsCall, analysis)

	// Try to resolve through imports when the object is not itself a call result.
	if !objectIsCall {
		if fc := resolveImportedCall(object, method, raw, filePath, line, startCol, endCol, args, receiverVar, chainID, assignedVar, analysis); fc != nil {
			return fc
		}
	}

	// Fallback: assume same package (local object or unresolved chain result).
	return &FunctionCall{
		Callee:      FunctionID{Package: analysis.PackagePath, Type: object, Name: method},
		Raw:         raw,
		FilePath:    filePath,
		Line:        line,
		StartCol:    startCol,
		EndCol:      endCol,
		Arguments:   args,
		ReceiverVar: receiverVar,
		ChainID:     chainID,
		AssignedVar: assignedVar,
	}
}

// resolveImportedCall attempts to resolve a module-qualified attribute call by looking
// up the object name (or its first dotted segment) in the file's import map.
// Returns a *FunctionCall when resolution succeeds; returns nil to signal fallback.
//
// Resolution order:
//  1. Direct import match: `import hashlib; hashlib.sha256()` → Package="hashlib".
//     When introduced via `from X import Y`, the real path becomes X.Y so that
//     `AES.new(key, mode)` emits Package="Crypto.Cipher.AES" (not "Crypto.Cipher").
//  2. Chained attribute: `cryptography.hazmat.primitives.hashes.SHA256()` — splits on
//     the first dot and resolves the leading segment through imports.
func resolveImportedCall(object, method, raw, filePath string, line, startCol, endCol int, args []string, receiverVar, chainID, assignedVar string, analysis *FileAnalysis) *FunctionCall {
	if pkg, ok := analysis.Imports[object]; ok {
		resolvedPkg := pkg
		if analysis.FromImports[object] {
			resolvedPkg = pkg + "." + object
		}
		return &FunctionCall{
			Callee:      FunctionID{Package: resolvedPkg, Name: method},
			Raw:         raw,
			FilePath:    filePath,
			Line:        line,
			StartCol:    startCol,
			EndCol:      endCol,
			Arguments:   args,
			ReceiverVar: receiverVar,
			ChainID:     chainID,
			AssignedVar: assignedVar,
		}
	}

	// Handle chained attribute access like `cryptography.hazmat.primitives.hashes.SHA256()`
	// Try to resolve by splitting off the first segment.
	dotIdx := strings.Index(object, ".")
	if dotIdx > 0 {
		firstSegment := object[:dotIdx]
		if pkg, ok := analysis.Imports[firstSegment]; ok {
			fullPath := pkg + "." + object[dotIdx+1:]
			return &FunctionCall{
				Callee:      FunctionID{Package: fullPath, Name: method},
				Raw:         raw,
				FilePath:    filePath,
				Line:        line,
				StartCol:    startCol,
				EndCol:      endCol,
				Arguments:   args,
				ReceiverVar: receiverVar,
				ChainID:     chainID,
				AssignedVar: assignedVar,
			}
		}
	}

	return nil
}

func (p *PythonParser) extractPythonCallArguments(node *sitter.Node, src []byte) []string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == pythonNodeArgumentList {
			return parseArgumentsFromDelimitedContent(child.Content(src))
		}
	}
	return nil
}

// parsePythonParameters extracts a function/method's declared parameters
// from field nodes (A2, python-parser-parity-2), never from
// node.Content(src) on the whole "parameters" node: a plain identifier
// parameter has no name/type field (the node itself IS the identifier); a
// typed_parameter has a "type" field but NO "name" field (its identifier is
// an unnamed direct child — firstIdentifierChild); default_parameter and
// typed_default_parameter both have a "name" field (and typed_default_parameter
// additionally has "type"); a splat parameter (*args/**kwargs) has no
// fields, its identifier again an unnamed direct child. This also populates
// FunctionParameter.Name (previously Java-only), feeding B13's per-parameter
// annotation propagation for free. Anonymous "/"/"*" separator tokens are
// never visited at all — NamedChildCount()/NamedChild() already exclude
// them, unlike the string-splitting approach this replaces.
func parsePythonParameters(node *sitter.Node, src []byte) []FunctionParameter {
	if node == nil {
		return nil
	}

	childCount := int(node.NamedChildCount())
	params := make([]FunctionParameter, 0, childCount)
	for i := 0; i < childCount; i++ {
		child := node.NamedChild(i)
		var nameNode, typeNode *sitter.Node
		switch child.Symbol() {
		case pythonSyms.identifier:
			nameNode = child
		case pythonSyms.typedParameter:
			nameNode = firstIdentifierChild(child)
			typeNode = child.ChildByFieldName("type")
		case pythonSyms.defaultParameter:
			nameNode = child.ChildByFieldName("name")
		case pythonSyms.typedDefaultParameter:
			nameNode = child.ChildByFieldName("name")
			typeNode = child.ChildByFieldName("type")
		case pythonSyms.listSplatPattern, pythonSyms.dictSplatPattern:
			nameNode = firstIdentifierChild(child)
		default:
			continue
		}
		if nameNode == nil {
			continue
		}
		param := FunctionParameter{Name: nameNode.Content(src)}
		if typeNode != nil {
			param.Type = typeNode.Content(src)
		}
		params = append(params, param)
	}
	if len(params) == 0 {
		return nil
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
		if funcChild != nil && funcChild.Type() == pythonNodeAttribute {
			obj := funcChild.ChildByFieldName("object")
			if obj != nil && obj.Type() == pythonNodeCall {
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
		if attrParent == nil || attrParent.Type() != pythonNodeAttribute {
			break
		}
		obj := attrParent.ChildByFieldName("object")
		if obj != root {
			break
		}
		// attrParent.parent should be a call node whose first child (function) is attrParent
		callParent := attrParent.Parent()
		if callParent == nil || callParent.Type() != pythonNodeCall {
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
	return node != nil && node.Type() == pythonNodeCall
}

// isPythonAttributeCallNode reports whether the call node's function child is
// an attribute whose object is itself a call (i.e., a chained call).
func isPythonAttributeCallNode(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	fn := node.Child(0)
	if fn == nil || fn.Type() != pythonNodeAttribute {
		return false
	}
	obj := fn.ChildByFieldName("object")
	return obj != nil && obj.Type() == pythonNodeCall
}

// pythonAssignedVarFromParent returns the variable name a Python call result is
// bound to when the call is on the right-hand side of an assignment statement.
// Returns "" for unassigned calls. Mirrors Java's assignedVarFromParent.
//
// Handles:
//   - `cipher = Cipher(a, m)` — expression_statement → assignment, plain identifier target
//   - `self.cipher = Cipher(a, m)` / `cls.cipher = Cipher(a, m)` — attribute target,
//     canonicalized to "self.cipher" (see pythonAssignmentTargetIdentity)
//   - direct assignment in a block
func pythonAssignedVarFromParent(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil {
		return ""
	}
	if parent.Type() == pythonNodeAssignment {
		return pythonAssignmentTargetIdentity(parent.ChildByFieldName("left"), src)
	}
	// expression_statement wrapping an assignment. "expression_statement" is a
	// generic tree-sitter node name shared across grammars (Python's grammar
	// uses the identical node name); rustNodeExpressionStatement is the
	// existing shared constant for it (see rust_parser.go), reused here to
	// avoid a duplicate string literal (goconst).
	if parent.Type() == rustNodeExpressionStatement {
		gp := parent.Parent()
		if gp != nil && gp.Type() == pythonNodeAssignment {
			return pythonAssignmentTargetIdentity(gp.ChildByFieldName("left"), src)
		}
	}
	return ""
}

// pythonAssignmentTargetIdentity returns the receiver identity text bound by
// an assignment's left-hand target: a plain identifier verbatim, or a
// self/cls-attribute canonicalized to "self.<attr>" (cls.<attr> maps to the
// same self.<attr> token — see the "self.attr identity" design decision).
// Any other target shape (tuple/star unpacking, etc.) returns "" —
// AssignedVar is only meaningful for a single-name/single-attribute binding.
func pythonAssignmentTargetIdentity(left *sitter.Node, src []byte) string {
	if left == nil {
		return ""
	}
	if left.Type() == goNodeIdentifier {
		return left.Content(src)
	}
	if attr, ok := pythonSelfOrClsAttrTarget(left, src); ok {
		return pythonSelfObjectName + "." + attr
	}
	return ""
}

// pythonReturnTypeOf extracts a function_definition node's declared return
// type from its "return_type" field node directly (A2, python-parser-parity-2)
// — never node.Content(src) on the whole function_definition, which would
// materialize the entire function body as a Go string per declaration (see
// TestPythonParser_ReturnTypeFromFieldNode, which pins the allocation
// budget this must satisfy). Returns "" when no return annotation is
// declared.
func pythonReturnTypeOf(node *sitter.Node, src []byte) string {
	returnType := node.ChildByFieldName("return_type")
	if returnType == nil {
		return ""
	}
	return strings.TrimSpace(returnType.Content(src))
}
