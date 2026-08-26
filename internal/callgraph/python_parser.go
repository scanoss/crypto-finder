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

	// ONE full-file traversal replaces what used to be several separate
	// tree walks: import/re-export discovery, the module-level synthetic
	// <module> entry point's direct-scope locals table, and every class's
	// self/cls attribute set + class-body-direct locals table. See
	// collectPythonFilePrepass's doc comment for the scope-stack contract.
	isInitPy := filepath.Base(filePath) == pythonInitPyFileName
	prepass := &pythonFilePrepass{moduleLocals: make(map[string]bool)}
	p.collectPythonFilePrepass(root, src, analysis, prepass, isInitPy, true, nil, false, nil)

	// Extract function and class declarations, consuming the prepass tables.
	p.extractDeclarations(root, src, filePath, packagePath, analysis, prepass)

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

// pythonClassScope accumulates one class's self/cls attribute set (attrs,
// collected across the FULL depth of the class body — self.attr=... may
// appear inside any method) and its own direct-body locals (directLocals,
// PRUNED at any nested function/class/decorated-definition/lambda boundary
// — used only for the synthetic <clinit> entry point's receiver-identity
// table, so a name bound only inside a method never leaks into it; see F3 /
// TestPythonParser_SyntheticEntryPoint_NoNestedScopeLeak).
type pythonClassScope struct {
	attrs        map[string]bool
	directLocals map[string]bool
}

// pythonFilePrepass is the accumulated output of collectPythonFilePrepass's
// single traversal: the module-level synthetic <module> entry point's
// direct-scope locals table, one pythonClassScope per class_definition node
// encountered, and one locals map per OUTERMOST function_definition node
// encountered (a top-level function or a method — see
// collectPythonFilePrepassFunc), each keyed by that node's StartByte (a
// cheap, collision-free-within-one-parse-tree node identity — two distinct
// nodes never start at the same byte offset). analysis.Imports/FromImports/
// ImportedTypes/WildcardImports/PythonReExports are populated as a side
// effect of the same traversal, not returned here.
type pythonFilePrepass struct {
	moduleLocals map[string]bool
	classScopes  map[uint32]*pythonClassScope
	funcLocals   map[uint32]map[string]bool
}

// collectPythonFilePrepass performs ONE full-file traversal, visiting every
// node exactly once, that replaces what were previously several separate
// tree walks: import/from-import discovery (recursing into the WHOLE file —
// `try`/`except`, `if` TYPE_CHECKING guards, and function bodies are all in
// scope, since Python permits imports anywhere a statement is valid),
// __init__.py re-export discovery, the module-level synthetic <module>
// entry point's direct-scope locals table (previously computed via an
// UNPRUNED collectPythonBindings(root) call that walked into every nested
// function/class body — the F3 nested-scope-leak bug, and the single
// costliest redundant traversal in the pre-remediation profile), every
// class's self/cls attribute set (previously its own separate full-depth
// walk per class, ALSO re-walking every method body a second time on top of
// that method's own bindings/calls walks), AND every top-level
// function's/method's own locals table (previously a THIRD full walk of
// that SAME body via collectPythonBindings, run again later by
// parseFunctionDef/extractCalls on nodes this same traversal had already
// visited moments earlier for import-discovery purposes).
//
// Import/re-export discovery is intentionally UNPRUNED — the descent always
// continues into every child regardless of scope. moduleDirect and each
// class's own directLocals tracking are independently PRUNED at
// pythonPrunedAtDefinitionNodeTypes-equivalent boundaries (function
// definition, class definition, decorated definition, lambda) so a name
// bound only inside a nested scope never leaks into an enclosing synthetic
// entry point's locals table, while a class's attrs tracking is NEVER
// pruned within that class's own subtree (it must see inside every method).
// Entering a NESTED class_definition (e.g. a class declared inside another
// class's body) starts a BRAND NEW, independent pythonClassScope — a
// self.attr assignment inside the nested class's own methods attributes to
// the nested class, never the enclosing one. This is a deliberate (and,
// versus the prior collectPythonClassAttrsInNode's flat unconditional scan,
// more correct) behavior: no test in this codebase exercises a class nested
// directly inside another class's body, and processClass is never invoked
// recursively for one either way, so the nested scope's own entry is simply
// unused — only the enclosing class's own (correctly unaffected) attrs are
// ever consumed.
//
// activeFunc mirrors activeClass but for function scope: entering a
// function_definition while activeFunc is nil starts a BRAND NEW locals
// bucket for it (see collectPythonFilePrepassFunc); entering one while
// activeFunc is ALREADY non-nil (a closure nested inside another function)
// does NOT start a new bucket — its binders keep flowing into the SAME
// enclosing bucket, matching parseFunctionDef's existing unpruned
// per-FunctionDecl scope (a nested closure's locals remain visible to calls
// anywhere in the same enclosing FunctionDecl, and vice versa). Unlike
// classDirect, function-scope locals collection is NEVER pruned within an
// active function (matches walkForCalls's own fully-unpruned call
// collection for a real FunctionDecl's body).
func (p *PythonParser) collectPythonFilePrepass(node *sitter.Node, src []byte, analysis *FileAnalysis, prepass *pythonFilePrepass, isInitPy, moduleDirect bool, activeClass *pythonClassScope, classDirect bool, activeFunc map[string]bool) {
	// node.Symbol() is a cgo call: read it ONCE per node (sym) rather than
	// re-invoking it once per switch case — visited-node count dominates
	// this walk's cost (every node in the file goes through this
	// dispatch), so a repeated per-case cgo call here would multiply that
	// cost several-fold across the whole traversal.
	sym := node.Symbol()
	switch {
	case sym == pythonSyms.importStatement:
		p.processImportStatement(node, src, analysis)
	case sym == pythonSyms.importFromStatement:
		p.processImportFromStatement(node, src, analysis)
		if isInitPy {
			p.recordPythonReExportsFromStatement(node, src, analysis)
		}
	case sym == pythonSyms.classDefinition:
		p.collectPythonFilePrepassClass(node, src, analysis, prepass, isInitPy, activeFunc)
		return
	case sym == pythonSyms.functionDefinition && activeFunc == nil:
		activeFunc = p.collectPythonFilePrepassFunc(node, src, prepass)
	default:
		recordPythonFilePrepassBinders(node, sym, src, prepass, moduleDirect, activeClass, classDirect, activeFunc)
	}

	// ChildCount() is also a cgo call: cache it once per node rather than
	// re-invoking it on every loop condition check (`i < node.ChildCount()`
	// would otherwise call it N+1 times for N children).
	childCount := int(node.ChildCount())
	for i := 0; i < childCount; i++ {
		child := node.Child(i)
		pruned := isPythonPrunedDefinitionSymbol(child.Symbol())
		p.collectPythonFilePrepass(child, src, analysis, prepass, isInitPy,
			moduleDirect && !pruned, activeClass, classDirect && !pruned, activeFunc)
	}
}

// collectPythonFilePrepassClass handles the collectPythonFilePrepass
// class_definition case: register a brand new pythonClassScope for node
// (keyed by StartByte) and recurse into its children with that fresh scope
// active. A class boundary always prunes the enclosing module's direct
// scope, regardless of the moduleDirect/classDirect values node itself
// inherited. activeFunc is threaded through unchanged: a class defined
// INSIDE a function body (rare) has its methods' calls/locals swept into
// the SAME enclosing function's bucket, matching walkForCalls's existing
// fully-unpruned treatment of that case (processClass is never invoked for
// such a class, so its own methods are never separately extracted either).
func (p *PythonParser) collectPythonFilePrepassClass(node *sitter.Node, src []byte, analysis *FileAnalysis, prepass *pythonFilePrepass, isInitPy bool, activeFunc map[string]bool) {
	scope := &pythonClassScope{attrs: make(map[string]bool), directLocals: make(map[string]bool)}
	if prepass.classScopes == nil {
		prepass.classScopes = make(map[uint32]*pythonClassScope)
	}
	prepass.classScopes[node.StartByte()] = scope
	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectPythonFilePrepass(node.Child(i), src, analysis, prepass, isInitPy, false, scope, true, activeFunc)
	}
}

// collectPythonFilePrepassFunc handles the collectPythonFilePrepass
// function_definition case for the OUTERMOST active function scope: register
// a brand new locals bucket for node (keyed by StartByte), pre-populate it
// with node's own declared parameter names (mirroring the removed
// collectPythonBindings' param handling), and return it so the caller's
// recursive descent threads it through as the active function scope.
func (p *PythonParser) collectPythonFilePrepassFunc(node *sitter.Node, src []byte, prepass *pythonFilePrepass) map[string]bool {
	locals := make(map[string]bool)
	for i := 0; i < int(node.ChildCount()); i++ {
		if child := node.Child(i); child.Type() == pythonNodeParameters {
			for _, name := range pythonParameterNames(child, src) {
				locals[name] = true
			}
			break
		}
	}
	if prepass.funcLocals == nil {
		prepass.funcLocals = make(map[uint32]map[string]bool)
	}
	prepass.funcLocals[node.StartByte()] = locals
	return locals
}

// recordPythonFilePrepassBinders applies collectPythonFilePrepass's binder
// detection for one non-import, non-class-definition node: module-direct
// locals (moduleDirect-gated), the active class's self/cls attribute set
// (always active within the class, at any depth), the active class's own
// direct-body locals (classDirect-gated), and the active function's own
// locals (always active within a function, at any depth — see
// collectPythonFilePrepass's activeFunc doc). See collectPythonFilePrepass's
// doc comment for the full scope-stack contract. sym is node.Symbol(),
// precomputed once by the caller's switch dispatch and threaded through
// here (and into every recordPythonBinderNode call below) so this node's
// symbol is never re-fetched via another cgo call.
func recordPythonFilePrepassBinders(node *sitter.Node, sym sitter.Symbol, src []byte, prepass *pythonFilePrepass, moduleDirect bool, activeClass *pythonClassScope, classDirect bool, activeFunc map[string]bool) {
	if moduleDirect {
		recordPythonBinderNode(node, sym, src, prepass.moduleLocals)
	}
	if activeFunc != nil {
		recordPythonBinderNode(node, sym, src, activeFunc)
	}
	if activeClass == nil {
		return
	}
	if sym == pythonSyms.assignment {
		if attr, ok := pythonSelfOrClsAttrTarget(node.ChildByFieldName("left"), src); ok {
			activeClass.attrs[attr] = true
		}
	}
	if classDirect {
		recordPythonBinderNode(node, sym, src, activeClass.directLocals)
	}
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
func (p *PythonParser) extractDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, prepass *pythonFilePrepass) {
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis, nil, prepass)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case pythonNodeClassDefinition:
			p.processClass(child, src, filePath, packagePath, analysis, prepass)
		case "decorated_definition":
			// Handle decorated functions and classes
			p.processDecorated(child, src, filePath, packagePath, analysis, prepass)
		}
	}

	if moduleDecl := p.buildModuleInitDecl(root, src, filePath, packagePath, analysis, prepass.moduleLocals); moduleDecl != nil {
		analysis.Functions = append(analysis.Functions, *moduleDecl)
	}
}

// buildModuleInitDecl builds the synthetic `<module>` FunctionDecl for a
// file's direct module-level calls (pruned at any nested
// function/class/decorated-definition/lambda boundary). Returns nil when the
// module body has no such calls — no decl is emitted for a call-free module,
// which is what keeps TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis at zero.
// moduleLocals is precomputed once per file by collectPythonFilePrepass,
// already scoped to ONLY module-level direct-statement binders (see F3).
func (p *PythonParser) buildModuleInitDecl(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, moduleLocals map[string]bool) *FunctionDecl {
	bindings := pythonBindings{locals: moduleLocals}
	calls := p.collectPythonDirectCalls(root, src, filePath, analysis, bindings)
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
// attrs is the enclosing class's attribute set (nil outside a class).
// prepass is the whole-file pre-pass output; node's own locals (parameters
// plus every binder found anywhere in its body, including nested closures —
// see collectPythonFilePrepassFunc) were already computed by
// collectPythonFilePrepass in the SAME earlier traversal that also found
// this node, and are looked up here by node identity (StartByte), not
// recomputed.
func (p *PythonParser) parseFunctionDef(node *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis, attrs map[string]bool, prepass *pythonFilePrepass) *FunctionDecl {
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
		ReturnType:   parsePythonReturnType(node.Content(src)),
		Parameters:   parsePythonParameters(paramNode, src),
	}

	if body != nil {
		bindings := pythonBindings{locals: prepass.funcLocals[node.StartByte()], attrs: attrs}
		decl.Calls = p.extractCalls(body, src, filePath, analysis, bindings)
	}

	return decl
}

// processClass processes a class_definition node and extracts its methods.
// prepass is the whole-file pre-pass output; this class's own scope (attrs +
// direct-body locals) was already computed by collectPythonFilePrepass in a
// single earlier traversal and is looked up here by node identity
// (StartByte), not recomputed.
func (p *PythonParser) processClass(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, prepass *pythonFilePrepass) {
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

	scope := prepass.classScopes[node.StartByte()]
	attrs, directLocals := make(map[string]bool), make(map[string]bool)
	if scope != nil {
		// Every class_definition node extractDeclarations/processDecorated
		// visits was also visited by the earlier collectPythonFilePrepass
		// traversal over this SAME tree, so scope is always non-nil in
		// practice; the fresh empty maps above are a defensive fallback
		// only, never exercised by a real parse.
		attrs, directLocals = scope.attrs, scope.directLocals
	}

	// Walk class body for method definitions.
	p.extractClassMethods(body, src, filePath, packagePath, className, bases, analysis, attrs, prepass)

	if clinit := p.buildClassInitDecl(body, src, filePath, packagePath, className, analysis, attrs, directLocals); clinit != nil {
		analysis.Functions = append(analysis.Functions, *clinit)
	}
}

// buildClassInitDecl builds the synthetic `<clinit>` FunctionDecl for a
// class's direct class-body calls (outside any method), pruned at any nested
// function/class/decorated-definition/lambda boundary. Returns nil when the
// class body has no such calls. directLocals is precomputed once per class
// by collectPythonFilePrepass, already scoped to ONLY class-body
// direct-statement binders (see F3).
func (p *PythonParser) buildClassInitDecl(classBody *sitter.Node, src []byte, filePath, packagePath, className string, analysis *FileAnalysis, attrs, directLocals map[string]bool) *FunctionDecl {
	bindings := pythonBindings{locals: directLocals, attrs: attrs}
	calls := p.collectPythonDirectCalls(classBody, src, filePath, analysis, bindings)
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
func (p *PythonParser) extractClassMethods(body *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis, attrs map[string]bool, prepass *pythonFilePrepass) {
	for i := 0; i < int(body.ChildCount()); i++ {
		child := body.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, className, analysis, attrs, prepass)
			if decl != nil {
				decl.OwnerBases = bases
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case "decorated_definition":
			p.extractDecoratedMethod(child, src, filePath, packagePath, className, bases, analysis, attrs, prepass)
		}
	}
}

// extractDecoratedMethod extracts a method from a decorated_definition within a class.
// bases are the direct superclass names of className, propagated from processClass.
// attrs is the class's shared self/cls attribute set.
func (p *PythonParser) extractDecoratedMethod(node *sitter.Node, src []byte, filePath, packagePath, className string, bases []string, analysis *FileAnalysis, attrs map[string]bool, prepass *pythonFilePrepass) {
	for j := 0; j < int(node.ChildCount()); j++ {
		inner := node.Child(j)
		if inner.Type() != pythonNodeFunctionDefinition {
			continue
		}
		decl := p.parseFunctionDef(inner, src, filePath, packagePath, className, analysis, attrs, prepass)
		if decl != nil {
			decl.OwnerBases = bases
			analysis.Functions = append(analysis.Functions, *decl)
		}
	}
}

// processDecorated handles a decorated_definition which wraps a function or class.
func (p *PythonParser) processDecorated(node *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis, prepass *pythonFilePrepass) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case pythonNodeFunctionDefinition:
			decl := p.parseFunctionDef(child, src, filePath, packagePath, "", analysis, nil, prepass)
			if decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		case pythonNodeClassDefinition:
			p.processClass(child, src, filePath, packagePath, analysis, prepass)
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

// pythonBindings is the per-scope answer to "can this receiver text be an
// object identity?". It combines every syntactic binder in the current
// function body (locals: parameters, assignment targets, with/for/except-as
// targets, walrus, unpacking, comprehension targets) with the enclosing
// class's attribute set (attrs: literal `self.<attr>`/`cls.<attr>` names
// assigned anywhere in the class body), so receiverIdentity can answer for
// both plain-name and self/cls-attribute receivers.
type pythonBindings struct {
	locals map[string]bool // parameters + all binder forms in this body
	attrs  map[string]bool // class-scoped attribute names (canonical, no prefix)
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
	if b.locals[object] {
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

// extractCalls walks a function body to find all call expressions. bindings
// (locals + attrs) is precomputed once per function/method by
// collectPythonFilePrepass/collectPythonFilePrepassFunc — see
// parseFunctionDef, which is this function's only caller.
func (p *PythonParser) extractCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings) []FunctionCall {
	var calls []FunctionCall
	p.walkForCalls(body, src, filePath, analysis, bindings, &calls)
	return calls
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

// recordPythonBinderNode records the identifier(s) bound by node, if node is
// one of the ordinary binder-node shapes: assignment, augmented_assignment,
// as_pattern (covers both `with ... as X` and `except ... as X` — the alias
// target lives under the "alias" field as an as_pattern_target wrapping an
// identifier), for_statement (an ordinary for loop's target leaks into the
// enclosing scope, unlike a comprehension's for_in_clause target — see
// isPythonComprehensionSymbol), or named_expression (walrus `x := ...`,
// which also leaks to the enclosing scope in real Python semantics, even
// inside a comprehension). Shared by collectPythonLocalVarsInNode (the
// per-function UNPRUNED walk) and collectPythonFilePrepass (the file-wide
// PRUNED module/class-direct-scope walk) so both use the SAME
// symbol-dispatched binder detection.
func recordPythonBinderNode(node *sitter.Node, sym sitter.Symbol, src []byte, locals map[string]bool) {
	switch sym {
	case pythonSyms.assignment, pythonSyms.augmentedAssignment:
		collectPythonAssignmentTargets(node.ChildByFieldName("left"), src, locals)
	case pythonSyms.asPattern:
		if aliasTarget := node.ChildByFieldName("alias"); aliasTarget != nil {
			if ident := firstIdentifierChild(aliasTarget); ident != nil {
				locals[ident.Content(src)] = true
			}
		}
	case pythonSyms.forStatement:
		collectPythonAssignmentTargets(node.ChildByFieldName("left"), src, locals)
	case pythonSyms.namedExpression:
		if name := node.ChildByFieldName("name"); name != nil && name.Symbol() == pythonSyms.identifier {
			locals[name.Content(src)] = true
		}
	}
}

// collectPythonAssignmentTargets records every identifier bound by an
// assignment-style target: a plain identifier, or a pattern_list/
// tuple_pattern/list_pattern of nested targets (arbitrarily deep, e.g.
// `a, (b, *rest) = ...`), or a list_splat_pattern/dictionary_splat_pattern
// (`*rest`, `**extra`). An attribute target (`self.attr = ...`) is
// deliberately NOT recorded here — it is a class-scoped attribute binding,
// handled separately by collectPythonFilePrepass.
func collectPythonAssignmentTargets(target *sitter.Node, src []byte, locals map[string]bool) {
	if target == nil {
		return
	}
	switch target.Type() {
	case goNodeIdentifier:
		locals[target.Content(src)] = true
	case "pattern_list", "tuple_pattern", "list_pattern":
		for i := 0; i < int(target.ChildCount()); i++ {
			collectPythonAssignmentTargets(target.Child(i), src, locals)
		}
	case pythonNodeListSplatPattern, pythonNodeDictSplatPattern:
		if ident := firstIdentifierChild(target); ident != nil {
			locals[ident.Content(src)] = true
		}
	}
}

func (p *PythonParser) walkForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, calls *[]FunctionCall) {
	sym := node.Symbol()
	if sym == pythonSyms.call {
		if call := p.parseCallExpr(node, src, filePath, analysis, bindings); call != nil {
			setFunctionCallASTAnchor(call, node)
			*calls = append(*calls, *call)
		}
	}

	scoped := bindings
	if isPythonComprehensionSymbol(sym) {
		scoped = bindings.withComprehensionTargets(node, src)
	}

	childCount := int(node.ChildCount())
	for i := 0; i < childCount; i++ {
		p.walkForCalls(node.Child(i), src, filePath, analysis, scoped, calls)
	}
}

// isPythonPrunedDefinitionSymbol reports whether sym is one of the symbols
// whose subtree calls must NOT be attributed to a `<module>`/`<clinit>`
// synthetic entry point (function definition, class definition, decorated
// definition, or lambda): they run at invocation time (a function/method
// call, a lambda call, or a nested class's own methods), not at
// module-load/class-body execution time. Also used by
// collectPythonFilePrepass to prune module/class-direct-scope locals
// collection at the same boundary (see F3).
func isPythonPrunedDefinitionSymbol(sym sitter.Symbol) bool {
	switch sym {
	case pythonSyms.functionDefinition, pythonSyms.classDefinition,
		pythonSyms.decoratedDefinition, pythonSyms.lambda:
		return true
	default:
		return false
	}
}

// collectPythonDirectCalls walks a module or class body collecting calls
// made directly in its own statements, PRUNING the walk at any nested
// function/class/decorated-definition/lambda boundary. Used only to build
// the `<module>`/`<clinit>` synthetic decls — ordinary function bodies keep
// using the unpruned walkForCalls.
func (p *PythonParser) collectPythonDirectCalls(body *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings) []FunctionCall {
	var calls []FunctionCall
	p.walkPrunedForCalls(body, src, filePath, analysis, bindings, &calls)
	return calls
}

func (p *PythonParser) walkPrunedForCalls(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, calls *[]FunctionCall) {
	sym := node.Symbol()
	if sym == pythonSyms.call {
		if call := p.parseCallExpr(node, src, filePath, analysis, bindings); call != nil {
			setFunctionCallASTAnchor(call, node)
			*calls = append(*calls, *call)
		}
	}

	scoped := bindings
	if isPythonComprehensionSymbol(sym) {
		scoped = bindings.withComprehensionTargets(node, src)
	}

	childCount := int(node.ChildCount())
	for i := 0; i < childCount; i++ {
		child := node.Child(i)
		if isPythonPrunedDefinitionSymbol(child.Symbol()) {
			continue
		}
		p.walkPrunedForCalls(child, src, filePath, analysis, scoped, calls)
	}
}

// withComprehensionTargets returns a copy of b whose locals additionally
// include every `for_in_clause` target declared directly in comprehension
// (not inside a NESTED comprehension, which scopes itself independently when
// the walker visits that nested node). The returned bindings must only be
// used for the recursive walk INTO comprehension's subtree — the original b
// is unchanged, so a same-named call outside the comprehension never sees
// this binding.
func (b pythonBindings) withComprehensionTargets(comprehension *sitter.Node, src []byte) pythonBindings {
	scopedLocals := make(map[string]bool, len(b.locals))
	for k, v := range b.locals {
		scopedLocals[k] = v
	}
	collectPythonComprehensionTargets(comprehension, src, scopedLocals)
	return pythonBindings{locals: scopedLocals, attrs: b.attrs}
}

// collectPythonComprehensionTargets records the for_in_clause target(s) that
// belong directly to one comprehension node, stopping at any nested
// comprehension boundary (a nested comprehension's own targets are scoped to
// itself, applied when the walker visits that nested node instead).
func collectPythonComprehensionTargets(node *sitter.Node, src []byte, locals map[string]bool) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		sym := child.Symbol()
		if isPythonComprehensionSymbol(sym) {
			continue
		}
		if sym == pythonSyms.forInClause {
			collectPythonAssignmentTargets(child.ChildByFieldName("left"), src, locals)
		}
		collectPythonComprehensionTargets(child, src, locals)
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
