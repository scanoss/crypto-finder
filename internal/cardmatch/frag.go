package cardmatch

// Graph fragment (schema graph-fragment-1.18, crypto-finder pkg/graphfrag/export.go) and the call
// sites built from it: match.load_sites plus match2.Frag.
//
// Only `functions`, `internal_edges_compact` / `internal_edge_strings` and `external_calls` are
// read; the OpenGrep-derived keys (crypto_annotations, supporting_calls, crypto_entry_points) are not
// decoded at all (match.FORBIDDEN). Every string field of the schema is `omitempty`, so an absent
// field and "" are the same thing (Python None).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// Source node types the flows follow into a call or a caller.
const (
	srcCallResult = "CALL_RESULT"
	srcParameter  = "PARAMETER"
)

// SourceNode is a node of the chain a call argument traces back to, as the
// graph fragment records it.
type SourceNode struct {
	Type           string       `json:"type"`
	Name           string       `json:"name"`
	DeclaredType   string       `json:"declared_type"`
	Value          string       `json:"value"`
	ParameterIndex *int         `json:"parameter_index"`
	SourceNodes    []SourceNode `json:"source_nodes"`
	MayValues      []string     `json:"may_values"` // graph-fragment-1.16
	// MayValuesExhaustive: every assignment of the variable is one of MayValues.
	MayValuesExhaustive bool `json:"may_values_exhaustive"`
	// Location is where the node is written; the Rust matcher finds a
	// CALL_RESULT's call by its line (rust_taint.go).
	Location *SourceLocation `json:"location"`
}

// SourceLocation is the line a source node is written on.
type SourceLocation struct {
	Line int `json:"line"`
}

// Param is a call argument of a call site, as the graph fragment records it.
type Param struct {
	ParameterIndex     int          `json:"parameter_index"`
	Type               string       `json:"type"`
	VariableName       string       `json:"variable_name"`
	ArgumentExpression string       `json:"argument_expression"`
	ResolvedValue      string       `json:"resolved_value"`
	SourceNodes        []SourceNode `json:"source_nodes"`
	// Keyword names a Python keyword argument (graph-fragment-1.24).
	Keyword string `json:"keyword"`
	// Qualified is a Python argument's text with its names qualified through
	// the file's imports (python.go); "" for other languages.
	Qualified string `json:"-"`
	// Written is a Python argument's text as written at the call when the
	// matcher reads its value in its place (pyParam); "" otherwise.
	Written string `json:"-"`
}

// writtenText is the argument's text as written at the call.
func (p *Param) writtenText() string {
	if p.Written != "" {
		return p.Written
	}
	return p.ArgumentExpression
}

// CallSiteJSON is a call site's arguments in the graph fragment.
type CallSiteJSON struct {
	Parameters []Param `json:"parameters"`
}

// FunctionJSON is a function of the graph fragment.
type FunctionJSON struct {
	Key      string `json:"key"`
	Package  string `json:"package"`
	FilePath string `json:"file_path"`
	// Read only by --reach (reach.go).
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	EntryKind string `json:"entry_kind"`
	// ParameterNames are the function's parameters in order (graph-fragment-1.21;
	// a Python method's self or cls left out), read in Python mode.
	ParameterNames []string `json:"parameter_names"`
	// Name and ReturnType are a C function's name and return type as
	// written, read in C mode.
	Name       string `json:"name"`
	ReturnType string `json:"return_type"`
	// ReturnSources are where the function's returned values come from
	// (graph-fragment-1.21), read in Go mode: an object a same-file
	// factory makes (go_flow.go).
	ReturnSources []SourceNode `json:"return_sources"`
	// WrittenParameters are a C++ function's parameters as written,
	// read in C++ mode (cpp_match.go).
	WrittenParameters []graphfrag.GraphFragmentWrittenParameter `json:"written_parameters"`
}

// ExternalJSON is a call of the graph fragment that leaves the project.
type ExternalJSON struct {
	CallerKey   string        `json:"caller_key"`
	TargetKey   string        `json:"target_key"`
	Raw         string        `json:"raw"`
	Line        *int          `json:"line"`
	Resolution  string        `json:"resolution"`
	MethodName  string        `json:"method_name"`
	Arity       int           `json:"arity"`
	ReceiverVar string        `json:"receiver_var"`
	AssignedVar string        `json:"assigned_var"`
	ChainID     string        `json:"chain_id"`
	StartCol    *int          `json:"start_col"`
	EndCol      *int          `json:"end_col"`
	EndLine     int           `json:"end_line"`
	EntryCall   *CallSiteJSON `json:"entry_call"`
	// CandidateModules (graph-fragment-1.29, Node): the modules a merged
	// module object the receiver holds combines; the key stays caller-local.
	CandidateModules []string `json:"candidate_modules"`
	// DeclaredType is the type a dispatch or name-only call is written on
	// (read in Go mode: the interface a call on an interface value names).
	DeclaredType string `json:"declared_type"`
}

// CompactEdge is one positional internal edge: caller, callee, line, resolution, declared type,
// method, arity, receiver var, assigned var, chain id, start col, end col, (flags), end line
// (graph-fragment-1.16, only on a call that spans lines), entry call.
// Short rows are padded with 0 (match.load_sites: c + [0] * (14 - len(c))).
type CompactEdge struct {
	N       [13]int
	EndLine int
	Entry   *CallSiteJSON
}

// UnmarshalJSON decodes the compact edge array: thirteen integers, then the
// optional end line and the optional call-site entry.
func (e *CompactEdge) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for i, r := range raw {
		switch {
		case i < 13:
			n, err := strconv.Atoi(string(r))
			if err != nil {
				return fmt.Errorf("compact edge field %d: %s", i, r)
			}
			e.N[i] = n
		case i == 13 && len(r) > 0 && r[0] != '{' && r[0] != 'n':
			n, err := strconv.Atoi(string(r))
			if err != nil {
				return fmt.Errorf("compact edge end line: %s", r)
			}
			e.EndLine = n
		case i >= 13 && len(r) > 0 && r[0] == '{':
			e.Entry = &CallSiteJSON{}
			if err := json.Unmarshal(r, e.Entry); err != nil {
				return err
			}
		}
	}
	return nil
}

// FragmentJSON is the graph fragment document the matcher reads.
type FragmentJSON struct {
	SchemaVersion string `json:"schema_version"`
	ScanMetadata  struct {
		EntryKinds bool   `json:"entry_kinds"`
		Ecosystem  string `json:"ecosystem"`
	} `json:"scan_metadata"`
	Functions           []FunctionJSON `json:"functions"`
	InternalEdgeStrings []string       `json:"internal_edge_strings"`
	InternalEdges       []CompactEdge  `json:"internal_edges_compact"`
	ExternalCalls       []ExternalJSON `json:"external_calls"`
	// SourceLines is the text of the lines the call sites cover, by file (graph-fragment-1.16).
	SourceLines map[string]map[int]string `json:"source_lines"`
	// ConstantRefs are the qualified constants the functions reference, at any
	// position (graph-fragment-1.17).
	ConstantRefs []graphfrag.GraphFragmentConstantRef `json:"constant_refs"`
	// Declarations are the functions' local variable and field declarations,
	// and Casts their casts of a call (graph-fragment-1.18).
	Declarations []graphfrag.GraphFragmentDeclaration `json:"declarations"`
	Casts        []graphfrag.GraphFragmentCast        `json:"casts"`
	// Imports are a Python fragment's import bindings by file, and
	// AttributeStores its assignments to attributes (graph-fragment-1.24).
	Imports         map[string][]graphfrag.GraphFragmentImport `json:"imports"`
	AttributeStores []graphfrag.GraphFragmentAttributeStore    `json:"attribute_stores"`
	// GoValues are a Go fragment's composite literals, new(T) expressions and
	// field stores by file (graph-fragment-1.34).
	GoValues map[string][]graphfrag.GraphFragmentGoValue `json:"go_values"`
	// GoBlocks are a Go fragment's function-body blocks, case clauses
	// included, by file (graph-fragment-1.36).
	GoBlocks map[string][]graphfrag.GraphFragmentGoBlock `json:"go_blocks"`
	// ObjectLiterals are a Node fragment's outermost object literals by file
	// (graph-fragment-1.28).
	ObjectLiterals map[string][]graphfrag.GraphFragmentObjectLiteral `json:"object_literals"`
	// PropertyReads are a Node fragment's property reads by file, keyed as a
	// call of the property would be (graph-fragment-1.29).
	PropertyReads map[string][]graphfrag.GraphFragmentPropertyRead `json:"property_reads"`
	// Items are a Rust fragment's declared items by file (graph-fragment-1.26).
	Items map[string][]graphfrag.GraphFragmentItem `json:"items"`
	// BinaryExprs are a Rust fragment's binary expressions of function
	// bodies by file (graph-fragment-1.30).
	BinaryExprs map[string][]graphfrag.GraphFragmentBinaryExpr `json:"binary_exprs"`
	// Strings are a C or C++ fragment's string literals by file
	// (graph-algo-c-1, graph-algo-cpp-1; optional).
	Strings map[string][]graphfrag.GraphFragmentString `json:"strings"`
	// CallAnchors are the AST anchors of the call sites (graph-fragment-1.20),
	// decoded only for a C++ fragment, whose construction sites the C++
	// matcher reads by their anchor kind.
	CallAnchors json.RawMessage `json:"call_anchors"`
	// Anchors are the call anchors of an in-memory fragment; read in place
	// of CallAnchors when set.
	Anchors []graphfrag.GraphFragmentCallAnchor `json:"-"`
	// LocalBindings are a Python fragment's statements binding locals bound
	// more than once (graph-algo-py-35).
	LocalBindings []graphfrag.GraphFragmentLocalBinding `json:"local_bindings"`
}

// python: the fragment is read in Python mode (python.go).
func (f *FragmentJSON) python() bool {
	return f.ScanMetadata.Ecosystem == ecosystemPython
}

// csharp: the fragment is read in C# mode (csharp.go).
func (f *FragmentJSON) csharp() bool {
	return f.ScanMetadata.Ecosystem == ecosystemCSharp
}

// ruby: the fragment is read in Ruby mode (ruby.go).
func (f *FragmentJSON) ruby() bool {
	return f.ScanMetadata.Ecosystem == ecosystemRuby
}

// c: the fragment is read in C mode (c.go): a C or a C++ graph.
func (f *FragmentJSON) c() bool {
	return f.ScanMetadata.Ecosystem == ecosystemC || f.ScanMetadata.Ecosystem == ecosystemCPP
}

// rust: the fragment is read in Rust mode (rust.go).
func (f *FragmentJSON) rust() bool {
	return f.ScanMetadata.Ecosystem == ecosystemRust
}

// hasDeclarations: the fragment's schema records declarations and casts
// (graph-fragment-1.18 and later), so a declaration it does not list is not
// one, and a cast it does not list is not written around the call.
func (f *FragmentJSON) hasDeclarations() bool {
	return f.schemaMinor() >= 18
}

// schemaMinor is the minor version of a graph-fragment-1.x schema, -1 when
// the fragment names another.
func (f *FragmentJSON) schemaMinor() int {
	minor, ok := strings.CutPrefix(f.SchemaVersion, "graph-fragment-1.")
	if !ok {
		return -1
	}
	n, err := strconv.Atoi(minor)
	if err != nil {
		return -1
	}
	return n
}

// Site is one call site (match.load_sites + the fields match2.Frag adds).
type Site struct {
	ID            int // position in Frag.Sites (Python object identity)
	File          string
	Line          int
	LineOK        bool // false: the external call had no line (Python None)
	Caller        string
	CallerPackage string
	Class         string // "" = None
	Method        string // "" = None
	Arity         int
	Raw           string
	Resolution    string
	Params        map[int]*Param
	ParamIdx      []int // sorted(site["params"])
	ParamOrder    []int // iteration order of the Python dict (first appearance of each index)
	Kind          string
	Col           int
	ColOK         bool
	EndCol        int // 0 = unknown
	EndLine       int // line EndCol is on when the call spans lines; 0 = Line
	ReceiverVar   string
	AssignedVar   string
	// DeclaredType is the receiver's declared type on an internal edge the call
	// graph expanded from it (interface_dispatch, name_only); "" otherwise.
	DeclaredType string
	// ArgsFrom is the site whose arguments a Python internal edge that
	// records none stands for (pySharedArguments); nil otherwise.
	ArgsFrom *Site
	// RefContext is the position kind of a constant reference site
	// (Kind "constant_ref"): compare, equals, case, return, assign, init,
	// array, arg or other; the initializer kind of a declaration site (Kind
	// "declaration": call, cast, null, literal, other, "" for none), whose
	// declared type is in Raw and name in AssignedVar. A cast site (Kind
	// "cast") has its target type in Raw.
	RefContext string
	// Operand is what a constant reference in a comparison is compared with
	// (graph-fragment-1.19); nil when the fragment has none.
	Operand *Param
	// Src is the source text of the call from its start column to the end of
	// its line, and Before the line's text up to that column, from the
	// fragment's source_lines (graph-fragment-1.16); "" when it has none.
	Src, Before string
	// Python: the site is read in Python mode (python.go); Positional is then
	// the number of its positional arguments.
	Python     bool
	Positional int
	// Go: the site is read in Go mode (go.go): its class is compared exactly.
	Go bool
	// Ruby: the site is read in Ruby mode (ruby.go): its class is a constant
	// path written with `::`, which a rule may name whole or through a
	// metavariable.
	Ruby bool
	// CSharp: the site is read in C# mode (csharp.go): its class may be
	// written short, and CSharpUsings are the namespaces its file brings into
	// scope, which qualify it.
	CSharp       bool
	CSharpUsings []string
	// GoValue: a Go composite literal, new(T) or field store (go_values.go),
	// read as a call of a pseudo-method; GoAddrCol is the column of a
	// literal's leading `&`, 0 without one.
	GoValue   bool
	GoAddrCol int
	// GoCallee: Go, the key the call targets (a function of the fragment
	// for an internal call).
	GoCallee string
	// PyDelegation: a Python internal edge to a class's `__init__` whose
	// written call does not name that class (`super().__init__(..)`,
	// `cls(..)`, `Base.__init__(self)`, a subclass instantiation reaching an
	// inherited `__init__`): no instantiation of the class (pyWrittenCall).
	PyDelegation bool
	// Variant tells apart the sites one Python call is read as when an
	// argument may hold one of a few literals (pyValueVariants): the values
	// read in its place; "" for a site read once.
	Variant string
	// node is a node (JavaScript/TypeScript) site's own data (frag_node.go);
	// nil on Java and Python sites.
	node *nodeSite
}

// dispatchExpanded: the call graph linked this site to a callee by expanding
// the receiver's declared type (or by name alone), not by resolving it to the
// one declaration the receiver's static type names.
func (s *Site) dispatchExpanded() bool {
	return s.Resolution == strInterfaceDispatch || s.Resolution == strNameOnly
}

// receiverClass is the class a typed receiver pattern is compared with: the
// callee's class on a resolved site, the declared receiver type on a
// dispatch-expanded one. OpenGrep types a receiver by its declaration, so
// `cipher.init(...)` on a BlockCipher is not an AESEngine call although the
// graph links it to AESEngine.init.
func (s *Site) receiverClass() string {
	if s.Python {
		return s.Class // "" for a name_only call
	}
	if s.dispatchExpanded() {
		return s.DeclaredType
	}
	return s.Class
}

// receiverless: the call is written without a receiver (`sha256(data)`), read
// from the raw call text or the source line. false when neither says.
func (s *Site) receiverless() bool {
	if s.Python || s.Method == strInit || s.GoValue {
		return false
	}
	if s.Raw != "" {
		return !strings.Contains(s.Raw, ".")
	}
	if s.ReceiverVar != "" || s.Src == "" || s.Method == "" {
		return false
	}
	if strings.HasSuffix(strings.TrimRight(s.Before, " \t"), ".") {
		return false // the column is the method name's, after a receiver
	}
	return startsCall(s.Src, s.Method)
}

// delegation: the constructor call is a `this(...)` or `super(...)` delegation,
// read from the raw call text or the source line. false when neither says.
func (s *Site) delegation() bool {
	if s.Python {
		return s.PyDelegation
	}
	if s.Method != strInit {
		return false
	}
	if s.Raw != "" {
		return s.Raw == "this" || s.Raw == "super"
	}
	return startsCall(s.Src, "this") || startsCall(s.Src, "super")
}

// startsCall: text starts with a call of name, `name(` or `name (`.
func startsCall(text, name string) bool {
	rest, ok := strings.CutPrefix(strings.TrimLeft(text, " \t"), name)
	return ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), "(")
}

// setSource fills Src and Before from the fragment's source lines.
func (s *Site) setSource(lines map[string]map[int]string) {
	line, ok := lines[s.File][s.Line]
	if !ok || !s.ColOK || s.Col < 1 || s.Col-1 > len(line) {
		return
	}
	s.Before, s.Src = line[:s.Col-1], line[s.Col-1:]
}

// lineOr0 is `site["line"] or 0`.
func (s *Site) lineOr0() int { return s.Line }
func (s *Site) colOr0() int  { return s.Col }

// parseKey is match.parse_key: KEY_RE = ^(.*)\.\(([^()]*)\)\.([^.#]*)#\d+$ -> (class path, method).
func parseKey(key string) (string, string, bool) { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	if strings.ContainsAny(key, "\n") || !isASCII(key) {
		// The package is optional, so this path reads the package-less key
		// the ASCII path below reads; a UTF-8 identifier is legal in Ruby.
		vals, ok, hit := reMatchNumbered(`^(?:(.*)\.)?\(([^()]*)\)\.([^.#]*)#\d+$`, key)
		if !hit {
			return "", "", false
		}
		if !ok[1] {
			return vals[2], vals[3], true
		}
		return vals[1] + "." + vals[2], vals[3], true
	}
	hash := strings.LastIndexByte(key, '#')
	if hash < 0 || hash == len(key)-1 {
		return "", "", false
	}
	for _, c := range key[hash+1:] {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	head := key[:hash]
	dot := strings.LastIndexByte(head, '.') // Y = [^.#]* after the last '.'
	if dot < 1 || head[dot-1] != ')' {
		return "", "", false
	}
	method := head[dot+1:]
	if strings.IndexByte(method, '#') >= 0 {
		return "", "", false
	}
	closeI := dot - 1
	openI := strings.LastIndexAny(head[:closeI], "()") // X = [^()]*
	if openI < 0 || head[openI] != '(' {
		return "", "", false
	}
	if openI == 0 {
		// A key with no package: "(Type).method#N". FunctionID.String()
		// writes one for a symbol no manifest names a package for -- every
		// Ruby file at the scan root, since a Ruby package is the directory
		// and the root has none. The type is still the type, and dropping it
		// would lose the receiver of every such call.
		return head[1:closeI], method, true
	}
	if head[openI-1] != '.' {
		return "", "", false
	}
	return head[:openI-1] + "." + head[openI+1:closeI], method, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func paramMap(c *CallSiteJSON) (map[int]*Param, []int, []int) {
	m := map[int]*Param{}
	var order []int
	if c != nil {
		for i := range c.Parameters {
			p := &c.Parameters[i]
			index := p.ParameterIndex
			if p.Keyword != "" {
				// A keyword argument is read by its name, not by where it
				// sits: a rule writes `..., digest_algorithm: $D, ...`, and
				// the position the caller happens to put it in is not part
				// of what the rule says.
				index = kwKey(p.Keyword)
			}
			if _, ok := m[index]; !ok {
				order = append(order, index)
			}
			m[index] = p // later wins, as in the dict comprehension
		}
	}
	idx := append([]int(nil), order...)
	sort.Ints(idx)
	return m, idx, order
}

func pairKey(a, b string) string { return a + "\x00" + b }

// Frag holds the call sites plus the per-function lookups the card matcher needs.
type Frag struct {
	Sites    []*Site
	Incoming map[string][]*Site // callee function key -> internal call sites
	// ResolveParams makes a taint or resolves pattern also read the values the
	// function's internal callers pass for a PARAMETER argument, as OpenGrep's
	// taint follows an argument into the calls of the same component.
	ResolveParams bool
	// negated is set while a `not` value pattern is read: a Python parameter
	// then matches a `from` only when every same-file caller passes a value
	// that matches it (mustFrom), not when one of them does.
	negated  bool
	ByCaller map[string][]*Site
	ByRaw    map[string][]*Site         // (caller, norm(raw))
	VarSites map[string][]*Site         // (caller, var) -> sites assigned to it
	VarInit  map[string]map[string]bool // (caller, var) -> initializer texts
	VarType  map[string]string          // (caller, var) -> declared type
	// CSharp is a C# fragment, and CSharpUsings the namespaces each of its
	// files brings into scope.
	CSharp       bool
	CSharpUsings map[string][]string
	Casts        map[string]map[string]bool // (caller, norm(raw), where) -> cast types
	CallerFile   map[string]string
	Roots        map[string]map[string]bool // file -> package roots of the classes it uses
	// Refs are the fragment's constant references (graph-fragment-1.17), as
	// sites of kind "constant_ref" with the reference text in Raw and its
	// position kind in RefContext; RefsByCaller groups them by function.
	Refs         []*Site
	RefsByCaller map[string][]*Site
	// Comparisons is how constant references read in a comparison, an
	// equals call or a case label (comparisonContext) are reported:
	// ComparisonsResolved (a 1.19 fragment) only when the compared value can
	// be the constant (comparedValueCanBe), ComparisonsAll (an older fragment,
	// which has no operands) every one, ComparisonsOff none.
	Comparisons ComparisonPolicy
	// HasDecls: the fragment records declarations and casts
	// (graph-fragment-1.18). Decls are its declarations as sites of kind
	// "declaration", DeclsByCaller them by function; CastsAt its casts as
	// sites of kind "cast", by the position of the call they wrap
	// (castKey).
	HasDecls      bool
	Decls         []*Site
	DeclsByCaller map[string][]*Site
	CastsAt       map[string][]*Site
	// CastList holds the cast sites in fragment order; a cast site's ID is
	// its index.
	CastList []*Site
	// Python: the fragment is read in Python mode (python.go); Names are its
	// files' import bindings (pyNames), by file.
	Python bool
	Go     bool // the fragment is read in Go mode (go.go)
	// GoAliases are, by file, the names a Go file's aliased imports bind and
	// their paths; GoImports tells that the fragment lists import specs at all
	// (graph-fragment-1.32), without which an alias cannot be checked.
	GoAliases map[string]map[string]string
	GoImports bool
	// GoImportPaths are, by file, the paths a Go file imports (1.32).
	GoImportPaths map[string]map[string]bool
	Names         map[string]map[string]string
	// Lines is the fragment's source lines (graph-fragment-1.16), by file.
	Lines map[string]map[int]string
	// Membership is how a Python constant reference read as an `in` operand
	// or element is reported (comparisonRef).
	Membership ComparisonPolicy
	// Stores are a Python fragment's attribute stores as sites of kind
	// "store": receiver in ReceiverVar, attribute in Method, operator in
	// RefContext, value in Operand.
	Stores         []*Site
	StoresByCaller map[string][]*Site
	// Params are a Python fragment's parameter names, by function,
	// LocalImports the names an import inside a function binds there and
	// ImportNames the names the imports of a file bind, by file.
	Params map[string][]string
	// GoParams are a Go fragment's parameter names, by function (the
	// object flow reads a receiver that is a parameter, go_flow.go).
	GoParams map[string][]string
	// GoAssigns are a Go fragment's assignments (go_values kind assign,
	// 1.36), by (function, name), in source order; GoBlocks its blocks by
	// file, and HasGoBlocks whether the fragment lists them.
	GoAssigns   map[string][]*goAssign
	GoBlocks    map[string][]graphfrag.GraphFragmentGoBlock
	HasGoBlocks bool
	// GoValueFacts are the fragment's go_values, by file; GoReturns the
	// return sources of its functions, by key (Go only).
	GoValueFacts map[string][]graphfrag.GraphFragmentGoValue
	GoReturns    map[string][]SourceNode
	LocalImports map[string]map[string]bool
	ImportNames  map[string]map[string]bool
	// Bindings are a Python fragment's local bindings, by (function, name)
	// (pyReaches), and Unpacked the call sites a tuple pattern unpacks into
	// a local, with the element it holds.
	Bindings map[string][]pyBinding
	Unpacked map[string][]pyElement
	// Node: a node fragment (newNodeFrag), matched by matchNodeIndex;
	// NodeData is what only that pass reads.
	Node     bool
	NodeData *nodeFrag
	// RustFacts: a Rust fragment carries the scope facts (imports, items,
	// declarations, constant references; graph-fragment-1.26), and
	// RustScopes are its files' imports and items (rust_scope.go).
	// RustAliases: its type alias items carry their aliased type
	// (graph-fragment-1.27). RustOps: it lists the binary expressions of
	// function bodies (RustBinaries, by file) and its fn items carry their
	// parameters (graph-fragment-1.30). RustNames: its constant references
	// also list one-segment paths read as values whose name starts with an
	// upper-case letter, and struct literal paths (graph-fragment-1.33).
	// RustTypes: they also list the paths written as types, in the position
	// kind type (graph-fragment-1.35).
	RustFacts    bool
	RustAliases  bool
	RustOps      bool
	RustNames    bool
	RustTypes    bool
	RustScopes   map[string]*rustFileScope
	RustBinaries map[string][]graphfrag.GraphFragmentBinaryExpr
	// CIncludes are a C or C++ fragment's #include directives, by file, and
	// CFuncs its functions by key (c_match.go).
	CIncludes map[string][]cInclude
	CFuncs    map[string]*FunctionJSON
	// CStrings are a C or C++ fragment's string literals by file; nil when
	// the fragment carries none.
	CStrings map[string][]graphfrag.GraphFragmentString
	// CUsings are a C++ fragment's using directives and declarations by
	// file (cpp_match.go).
	CUsings map[string][]cppUsing
	// CPP: the fragment is C++; CAnchorKinds are the AST kinds of its
	// sites' anchors by place.
	CPP          bool
	CAnchorKinds map[cAnchorAt]string
}

// loadDecls makes a site per declaration and per cast of the fragment.
func (fr *Frag) loadDecls(frag *FragmentJSON) {
	fr.HasDecls = frag.hasDeclarations()
	fr.DeclsByCaller, fr.CastsAt = map[string][]*Site{}, map[string][]*Site{}
	for i := range frag.Declarations {
		d := &frag.Declarations[i]
		if d.Function < 0 || d.Function >= len(frag.Functions) {
			continue
		}
		fn := &frag.Functions[d.Function]
		s := &Site{
			ID: -1, File: fn.FilePath, Line: d.Line, LineOK: true, Caller: fn.Key, CallerPackage: fn.Package,
			Raw: d.Type, Kind: "declaration", Col: d.StartCol, ColOK: true, EndCol: d.EndCol, EndLine: d.EndLine,
			AssignedVar: d.Name, RefContext: d.Init,
		}
		fr.Decls = append(fr.Decls, s)
		fr.DeclsByCaller[s.Caller] = append(fr.DeclsByCaller[s.Caller], s)
	}
	for i := range frag.Casts {
		c := &frag.Casts[i]
		if c.Function < 0 || c.Function >= len(frag.Functions) {
			continue
		}
		fn := &frag.Functions[c.Function]
		s := &Site{
			File: fn.FilePath, Line: c.Line, LineOK: true, Caller: fn.Key, CallerPackage: fn.Package,
			Raw: c.Type, Kind: "cast", Col: c.StartCol, ColOK: true, EndCol: c.EndCol, EndLine: c.EndLine, ID: len(fr.CastList),
		}
		fr.CastList = append(fr.CastList, s)
		k := castKey(fn.Key, c.InnerLine, c.InnerCol)
		fr.CastsAt[k] = append(fr.CastsAt[k], s)
	}
}

func castKey(caller string, line, col int) string {
	return caller + "\x00" + strconv.Itoa(line) + ":" + strconv.Itoa(col)
}

// castSites: the casts written around the call site (graph-fragment-1.18).
func (fr *Frag) castSites(s *Site) []*Site {
	if !s.LineOK || !s.ColOK {
		return nil
	}
	return fr.CastsAt[castKey(s.Caller, s.Line, s.Col)]
}

// declarationOf: the declaration of name in the site's function whose
// initializer holds the site, if the fragment has one: the site's value is
// stored by `T name = ...;`, not by a plain assignment.
func (fr *Frag) declarationOf(s *Site, name string) *Site {
	for _, d := range fr.DeclsByCaller[s.Caller] {
		if d.AssignedVar == name && d.contains(s) {
			return d
		}
	}
	return nil
}

// comparisonContext: a constant reference in this position kind is read, not
// passed on (== / !=, equals, a case label).
func comparisonContext(context string) bool {
	return context == "compare" || context == "equals" || context == "case"
}

// ComparisonPolicy is how constant references read in comparisons are
// reported (Options.ConstantComparisons, Options.PyMembership).
type ComparisonPolicy string

// The comparison policies: report a comparison only when the compared value
// can be the constant, every comparison, or none.
const (
	ComparisonsResolved ComparisonPolicy = "resolved"
	ComparisonsAll      ComparisonPolicy = "all"
	ComparisonsOff      ComparisonPolicy = "off"
)

// reportComparison: the constant reference ref, read in a comparison, is
// reported under the fragment's policy.
func (fr *Frag) reportComparison(ref *Site) bool {
	switch fr.Comparisons {
	case ComparisonsAll:
		return true
	case ComparisonsOff:
		return false
	case ComparisonsResolved:
		return fr.comparedValueCanBe(ref)
	}
	return fr.comparedValueCanBe(ref)
}

// comparedValueCanBe: a value the operand compared with ref can hold is the
// constant ref names, read as a call argument's values are (localValues, and
// same-file callers' arguments for a parameter, paramValues). A field's
// constructor parameter is not the function's own parameter, so it is not
// followed to the function's callers.
func (fr *Frag) comparedValueCanBe(ref *Site) bool {
	op := ref.Operand
	if op == nil {
		return false
	}
	cands := localValues(op)
	if fr.ResolveParams {
		own := *op
		own.SourceNodes = withoutFieldParameters(op.SourceNodes)
		cands = append(cands, paramValues(ref.Caller, ref.File, &own, fr.Incoming, 0)...)
	}
	for _, c := range cands {
		if sameConstant(c.Value, ref.Raw) {
			return true
		}
		// Python: the same name once both are qualified through the file's
		// imports (`CERT_NONE` passed, `ssl.CERT_NONE` referenced).
		if fr.Python && norm(fr.qualifyIn(ref.Caller, c.Value)) == norm(fr.qualifyIn(ref.Caller, ref.Raw)) {
			return true
		}
	}
	return false
}

// sameConstant: value names the constant ref, written qualified or not
// (`a.b.Alg.X` and `Alg.X`).
func sameConstant(value, ref string) bool {
	value = strings.Join(strings.Fields(value), "")
	return value == ref || strings.HasSuffix(value, "."+ref) || strings.HasSuffix(ref, "."+value) && strings.Contains(value, ".")
}

// withoutFieldParameters copies nodes without what a FIELD node traces to.
func withoutFieldParameters(nodes []SourceNode) []SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]SourceNode, len(nodes))
	for i := range nodes {
		n := nodes[i]
		if n.Type == strField {
			n.SourceNodes = nil
		} else {
			n.SourceNodes = withoutFieldParameters(n.SourceNodes)
		}
		out[i] = n
	}
	return out
}

// comparisonsFor is the policy a fragment allows: only a 1.19 fragment
// carries the compared operands.
func comparisonsFor(frag *FragmentJSON) ComparisonPolicy {
	if frag.schemaMinor() >= 19 {
		return ComparisonsResolved
	}
	return ComparisonsAll
}

// loadRefs makes a site per constant reference of the fragment.
func loadRefs(frag *FragmentJSON) []*Site {
	out := make([]*Site, 0, len(frag.ConstantRefs))
	var alts map[string]map[string][]string
	if frag.python() {
		alts = pyAlternativesByFile(frag)
	}
	for i := range frag.ConstantRefs {
		r := &frag.ConstantRefs[i]
		if r.Function < 0 || r.Function >= len(frag.Functions) {
			continue
		}
		fn := &frag.Functions[r.Function]
		out = append(out, &Site{
			ID: -1, File: fn.FilePath, Line: r.Line, LineOK: true, Caller: fn.Key, CallerPackage: fn.Package,
			Raw: r.Text, Kind: "constant_ref", Col: r.StartCol, ColOK: true, EndCol: r.EndCol, EndLine: r.EndLine, RefContext: r.Context,
			Operand: operandParam(r.Operand),
		})
		ref := out[len(out)-1]
		for _, text := range pyAlternativeNames(r.Text, alts[fn.FilePath]) {
			v := *ref
			v.Raw = text
			out = append(out, &v)
		}
	}
	return out
}

// operandParam reads a compared operand as the matcher reads a call
// argument: the parameter object has the same fields.
func operandParam(op *graphfrag.GraphFragmentParameter) *Param {
	if op == nil {
		return nil
	}
	data, err := json.Marshal(op)
	if err != nil {
		return nil
	}
	var p Param
	if json.Unmarshal(data, &p) != nil {
		return nil
	}
	return &p
}

// contains: the reference lies within the call's span.
func (s *Site) contains(ref *Site) bool {
	if !s.LineOK || !s.ColOK || s.EndCol == 0 {
		return false
	}
	endLine := max(s.EndLine, s.Line)
	if ref.Line < s.Line || ref.Line > endLine {
		return false
	}
	if ref.Line == s.Line && ref.Col < s.Col {
		return false
	}
	return ref.Line != endLine || ref.Col < s.EndCol
}

// refAt: the constant reference of the site's caller written as text inside
// the site, if the fragment has one.
func (fr *Frag) refAt(s *Site, text string) *Site {
	for _, r := range fr.RefsByCaller[s.Caller] {
		if r.Raw == text && s.contains(r) {
			return r
		}
	}
	return nil
}

func walkNodes(nodes []SourceNode, fn func(*SourceNode)) {
	for i := range nodes {
		fn(&nodes[i])
		walkNodes(nodes[i].SourceNodes, fn)
	}
}

// loadSites is match.load_sites: external calls first, then internal edges, in fragment order.
func loadSites(frag *FragmentJSON, names map[string]map[string]string) ([]*Site, map[string][]*Site) { //nolint:funlen,gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	python, golang := frag.python(), frag.golang()
	var alts map[string]map[string][]string
	if python {
		alts = pyAlternativesByFile(frag)
	}
	var usings map[string][]string
	if frag.csharp() {
		usings = csharpUsingsByFile(frag.Imports)
	}
	byKey := make(map[string]*FunctionJSON, len(frag.Functions))
	for i := range frag.Functions {
		byKey[frag.Functions[i].Key] = &frag.Functions[i] // later wins
	}
	strs := frag.InternalEdgeStrings
	sites := make([]*Site, 0, len(frag.ExternalCalls)+len(frag.InternalEdges))
	incoming := map[string][]*Site{}
	for i := range frag.ExternalCalls {
		e := &frag.ExternalCalls[i]
		s := &Site{
			Caller: e.CallerKey, Method: e.MethodName, Arity: e.Arity, Raw: e.Raw, Resolution: e.Resolution,
			Kind: "external", ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar,
		}
		if c := byKey[e.CallerKey]; c != nil {
			s.File, s.CallerPackage = c.FilePath, c.Package
		}
		if cls, _, ok := parseKey(e.TargetKey); ok {
			s.Class = cls
		}
		if e.Line != nil {
			s.Line, s.LineOK = *e.Line, true
		}
		if e.StartCol != nil {
			s.Col, s.ColOK = *e.StartCol, true
		}
		if e.EndCol != nil {
			s.EndCol = *e.EndCol
		}
		s.EndLine = e.EndLine
		switch {
		case python:
			pySite(s, e.TargetKey, e.EntryCall, names[s.File])
		case golang:
			goSite(s, e.TargetKey, e.EntryCall)
			s.DeclaredType = e.DeclaredType
		default:
			s.Ruby = frag.ruby()
			s.CSharp, s.CSharpUsings = frag.csharp(), usings[s.File]
			s.Params, s.ParamIdx, s.ParamOrder = paramMap(e.EntryCall)
		}
		s.setSource(frag.SourceLines)
		for _, v := range pyImportAlternatives(readings(s, names[s.File]), alts[s.File]) {
			v.ID = len(sites)
			sites = append(sites, v)
		}
	}
	for i := range frag.InternalEdges {
		c := &frag.InternalEdges[i]
		caller, callee := &frag.Functions[c.N[0]], &frag.Functions[c.N[1]]
		cls, method, _ := parseKey(callee.Key)
		s := &Site{
			File: caller.FilePath, Line: c.N[2], LineOK: true, Caller: caller.Key, CallerPackage: caller.Package,
			Class: cls, Method: strs[c.N[5]], Arity: c.N[6], Resolution: strs[c.N[3]], Kind: "internal",
			Col: c.N[10], ColOK: true, EndCol: c.N[11], EndLine: c.EndLine, ReceiverVar: strs[c.N[7]], AssignedVar: strs[c.N[8]],
			DeclaredType: strs[c.N[4]],
		}
		if s.Method == "" {
			s.Method = method
		}
		switch {
		case python:
			pySite(s, callee.Key, c.Entry, names[s.File])
		case golang:
			goSite(s, callee.Key, c.Entry)
		default:
			s.CSharp, s.CSharpUsings = frag.csharp(), usings[s.File]
			s.Params, s.ParamIdx, s.ParamOrder = paramMap(c.Entry)
		}
		s.setSource(frag.SourceLines)
		if python {
			pyWrittenCall(s, callee.Key, names[s.File])
		}
		for _, v := range pyImportAlternatives(readings(s, names[s.File]), alts[s.File]) {
			v.ID = len(sites)
			sites = append(sites, v)
			incoming[callee.Key] = append(incoming[callee.Key], v)
		}
	}
	if python {
		pySharedArguments(sites)
	}
	return sites, incoming
}

// readings are the sites a loaded site is matched as: itself, or the
// variants of a Python call (pyValueVariants), read through the file's
// imports names.
func readings(s *Site, names map[string]string) []*Site {
	if s.Python {
		if variants := pyValueVariants(s, names); variants != nil {
			return variants
		}
	}
	return []*Site{s}
}

func addSet(m map[string]map[string]bool, k, v string) {
	s := m[k]
	if s == nil {
		s = map[string]bool{}
		m[k] = s
	}
	s[v] = true
}

func newFrag(frag *FragmentJSON) *Frag { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	if frag.node() {
		return newNodeFrag(frag)
	}
	var names map[string]map[string]string
	if frag.python() {
		names = make(map[string]map[string]string, len(frag.Imports))
		for file, imports := range frag.Imports {
			names[file] = pyNames(imports)
		}
	}
	sites, incoming := loadSites(frag, names)
	if frag.golang() {
		sites = append(sites, goValueSites(frag, len(sites))...)
	}
	fr := &Frag{
		Sites: sites, Incoming: incoming, ByCaller: map[string][]*Site{}, ByRaw: map[string][]*Site{},
		VarSites: map[string][]*Site{}, VarInit: map[string]map[string]bool{}, VarType: map[string]string{},
		Casts: map[string]map[string]bool{}, CallerFile: map[string]string{}, Roots: map[string]map[string]bool{},
		Python: frag.python(), Go: frag.golang(), Names: names, Lines: frag.SourceLines,
	}
	if fr.Go {
		fr.loadGo(frag)
	}
	if fr.Python {
		fr.Params, fr.LocalImports, fr.ImportNames = pyFunctionNames(frag)
		fr.Bindings = pyBindings(frag)
	}
	fr.Comparisons = comparisonsFor(frag)
	fr.Membership = ComparisonsResolved
	fr.Refs = loadRefs(frag)
	fr.Stores = loadStores(frag, names, frag.ruby(), frag.csharp(), csharpUsingsByFile(frag.Imports))
	fr.StoresByCaller = map[string][]*Site{}
	for _, st := range fr.Stores {
		fr.StoresByCaller[st.Caller] = append(fr.StoresByCaller[st.Caller], st)
	}
	fr.loadDecls(frag)
	fr.RefsByCaller = map[string][]*Site{}
	for _, r := range fr.Refs {
		fr.RefsByCaller[r.Caller] = append(fr.RefsByCaller[r.Caller], r)
		if _, ok := fr.CallerFile[r.Caller]; !ok {
			fr.CallerFile[r.Caller] = r.File
		}
	}
	for _, s := range sites {
		if _, ok := fr.CallerFile[s.Caller]; !ok {
			fr.CallerFile[s.Caller] = s.File
		}
		fr.noteRoot(s.File, s.Class)
		for _, i := range s.ParamIdx {
			fr.noteRoot(s.File, s.Params[i].Type)
		}
	}
	fr.indexSites(sites)
	if fr.Python {
		fr.Unpacked = pyUnpacked(frag, fr.ByCaller)
	}
	if frag.c() {
		fr.loadC(frag)
	}
	if frag.rust() {
		fr.RustFacts = frag.schemaMinor() >= 26
		fr.RustAliases = frag.schemaMinor() >= 27
		fr.RustOps = frag.schemaMinor() >= 30
		fr.RustNames = frag.schemaMinor() >= 33
		fr.RustTypes = frag.schemaMinor() >= 35
		fr.RustScopes = rustScopes(frag.Imports, frag.Items)
		fr.RustBinaries = frag.BinaryExprs
	}
	if frag.csharp() {
		fr.CSharp, fr.CSharpUsings = true, csharpUsingsByFile(frag.Imports)
	}
	return fr
}

// indexSites files each site by caller, raw callee and assigned variable, and
// notes the casts and variable types its parameters carry.
func (fr *Frag) indexSites(sites []*Site) {
	for _, s := range sites {
		fr.ByCaller[s.Caller] = append(fr.ByCaller[s.Caller], s)
		if s.Raw != "" {
			k := pairKey(s.Caller, norm(s.Raw))
			fr.ByRaw[k] = append(fr.ByRaw[k], s)
		}
		if s.AssignedVar != "" {
			k := pairKey(s.Caller, s.AssignedVar)
			fr.VarSites[k] = append(fr.VarSites[k], s)
		}
		// Python iterates s["params"].values(): insertion order of the dict = order of first
		// appearance of each index in the fragment. Only set contents and setdefault depend on it.
		for _, p := range paramsInDictOrder(s) {
			if p.ArgumentExpression != "" {
				fr.noteCast(s.Caller, p.ArgumentExpression, whereLine(s))
			}
			walkNodes(p.SourceNodes, func(n *SourceNode) { fr.noteVariable(s, n) })
		}
	}
}

// noteVariable records the declared type of a variable node of site s and the
// casts of the values that initialize it.
func (fr *Frag) noteVariable(s *Site, n *SourceNode) {
	if n.Type != strVariable || n.Name == "" {
		return
	}
	key := pairKey(s.Caller, n.Name)
	if n.DeclaredType != "" {
		if _, ok := fr.VarType[key]; !ok {
			fr.VarType[key] = n.DeclaredType
		}
	}
	for ci := range n.SourceNodes {
		child := &n.SourceNodes[ci]
		if (child.Type == srcCallResult || child.Type == "EXPRESSION") && child.Value != "" {
			addSet(fr.VarInit, key, child.Value)
			fr.noteCast(s.Caller, child.Value, whereVar(n.Name))
		}
	}
}

// Cast keys: Python keys them by (caller, prefix, where) with where = the line of the enclosing call
// or the variable name; a None line and a None assigned_var are the same key (None).
func whereLine(s *Site) string {
	if s.LineOK {
		return "L" + strconv.Itoa(s.Line)
	}
	return "N"
}

func whereVar(v string) string {
	if v != "" {
		return "V" + v
	}
	return "N"
}

// paramsInDictOrder returns the params in the order a Python dict built from the fragment list
// would iterate them (first appearance of each parameter_index, value of the last one).
func paramsInDictOrder(s *Site) []*Param {
	out := make([]*Param, 0, len(s.ParamOrder))
	for _, i := range s.ParamOrder {
		out = append(out, s.Params[i])
	}
	return out
}

func (fr *Frag) noteRoot(file, name string) {
	if name != "" && qualifiedMatch(name) {
		parts := strings.SplitN(name, ".", 3)
		addSet(fr.Roots, file, parts[0]+"."+parts[1])
	}
}

// uses: does the file of this function use some class of the package root (two segments) of
// `qualified`? A card name without a package needs no evidence.
func (fr *Frag) uses(caller, qualified string) bool {
	if !qualifiedMatch(qualified) {
		return true
	}
	parts := strings.SplitN(qualified, ".", 3)
	return fr.Roots[fr.CallerFile[caller]][parts[0]+"."+parts[1]]
}

// noteCast: a cast is visible only in expression text, `(T) call(...)` as an argument (keyed by the
// line of the enclosing call) or as the initializer of a local (keyed by the variable).
func (fr *Frag) noteCast(caller, text, where string) {
	cast, rest := stripCast(text)
	if cast == "" {
		return
	}
	if call := parseCall(rest); call != nil {
		addSet(fr.Casts, caller+"\x00"+norm(call.Prefix)+"\x00"+where, cast)
	}
}

func (fr *Frag) castsOf(s *Site) map[string]bool {
	key := s.Caller + "\x00" + norm(s.Raw) + "\x00"
	out := map[string]bool{}
	for c := range fr.Casts[key+whereLine(s)] {
		out[c] = true
	}
	for c := range fr.Casts[key+whereVar(s.AssignedVar)] {
		out[c] = true
	}
	return out
}

// siteFor: the call site whose call expression is `text` (same function), if the fragment has it.
// line < 0 means None.
func (fr *Frag) siteFor(caller, text string, line int, lineOK bool) *Site {
	call := parseCall(text)
	if call == nil {
		return nil
	}
	var best *Site
	bestD := 0
	for _, s := range fr.ByRaw[pairKey(caller, norm(call.Prefix))] {
		if s.Arity != len(call.Args) {
			continue
		}
		ref := s.lineOr0()
		if lineOK && line != 0 { // Python: line or s["line"] or 0
			ref = line
		}
		d := s.lineOr0() - ref
		if d < 0 {
			d = -d
		}
		if best == nil || d < bestD {
			best, bestD = s, d
		}
	}
	return best
}

func (fr *Frag) receiverText(s *Site) string {
	if s.ReceiverVar != "" {
		return s.ReceiverVar
	}
	if s.Raw != "" && s.Method != "" && s.Method != strInit {
		raw := pyRStrip(s.Raw)
		if strings.HasSuffix(raw, "."+s.Method) {
			return pyStrip(raw[:len(raw)-len(s.Method)-1])
		}
	}
	return ""
}

// loadGo reads what only a Go fragment carries: import specs, parameter
// names, assignments, blocks, values and return sources.
func (fr *Frag) loadGo(frag *FragmentJSON) {
	fr.GoImports, fr.GoAliases = goImportAliases(frag)
	fr.GoImportPaths = goImportPaths(frag)
	fr.GoParams = goParamNames(frag)
	fr.GoAssigns = goAssigns(frag)
	fr.GoBlocks, fr.HasGoBlocks = frag.GoBlocks, frag.schemaMinor() >= 36
	fr.GoValueFacts = frag.GoValues
	fr.GoReturns = map[string][]SourceNode{}
	for i := range frag.Functions {
		if f := &frag.Functions[i]; len(f.ReturnSources) > 0 {
			fr.GoReturns[f.Key] = f.ReturnSources
		}
	}
}
