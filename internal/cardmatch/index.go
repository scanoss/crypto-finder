package cardmatch

// The compiled index (compile_rules.py output) and its matcher: a port of match.py (call_matches,
// constraints_hold, taint_matches with --resolve-params, match) with match2.call_matches_const
// installed, as match2.run does, and either match.fill ("raw", what match2.py's CLI and heldout.py
// use) or bench_score.cf_fill ("cf", crypto-finder's way, what bench_score.py --cards uses).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/scanoss/crypto-finder/internal/cardmatch/internal/jspat"
)

// jsonNumber is a number from index.json, kept as written (Python keeps int or float).
type jsonNumber string

func pyJSONNumberStr(s string) string {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			panic(err)
		}
		return pyFloatRepr(f)
	}
	return s
}

// JSONMeta is a metadata object with its key order (decoded token by token).
type JSONMeta struct{ M *OMap }

// UnmarshalJSON decodes the object keeping its key order.
func (j *JSONMeta) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeOrdered(dec)
	if err != nil {
		return err
	}
	m, ok := v.(*OMap)
	if !ok {
		return fmt.Errorf("metadata is not an object")
	}
	j.M = m
	return nil
}

func decodeOrdered(dec *json.Decoder) (any, error) { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := &OMap{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := decodeOrdered(dec)
				if err != nil {
					return nil, err
				}
				m.Set(as[string](k), v)
			}
			_, err := dec.Token()
			return m, err
		case '[':
			var l []any
			for dec.More() {
				v, err := decodeOrdered(dec)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			_, err := dec.Token()
			if l == nil {
				l = []any{}
			}
			return l, err
		}
	case json.Number:
		return jsonNumber(t), nil
	}
	return tok, nil // string, bool, nil
}

// IndexArg is an argument condition of an index entry.
type IndexArg struct {
	Kind  string  `json:"kind"`
	Value *string `json:"value"`
	Index *int    `json:"index"`
	Name  *string `json:"name"`
	// Keyword: a Python keyword argument (`kw=$X` in the rule), read by
	// name; Index is then nil.
	Keyword *string `json:"keyword"`
	// Call: a nested call argument (kind "call", compile_py_ext.go): the
	// call written as the argument must match it.
	Call *Entry `json:"call"`
	// Unquote: a Python "$X" argument (kind metavar): a string literal,
	// whose content $X binds.
	Unquote bool `json:"unquote"`
	// Names / Keys: a Python dict or list display argument (kind
	// "container", Value its opening bracket) holding metavariables Names,
	// with the dict keys Keys.
	Names []string `json:"names"`
	Keys  []string `json:"keys"`
}

// param is the site argument the entry argument names.
func (a *IndexArg) param(params map[int]*Param) *Param {
	switch {
	case a.Keyword != nil:
		return params[kwKey(*a.Keyword)]
	case a.Index != nil:
		return params[*a.Index]
	}
	return nil
}

// Constraint is a regex condition on a call argument of an index entry.
type Constraint struct {
	ArgIndex *int    `json:"arg_index"`
	Regex    *string `json:"regex"`
	Kind     *string `json:"kind"`
	Clause   string  `json:"clause"`
	// Qualified: the regex is also tried on a Python argument's text
	// qualified through the file's imports (a metavariable-pattern of
	// dotted names).
	Qualified bool `json:"qualified"`
	// Unquote: the regex is matched against a Python string argument's
	// content ("$X" in the pattern).
	Unquote bool `json:"unquote"`
	// DictKey: the regex is matched against the value of this key in a
	// Python dict display argument (`{..., "k": $X, ...}`).
	DictKey *string `json:"dict_key"`
	// Metavar is the metavariable the regex reads. A node entry's
	// constraint reads its binding (ArgIndex is nil); a Python entry's names
	// it for the record.
	Metavar string `json:"metavar,omitempty"`
}

// Entry is one compiled rule sink of the card index.
type Entry struct {
	Receiver    string       `json:"receiver"`
	Type        *string      `json:"type"`
	Method      *string      `json:"method"`
	MinArity    int          `json:"min_arity"`
	MaxArity    *int         `json:"max_arity"`
	Args        []IndexArg   `json:"args"`
	MethodRegex *string      `json:"method_regex"`
	Constraints []Constraint `json:"constraints"`
	NotCalls    []*Entry     `json:"not_calls"`
	FocusArg    *int         `json:"focus_arg"`
	// FocusReceiver: Go, the focus-metavariable is the receiver; the finding
	// is reported at the receiver's span.
	FocusReceiver bool `json:"focus_receiver,omitempty"`
	// GoAliasOf: Go, the receiver is bound by `import $P "p"`, which binds
	// only an aliased import: the call's qualifier must be an alias of this
	// path in the call's file.
	GoAliasOf string `json:"go_alias_of,omitempty"`
	// GoAddr: Go, a composite literal written with `&` (`&T{...}`), which
	// matches only a literal written so and is reported from the `&`.
	GoAddr bool `json:"go_addr,omitempty"`
	// GoFileImports: Go, the site's file must import this path (a store
	// rule written inside an import clause, its receiver untyped).
	GoFileImports  string    `json:"go_file_imports,omitempty"`
	DroppedClauses []string  `json:"dropped_clauses"`
	RuleID         string    `json:"rule_id"`
	Taint          bool      `json:"taint"`
	Metadata       JSONMeta  `json:"metadata"`
	TaintSources   []*string `json:"taint_sources"`
	MethodMetavar  *string   `json:"method_metavar"`
	CalleePackages []string  `json:"callee_packages"`
	CallerPackages []string  `json:"caller_packages"`
	// TypeMetavar: a Python callee `a.$C.m(...)` (Type "a.$C"): the class
	// name binds $C and matches TypeRegex when given.
	TypeMetavar *string `json:"type_metavar"`
	TypeRegex   *string `json:"type_regex"`
	// The Python extensions of the compiler (compile_py_ext.go, index_py.go).
	Insides   [][]*Origin `json:"insides"`    // each group: one origin holds
	NotInside []*Entry    `json:"not_inside"` // not written inside a matching call
	Flow      string      `json:"flow"`       // "object": a taint rule matched as a call
	At        []string    `json:"at"`         // constant: the position kinds reported
	NotAt     []string    `json:"not_at"`     // constant: position kinds never reported
	Pattern   string      `json:"pattern"`
	// ReceiverVar is a site card's receiver metavariable, what Pattern gives
	// a compiled entry (receiverMetavar).
	ReceiverVar string `json:"receiver_var"`
	// The node extension (compile_node.go, index_node.go): set on JavaScript
	// and TypeScript entries only, so Java and Python entries keep their JSON.
	Callee       *NodeCallee `json:"callee,omitempty"`        // what the call is a call of
	ArgPattern   *string     `json:"arg_pattern,omitempty"`   // jspat argument-list pattern; nil = `...`
	FocusMetavar string      `json:"focus_metavar,omitempty"` // focus-metavariable bound in ArgPattern
	NotImports   []string    `json:"not_imports,omitempty"`   // the file imports none of these modules
	// Consumers: node only, the call counts only where one of these takes
	// it (or the variable it is assigned to) as an argument.
	Consumers []*NodeConsumer `json:"consumers,omitempty"`
	// NotRegexes: node only, pattern-not-regex: no finding where one of
	// these is found in the call's text (callee and arguments as written).
	NotRegexes []string `json:"not_regexes,omitempty"`
	// Producers: node only, an argument metavariable the rule binds to a
	// call's result in a context (`$K = $GEN($TYPE)` ... `f({key: <... $K
	// ...>})`): the call counts only where each producer holds.
	Producers []*NodeProducer `json:"producers,omitempty"`
	// NotEntries: node only, a pattern-not written as a sub-rule: no
	// finding where one of these entries matches the same call.
	NotEntries []*Entry `json:"not_entries,omitempty"`
	// NotEnclosed: node only, pattern-not-insides that place the matched
	// expression somewhere: "argument" (a direct argument of another call or
	// new, `$FN(..., X, ...)`) or "property" (a property value of an object
	// literal, `{..., $K: X, ...}`). No finding where it stands there.
	NotEnclosed []string `json:"not_enclosed,omitempty"`
	// Within: node only, a literal entry written inside a context call
	// (`$H.setProtectedHeader(...)` around `{..., alg: "x", ...}`): the
	// object lies within a call of its function that one of these matches.
	Within []*Entry `json:"within,omitempty"`
	// Read: node only, the pattern is a property read (`ns.enums.hash.md5`),
	// matched on the fragment's property reads, never on a call.
	Read bool `json:"read,omitempty"`
	// NotProducers: node only, pattern-not-insides `$V = <expr>; ...`: no
	// finding where one of these producers holds for the call.
	NotProducers []*NodeProducer `json:"not_producers,omitempty"`
	// Rust is the pattern of an entry the Rust compiler made (compile_rust.go):
	// the Rust matcher reads it, the Java and Python matchers skip the entry.
	Rust *RustPattern `json:"rust,omitempty"`
	// C is the pattern of an entry the C compiler made (compile_c.go): the C
	// matcher reads it, the other matchers skip the entry.
	C *CPattern `json:"c,omitempty"`

	methodGroups map[string]Groups // re.match(method_regex) per method name, nil = no match
	jsArgs       []*jspat.Node     // ArgPattern parsed (prepareNode)
}

// Index is the compiled card index: the entries the matcher tests call sites against.
type Index struct {
	Entries []*Entry `json:"entries"`
}

// loadIndex reads an index.json (compile_rules.py's, or compile_rules_py.py's
// with symbolic Python keyword indices, turned into keyword ids as CompileIndex
// does).
func loadIndex(path string) (*Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte(`"kw:`)) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		doc, err := decodeOrdered(dec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		m, ok := doc.(*OMap)
		if !ok {
			return nil, fmt.Errorf("%s: not an index", path)
		}
		var entries []*OMap
		for _, e := range listOf(m.GetOr("entries")) {
			entries = append(entries, as[*OMap](e))
		}
		keywordIndices(entries)
		data = []byte(jsonValue(m))
	}
	var ix Index
	if err := json.Unmarshal(data, &ix); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := ix.validateNode(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ix.prepare()
	return &ix, nil
}

// methodMatch is `re.match(entry["method_regex"] or ".*", site["method"] or "")`, once per name.
func (e *Entry) methodMatch(method string) Groups {
	if e.methodGroups == nil {
		e.methodGroups = map[string]Groups{}
	}
	if g, ok := e.methodGroups[method]; ok {
		return g
	}
	rx := ".*"
	if e.MethodRegex != nil && *e.MethodRegex != "" {
		rx = *e.MethodRegex
	}
	g := reMatch(rx, method)
	e.methodGroups[method] = g
	return g
}

func inList(s string, l []string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// callMatchesOrig is match.call_matches: callee type + method + arity + literal/text args.
// params is the site's params (possibly patched by callMatches). nil = no match.
func callMatchesOrig(e *Entry, s *Site, params map[int]*Param) Groups { //nolint:funlen,gocognit,gocyclo // callMatchesOrig keeps the original call-match order that callMatches is checked against
	if e.MinArity > s.Arity || (e.MaxArity != nil && s.Arity > *e.MaxArity) {
		return nil
	}
	if s.Python && s.PyDelegation {
		return nil // instantiates no class (pyWrittenCall)
	}
	groups := Groups{}
	if e.Method != nil {
		if s.Method == "" || s.Method != *e.Method {
			return nil
		}
	} else {
		g := e.methodMatch(s.Method)
		if g == nil {
			return nil
		}
		for k, v := range g {
			groups[k] = v
		}
	}
	if e.Method != nil && *e.Method == strInit && s.delegation() {
		// OpenGrep's `new T(...)` does not match a `this(...)` / `super(...)`
		// delegation, although the graph links it to T.<init>.
		return nil
	}
	switch e.Receiver {
	case strType, strTypedMetavar, strAny:
		// A pattern written with a receiver does not match a call written
		// without one (`sha256(data)` inside DigestUtils).
		if s.receiverless() {
			return nil
		}
	}
	switch e.Receiver {
	case strType, strTypedMetavar:
		cls := s.receiverClass()
		switch {
		case s.Ruby && e.TypeMetavar != nil:
			if !rubyTypeMetavarMatch(e, cls, s, groups) {
				return nil
			}
		case s.Python && e.TypeMetavar != nil:
			if !pyTypeMetavarMatch(e, cls, s, groups) {
				return nil
			}
		case s.Python:
			// Exact: the resolved callee is the rule's dotted name, or the
			// call is written as the rule writes it (how OpenGrep matches a
			// pattern it cannot qualify).
			if e.Type == nil || (cls != *e.Type && norm(s.Raw) != *e.Type+"."+s.Method) {
				return nil
			}
		case s.Go:
			// Exact, as Python: the import path (and type) the rule names, or,
			// for a rule that names no import, the package's own name.
			if e.Type == nil || (cls != *e.Type && goShortClass(cls) != *e.Type) {
				return nil
			}
		case s.CSharp:
			// C# has no single-type import: a qualified pattern matches a
			// type written short wherever a using brings its namespace in.
			if e.Type == nil || !csharpClassMatch(*e.Type, cls, s) {
				return nil
			}
		case cls == "" || e.Type == nil || (cls != *e.Type && !strings.HasSuffix(cls, "."+*e.Type)):
			return nil
		}
		if len(e.CalleePackages) > 0 {
			pkg := cls
			if i := strings.LastIndexByte(cls, '.'); i >= 0 {
				pkg = cls[:i]
			}
			if !inList(pkg, e.CalleePackages) {
				return nil
			}
		}
	case strNone:
		if s.Raw != "" && strings.Contains(s.Raw, ".") {
			return nil
		}
		if s.Python && s.Raw != "" && s.Raw != s.Method {
			return nil // OpenGrep matches `C(...)` only where C is written (not `cls(...)`)
		}
	}
	if len(e.CallerPackages) > 0 && (s.CallerPackage == "" || !inList(s.CallerPackage, e.CallerPackages)) {
		return nil
	}
	for i := range e.Args {
		a := &e.Args[i]
		p := a.param(params)
		if s.Python && a.Kind == strMetavar && p == nil && (a.Keyword != nil || a.Index != nil) {
			return nil // a keyword metavariable must be passed
		}
		switch a.Kind {
		case strLiteral:
			if p == nil {
				return nil
			}
			v := norm(*a.Value)
			if v != norm(p.ArgumentExpression) && v != norm(p.ResolvedValue) {
				return nil
			}
		case "container":
			if p == nil || !pyContainerArg(a, p) {
				return nil
			}
		case strMetavar:
			if a.Unquote && (p == nil || pyStringContent(p) == nil) {
				return nil
			}
		case "string_regex":
			if p == nil || !pyStringMatches(*a.Value, p) {
				return nil
			}
		case "any_string":
			if p == nil || (!strings.HasPrefix(p.ArgumentExpression, `"`) && !strings.HasPrefix(p.ResolvedValue, `"`)) {
				return nil
			}
		case strText:
			// A Python name the rule writes qualified also matches the
			// source's text qualified through the file's imports.
			if p == nil || (norm(p.ArgumentExpression) != *a.Value && (!s.Python || norm(p.Qualified) != *a.Value)) {
				return nil
			}
		}
	}
	return groups
}

// callMatches is match2.call_matches_const: match.call_matches, plus an argument the rule gives as
// a qualified constant also matches the source's shorter name, with package evidence (Frag.uses).
func callMatches(e *Entry, s *Site, fr *Frag) Groups { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	if e.GoAliasOf != "" && !goAliasedCall(e, s, fr) {
		return nil
	}
	if !goValueHolds(e, s) || (e.GoFileImports != "" && !goFileImports(e, s, fr)) {
		return nil
	}
	if s.Python {
		g := callMatchesOrig(e, s, s.Params)
		if g != nil && !nestedMatch(e, s, fr, g) {
			return nil
		}
		return g
	}
	if g := callMatchesOrig(e, s, s.Params); g != nil {
		return g
	}
	var patched map[int]*Param
	for _, a := range e.Args {
		if a.Kind != strText || !qualifiedMatch(*a.Value) && !s.CSharp {
			continue
		}
		var p *Param
		if a.Index != nil {
			p = s.Params[*a.Index]
		}
		if p == nil {
			continue
		}
		t := norm(p.ArgumentExpression)
		if strings.Contains(t, ".") && t != *a.Value && strings.HasSuffix(*a.Value, "."+t) && fr.uses(s.Caller, *a.Value) && csharpUsingBrings(*a.Value, t, s) {
			if patched == nil {
				patched = make(map[int]*Param, len(s.Params))
				for k, v := range s.Params {
					patched[k] = v
				}
			}
			cp := *patched[*a.Index]
			cp.ArgumentExpression = *a.Value
			patched[*a.Index] = &cp
		}
	}
	if patched == nil {
		return nil
	}
	return callMatchesOrig(e, s, patched)
}

func startsWithQuoteValueChild(nodes []SourceNode) bool {
	for i := range nodes {
		n := &nodes[i]
		if n.Type != strVariable && n.Type != strField {
			continue
		}
		for j := range n.SourceNodes {
			v := &n.SourceNodes[j]
			if v.Type == "VALUE" && strings.HasPrefix(v.Value, `"`) {
				return true
			}
		}
		// A variable every assignment of which is a string literal: OpenGrep
		// propagates it as a string constant, so its `"..."` patterns exclude
		// the call.
		if n.MayValuesExhaustive && len(n.MayValues) > 0 {
			return true
		}
	}
	return false
}

// constraintsHold is match.constraints_hold; it adds regex groups to `groups` as it goes.
func constraintsHold(e *Entry, s *Site, groups Groups, fr *Frag) bool { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	for _, c := range e.Constraints {
		var p *Param
		if c.ArgIndex != nil {
			p = s.Params[*c.ArgIndex]
		}
		if c.Kind != nil && *c.Kind == "not_assigned_string_literal" {
			if p != nil && (strings.HasPrefix(p.ResolvedValue, `"`) || startsWithQuoteValueChild(p.SourceNodes)) {
				return false
			}
			continue
		}
		if p == nil || p.ArgumentExpression == "" {
			return false
		}
		if c.DictKey != nil {
			if !pyDictValueMatches(&c, p, s, fr, groups) {
				return false
			}
			continue
		}
		if c.Unquote {
			content := pyStringContent(p)
			if content == nil {
				return false
			}
			m := reMatch(*c.Regex, *content)
			if m == nil {
				return false
			}
			for k, v := range m {
				groups[k] = v
			}
			continue
		}
		m := reMatch(*c.Regex, p.ArgumentExpression)
		if m == nil && c.Qualified && p.Qualified != "" {
			m = reMatch(*c.Regex, p.Qualified)
		}
		if m == nil {
			return false
		}
		for k, v := range m {
			groups[k] = v
		}
	}
	return true
}

type valueHow struct {
	How   string
	Value string
}

// localValues is match.local_values: candidate source values within the calling function.
func localValues(p *Param) []valueHow {
	var out []valueHow
	if p.ArgumentExpression != "" {
		out = append(out, valueHow{"direct", p.ArgumentExpression})
	}
	if p.ResolvedValue != "" {
		out = append(out, valueHow{"resolved", p.ResolvedValue})
	}
	walkNodes(p.SourceNodes, func(n *SourceNode) {
		if n.Type == strValue && n.Value != "" {
			out = append(out, valueHow{"resolved", n.Value})
		}
		for _, v := range n.MayValues {
			out = append(out, valueHow{"resolved", v})
		}
	})
	return out
}

const maxDepth = 4

// paramValues is match.param_values: values passed for a PARAMETER argument of caller's
// function by its internal callers written in the same file, following parameters up to maxDepth
// callers. OpenGrep's taint follows an argument into a function of the same file only; a value
// from another file is left to crypto-finder's conditioned step, as it is with OpenGrep.
func paramValues(caller, file string, p *Param, incoming map[string][]*Site, depth int) []valueHow { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var out []valueHow
	if depth >= maxDepth {
		return out
	}
	walkNodes(p.SourceNodes, func(n *SourceNode) {
		if n.Type != srcParameter || n.ParameterIndex == nil {
			return
		}
		for _, cs := range incoming[caller] {
			if cs.File != file {
				continue
			}
			cp := callerArgument(cs, n)
			if cp == nil {
				continue
			}
			lvs := localValues(cp)
			if cs.Go {
				lvs = append(lvs, goCallValues(cp)...)
			}
			for _, lv := range lvs {
				if lv.How != "direct" || strings.HasPrefix(lv.Value, `"`) {
					out = append(out, valueHow{"param", lv.Value})
				}
			}
			out = append(out, paramValues(cs.Caller, cs.File, cp, incoming, depth+1)...)
		}
	})
	return out
}

// callerArgument is the argument call site cs passes for the parameter n
// names: the one at its index. Python: the keyword argument of the
// parameter's name, else the positional argument at its index (a
// keyword-only parameter has index -1 and no position) unless a `*args`
// spread at or before it leaves the position unknown. An edge without
// arguments reads those of the call written at its position (ArgsFrom).
func callerArgument(cs *Site, n *SourceNode) *Param {
	index := *n.ParameterIndex
	if !cs.Python {
		return cs.Params[index]
	}
	if cs.ArgsFrom != nil {
		cs = cs.ArgsFrom
	}
	if n.Name != "" {
		if p := cs.Params[kwKey(n.Name)]; p != nil {
			return p
		}
	}
	// Positional arguments are filed 0..n-1: a position past them, and -1, hold none.
	for i := 0; i <= index; i++ {
		if p := cs.Params[i]; p == nil || strings.HasPrefix(p.ArgumentExpression, "*") {
			return nil
		}
	}
	return cs.Params[index]
}

// taintHit is (how, value, groupdict): the groupdict keeps None values (match.py does not drop them),
// and holds every group by its number as well as by its name.
type taintHit struct {
	How    string
	Value  string
	Groups map[string]*string
}

func reMatchFull(rx, text string) (map[string]*string, bool) {
	r := compileRx(rx)
	m, err := r.match.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return nil, false
	}
	out := map[string]*string{}
	group := func(key, name string) {
		g := m.GroupByName(name)
		if g != nil && len(g.Captures) > 0 {
			v := g.String()
			out[key] = &v
		} else {
			out[key] = nil
		}
	}
	for _, n := range r.named {
		group(n, n)
	}
	// Every group by its number too, as pyRegex.groups gives a constraint's.
	for i, n := range r.order {
		group(strconv.Itoa(i+1), n)
	}
	return out, true
}

func taintMatches(e *Entry, s *Site, incoming map[string][]*Site, resolveParams bool) []taintHit {
	idxs := s.ParamIdx
	if e.FocusArg != nil {
		idxs = []int{*e.FocusArg}
	}
	return taintHits(e.TaintSources, idxs, s, incoming, resolveParams)
}

// taintHits are the values of the arguments idxs of s that a source regex
// (nil: any value) matches, a value held at the call before one passed by a
// caller (param).
func taintHits(sources []*string, idxs []int, s *Site, incoming map[string][]*Site, resolveParams bool) []taintHit { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var hits []taintHit
	for _, i := range idxs {
		p := s.Params[i]
		if p == nil {
			continue
		}
		cands := localValues(p)
		if s.Python {
			cands = append(cands, pyDisplayLiterals(p)...)
		}
		if s.Go {
			cands = append(cands, goCallValues(p)...)
		}
		if resolveParams {
			cands = append(cands, paramValues(s.Caller, s.File, p, incoming, 0)...)
		}
		for _, c := range cands {
			for _, rx := range sources {
				if rx == nil {
					hits = append(hits, taintHit{c.How, c.Value, map[string]*string{}})
					break
				}
				if g, ok := reMatchFull(*rx, c.Value); ok {
					hits = append(hits, taintHit{c.How, c.Value, g})
					break
				}
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	for _, h := range hits {
		if h.How != "param" {
			return []taintHit{h}
		}
	}
	seen := map[string]bool{}
	var out []taintHit
	for _, h := range hits {
		if !seen[h.Value] {
			seen[h.Value] = true
			out = append(out, h)
		}
	}
	return out
}

// fillGroups is dict(groups, **g): call/constraint groups overridden by the taint groupdict,
// whose values can be None.
type fillGroups map[string]*string

// fillRaw is match.fill: `$NAME` (or a numbered `$1`) takes a regex group, else a metavariable's argument text;
// anything else stays as written; non-string values pass through.
func fillRaw(tmpl *OMap, groups fillGroups, s *Site, e *Entry) *OMap {
	metavars := map[string]*string{}
	for i := range e.Args {
		if a := &e.Args[i]; a.Name != nil && *a.Name != "" && a.Kind == strMetavar {
			metavars[*a.Name] = argText(a.param(s.Params))
		}
	}
	if e.MethodMetavar != nil && *e.MethodMetavar != "" {
		metavars[*e.MethodMetavar] = methodPtr(s)
	}
	out := &OMap{}
	for i, k := range tmpl.Keys {
		v := tmpl.Vals[i]
		str, ok := v.(string)
		if !ok {
			out.Set(k, v)
			continue
		}
		out.Set(k, reSubFunc(`\$([A-Za-z_]\w*|\d+)`, str, func(full string, g []string) string {
			name := g[1]
			if val, ok := groups[name]; ok {
				if val == nil {
					// A taint source group that did not take part: re.sub treats the None the
					// replacement function returns as "" (the `$NAME` disappears).
					return ""
				}
				return *val
			}
			if mv, ok := metavars["$"+name]; ok && mv != nil {
				return *mv
			}
			return full
		}))
	}
	return out
}

func argText(p *Param) *string {
	if p == nil || p.ArgumentExpression == "" {
		return nil
	}
	v := p.ArgumentExpression
	return &v
}

func methodPtr(s *Site) *string {
	if s.Method == "" {
		return nil
	}
	m := s.Method
	return &m
}

const (
	cfIdentRx = `^[A-Za-z_][\w.]*$`
	litRx     = `^(".*"|-?\d+[lL]?)$`
)

// cfMetavarValue is bench_score.metavar_value: the constant a name resolves to, else the text.
func cfMetavarValue(p *Param) *string {
	if p == nil {
		return nil
	}
	text, resolved := p.ArgumentExpression, p.ResolvedValue
	if text != "" && reMatchOK(cfIdentRx, text) && resolved != "" && reMatchOK(litRx, resolved) {
		return &resolved
	}
	if text == "" {
		return nil
	}
	return &text
}

// fillCF is bench_score.cf_fill: `$REF` takes the bound value with quotes trimmed; a field whose
// `$REF` did not bind is left out (except parameterCondition); non-strings are stringified.
func fillCF(tmpl *OMap, groups fillGroups, s *Site, e *Entry) *OMap {
	metavars := map[string]*string{}
	for i := range e.Args {
		if a := &e.Args[i]; a.Name != nil && *a.Name != "" && a.Kind == strMetavar {
			metavars[*a.Name] = cfMetavarValue(a.param(s.Params))
		}
	}
	if e.MethodMetavar != nil && *e.MethodMetavar != "" {
		metavars[*e.MethodMetavar] = methodPtr(s)
	}
	out := &OMap{}
	for i, k := range tmpl.Keys {
		v := tmpl.Vals[i]
		str, ok := v.(string)
		if !ok {
			out.Set(k, metadataStr(v))
			continue
		}
		complete := true
		res := reSubFunc(`\$(?:[A-Za-z_]\w*|\d+)`, str, func(full string, _ []string) string {
			name := full[1:]
			val := groups[name]
			if val == nil {
				val = metavars["$"+name]
			}
			if val != nil && *val != "" {
				return trimQuotes(*val)
			}
			complete = false
			return full
		})
		if (complete || k == "parameterCondition") && res != "" {
			out.Set(k, res)
		}
	}
	return out
}

// Finding is one result, in match2.py's shape.
type Finding struct {
	RuleID     string
	File       string
	Line       int
	LineOK     bool
	Col        int
	ColOK      bool
	Taint      bool
	How        string
	Value      *string
	Resolution string
	SiteKind   string
	Callee     string
	Metadata   *OMap
	Approx     []string
	Card       *string
	Caller     string // function key of the matched site's caller
	EndCol     int    // end column (exclusive) of the matched call expression; 0 = unknown
	EndLine    int    // line EndCol is on when the call spans lines; 0 = Line
	// FocusArg is the argument the rule reports instead of the whole call (its
	// focus-metavariable), with the argument's text; nil when the rule reports the call.
	FocusArg  *int
	FocusText string
	// TerminalCol and TerminalEndCol keep the matched call's columns when the
	// finding is reported at a part of it (a Go receiver focus), so the crypto
	// call is still selected by the call's span; 0 when it is reported at the call.
	TerminalCol, TerminalEndCol int
}

func calleeOf(s *Site) string {
	cls, m := s.Class, s.Method
	if cls == "" {
		cls = "?"
	}
	if m == "" {
		m = "?"
	}
	return cls + "." + m
}

func findingKey(rule string, s *Site, val *string) string {
	var b strings.Builder
	b.WriteString(rule)
	b.WriteByte(0)
	b.WriteString(s.File)
	b.WriteByte(0)
	if s.LineOK {
		b.WriteString(strconv.Itoa(s.Line))
	} else {
		b.WriteString("None")
	}
	b.WriteByte(0)
	// The column: two calls of one rule on one line are two findings, as
	// they are for OpenGrep.
	if s.ColOK {
		b.WriteString(strconv.Itoa(s.Col))
	}
	b.WriteByte(0)
	if val != nil {
		b.WriteString("v")
		b.WriteString(*val)
	}
	b.WriteByte(0)
	b.WriteString(s.Variant)
	return b.String()
}

// newFinding is the finding entry e makes at site s for hit h: the metadata
// filled from the call's groups and the hit's (fill "cf" or "raw"), the
// clauses it approximates, the focus argument. It is nil when a finding with
// the same key (findingKey) was already made: seen records the keys. The
// Java/Python pass (matchIndex) and the node pass (matchNodeIndex) share it.
func newFinding(e *Entry, s *Site, groups Groups, h taintHit, fill string, seen map[string]bool) *Finding {
	var val *string
	if e.Taint {
		v := h.Value
		val = &v
	}
	key := findingKey(e.RuleID, s, val)
	if seen[key] {
		return nil
	}
	seen[key] = true
	fg := fillGroups{}
	for k, v := range groups {
		v := v
		fg[k] = &v
	}
	for k, v := range h.Groups {
		fg[k] = v
	}
	var md *OMap
	if fill == "cf" {
		md = fillCF(e.Metadata.M, fg, s, e)
	} else {
		md = fillRaw(e.Metadata.M, fg, s, e)
	}
	approx := append([]string{}, e.DroppedClauses...)
	for _, c := range e.Constraints {
		if c.Kind != nil && *c.Kind == "not_assigned_string_literal" {
			approx = append(approx, c.Clause+" approximated")
		}
	}
	focusText := ""
	if e.FocusArg != nil && s.Params[*e.FocusArg] != nil {
		focusText = s.Params[*e.FocusArg].writtenText()
	}
	f := &Finding{
		FocusArg: e.FocusArg, FocusText: focusText,
		RuleID: e.RuleID, File: s.File, Line: s.Line, LineOK: s.LineOK, Col: s.Col, ColOK: s.ColOK,
		Taint: e.Taint, How: h.How, Value: val, Resolution: s.Resolution, SiteKind: s.Kind,
		Callee: calleeOf(s), Metadata: md, Approx: approx, Caller: s.Caller, EndCol: s.EndCol, EndLine: s.EndLine,
	}
	if e.FocusReceiver {
		goFocusReceiver(f, s)
	}
	if e.GoAddr && s.GoAddrCol > 0 {
		f.Col = s.GoAddrCol
	}
	return f
}

// goFocusReceiver reports a Go finding whose focus-metavariable is the
// receiver at the receiver's span (`key` of `key.Sign(m)`), read from the
// call's source; a call spanning lines, or one without source, keeps the
// call's span.
func goFocusReceiver(f *Finding, s *Site) {
	if !s.ColOK || s.EndCol <= s.Col || (s.EndLine != 0 && s.EndLine != s.Line) || len(s.Src) < s.EndCol-s.Col {
		return
	}
	if n, ok := goReceiverSpan(s.Src[:s.EndCol-s.Col], s.Method); ok {
		f.TerminalCol, f.TerminalEndCol = s.Col, s.EndCol
		f.EndCol, f.EndLine = s.Col+n, 0
		f.FocusText = s.Src[:n]
	}
}

// matchIndex is match.match over the compiled entries, with the method-regex entries tested once
// per distinct method name instead of once per site (same candidates, same order).
func matchIndex(entries []*Entry, fr *Frag, resolveParams bool, fill string) []*Finding { //nolint:gocognit,gocyclo // matchIndex is the port of match.py's index pass, one pass over the entries by kind
	byMethod := map[string][]*Entry{}
	var regexEntries, constants []*Entry
	for _, e := range entries {
		if e.Receiver == strConstant {
			constants = append(constants, e)
			continue
		}
		if e.Method != nil {
			byMethod[*e.Method] = append(byMethod[*e.Method], e)
		} else {
			regexEntries = append(regexEntries, e)
		}
	}
	regexFor := map[string][]*Entry{}
	var findings []*Finding
	seen := map[string]bool{}
	for _, s := range fr.Sites {
		rx, ok := regexFor[s.Method]
		if !ok {
			for _, e := range regexEntries {
				if e.methodMatch(s.Method) != nil {
					rx = append(rx, e)
				}
			}
			regexFor[s.Method] = rx
		}
		var cands []*Entry
		if s.Method != "" {
			cands = byMethod[s.Method]
		}
		for _, list := range [2][]*Entry{cands, rx} {
			for _, e := range list {
				groups := callMatches(e, s, fr)
				if groups == nil || !constraintsHold(e, s, groups, fr) {
					continue
				}
				if !insidesHold(e, s, fr) || notInsideHit(e.NotInside, s, fr) {
					continue
				}
				negated := false
				for _, n := range e.NotCalls {
					if callMatches(n, s, fr) != nil { // dict(n, constraints=[]): not_calls have no constraints
						negated = true
						break
					}
				}
				if negated {
					continue
				}
				var hits []taintHit
				if e.Taint && e.Flow != flowObject {
					hits = taintMatches(e, s, fr.Incoming, resolveParams)
				} else {
					how := "symbol"
					if len(e.Constraints) > 0 {
						how = strText
					}
					hits = []taintHit{{How: how}}
				}
				for _, h := range hits {
					if f := newFinding(e, s, groups, h, fill, seen); f != nil {
						findings = append(findings, f)
					}
				}
			}
		}
	}
	return append(findings, matchConstantEntries(constants, fr, seen)...)
}
