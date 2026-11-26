// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

// Python mode: the call sites of a Python fragment read in the shape the
// matcher reads Java sites (the PoC's pymatch.py normalisation, E2.7-py.9).
// A fragment whose scan_metadata names the python ecosystem is read this way;
// every other fragment is read as before.
//
//   - Callee: a target key `a.b.(C).m` is class `a.b.C`, method `m`; a class
//     instantiation `a.b.(C).<init>` is the call `a.b.C`, so class `a.b`,
//     method `C` (a card writes `call: a.b.C`; Python has no `new`); a module
//     function `a.b.f` is class `a.b`, method `f`. A `name_only` call (a
//     method on an untyped receiver, a local callable) has no class.
//   - Types compare exactly: the resolved class equals the card's dotted name,
//     or the receiver as written equals it once qualified through the file's
//     imports. No suffix reading (`notpyjwt.jose.jwt.decode` is no
//     `jwt.decode`), no receiverless or delegation reading (`Cipher(..)`
//     after a from-import is the call `...ciphers.Cipher`).
//   - Arguments: a positional argument is filed under its place among the
//     positional arguments, a keyword argument under its keyword (kwKey). The
//     arity is the number of arguments, keyword ones included.
//   - Text: a plain single-quoted literal reads double-quoted, redundant
//     parentheses around an argument are dropped, and each argument keeps a
//     second text qualified through the file's imports (Param.Qualified).

import (
	"iter"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/scanoss/reach/graphfrag"
)

const ecosystemPython = "python"

// kwBase is the first parameter index a keyword argument is filed under:
// far above any positional index.
const kwBase = 1 << 20

// kwIDs numbers keyword names (guarded by the matching lock).
var kwIDs = map[string]int{}

// kwKey is the parameter index of keyword argument name.
func kwKey(name string) int {
	id, ok := kwIDs[name]
	if !ok {
		id = kwBase + len(kwIDs)
		kwIDs[name] = id
	}
	return id
}

// pyCallee splits a Python function key into the class and method a card
// names: `a.b.(C).m` -> (a.b.C, m), `a.b.(C).<init>` -> (a.b, C), `a.b.f` ->
// (a.b, f). A chained call the contracts typed keeps an arity suffix
// (`_hashlib.(HASH).hexdigest#-1`), dropped.
func pyCallee(key string) (cls, method string) {
	if hash := strings.LastIndexByte(key, '#'); hash >= 0 {
		if _, err := strconv.Atoi(key[hash+1:]); err == nil {
			key = key[:hash]
		}
	}
	if owner, typ, m, ok := pyKeyParts(key); ok {
		if m == strInit {
			return owner, typ
		}
		return owner + "." + typ, m
	}
	if open := strings.LastIndex(key, ".("); open >= 0 {
		if closeAt := strings.Index(key[open:], ")."); closeAt > 0 {
			owner, typ, m := key[:open], key[open+2:open+closeAt], key[open+closeAt+2:]
			if m == strInit {
				return owner, typ
			}
			return owner + "." + typ, m
		}
	}
	dot := strings.LastIndexByte(key, '.')
	if dot < 0 {
		return "", key
	}
	return key[:dot], key[dot+1:]
}

// pyKeyParts splits `owner.(type).method` where the part in parentheses can
// be a receiver's source text holding parentheses and `).` itself
// (`app.(ec.Numbers(x, ec.P256()).public_key()).verify`): the owner is the
// dotted name before the first `.(`, the type runs to its matching `)`.
func pyKeyParts(key string) (owner, typ, method string, ok bool) { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	open := strings.Index(key, ".(")
	if open <= 0 {
		return "", "", "", false
	}
	for _, c := range key[:open] {
		if c != '.' && c != '_' && c != '<' && c != '>' && c != '-' && (('a' > c || c > 'z') && ('A' > c || c > 'Z') && ('0' > c || c > '9')) {
			return "", "", "", false
		}
	}
	depth := 0
	for i := open + 1; i < len(key); i++ {
		switch key[i] {
		case '"', '\'':
			i = literalEnd(key, i) - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if !strings.HasPrefix(key[i:], ").") || strings.ContainsAny(key[i+2:], "()") {
					return "", "", "", false
				}
				return key[:open], key[open+2 : i], key[i+2:], true
			}
		}
	}
	return "", "", "", false
}

// dq writes every plain single-quoted literal of an expression (no quote,
// backslash or newline inside) with double quotes, so the checks for a string
// literal (`"..."`) hold for Python.
func dq(text string) string {
	if !strings.Contains(text, "'") {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		c := text[i]
		if c != '"' && c != '\'' {
			b.WriteByte(c)
			i++
			continue
		}
		end := literalEnd(text, i)
		lit := text[i:end]
		if c == '\'' && end-i >= 2 && text[end-1] == '\'' && !strings.ContainsAny(lit[1:len(lit)-1], "\"\\\n") {
			lit = `"` + lit[1:len(lit)-1] + `"`
		}
		b.WriteString(lit)
		i = end
	}
	return b.String()
}

// literalEnd is the end of the string literal that opens at text[start]:
// after its closing quote, or the end of the text.
func literalEnd(text string, start int) int {
	quote := text[start]
	for i := start + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case quote:
			return i + 1
		}
	}
	return len(text)
}

// pyNames maps each name a file's imports bind to what it stands for:
// `import a.b as c` binds c to a.b, `from m import n as k` binds k to m.n
// (module-level bindings first, then those inside functions; the first
// binding of a name wins). `import a.b` binds a to itself and adds nothing,
// but as a first binding it still wins over a later one (`try: import ssl` /
// `except ImportError: import dns._no_ssl as ssl` keeps ssl as ssl).
func pyNames(imports []graphfrag.GraphFragmentImport) map[string]string { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	out := map[string]string{}
	itself := map[string]bool{}
	for _, local := range []bool{false, true} {
		for _, im := range imports {
			if im.Local != local || im.Name == "*" {
				continue
			}
			name, target := pyImportBinding(im)
			if name == "" {
				continue
			}
			if name == target {
				if _, seen := out[name]; !seen {
					itself[name] = true
				}
				continue
			}
			if _, seen := out[name]; !seen && !itself[name] {
				out[name] = target
			}
		}
	}
	return out
}

// pyImportBinding is the name an import binds and what it stands for:
// `import a.b as c` -> (c, a.b), `from m import n as k` -> (k, m.n),
// `import a.b` -> (a, a).
func pyImportBinding(im graphfrag.GraphFragmentImport) (name, target string) {
	name, target = im.Alias, im.Module
	if im.Name != "" {
		target = im.Module + "." + im.Name
		if name == "" {
			name = im.Name
		}
	} else if name == "" {
		name, _, _ = strings.Cut(im.Module, ".")
		target = name
	}
	return name, target
}

var pyToken = regexp2.MustCompile(`("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?<![\w.])([A-Za-z_]\w*)`, regexp2.None)

// qualify writes the leading name of each dotted reference of text (outside
// string literals) as what the file's imports bind it to:
// `AES.MODE_GCM` -> `Crypto.Cipher.AES.MODE_GCM` after `from Crypto.Cipher import AES`.
func qualify(text string, names map[string]string) string {
	if text == "" || len(names) == 0 {
		return text
	}
	out, err := pyToken.ReplaceFunc(text, func(m regexp2.Match) string {
		if g := m.GroupByNumber(1); g.Length > 0 {
			return g.String()
		}
		name := m.GroupByNumber(2).String()
		if q, ok := names[name]; ok {
			return q
		}
		return name
	}, -1, -1)
	if err != nil {
		return text
	}
	return out
}

// pyBoundLocally reports whether the calling function binds the leading
// name of a receiver that an import of the file binds too, so the name is
// a local or a parameter and not the module the import binds it to
// (`import rsa` + `def f(rsa): rsa.encrypt(..)`): the parser identified the
// receiver as a local object (site.ReceiverVar, which it sets for a bare
// receiver exactly when the function's own scope binds the name: a
// parameter, an assignment, a for, with or except target, a comprehension
// variable), or the name is a parameter of the function or a local
// assigned a call in it.
//
// Not in a module or class body (`<module>`, `<clinit>`), where an import
// and another binding of its name are one variable (`try: import rsa` /
// `except ImportError: rsa = None`), nor for a name an import inside the
// function binds. A name no import binds reads as written, as before.
func (fr *Frag) pyBoundLocally(caller, recv string, site *Site) bool {
	name, _, _ := strings.Cut(recv, ".")
	if name == "" || !fr.ImportNames[fr.CallerFile[caller]][name] || fr.LocalImports[caller][name] ||
		strings.HasSuffix(caller, ".<module>") || strings.HasSuffix(caller, ".<clinit>") {
		return false
	}
	if site != nil && site.ReceiverVar == name {
		return true
	}
	return slices.Contains(fr.Params[caller], name) || len(fr.VarSites[pairKey(caller, name)]) > 0
}

// pyFunctionNames are a Python fragment's parameter names by function, and
// the names an import written inside a function's lines binds, by function.
func pyFunctionNames(frag *FragmentJSON) (params map[string][]string, local, files map[string]map[string]bool) { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	params = make(map[string][]string, len(frag.Functions))
	local, files = map[string]map[string]bool{}, map[string]map[string]bool{}
	for file, imports := range frag.Imports {
		for _, im := range imports {
			if name := pyImportName(im); name != "" {
				if files[file] == nil {
					files[file] = map[string]bool{}
				}
				files[file][name] = true
			}
		}
	}
	for i := range frag.Functions {
		f := &frag.Functions[i]
		if len(f.ParameterNames) > 0 {
			params[f.Key] = f.ParameterNames
		}
		for _, im := range frag.Imports[f.FilePath] {
			name := pyImportName(im)
			if !im.Local || im.Line < f.StartLine || im.Line > f.EndLine || name == "" {
				continue
			}
			if local[f.Key] == nil {
				local[f.Key] = map[string]bool{}
			}
			local[f.Key][name] = true
		}
	}
	return params, local, files
}

// pyImportName is the name an import binds: its alias, the imported name,
// or the first segment of the module (`import a.b` binds a); "" for `*`.
func pyImportName(im graphfrag.GraphFragmentImport) string {
	switch {
	case im.Name == "*":
		return ""
	case im.Alias != "":
		return im.Alias
	case im.Name != "":
		return im.Name
	}
	name, _, _ := strings.Cut(im.Module, ".")
	return name
}

// qualifyIn qualifies text through the imports of caller's file.
func (fr *Frag) qualifyIn(caller, text string) string {
	return qualify(text, fr.Names[fr.CallerFile[caller]])
}

// pyNodes copies source nodes with their string values double-quoted.
func pyNodes(nodes []SourceNode) []SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]SourceNode, len(nodes))
	for i := range nodes {
		n := nodes[i]
		n.Value = dq(n.Value)
		if len(n.MayValues) > 0 {
			vals := make([]string, len(n.MayValues))
			for j, v := range n.MayValues {
				vals[j] = dq(v)
			}
			n.MayValues = vals
		}
		n.SourceNodes = pyNodes(n.SourceNodes)
		out[i] = n
	}
	return out
}

// pyParam is a Python argument as the matcher reads it (a copy).
func pyParam(p Param, names map[string]string) *Param {
	if p.ArgumentExpression != "" {
		p.ArgumentExpression = unwrap(pyStrip(dq(p.ArgumentExpression)))
	}
	p.ResolvedValue = dq(p.ResolvedValue)
	p.SourceNodes = pyNodes(p.SourceNodes)
	// An argument whose value the graph knows for certain reads as that
	// value, as if it were written in its place: a dispatch table read
	// whose key selects one entry (`TABLE["HS512"]`, `{...}[alg]` with alg
	// known), and a name every binding of which, or the branch it is used
	// in, fixes to one literal or constant (`alg = "sha256"`,
	// `variant = Type.ID`). A parameter, or a name that may hold anything
	// else, stays as written.
	if p.ResolvedValue != "" && (strings.HasSuffix(p.ArgumentExpression, "]") || pyFixedName(&p)) {
		p.Written, p.ArgumentExpression = p.ArgumentExpression, p.ResolvedValue
	}
	p.Qualified = qualify(p.ArgumentExpression, names)
	return &p
}

var pyName = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// pyFixedName reports an argument that is a bare name whose source is a
// VARIABLE of that name holding only fixed values (VALUE nodes, through
// VARIABLEs and str enum FIELDs): a local or module name bound to a literal
// or a constant, or one a branch fixes. A PARAMETER, a call result or a
// may-value anywhere under it leaves the name as written.
func pyFixedName(p *Param) bool {
	if !pyName.MatchString(p.ArgumentExpression) || len(p.SourceNodes) != 1 {
		return false
	}
	top := &p.SourceNodes[0]
	return top.Type == strVariable && top.Name == p.ArgumentExpression && pyOnlyValues(top.SourceNodes)
}

func pyOnlyValues(nodes []SourceNode) bool {
	if len(nodes) == 0 {
		return false
	}
	for i := range nodes {
		n := &nodes[i]
		switch {
		case len(n.MayValues) > 0:
			return false
		case n.Type == strValue:
		case (n.Type == strVariable || n.Type == strField) && pyOnlyValues(n.SourceNodes):
		default:
			return false
		}
	}
	return true
}

// pyMaxVariants bounds the sites one Python call is read as.
const pyMaxVariants = 8

// pyValueVariants reads a Python call with a bare-name argument that may
// hold one of a few values and nothing else (exhaustive may-values: every
// binding of the name, or the branch it is used in, writes a string
// literal; or the values a branch fixes, `if h in (hashes.SHA256,
// hashes.SHA512):`) as one site per value, each with that value in the
// argument's place, as a name fixed to one value reads (pyFixedName). nil
// when no argument is such a name, or the values of all of them would make
// more than pyMaxVariants sites. names are the file's imports, which
// qualify a value.
func pyValueVariants(s *Site, names map[string]string) []*Site {
	variants := []*Site{s}
	for _, idx := range s.ParamIdx {
		p := s.Params[idx]
		values := pyExhaustiveValues(p)
		if values == nil {
			continue
		}
		if len(variants)*len(values) > pyMaxVariants {
			return nil
		}
		next := make([]*Site, 0, len(variants)*len(values))
		for _, v := range variants {
			for _, value := range values {
				c := *v
				c.Params = maps.Clone(v.Params)
				cp := *p
				cp.Written, cp.ArgumentExpression, cp.ResolvedValue, cp.Qualified = p.ArgumentExpression, value, value, qualify(value, names)
				cp.SourceNodes = []SourceNode{{Type: strVariable, Name: p.ArgumentExpression, SourceNodes: []SourceNode{{Type: strValue, Value: value}}}}
				c.Params[idx] = &cp
				c.Variant = v.Variant + "\x00" + strconv.Itoa(idx) + "=" + value
				next = append(next, &c)
			}
		}
		variants = next
	}
	if len(variants) == 1 {
		return nil
	}
	return variants
}

// pyExhaustiveValues are the values a bare-name argument may hold when it
// holds no other value, two or more: its exhaustive may-values, or the
// VALUE nodes side by side under its VARIABLE; nil otherwise.
func pyExhaustiveValues(p *Param) []string {
	if !pyName.MatchString(p.ArgumentExpression) || len(p.SourceNodes) != 1 {
		return nil
	}
	top := &p.SourceNodes[0]
	if top.Type != strVariable || top.Name != p.ArgumentExpression {
		return nil
	}
	if len(top.MayValues) > 0 {
		if !top.MayValuesExhaustive || len(top.MayValues) < 2 || len(top.SourceNodes) > 0 {
			return nil
		}
		return top.MayValues
	}
	var values []string
	for i := range top.SourceNodes {
		n := &top.SourceNodes[i]
		if n.Type != strValue || n.Value == "" || len(n.MayValues) > 0 {
			return nil
		}
		if !slices.Contains(values, n.Value) {
			values = append(values, n.Value)
		}
	}
	if len(values) < 2 {
		return nil
	}
	return values
}

// pyParamMap files a Python call's arguments: positional ones by their place
// among the positional arguments, keyword ones by kwKey. It returns the
// arguments in call order and the number of positional ones.
// pyUnpassed: a parameter entry that carries only the callee's declared type
// (a Python internal edge lists the callee's annotated parameters the call
// does not pass, with no argument): no argument of the call.
func pyUnpassed(p *Param) bool {
	return p.ArgumentExpression == "" && p.VariableName == "" && p.ResolvedValue == "" && len(p.SourceNodes) == 0 &&
		p.Keyword == ""
}

func pyParamMap(c *CallSiteJSON, names map[string]string) (map[int]*Param, []int, int) {
	m := map[int]*Param{}
	var order []int
	positional := 0
	if c == nil {
		return m, order, 0
	}
	for i := range c.Parameters {
		if pyUnpassed(&c.Parameters[i]) {
			continue
		}
		p := pyParam(c.Parameters[i], names)
		idx := positional
		if p.Keyword != "" {
			idx = kwKey(p.Keyword)
		} else {
			positional++
		}
		if _, seen := m[idx]; !seen {
			order = append(order, idx)
		}
		m[idx] = p
	}
	return m, order, positional
}

// pySite reads a loaded site the Python way: callee from key, arguments by
// position or keyword.
func pySite(s *Site, key string, call *CallSiteJSON, names map[string]string) {
	s.Python = true
	cls, method := pyCallee(key)
	s.Class, s.Method = cls, method
	if s.Resolution == strNameOnly {
		s.Class = ""
	}
	s.Params, s.ParamIdx, s.Positional = pyParamMap(call, names)
	s.ParamOrder = s.ParamIdx
	s.Arity = len(s.ParamIdx)
}

// pyAlternativesByFile: per file, the other targets of each module-level name
// that the file's imports bind more than once to different targets
// (`try: from a import X` / `except ImportError: from b import X`), keyed by
// each target. The graph types a call through the first binding; OpenGrep
// reads the later one; either is the class the code runs with.
func pyAlternativesByFile(frag *FragmentJSON) map[string]map[string][]string { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	out := map[string]map[string][]string{}
	for file, imports := range frag.Imports {
		targets := map[string][]string{}
		for _, im := range imports {
			if im.Local || im.Name == "*" {
				continue
			}
			name, target := pyImportBinding(im)
			if name == "" || slices.Contains(targets[name], target) {
				continue
			}
			targets[name] = append(targets[name], target)
		}
		for _, ts := range targets {
			if len(ts) < 2 {
				continue
			}
			if out[file] == nil {
				out[file] = map[string][]string{}
			}
			for _, t := range ts {
				for _, other := range ts {
					if other != t {
						out[file][t] = append(out[file][t], other)
					}
				}
			}
		}
	}
	return out
}

// pyAlternativeNames: a dotted name rooted in one target of a name bound to
// several (pyAlternativesByFile), written with each other target.
func pyAlternativeNames(name string, alts map[string][]string) []string {
	if len(alts) == 0 || name == "" {
		return nil
	}
	var out []string
	for _, t := range slices.Sorted(maps.Keys(alts)) {
		rest, ok := strings.CutPrefix(name, t)
		if !ok || (rest != "" && rest[0] != '.') {
			continue
		}
		for _, other := range alts[t] {
			out = append(out, other+rest)
		}
	}
	return out
}

// pyImportAlternatives adds to the readings of a typed Python call one per
// other binding of the import its callee is named through: the same site with
// the callee's class written through that binding.
func pyImportAlternatives(sites []*Site, alts map[string][]string) []*Site {
	if len(alts) == 0 {
		return sites
	}
	out := sites
	for _, s := range sites {
		if !s.Python || s.Class == "" || s.Method == "" {
			continue
		}
		for _, full := range pyAlternativeNames(s.Class+"."+s.Method, alts) {
			v := *s
			v.Class = strings.TrimSuffix(full, "."+s.Method)
			out = append(out, &v)
		}
	}
	return out
}

// pyCallText is the callee as a call is written at the start of its source
// text: a dotted name followed by `(`.
var pyCallText = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\(`)

// pyWrittenCall reads a Python internal edge's call as written, which the
// edge does not record (an external call carries it as raw): Raw is the
// dotted callee written at the call when it ends with the method the edge
// reaches, so a pattern written without a receiver does not match
// `self.m(..)` or `super(C, cls).m(..)` and one written as `SHA512.new(..)`
// matches the call written so. An edge to `a.b.(C).<init>` whose written callee is not C, nor a name
// the file's imports bind to C, is a delegation (Site.PyDelegation): the
// graph links `super().__init__(..)`, `cls(..)` and an inherited `__init__`
// to C's, but the call instantiates no C; `cls(..)` does instantiate it (Raw
// "cls", which no pattern written without a receiver matches, see
// callMatchesOrig). Without source text nothing changes.
func pyWrittenCall(s *Site, calleeKey string, names map[string]string) {
	m := pyCallText.FindStringSubmatch(s.Src)
	if s.Src == "" {
		return
	}
	written, last := "", ""
	if m != nil {
		written = m[1]
		last = written[strings.LastIndexByte(written, '.')+1:]
	}
	if !strings.HasSuffix(calleeKey, ").<init>") {
		if written != "" && last == s.Method {
			s.Raw = written
		} else if i := strings.Index(s.Src, "."+s.Method+"("); i > 0 {
			// A method on a receiver that is no dotted name (`super(C,
			// cls).verify(..)`, `f(x).m(..)`): the text up to the method.
			s.Raw = s.Src[:i+1+len(s.Method)]
		}
		return
	}
	if written == "cls" {
		s.Raw = written // a classmethod instantiating its class
		return
	}
	if written != "" && last != s.Method { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		head, rest, _ := strings.Cut(written, ".")
		if target, ok := names[head]; ok {
			q := target
			if rest != "" {
				q += "." + rest
			}
			if q[strings.LastIndexByte(q, '.')+1:] == s.Method {
				last = s.Method
			}
		}
	}
	if written == "" || last != s.Method {
		s.PyDelegation = true
		return
	}
	s.Raw = written
}

// pySharedArguments gives an internal edge that records no argument the
// arguments of the call written at its position: a Python class
// instantiation is the call `a.b.C` (which carries them) and an edge to
// `a.b.(C).<init>` (which does not), as is a call of a re-exported name.
// The edge matches as the call written there, with its arguments: an edge
// to `C.__init__` is no call `C()` when `C(cptr, 1)` is written.
func pySharedArguments(sites []*Site) {
	type position struct {
		caller            string
		line, col, endCol int
	}
	written := map[position]*Site{}
	for _, s := range sites {
		if len(s.Params) > 0 && s.LineOK && s.ColOK {
			if at := (position{s.Caller, s.Line, s.Col, s.EndCol}); written[at] == nil {
				written[at] = s
			}
		}
	}
	for _, s := range sites {
		if len(s.Params) == 0 {
			s.ArgsFrom = written[position{s.Caller, s.Line, s.Col, s.EndCol}]
			if w := s.ArgsFrom; w != nil && s.Kind == "internal" && s.Arity == 0 {
				s.Params, s.ParamIdx, s.ParamOrder, s.Positional, s.Arity = w.Params, w.ParamIdx, w.ParamOrder, w.Positional, w.Arity
			}
		}
	}
}

// argIndex is the parameter a card's argument key names. Java: an integer,
// negative from the end. Python: an integer is a positional argument
// (negative from the last positional one), a name is a keyword argument, and
// "i|name" is the parameter passed at position i or as keyword name (the
// rules' `param[i|name]` selector). positional is the number of positional
// arguments of the call. A language with no keyword arguments reads "i|name"
// as position i, and a name as a keyword no argument of its calls is passed
// under: a card tree loaded whole runs every language's cards on its sites.
func argIndex(k any, arity, positional int, python bool) int {
	if s, ok := k.(string); ok {
		if pos, name, both := strings.Cut(s, "|"); both {
			i, err := strconv.Atoi(pos)
			if err != nil {
				panic("argument key " + s)
			}
			switch {
			case !python:
				k = int64(i)
			case i < positional:
				return i
			default:
				return kwKey(name)
			}
		} else if _, err := strconv.Atoi(s); err != nil {
			return kwKey(s)
		}
	}
	i := pyInt(k)
	if i < 0 {
		if python {
			return positional + i
		}
		return arity + i
	}
	return i
}

// pyCallArgs files the arguments of a call read from text (`f(a, k=v)`).
func pyCallArgs(args []string) (keys []int, texts []string, positional int) {
	for _, a := range args {
		if kw, value, ok := splitKeyword(a); ok {
			keys, texts = append(keys, kwKey(kw)), append(texts, value)
			continue
		}
		keys, texts = append(keys, positional), append(texts, a)
		positional++
	}
	return keys, texts, positional
}

var pyKeywordArg = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=([^=][\s\S]*)$`)

// splitKeyword reads `name=value` (not `name==value`).
func splitKeyword(arg string) (string, string, bool) {
	m := pyKeywordArg.FindStringSubmatch(arg)
	if m == nil {
		return "", "", false
	}
	return m[1], pyStrip(m[2]), true
}

// pyParsedCallee is the callee of a Python call read from text, qualified
// through the file's imports: `algorithms.AES(k)` -> (AES, ...ciphers.algorithms).
func pyParsedCallee(parsed *ParsedCall, qualified string) (method, cls string) {
	dot := strings.LastIndexByte(qualified, '.')
	if dot < 0 {
		return parsed.Method, ""
	}
	return parsed.Method, qualified[:dot]
}

// expandObjects rewrites every `object:` of a card's call patterns (a card
// format addition, cards-py/README.md in the PoC): the receiver is an object
// of a class, known because the fragment typed the receiver, or because it is
// a local assigned from one of the listed calls (the rules spell this
// `$X.m(...)` + `pattern-inside: $X = Factory(...) ...`):
//
//	{method: m, object: {type: T, from: [F, ...], via: v}, ...}
//	-> {any: [{call: T.m, ...}, {method: m, receiver: {via: v, from: {any: [{call: F}, ...]}}, ...}]}
//
// via defaults to var; an item of from may be a call pattern.
func expandObjects(v any) any { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = expandObjects(e)
		}
		return out
	case *OMap:
		node := &OMap{}
		for i, k := range x.Keys {
			node.Set(k, expandObjects(x.Vals[i]))
		}
		obj, ok := node.Get("object")
		if !ok {
			return node
		}
		o := mustMap(obj, "object")
		rest := func() *OMap {
			out := &OMap{}
			for i, k := range node.Keys {
				if k != any("object") && k != any("method") {
					out.Set(k, node.Vals[i])
				}
			}
			return out
		}
		var alts []any
		if types := o.GetOr(strType); pyTruthy(types) {
			var calls []any
			for _, t := range asList(types) {
				for _, m := range asList(node.GetOr("method")) {
					calls = append(calls, mustStr(t, "object type")+"."+mustStr(m, "method"))
				}
			}
			alt := rest()
			alt.Set("call", calls)
			alts = append(alts, alt)
		}
		if v := o.GetOr("from"); pyTruthy(v) {
			froms := asList(v)
			items := make([]any, len(froms))
			for i, f := range froms {
				if s, isStr := f.(string); isStr {
					items[i] = &OMap{Keys: []any{"call"}, Vals: []any{s}}
				} else {
					items[i] = f
				}
			}
			via := o.GetOr("via")
			if via == nil {
				via = "var"
			}
			alt := rest()
			alt.Set("method", node.GetOr("method"))
			alt.Set("receiver", &OMap{Keys: []any{"via", "from"}, Vals: []any{via, &OMap{Keys: []any{strAny}, Vals: []any{items}}}})
			alts = append(alts, alt)
		}
		return &OMap{Keys: []any{strAny}, Vals: []any{alts}}
	}
	return v
}

// encloses: site is written in the argument list of outer, a call of the
// same function: within outer's span, and an argument of outer holds site's
// call text.
func encloses(outer, site *Site) bool {
	if outer == site || outer.Caller != site.Caller || site.Raw == "" || !outer.contains(site) {
		return false
	}
	needle := norm(site.Raw) + "("
	for _, i := range outer.ParamIdx {
		if strings.Contains(norm(outer.Params[i].ArgumentExpression), needle) {
			return true
		}
	}
	return false
}

// insideCallOf: a call of the site's function whose argument list holds the
// site matches one of pats (card keys inside / not_inside).
func (fr *Frag) insideCallOf(site *Site, pats any, env Env) bool {
	for _, outer := range fr.ByCaller[site.Caller] {
		if !encloses(outer, site) {
			continue
		}
		for _, p := range asList(pats) {
			for range mCall(p, Expr{Site: outer, Caller: outer.Caller}, env, fr) {
				return true
			}
		}
	}
	return false
}

// flowsTo: the result of site is passed as argument `arg` of a call that
// matches `to` (card key flows_to): written there inline, or stored in a
// local that a later call passes there.
func (fr *Frag) flowsTo(site *Site, target *OMap, env Env) bool {
	key, to := target.GetOr("arg"), target.GetOr("to")
	for _, t := range fr.ByCaller[site.Caller] {
		if t == site {
			continue
		}
		p := t.Params[argIndex(key, t.Arity, t.Positional, fr.Python)]
		if p == nil {
			continue
		}
		text := p.ArgumentExpression
		stored := site.AssignedVar != "" && lessPos(site, t) && norm(text) == norm(site.AssignedVar) &&
			(!fr.Python || fr.pyReaches(site, site.AssignedVar, t.Line, t.Col))
		if !stored && (parseCall(text) == nil || fr.siteFor(site.Caller, text, t.Line, t.LineOK) != site) {
			continue
		}
		for range mCall(to, Expr{Site: t, Caller: t.Caller}, env, fr) {
			return true
		}
	}
	return false
}

func (fr *Frag) anyFlow(site *Site, targets any, env Env) bool {
	for _, t := range asList(targets) {
		if fr.flowsTo(site, mustMap(t, "flows_to"), env) {
			return true
		}
	}
	return false
}

// expandList is expandObjects over a card's with / without / optional items.
func expandList(items []any) []any {
	if items == nil {
		return nil
	}
	return as[[]any](expandObjects(items))
}

// pyConstMatch is constMatch for Python: the reference, qualified through the
// file's imports, is the card's constant, or a member of its owner whose name
// matches `member`. nil = no match.
func pyConstMatch(pat *OMap, text string) Groups {
	if !wordDotsMatch(text) || !strings.Contains(text, ".") {
		return nil
	}
	consts := asList(pat.GetOr("const"))
	if member, ok := pat.Get("member"); ok {
		i := strings.LastIndexByte(text, '.')
		owner, name := text[:i], text[i+1:]
		g := memoMatch(mustStr(member, "member"), name)
		if g == nil {
			return nil
		}
		for _, c := range consts {
			if mustStr(c, "const") == owner {
				return g
			}
		}
		return nil
	}
	for _, c := range consts {
		if mustStr(c, "const") == text {
			return Groups{}
		}
	}
	return nil
}

// typeNamed: a type name of the fragment (a declaration's, a cast's, an
// assigned local's) is the card's type. Python: exactly, once qualified
// through the file's imports. Java: as written or the card's suffix, and the
// card's qualified name for a short one with package evidence when evidence.
func (fr *Frag) typeNamed(want, have, caller string, evidence bool) bool {
	if fr.Python {
		return have != "" && fr.qualifyIn(caller, have) == want
	}
	if evidence {
		return nameOK(want, have, fr, caller, true)
	}
	return nameOK(want, have, nil, "", false)
}

// comparisonRef: a constant reference in this position kind is read, not
// passed on, so it is reported under the comparison policy (reportComparison):
// == / !=, equals, a case label, and for Python an `in` test (an operand, or
// an element of the container tested), unless Membership is ComparisonsAll.
// A dict entry, like a list / tuple / set element (array), is a table entry:
// always reported, as a Java array or initializer entry is (owner decision,
// E2.7-py.9). Options.PyMembership set to ComparisonsAll reports every `in`
// operand too, for debugging.
func (fr *Frag) comparisonRef(context string) bool {
	if comparisonContext(context) {
		return true
	}
	return fr.Python && context == "in" && fr.Membership != ComparisonsAll
}

// loadStores makes a site per attribute store. Python writes an attribute
// with an assignment, Ruby with a setter call and C# with a property write,
// and a rule says the same thing about any of them: the attribute, the
// operator and the value written.
func loadStores(frag *FragmentJSON, names map[string]map[string]string, ruby, csharp bool, usings map[string][]string) []*Site {
	out := make([]*Site, 0, len(frag.AttributeStores))
	for i := range frag.AttributeStores {
		st := &frag.AttributeStores[i]
		if st.Function < 0 || st.Function >= len(frag.Functions) {
			continue
		}
		fn := &frag.Functions[st.Function]
		value := operandParam(&st.Value) // a parameter always encodes
		out = append(out, &Site{
			ID: -1, File: fn.FilePath, Line: st.Line, LineOK: true, Caller: fn.Key, CallerPackage: fn.Package,
			Kind: "store", Col: st.StartCol, ColOK: true, EndCol: st.EndCol, EndLine: st.EndLine,
			Python: !ruby && !csharp, Ruby: ruby, CSharp: csharp, CSharpUsings: usings[fn.FilePath],
			ReceiverVar: st.Receiver, Method: st.Attribute, RefContext: st.Operator, Operand: pyParam(*value, names[fn.FilePath]),
		})
	}
	return out
}

// storeEnvs matches a store card's pattern against a store: the attribute
// (one name or a list), the operator (`=`, `|=`, ...; any when not given),
// the receiver and the value (value patterns).
func storeEnvs(pat *OMap, st *Site, fr *Frag) iter.Seq[Env] {
	return func(yield func(Env) bool) {
		if !listHas(asList(pat.GetOr("attribute")), st.Method) {
			return
		}
		if op, ok := pat.Get("operator"); ok && !listHas(asList(op), st.RefContext) {
			return
		}
		envs := []Env{{}}
		if v, ok := pat.Get("receiver"); ok {
			recv := Val{Text: st.ReceiverVar, HasText: st.ReceiverVar != "", Caller: st.Caller, Line: st.Line, LineOK: true, Col: st.Col}
			var nxt []Env
			for _, e := range envs {
				nxt = append(nxt, mValue(v, recv, e, fr)...)
			}
			envs = nxt
		}
		if v, ok := pat.Get("value"); ok {
			val := Val{
				Text: st.Operand.ArgumentExpression, HasText: st.Operand.ArgumentExpression != "", Param: st.Operand,
				Caller: st.Caller, Line: st.Line, LineOK: true,
			}
			var nxt []Env
			for _, e := range envs {
				nxt = append(nxt, mValue(v, val, e, fr)...)
			}
			envs = nxt
		}
		for _, e := range envs {
			if !yield(e) {
				return
			}
		}
	}
}

// attributeOrigins: the calls a Python attribute `recv.attr` is assigned
// from in the function (`b.c = Fernet(k)`, an attribute store whose value is
// a call), as call expressions (originExprs, via var).
func (fr *Frag) attributeOrigins(caller, text string) []Expr {
	dot := strings.LastIndexByte(text, '.')
	recv, attr := text[:dot], text[dot+1:]
	var out []Expr
	for _, st := range fr.StoresByCaller[caller] {
		if st.ReceiverVar != recv || st.Method != attr || st.RefContext != "=" {
			continue // a value that is no call matches no call pattern
		}
		value := st.Operand.ArgumentExpression
		out = append(out, Expr{Site: fr.siteFor(caller, value, st.Line, true), Text: value, Caller: caller, Assigned: text})
	}
	return out
}

// pyBinding is a statement binding a local (graph-fragment local_bindings):
// where it starts, where the name holds the new value, the end of the block
// that always runs it (0: none) and the start of the outermost loop around
// it (0: none).
type pyBinding struct {
	line, col, effLine, effCol, blockLine, blockCol, loopLine, loopCol int
}

// pyElement is a call site whose value a tuple pattern unpacks, and the
// element a local holds (Frag.Unpacked).
type pyElement struct {
	site    *Site
	element int
}

// pyUnpacked indexes, by (function, name), the call sites whose value a
// tuple or list pattern unpacks into the local (local_bindings with an
// element): the site written at the binding's value position, the
// outermost one when calls of a chain start there.
func pyUnpacked(frag *FragmentJSON, byCaller map[string][]*Site) map[string][]pyElement { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	out := map[string][]pyElement{}
	for _, b := range frag.LocalBindings {
		if !b.Unpacked || b.Function < 0 || b.Function >= len(frag.Functions) {
			continue
		}
		caller := frag.Functions[b.Function].Key
		var at []*Site
		for _, s := range byCaller[caller] {
			if !s.LineOK || !s.ColOK || s.Line != b.ValueLine || s.Col != b.ValueCol || s.Kind == "store" {
				continue
			}
			if len(at) > 0 && posBefore(at[0].EndLine, at[0].EndCol, s.EndLine, s.EndCol) {
				at = at[:0] // an outer call of the chain
			}
			if len(at) == 0 || !posBefore(s.EndLine, s.EndCol, at[0].EndLine, at[0].EndCol) {
				at = append(at, s)
			}
		}
		k := pairKey(caller, b.Name)
		for _, s := range at {
			out[k] = append(out[k], pyElement{s, b.Element})
		}
	}
	return out
}

// pyBindings indexes a fragment's local bindings by (function, name).
func pyBindings(frag *FragmentJSON) map[string][]pyBinding {
	out := map[string][]pyBinding{}
	for _, b := range frag.LocalBindings {
		if b.Function < 0 || b.Function >= len(frag.Functions) {
			continue
		}
		k := pairKey(frag.Functions[b.Function].Key, b.Name)
		out[k] = append(out[k], pyBinding{b.Line, b.Col, b.EffectLine, b.EffectCol, b.BlockEndLine, b.BlockEndCol, b.LoopLine, b.LoopCol})
	}
	return out
}

func posBefore(line, col, line2, col2 int) bool {
	return line < line2 || line == line2 && col < col2
}

// pyReaches reports whether the call site d, assigned to local name, may be
// the value name holds where it is used (line, col of d's function), from
// the function's local bindings (reaching definitions over straight-line
// code and branches, conservative): d's own binding is the statement that
// holds the call. A use before that binding takes effect reads it only on
// a later iteration of a loop around both. A later use reads it unless
// another binding of name takes effect between the two in a block that
// holds the use (that binding runs on every path to the use): bindings in
// another branch leave both values, the union of the reaching ones. With no
// binding recorded for d (a name bound once, a binding the producer does
// not place, an older fragment) every assignment reaches, as before.
func (fr *Frag) pyReaches(d *Site, name string, line, col int) bool { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	bs := fr.Bindings[pairKey(d.Caller, name)]
	if len(bs) == 0 || !d.LineOK || line == 0 {
		return true
	}
	own := -1
	for i, b := range bs { // sorted by start: the innermost statement wins
		if !posBefore(d.Line, d.Col, b.line, b.col) && posBefore(d.Line, d.Col, b.effLine, b.effCol) {
			own = i
		}
	}
	if own < 0 {
		return true
	}
	db := bs[own]
	if posBefore(line, col, db.effLine, db.effCol) {
		return db.loopLine != 0 && !posBefore(line, col, db.loopLine, db.loopCol)
	}
	for i, k := range bs {
		if i != own && posBefore(db.effLine, db.effCol, k.effLine, k.effCol) && !posBefore(line, col, k.effLine, k.effCol) &&
			k.blockLine != 0 && posBefore(line, col, k.blockLine, k.blockCol) {
			return false
		}
	}
	return true
}

// parameterOrigins: when val is a parameter of its function that no
// binding of the body replaces before the use, the origins of the argument
// each caller in the same file passes for it (E2.7-py.14b gap 5), read in
// the caller's function with the same via: `def sign_with(acct, t):
// acct.sign_message(t)` called as `sign_with(Account.from_key(k), t)` has
// the origin Account.from_key(k). OpenGrep's taint follows an argument into
// a function of the same file; a caller in another file is not read.
func (fr *Frag) parameterOrigins(val Val, via []any, deep bool, depth int) []Expr {
	args, _ := fr.parameterArgs(val)
	out := make([]Expr, 0, len(args))
	for _, arg := range args {
		out = append(out, originExprsAt(arg, via, deep, fr, depth+1)...)
	}
	return out
}

// parameterArgs is the argument each same-file internal caller passes for
// the parameter val names (none when val is not a parameter of its function,
// or the body rebinds it before the use). A caller that passes nothing for it
// (the default) or spreads `*args` is left out, and every is then false.
func (fr *Frag) parameterArgs(val Val) (args []Val, every bool) {
	idx := slices.Index(fr.Params[val.Caller], val.Text)
	if idx < 0 || !fr.pyParamReaches(val.Caller, val.Text, val.Line, val.Col) {
		return nil, false
	}
	n := SourceNode{Type: srcParameter, Name: val.Text, ParameterIndex: &idx}
	file := fr.CallerFile[val.Caller]
	every = true
	for _, cs := range fr.Incoming[val.Caller] {
		if cs.File != file {
			continue
		}
		cp := callerArgument(cs, &n)
		if cp == nil || cp.ArgumentExpression == "" || strings.HasPrefix(cp.ArgumentExpression, "*") {
			every = false
			continue
		}
		args = append(args, Val{Text: cp.ArgumentExpression, HasText: true, Param: cp, Caller: cs.Caller, Line: cs.Line, LineOK: cs.LineOK, Col: cs.Col})
	}
	return args, every
}

// pyParamReaches reports whether the value a caller passes for parameter
// name may be the one it holds at a use (line, col): no binding of the body
// takes effect before the use in a block that holds it.
func (fr *Frag) pyParamReaches(caller, name string, line, col int) bool {
	for _, k := range fr.Bindings[pairKey(caller, name)] {
		if line != 0 && k.blockLine != 0 && !posBefore(line, col, k.effLine, k.effCol) && posBefore(line, col, k.blockLine, k.blockCol) {
			return false
		}
	}
	return true
}
