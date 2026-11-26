package cardmatch

// Card format v2 (CARDS.md) and its matcher: a port of match2.py's pattern section (m_value,
// origin_exprs, m_call, related, solve, card_envs), fill, load_cards and match_cards.
//
// Python generators are mirrored with iter.Seq where the Python code is lazy (m_call, related,
// solve, card_envs), so that "first environment that ..." and any(...) stop at the same point;
// m_value is eager per key in Python (lists), and is eager here too. Patterns stay as the ordered
// YAML maps (*OMap): m_value walks a value pattern's keys in document order.

import (
	"fmt"
	"iter"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Env maps `$VAR` to a local variable name and plain names to metadata values. Immutable: every
// extension copies. pyNone stands for a None value (bind_method of a call with no method name).
type Env map[string]string

const pyNone = "\x00None"

// keyDeep is the value-pattern key that follows an origin through calls.
const keyDeep = "deep"

func (e Env) with(kv ...string) Env {
	out := make(Env, len(e))
	for k, v := range e {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func (e Env) withGroups(g Groups) Env {
	if len(g) == 0 {
		return e.with()
	}
	out := e.with()
	for k, v := range g {
		out[k] = v
	}
	return out
}

func pcreToPy(rx string) string { return rx } // (?<n>...) is native in regexp2; pyToNet handles (?P<n>

var (
	callKeys = setOf("call", "new", "super", "method", "method_regex", strType, "arity", "args", "any_arg", "receiver", "assigned",
		"stored", "assigned_type", "cast", "bind_method", "not", "when", "min_count", strAny, "inside", "not_inside", "flows_to",
		"element")
	valueKeys = setOf("var", "bind", "regex", strTaint, "resolves", strLiteral, "literal_in", "string_var", "init_search", "string", "number", "const", "member", strType, "from", "via", keyDeep, "not", strAny)
	cardKeys  = setOf("rule", "match", strConstant, "declaration", "store", keyRustCard, "not_in", "caller_type", "with", "without", "optional", "metadata", "lossy", "note")
	declKeys  = setOf(strType, "init")
	storeKeys = setOf("attribute", "operator", "receiver", "value")
	constKeys = setOf("const", "member", "at")
)

// Patterns already checked for unknown keys (Python checks on every call; the answer is fixed).
var validCall, validValue = map[*OMap]bool{}, map[*OMap]bool{}

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func unknownKeys(m *OMap, allowed map[string]bool) []string {
	var out []string
	for _, k := range m.Keys {
		s, ok := k.(string)
		if !ok || !allowed[s] {
			out = append(out, pyRepr(k))
		}
	}
	sort.Strings(out)
	return out
}

func mustMap(v any, what string) *OMap {
	m, ok := v.(*OMap)
	if !ok {
		panic(fmt.Sprintf("%s: expected a mapping, got %s", what, pyRepr(v)))
	}
	return m
}

func mustStr(v any, what string) string {
	s, ok := v.(string)
	if !ok {
		panic(fmt.Sprintf("%s: expected a string, got %s", what, pyRepr(v)))
	}
	return s
}

// --- type and name comparison --------------------------------------------------------------------

// typeOK: a card type matches a resolved class the way match.py does (equal, or the card gives a
// suffix), or an unresolved class as written in the source with package evidence.
func typeOK(want, have string, fr *Frag, caller string, useFr bool) bool {
	if have == "" {
		return false
	}
	if have == want || strings.HasSuffix(have, "."+want) {
		return true
	}
	if fr != nil && fr.CSharp {
		return csharpNameMatch(want, have, fr, caller)
	}
	first, _ := utf8.DecodeRuneInString(have)
	return unicode.IsUpper(first) && strings.HasSuffix(want, "."+have) && (!useFr || fr.uses(caller, want))
}

// nameOK: a name as written in the source against the card's name; equal, or one is a dotted
// suffix of the other (the short-name reading needs package evidence when fr is given).
func nameOK(want, text string, fr *Frag, caller string, useFr bool) bool {
	if text == "" {
		return false
	}
	if text == want || strings.HasSuffix(text, "."+want) {
		return true
	}
	if fr != nil && fr.CSharp {
		return csharpNameMatch(want, text, fr, caller)
	}
	return strings.HasSuffix(want, "."+text) && (!useFr || fr.uses(caller, want))
}

// --- values --------------------------------------------------------------------------------------

// Val is a value a value pattern is matched against: {text, param?, caller, line}.
type Val struct {
	Text    string
	HasText bool
	Param   *Param // nil: no param (Python `val.get("param") or {}`)
	Caller  string
	Line    int
	LineOK  bool
	// Col is where the value is used on Line (the call's start), 0 when
	// unknown (read as the start of the line).
	Col int
}

// Expr is a call expression a call pattern is matched against: {site?, text?, caller, assigned?}.
type Expr struct {
	Site     *Site
	Text     string // "" = None
	Caller   string
	Assigned string // "" = None
	// Element is 1 + the element of the call's value Assigned holds when a
	// tuple pattern unpacks it (`pub, priv = rsa.newkeys(..)`: priv is
	// element 1, Element 2); 0 when Assigned holds the value itself.
	Element int
}

// unify binds `$VAR` to a name (normalised), or checks it against the earlier binding.
func unify(env Env, v, name string) (Env, bool) {
	name = norm(name)
	if name == "" {
		return nil, false
	}
	if old, ok := env[v]; ok && old != name {
		return nil, false
	}
	return env.with(v, name), true
}

// metavarValue is match2.metavar_value: the constant a name resolves to, else the text.
func metavarValue(val Val) string {
	var resolved string
	if val.Param != nil {
		resolved = val.Param.ResolvedValue
	}
	if identMatch(val.Text) && resolved != "" && reMatchOK(`^(".*"|-?\d+[lL]?)$`, resolved) {
		return resolved
	}
	return val.Text
}

var numberCondRx = `^\s*(%\s*(\d+)\s*)?(>=|<=|==|>|<)\s*(-?\d+)\s*$`

func bigOf(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("int(" + s + ")")
	}
	return n
}

// numberOK is match2.number_ok: ">0", "<=512", "%8==0".
func numberOK(n *big.Int, cond string) bool {
	g, ok, hit := reMatchNumbered(numberCondRx, cond)
	if !hit {
		panic("number condition " + cond) // Python: AttributeError on None.group
	}
	if ok[2] {
		n = new(big.Int).Mod(n, bigOf(g[2])) // Python % with a positive divisor
	}
	b := bigOf(g[4])
	c := n.Cmp(b)
	switch g[3] {
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "==":
		return c == 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	}
	return false
}

// memoMatch caches re.match results for patterns tested against a small set of names (member
// names of constants, method names). The cached Groups are never mutated (withGroups copies).
var memberMemo = map[string]map[string]Groups{}

func memoMatch(rx, text string) Groups {
	m := memberMemo[rx]
	if m == nil {
		m = map[string]Groups{}
		memberMemo[rx] = m
	}
	if g, ok := m[text]; ok {
		return g
	}
	g := reMatch(rx, text)
	m[text] = g
	return g
}

// constAt: a constant card's `at` (a position kind or a list of them:
// arg, array, dict, init, assign, return, compare, in, case, other) admits a
// reference at position kind context; a card without `at` admits any. A
// constant written as an argument of a call with no reference of its own
// is at "arg".
func constAt(pat *OMap, context string) bool {
	at, ok := pat.Get("at")
	if !ok {
		return true
	}
	return listHas(asList(at), context)
}

// constMatch is match2.const_match: `const` is a qualified constant, or with `member` the owner
// whose member name must match the regex. nil = no match.
func constMatch(pat *OMap, text string, fr *Frag, caller string) Groups {
	if fr.Python {
		return pyConstMatch(pat, norm(fr.qualifyIn(caller, norm(text))))
	}
	if fr.Go {
		return goConstMatch(pat, norm(text))
	}
	text = norm(text)
	if !wordDotsMatch(text) || !strings.Contains(text, ".") {
		return nil
	}
	consts := asList(pat.GetOr("const"))
	if member, ok := pat.Get("member"); ok {
		i := strings.LastIndexByte(text, '.')
		owner, name := text[:i], text[i+1:]
		g := memoMatch(pcreToPy(mustStr(member, "member")), name)
		if g == nil {
			return nil
		}
		for _, c := range consts {
			if nameOK(mustStr(c, "const"), owner, fr, caller, true) {
				return g
			}
		}
		return nil
	}
	for _, c := range consts {
		cs := mustStr(c, "const")
		if strings.Contains(cs, ".") && nameOK(cs, text, fr, caller, true) {
			return Groups{}
		}
	}
	return nil
}

var literalRx = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

func holdsStringLiteral(p *Param) bool {
	return strings.HasPrefix(p.ResolvedValue, `"`) || startsWithQuoteValueChild(p.SourceNodes)
}

func firstIsDigit(s string) bool {
	for _, r := range s {
		return unicode.IsDigit(r)
	}
	return false
}

var varShorthand = map[string]*OMap{}

// mValue is match2.m_value: match a value pattern against a value; returns the environments.
func mValue(patAny any, val Val, env Env, fr *Frag) []Env { //nolint:funlen,gocognit,gocyclo // mValue is the port of match2.m_value, one case per value-card key; the cases share the environment it threads
	var pat *OMap
	if s, ok := patAny.(string); ok {
		pat = varShorthand[s]
		if pat == nil {
			pat = &OMap{Keys: []any{"var"}, Vals: []any{s}}
			varShorthand[s] = pat
		}
	} else {
		pat = mustMap(patAny, "value pattern")
	}
	if !validValue[pat] {
		if unk := unknownKeys(pat, valueKeys); len(unk) > 0 {
			panic(fmt.Sprintf("unknown value pattern key(s): %v", unk))
		}
		validValue[pat] = true
	}
	if !val.HasText {
		return nil
	}
	text, p := val.Text, val.Param
	pEmpty := &Param{}
	if p == nil {
		p = pEmpty
	}
	envs := []Env{env}
	for ki, kAny := range pat.Keys {
		key := as[string](kAny)
		pv := pat.Vals[ki]
		if key == "via" || key == keyDeep || key == "member" {
			continue
		}
		var nxt []Env
		for _, e := range envs {
			switch key {
			case "var":
				if u, ok := unify(e, mustStr(pv, "var"), text); ok {
					nxt = append(nxt, u)
				}
			case "bind":
				nxt = append(nxt, e.with(strings.TrimLeft(mustStr(pv, "bind"), "$"), metavarValue(val)))
			case "regex":
				if g := memoMatch(pcreToPy(mustStr(pv, "regex")), text); g != nil {
					nxt = append(nxt, e.withGroups(g))
				}
			case strTaint, "resolves":
				var cands []valueHow
				if val.Param != nil {
					cands = localValues(val.Param)
					if fr.ResolveParams {
						cands = append(cands, paramValues(val.Caller, fr.CallerFile[val.Caller], val.Param, fr.Incoming, 0)...)
					}
				} else {
					cands = []valueHow{{"direct", text}}
				}
			cand:
				for _, c := range cands {
					for _, rx := range asList(pv) {
						if g := reMatch(pcreToPy(mustStr(rx, key)), c.Value); g != nil {
							nxt = append(nxt, e.withGroups(g).with("__value", c.Value))
							break cand
						}
					}
				}
			case "literal_in":
				lits := literalRx.FindAllString(text, -1)
				if val.Param != nil {
					for _, lv := range localValues(val.Param) {
						if strings.HasPrefix(lv.Value, `"`) {
							lits = append(lits, lv.Value)
						}
					}
				}
				for _, lit := range lits {
					var hit Groups
					for _, rx := range asList(pv) {
						if g := reMatch(pcreToPy(mustStr(rx, key)), lit); g != nil {
							hit = g
							break
						}
					}
					if hit != nil {
						nxt = append(nxt, e.with("__value", lit).withGroups(hit))
						break
					}
				}
			case strLiteral:
				for _, lit := range asList(pv) {
					l := norm(pyStr(lit))
					if l == norm(text) || l == norm(p.ResolvedValue) {
						nxt = append(nxt, e)
						break
					}
				}
			case "string":
				isStr := strings.HasPrefix(text, `"`) || strings.HasPrefix(p.ResolvedValue, `"`)
				if isStr == pyTruthy(pv) {
					nxt = append(nxt, e)
				}
			case "string_var":
				holds := wordDotsMatch(text) && !firstIsDigit(text) && holdsStringLiteral(p)
				if holds == pyTruthy(pv) {
					nxt = append(nxt, e)
				}
			case "number":
				for _, cand := range []string{text, p.ResolvedValue} {
					g, ok, hit := reMatchNumbered(`^(-?\d[\d_]*)[lL]?$`, cand)
					if !hit || !ok[1] {
						continue
					}
					n := bigOf(strings.ReplaceAll(g[1], "_", ""))
					all := true
					for _, c := range asList(pv) {
						if !numberOK(n, mustStr(c, "number")) {
							all = false
							break
						}
					}
					if all {
						nxt = append(nxt, e)
					}
					break
				}
			case "init_search":
				k := pairKey(val.Caller, text)
				texts := map[string]bool{}
				for t := range fr.VarInit[k] {
					texts[t] = true
				}
				for _, s := range fr.VarSites[k] {
					parts := make([]string, len(s.ParamIdx))
					for j, i := range s.ParamIdx {
						parts[j] = s.Params[i].ArgumentExpression
					}
					texts[s.Raw+"("+strings.Join(parts, ",")+")"] = true
				}
				for _, t := range sortedKeys(texts) {
					if g := reSearch(pcreToPy(mustStr(pv, key)), t); g != nil {
						nxt = append(nxt, e.withGroups(g))
						break
					}
				}
			case "const":
				if fr.Go {
					text = fr.goQualifiedRef(val, text)
				}
				if g := constMatch(pat, text, fr, val.Caller); g != nil {
					nxt = append(nxt, e.withGroups(g))
				}
			case strType:
				var have string
				if val.Param != nil && val.Param.VariableName != "" {
					have = val.Param.Type
				} else {
					have = fr.VarType[pairKey(val.Caller, text)]
				}
				if identMatch(text) && have != "" {
					for _, t := range asList(pv) {
						if nameOK(mustStr(t, strType), have, nil, "", false) {
							nxt = append(nxt, e)
							break
						}
					}
				}
			case "from":
				via := asList(pat.GetOr("via"))
				if !pyTruthy(pat.GetOr("via")) {
					via = []any{"chain", "var"}
				}
				if fr.negated {
					nxt = append(nxt, mustFrom(pv, val, via, pyTruthy(pat.GetOr(keyDeep)), e, fr, 0)...)
					break
				}
				for _, ex := range originExprs(val, via, pyTruthy(pat.GetOr(keyDeep)), fr) {
					for x := range mCall(pv, ex, e, fr) {
						nxt = append(nxt, x)
					}
				}
			case "not":
				found := false
				fr.negated = !fr.negated
				for _, neg := range asList(pv) {
					if len(mValue(neg, val, e, fr)) > 0 {
						found = true
						break
					}
				}
				fr.negated = !fr.negated
				if !found {
					nxt = append(nxt, e)
				}
			case strAny:
				for _, alt := range as[[]any](pv) {
					nxt = append(nxt, mValue(alt, val, e, fr)...)
				}
			}
		}
		envs = nxt
		if len(envs) == 0 {
			return nil
		}
	}
	return envs
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func listHas(l []any, s string) bool {
	for _, x := range l {
		if x == any(s) {
			return true
		}
	}
	return false
}

// originExprs: call expressions a value comes from (the value itself when it is a call: chain; the
// calls assigned to it when it is a local: var). With deep, also every earlier link of a chain.
func originExprs(val Val, via []any, deep bool, fr *Frag) []Expr {
	return originExprsAt(val, via, deep, fr, 0)
}

// originExprsAt is originExprs depth parameters away from the use (Python:
// a parameter's origins are those of the arguments its same-file callers
// pass, up to maxDepth callers, as py.11 follows literals).
func originExprsAt(val Val, via []any, deep bool, fr *Frag, depth int) []Expr {
	return originExprsOf(val, via, deep, fr, depth, true)
}

// mustFrom is a `from` read inside a `not`: the value's own origins (a call
// written in place, the calls assigned to a local) match as in originExprs,
// but a Python parameter matches only when each same-file caller passes a
// value that matches in turn (and every one of them passes it). `def lock(key, iv): modes.CBC(iv)` called with
// `os.urandom(16)` by one caller and a literal by another is not excluded by
// `not: {via: var, from: os.urandom}`; called with draws only, it is.
func mustFrom(pv any, val Val, via []any, deep bool, e Env, fr *Frag, depth int) []Env {
	var out []Env
	for _, ex := range originExprsOf(val, via, deep, fr, depth, false) {
		for x := range mCall(pv, ex, e, fr) {
			out = append(out, x)
		}
	}
	if len(out) > 0 || !listHas(via, "var") || !fr.Python || !fr.ResolveParams || depth >= maxDepth || !identMatch(val.Text) {
		return out
	}
	args, every := fr.parameterArgs(val)
	if !every {
		return nil // a caller passes the default or spreads *args
	}
	for _, arg := range args {
		m := mustFrom(pv, arg, via, deep, e, fr, depth+1)
		if len(m) == 0 {
			return nil
		}
		out = append(out, m...)
	}
	return out
}

func originExprsOf(val Val, via []any, deep bool, fr *Frag, depth int, params bool) []Expr { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	text, caller := val.Text, val.Caller
	var out []Expr
	if listHas(via, "var") && fr.Python && strings.Contains(text, ".") && wordDotsMatch(text) {
		out = append(out, fr.attributeOrigins(caller, text)...)
	}
	if listHas(via, "var") && (identMatch(text) || fr.Python && wordDotsMatch(text)) {
		k := pairKey(caller, text)
		seen := map[string]bool{}
		for _, s := range fr.VarSites[k] {
			seen[norm(s.Raw)] = true
			if fr.Python && val.LineOK && !fr.pyReaches(s, text, val.Line, val.Col) {
				continue // another assignment of the local is the one the use reads
			}
			out = append(out, Expr{Site: s, Caller: caller, Assigned: text})
		}
		for _, el := range fr.Unpacked[k] {
			if !val.LineOK || fr.pyReaches(el.site, text, val.Line, val.Col) {
				out = append(out, Expr{Site: el.site, Caller: caller, Assigned: text, Element: el.element + 1})
			}
		}
		for _, init := range sortedKeys(fr.VarInit[k]) {
			call := parseCall(init)
			if call != nil && !seen[norm(call.Prefix)] {
				out = append(out, Expr{Site: fr.siteFor(caller, init, 0, false), Text: init, Caller: caller, Assigned: text})
			}
		}
		if params && fr.Python && fr.ResolveParams && depth < maxDepth && identMatch(text) {
			out = append(out, fr.parameterOrigins(val, via, deep, depth)...)
		}
	}
	if listHas(via, "chain") && parseCall(text) != nil {
		out = append(out, Expr{Site: fr.siteFor(caller, text, val.Line, val.LineOK), Text: text, Caller: caller})
	}
	if deep { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		todo := append([]Expr(nil), out...)
		for len(todo) > 0 {
			ex := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			var recv string
			if ex.Site != nil {
				recv = fr.receiverText(ex.Site)
			} else if c := parseCall(ex.Text); c != nil {
				recv = c.Receiver
			}
			if recv != "" && parseCall(recv) != nil {
				line, lineOK := 0, false
				if ex.Site != nil {
					line, lineOK = ex.Site.Line, ex.Site.LineOK
				}
				inner := Expr{Site: fr.siteFor(caller, recv, line, lineOK), Text: recv, Caller: caller}
				out = append(out, inner)
				todo = append(todo, inner)
			}
		}
	}
	return out
}

// target is one (type, method, method_regex) alternative of a call pattern.
type target struct {
	Type   string // "" = None
	Method any    // nil = None; otherwise the YAML value (a string for every real card)
	Rx     string
	HasRx  bool
}

var targetCache = map[*OMap][]target{}

// callTargets is match2.call_targets (computed once per pattern).
func callTargets(pat *OMap) []target {
	if t, ok := targetCache[pat]; ok {
		return t
	}
	t := computeTargets(pat)
	targetCache[pat] = t
	return t
}

func computeTargets(pat *OMap) []target { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var out []target
	if v := pat.GetOr("call"); pyTruthy(v) {
		for _, c := range asList(v) {
			cs := mustStr(c, "call")
			t, m := "", cs
			if i := strings.LastIndexByte(cs, '.'); i >= 0 {
				t, m = cs[:i], cs[i+1:]
			}
			out = append(out, target{Type: t, Method: m})
		}
	}
	if v := pat.GetOr("new"); pyTruthy(v) {
		for _, t := range asList(v) {
			out = append(out, target{Type: mustStr(t, "new"), Method: strInit})
		}
	}
	if pyTruthy(pat.GetOr("super")) {
		out = append(out, target{Method: strInit})
	}
	types := []any{nil}
	if v := pat.GetOr(strType); pyTruthy(v) {
		types = asList(v)
	}
	for _, t := range types {
		ts := ""
		if t != nil {
			ts = mustStr(t, strType)
		}
		if v := pat.GetOr("method"); pyTruthy(v) {
			for _, m := range asList(v) {
				out = append(out, target{Type: ts, Method: m})
			}
		}
		if v := pat.GetOr("method_regex"); pyTruthy(v) {
			out = append(out, target{Type: ts, Rx: pcreToPy(mustStr(v, "method_regex")), HasRx: true})
		}
	}
	return out
}

// methodEq is `method != want_method` negated, with the site's None method never equal.
func methodEq(method string, want any) bool {
	s, ok := want.(string)
	return ok && method != "" && method == s
}

func cardArity(v any) (int, *int) {
	if l, ok := v.([]any); ok {
		l = append(append([]any{}, l...), nil)
		lo := pyInt(l[0])
		if l[1] == nil {
			return lo, nil
		}
		hi := pyInt(l[1])
		return lo, &hi
	}
	n := pyInt(v)
	return n, &n
}

// mCall is match2.m_call: match a call pattern against a call expression.
func mCall(patAny any, expr Expr, env Env, fr *Frag) iter.Seq[Env] { //nolint:funlen,gocognit,gocyclo // mCall is the port of match2.m_call, one case per call-card key; the cases share the environment it threads
	return func(yield func(Env) bool) {
		pat := mustMap(patAny, "call pattern")
		if alts, ok := pat.Get(strAny); ok {
			for _, alt := range as[[]any](alts) {
				for x := range mCall(alt, expr, env, fr) {
					if !yield(x) {
						return
					}
				}
			}
			return
		}
		if !validCall[pat] {
			if unk := unknownKeys(pat, callKeys); len(unk) > 0 {
				panic(fmt.Sprintf("unknown call pattern key(s): %v", unk))
			}
			validCall[pat] = true
		}
		// An element of a call's value is no value of the call: only a
		// pattern naming that element (`element: i`) matches it.
		if want, ok := pat.Get("element"); ok != (expr.Element != 0) || ok && pyInt(want) != expr.Element-1 {
			return
		}
		site, caller := expr.Site, expr.Caller
		var cast, text string
		if expr.Text != "" {
			cast, text = stripCast(expr.Text)
		}
		var parsed *ParsedCall
		if text != "" {
			parsed = parseCall(text)
		}
		var method, cls, recvText, assigned string
		var arity, positional int
		var args map[int]Val // built on first use: most calls are rejected before the arguments
		var argIdx []int
		switch {
		case site != nil:
			method, cls, arity, positional = site.Method, site.receiverClass(), site.Arity, site.Positional
			recvText = fr.receiverText(site)
			assigned = site.AssignedVar
			if assigned == "" {
				assigned = expr.Assigned
			}
		case parsed != nil:
			method, arity, recvText = parsed.Method, len(parsed.Args), parsed.Receiver
			assigned = expr.Assigned
			if fr.Python {
				method, cls = pyParsedCallee(parsed, fr.qualifyIn(caller, parsed.Prefix))
				if parsed.Receiver != "" && fr.pyBoundLocally(caller, parsed.Receiver, nil) {
					cls = "" // a local or parameter, not the module its name spells
				}
			}
		default:
			return
		}
		buildArgs := func() {
			if args != nil {
				return
			}
			args = map[int]Val{}
			if site != nil {
				for _, i := range site.ParamIdx {
					p := site.Params[i]
					args[i] = Val{
						Text: p.ArgumentExpression, HasText: p.ArgumentExpression != "", Param: p, Caller: caller,
						Line: site.Line, LineOK: site.LineOK, Col: site.Col,
					}
				}
				argIdx = site.ParamIdx
				return
			}
			if fr.Python {
				keys, texts, _ := pyCallArgs(parsed.Args)
				for j, k := range keys {
					t := unwrap(dq(texts[j]))
					args[k] = Val{Text: t, HasText: true, Caller: caller}
					argIdx = append(argIdx, k)
				}
				return
			}
			for i, a := range parsed.Args {
				args[i] = Val{Text: a, HasText: true, Caller: caller}
				argIdx = append(argIdx, i)
			}
		}
		if parsed != nil && site == nil && fr.Python {
			_, _, positional = pyCallArgs(parsed.Args)
		}
		if site != nil && site.Python && site.PyDelegation {
			return // instantiates no class (pyWrittenCall)
		}
		e := env
		matched := false
		for _, t := range callTargets(pat) {
			e = env
			if t.Method != nil && !methodEq(method, t.Method) {
				continue
			}
			if t.HasRx {
				g := memoMatch(t.Rx, method) // a pure function of (pattern, name): computed once per name
				if g == nil {
					continue
				}
				e = e.withGroups(g)
			}
			if t.Type != "" && site != nil && (site.receiverless() || site.delegation()) {
				// A typed call is not one written without a receiver, and
				// `new T` is not a `this(...)` / `super(...)` delegation.
				continue
			}
			if t.Type != "" && fr.Go && cls != t.Type && goShortClass(cls) != t.Type {
				// Exact, as callMatches reads a Go sink: the import path
				// (and type) the pattern names, or the package's own name.
				continue
			}
			if t.Type != "" && fr.Python { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
				// Exact: the resolved class, or the receiver as written
				// qualified through the file's imports, unless the calling
				// function binds the receiver's name itself.
				if cls != t.Type && (cls != "" || recvText == "" || fr.qualifyIn(caller, recvText) != t.Type ||
					fr.pyBoundLocally(caller, recvText, site)) {
					continue
				}
			} else if t.Type != "" && !fr.Go && !typeOK(t.Type, cls, fr, caller, true) {
				var named string
				if parsed != nil && parsed.Type != "" {
					named = parsed.Type
				} else if method != strInit {
					named = recvText
				}
				if cls != "" || named == "" || !wordDotsMatch(named) || !nameOK(t.Type, named, fr, caller, true) {
					continue
				}
			}
			matched = true
			break
		}
		if !matched {
			return
		}
		if pyTruthy(pat.GetOr("super")) && (site == nil || site.Raw != "super") {
			return
		}
		if v, ok := pat.Get("arity"); ok {
			lo, hi := cardArity(v)
			if arity < lo || (hi != nil && arity > *hi) {
				return
			}
		}
		if v := pat.GetOr("bind_method"); pyTruthy(v) {
			m := method
			if m == "" {
				m = pyNone
			}
			e = e.with(strings.TrimLeft(mustStr(v, "bind_method"), "$"), m)
		}
		if v, ok := pat.Get("cast"); ok { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
			if cast == "" && site != nil && fr.HasDecls {
				// The fragment records every cast of a call: the finding
				// is the cast, as OpenGrep reports `(T) $F.m(...)`.
				at := castAt(v, fr.castSites(site), fr)
				if at == nil {
					return
				}
				e = e.with(atKey, strconv.Itoa(at.ID))
			} else {
				var casts map[string]bool
				if cast != "" {
					casts = map[string]bool{cast: true}
				} else if site != nil && site.Raw != "" {
					casts = fr.castsOf(site)
				}
				hit := false
				for _, t := range asList(v) {
					for c := range casts {
						if nameOK(mustStr(t, "cast"), c, nil, "", false) {
							hit = true
						}
					}
				}
				if !hit {
					return
				}
			}
		}
		if v, ok := pat.Get("stored"); ok && (assigned != "") != pyTruthy(v) {
			return
		}
		envs := []Env{e}
		if v, ok := pat.Get("assigned"); ok {
			name := mustStr(v, "assigned")
			var nxt []Env
			for _, x := range envs {
				if assigned != "" {
					if u, ok := unify(x, name, assigned); ok {
						nxt = append(nxt, u)
					}
				} else if old, ok := x[name]; !ok || old == "" {
					nxt = append(nxt, x.with(name, ""))
				}
			}
			envs = nxt
		}
		if v, ok := pat.Get("assigned_type"); ok { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
			var have string
			switch {
			case assigned == "":
			case site != nil && fr.HasDecls:
				// Only `T v = call();`: a plain assignment `v = call();`
				// is not a declaration.
				if d := fr.declarationOf(site, assigned); d != nil {
					have = d.Raw
				}
			default:
				have = fr.VarType[pairKey(caller, assigned)]
			}
			hit := false
			if have != "" {
				for _, t := range asList(v) {
					if fr.typeNamed(mustStr(t, "assigned_type"), have, caller, false) {
						hit = true
						break
					}
				}
			}
			if !hit {
				return
			}
		}
		if v, ok := pat.Get("receiver"); ok {
			rv := Val{Text: recvText, HasText: recvText != "", Caller: caller}
			if site != nil {
				rv.Line, rv.LineOK, rv.Col = site.Line, site.LineOK, site.Col
			}
			var nxt []Env
			for _, x := range envs {
				nxt = append(nxt, mValue(v, rv, x, fr)...)
			}
			envs = nxt
		}
		if v, ok := pat.Get("args"); ok && pyTruthy(v) {
			am := mustMap(v, "args")
			buildArgs()
			for ai, k := range am.Keys {
				apat := am.Vals[ai]
				buildArgs()
				i := argIndex(k, arity, positional, fr.Python)
				a, ok := args[i]
				if !ok {
					if m, isMap := apat.(*OMap); isMap && m.Len() == 1 && m.Has("bind") {
						continue
					}
					return
				}
				var nxt []Env
				for _, x := range envs {
					nxt = append(nxt, mValue(apat, a, x, fr)...)
				}
				envs = nxt
			}
		}
		if v, ok := pat.Get("any_arg"); ok {
			buildArgs()
			var nxt []Env
			for _, x := range envs {
				for _, i := range argIdx {
					nxt = append(nxt, mValue(v, args[i], x, fr)...)
				}
			}
			envs = nxt
		}
		var negs []any
		if v := pat.GetOr("not"); pyTruthy(v) {
			negs = asList(v)
		}
		inside, hasInside := pat.Get("inside")
		notInside, hasNotInside := pat.Get("not_inside")
		flows, hasFlows := pat.Get("flows_to")
		if (hasInside || hasNotInside || hasFlows) && site == nil {
			return // these keys need a recorded call site
		}
		for _, x := range envs {
			if anyCall(negs, expr, x, fr) {
				continue
			}
			if hasInside && !fr.insideCallOf(site, inside, x) || hasNotInside && fr.insideCallOf(site, notInside, x) {
				continue
			}
			if hasFlows && !fr.anyFlow(site, flows, x) {
				continue
			}
			if !yield(x) {
				return
			}
		}
	}
}

func anyCall(pats []any, expr Expr, env Env, fr *Frag) bool {
	for _, neg := range pats {
		for range mCall(neg, expr, env, fr) {
			return true
		}
	}
	return false
}

func lessPos(a, b *Site) bool {
	if a.lineOr0() != b.lineOr0() {
		return a.lineOr0() < b.lineOr0()
	}
	return a.colOr0() < b.colOr0()
}

var singleCache = map[*OMap]*OMap{}

// related: environments for another call of the same function that matches `pat` (a with item).
func related(pat *OMap, anchor *Site, env Env, fr *Frag, only *Site) iter.Seq[Env] { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	return func(yield func(Env) bool) {
		when := pat.GetOr("when")
		if mc, ok := pat.Get("min_count"); ok { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
			single := singleCache[pat]
			if single == nil {
				single = &OMap{}
				for i, k := range pat.Keys {
					if k != any("min_count") {
						single.Set(k, pat.Vals[i])
					}
				}
				singleCache[pat] = single
			}
			hits := 0
			for _, s := range fr.ByCaller[anchor.Caller] {
				if s == anchor {
					continue
				}
				for range related(single, anchor, env, fr, s) {
					hits++
					break
				}
			}
			if hits >= pyInt(mc) {
				yield(env)
			}
			return
		}
		sites := fr.ByCaller[anchor.Caller]
		if only != nil {
			sites = []*Site{only}
		}
		for _, s := range sites {
			if s == anchor {
				continue
			}
			before := lessPos(s, anchor)
			if (when == any("before") && !before) || (when == any("after") && before) {
				continue
			}
			if !patAccepts(pat, s.Method) { // m_call would yield nothing for this method name
				continue
			}
			for x := range mCall(pat, Expr{Site: s, Caller: s.Caller}, env, fr) {
				if !yield(x) {
					return
				}
			}
		}
	}
}

func solve(items []any, anchor *Site, env Env, fr *Frag) iter.Seq[Env] {
	return func(yield func(Env) bool) {
		if len(items) == 0 {
			yield(env)
			return
		}
		for e := range related(mustMap(items[0], "with item"), anchor, env, fr, nil) {
			for x := range solve(items[1:], anchor, e, fr) {
				if !yield(x) {
					return
				}
			}
		}
	}
}

func callerType(s *Site) (string, bool) {
	return reSearchGroup1(`\(([^()]*)\)\.[^.]*$`, s.Caller)
}

// Card is one hand card with the rule's metadata and taint flag filled in (load_cards).
type Card struct {
	Raw      *OMap
	Rule     string
	Match    *OMap // nil for a constant or declaration card
	Constant *OMap
	// Declaration is a declaration card's {type, init}: a local variable or
	// field declared with one of the types, reported at the declaration
	// (graph-fragment-1.18).
	Declaration *OMap
	// Store is a store card's {attribute, operator, receiver, value}: an
	// assignment to an attribute (Python attribute_stores), reported at the
	// assignment.
	Store    *OMap
	Metadata *OMap
	Taint    bool
	File     string
	Lossy    []string
	With     []any
	Without  []any
	Optional []any
	NotIn    []any

	mark int // last site (ID+1) this card was tried on: a card in both buckets runs once
}

func listOf(v any) []any {
	if !pyTruthy(v) {
		return nil
	}
	return as[[]any](v)
}

// cardEnvs is match2.card_envs: at most one environment.
func cardEnvs(c *Card, s *Site, fr *Frag) (Env, bool) {
	if ct, ok := c.Raw.Get("caller_type"); ok {
		have, found := callerType(s)
		hit := false
		for _, t := range asList(ct) {
			if (found && t == any(have)) || (!found && t == nil) { // Python: None in [...]
				hit = true
			}
		}
		if !hit {
			return nil, false
		}
	}
	return finishEnv(c, s, mCall(c.Match, Expr{Site: s, Caller: s.Caller}, Env{}, fr), fr)
}

// finishEnv: the first environment of envs that the card's with, without
// and optional items accept, completed by them.
func finishEnv(c *Card, s *Site, envs iter.Seq[Env], fr *Frag) (Env, bool) { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	for env := range envs {
		at := env[atKey]
		for e := range solve(c.With, s, env, fr) {
			rejected := false
			for _, neg := range c.Without {
				for range related(mustMap(neg, "without item"), s, e, fr, nil) {
					rejected = true
					break
				}
				if rejected {
					break
				}
			}
			if rejected {
				continue
			}
			for _, opt := range c.Optional {
				for x := range related(mustMap(opt, "optional item"), s, e, fr, nil) {
					e = x
					break
				}
			}
			if e[atKey] != at { // a with or optional call's cast is not where the card reports
				e = e.with(atKey, at)
			}
			return e, true
		}
	}
	return nil, false
}

// fillCard is match2.fill.
func fillCard(tmpl *OMap, env Env) *OMap {
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
			val, ok := env[full[1:]]
			if ok && val != "" && val != pyNone {
				return trimQuotes(val)
			}
			complete = false
			return full
		})
		if (complete || k == any("parameterCondition")) && res != "" {
			out.Set(k, res)
		}
	}
	return out
}

// --- loading -------------------------------------------------------------------------------------

// pyGlob is sorted(glob.glob(os.path.join(dir, "**", pattern), recursive=True)): every file under
// dir whose name matches, hidden names (leading dot) skipped as glob does.
func pyGlob(dir string, match func(string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && match(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

type ruleInfo struct {
	Meta  *OMap
	Taint bool
	// Rust: the rule is a Rust rule, which a `rust:` hand card may replace.
	Rust bool
	// Lang: the language directory of the v3 card file that defines the
	// rule (cards/<language>/...); "" for a rule read from YAML.
	Lang string
}

// sameLanguage: a card file under cards/<language>/ holds cards of that
// language's rules only. A card for another language's rule would replace
// that rule: its entries drop out of its own language's scans, and the card
// runs on these.
func (info ruleInfo) sameLanguage(path, lang, rule string) error {
	if info.Lang != "" && lang != "" && lang != info.Lang {
		return fmt.Errorf("%s: card %s: the rule is a %s rule, the card is under cards/%s", path, rule, info.Lang, lang)
	}
	return nil
}

// ruleTable is match2.rule_table: rule id -> (metadata.crypto, is taint,
// is Rust: its languages name rust).
func (s *settings) ruleTable(rulesDir string) (map[string]ruleInfo, error) {
	paths, err := pyGlob(rulesDir, func(n string) bool {
		ok := lenient(filepath.Match("*.y*ml", n))
		return ok
	})
	if err != nil {
		return nil, err
	}
	table := map[string]ruleInfo{}
	for _, path := range paths {
		doc, err := s.loadYAML(path)
		if err != nil {
			return nil, err
		}
		if !pyTruthy(doc) {
			continue
		}
		for _, r := range listOf(mustMap(doc, path).GetOr("rules")) {
			rm := mustMap(r, path)
			meta := &OMap{}
			if md := rm.GetOr("metadata"); pyTruthy(md) {
				if cr := mustMap(md, path).GetOr(s.metaKey); pyTruthy(cr) {
					meta = mustMap(cr, path)
				}
			}
			table[mustStr(rm.GetOr("id"), path)] = ruleInfo{Meta: meta, Taint: rm.GetOr("mode") == any(strTaint), Rust: rustRule(rm)}
		}
	}
	return table, nil
}

// CardSet is the cards loaded from a cards directory and the ids of the rules they cover.
type CardSet struct {
	Cards   []*Card
	RuleIDs map[string]bool
	// Rust are the index entries of the Rust hand cards (rust_card.go): only
	// the Rust matcher runs them, in place of their rules' compiled entries.
	Rust []*Entry
}

// loadCards is match2.load_cards.
func (s *settings) loadCards(cardsDir, rulesDir string) (*CardSet, error) {
	set := &CardSet{RuleIDs: map[string]bool{}}
	if cardsDir == "" {
		return set, nil
	}
	table, err := s.ruleTable(rulesDir)
	if err != nil {
		return nil, err
	}
	// A ruleset release names its card files rules.cards: releases without the
	// cards scanner pass every .yaml file of a ruleset to OpenGrep as rules.
	// .yaml stays for a cards directory given on its own (--cards-dir).
	paths, err := pyGlob(cardsDir, func(n string) bool {
		return strings.HasSuffix(n, ".cards") || strings.HasSuffix(n, ".yaml")
	})
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		doc, err := s.loadYAML(path)
		if err != nil {
			return nil, err
		}
		if !pyTruthy(doc) {
			continue
		}
		rel := lenient(filepath.Rel(cardsDir, path))
		for _, cAny := range listOf(mustMap(doc, path).GetOr("cards")) {
			if err := set.add(mustMap(cAny, path), path, s.languageOf(path), rel, table); err != nil {
				return nil, err
			}
		}
	}
	return set, nil
}

// add loads card c of the card file at path (rel under the cards directory),
// whose rule table is table.
func (set *CardSet) add(c *OMap, path, lang, rel string, table map[string]ruleInfo) error { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	rule := asOr[string](c.GetOr("rule"))
	info, known := table[rule]
	kinds := 0
	for _, k := range []string{"match", strConstant, "declaration", "store", keyRustCard} {
		if c.Has(k) {
			kinds++
		}
	}
	if unk := unknownKeys(c, cardKeys); len(unk) > 0 || !known || kinds != 1 {
		return fmt.Errorf("%s: bad card %s %v", path, rule, unk)
	}
	if err := info.sameLanguage(path, lang, rule); err != nil {
		return err
	}
	if f, ok := c.Get(keyRustCard); ok {
		return set.addRust(c, f, path, rule, info)
	}
	card := &Card{
		Raw: c, Rule: rule, Metadata: info.Meta, Taint: info.Taint, File: rel,
		With: listOf(c.GetOr("with")), Without: listOf(c.GetOr("without")), Optional: listOf(c.GetOr("optional")),
		NotIn: listOf(c.GetOr("not_in")),
	}
	if md := c.GetOr("metadata"); pyTruthy(md) {
		card.Metadata = mustMap(md, path)
	}
	if m, ok := c.Get("match"); ok { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		card.Match = mustMap(expandObjects(m), path)
		card.With, card.Without, card.Optional = expandList(card.With), expandList(card.Without), expandList(card.Optional)
	} else if st, ok := c.Get("store"); ok {
		card.Store = mustMap(st, path)
		if unk := unknownKeys(card.Store, storeKeys); len(unk) > 0 || !card.Store.Has("attribute") {
			return fmt.Errorf("%s: bad store card %s %v", path, rule, unk)
		}
	} else if d, ok := c.Get("declaration"); ok {
		card.Declaration = mustMap(d, path)
		if unk := unknownKeys(card.Declaration, declKeys); len(unk) > 0 || !card.Declaration.Has(strType) {
			return fmt.Errorf("%s: bad declaration card %s %v", path, rule, unk)
		}
	} else {
		card.Constant = mustMap(c.GetOr(strConstant), path)
		if unk := unknownKeys(card.Constant, constKeys); len(unk) > 0 || !card.Constant.Has("const") {
			return fmt.Errorf("%s: bad constant card %s %v", path, rule, unk)
		}
	}
	if l := c.GetOr("lossy"); pyTruthy(l) {
		if s, ok := l.(string); ok { // list("text"): its characters
			for _, r := range s {
				card.Lossy = append(card.Lossy, string(r))
			}
		} else {
			for _, x := range as[[]any](l) {
				card.Lossy = append(card.Lossy, pyStr(x))
			}
		}
	}
	set.Cards = append(set.Cards, card)
	set.RuleIDs[rule] = true
	return nil
}

// cardMethods is match2.card_methods: method names a call pattern can report on; ok=false for
// the "any method" bucket (None). Non-string names (a YAML 1.1 boolean) never meet a site.
func cardMethods(pat *OMap) (names []string, anyMethod bool) {
	if alts, ok := pat.Get(strAny); ok {
		for _, alt := range as[[]any](alts) {
			n, a := cardMethods(mustMap(alt, strAny))
			names = append(names, n...)
			anyMethod = anyMethod || a
		}
		return
	}
	for _, t := range callTargets(pat) {
		if t.HasRx || t.Method == nil {
			anyMethod = true
		} else if s, ok := t.Method.(string); ok {
			names = append(names, s)
		}
	}
	return
}

// acceptsMethod: can m_call get past the call-target loop for this method name? Used to skip, for
// a site, the cards of the "any method" bucket that cannot match its method (cached per name).
func acceptsMethod(pat *OMap, method string) bool {
	if alts, ok := pat.Get(strAny); ok {
		for _, alt := range as[[]any](alts) {
			if acceptsMethod(mustMap(alt, strAny), method) {
				return true
			}
		}
		return false
	}
	for _, t := range callTargets(pat) {
		if t.Method != nil && !methodEq(method, t.Method) {
			continue
		}
		if t.HasRx && reMatch(t.Rx, method) == nil {
			continue
		}
		return true
	}
	return false
}

var acceptCache = map[*OMap]map[string]bool{}

// patAccepts is acceptsMethod cached per (pattern, method name).
func patAccepts(pat *OMap, method string) bool {
	m := acceptCache[pat]
	if m == nil {
		m = map[string]bool{}
		acceptCache[pat] = m
	}
	v, ok := m[method]
	if !ok {
		v = acceptsMethod(pat, method)
		m[method] = v
	}
	return v
}

// matchCards is match2.match_cards.
func matchCards(cards []*Card, fr *Frag) []*Finding { //nolint:funlen,gocognit,gocyclo // matchCards is the port of match2.match_cards, one pass over the cards by kind
	byMethod := map[string][]*Card{}
	var anyMethod, constants, declarations, stores []*Card
	for _, c := range cards {
		switch {
		case c.Declaration != nil:
			declarations = append(declarations, c)
		case c.Store != nil:
			stores = append(stores, c)
		case c.Match != nil:
			names, am := cardMethods(c.Match)
			seenName := map[string]bool{}
			for _, n := range names {
				if !seenName[n] {
					seenName[n] = true
					byMethod[n] = append(byMethod[n], c)
				}
			}
			if am {
				anyMethod = append(anyMethod, c)
			}
		default:
			constants = append(constants, c)
		}
	}
	// current is the card being evaluated: a card the matcher cannot
	// evaluate stops the match with an error naming it (Assets.Match).
	var current *Card
	defer func() {
		if r := recover(); r != nil && current != nil {
			panic(cardPanic{card: current, cause: r})
		}
	}()
	var findings []*Finding
	seen := map[string]bool{}
	emit := func(c *Card, s *Site, env Env, how string) {
		pos := s
		if at, ok := env[atKey]; ok && at != "" {
			pos = fr.CastList[atoi(at)] // a cast card reports the cast
		}
		key := findingKey(c.Rule, pos, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		var val *string
		if v, ok := env["__value"]; ok && v != pyNone {
			val = &v
		}
		file := c.File
		findings = append(findings, &Finding{
			RuleID: c.Rule, File: pos.File, Line: pos.Line, LineOK: pos.LineOK, Col: pos.Col, ColOK: pos.ColOK, Taint: c.Taint,
			How: how, Value: val, Resolution: s.Resolution, SiteKind: s.Kind, Callee: calleeOf(s),
			Metadata: fillCard(c.Metadata, env), Approx: append([]string{}, c.Lossy...), Card: &file, Caller: s.Caller, EndCol: pos.EndCol, EndLine: pos.EndLine,
		})
	}
	anyFor := map[string][]*Card{} // cards of the "any method" bucket whose targets can take this name
	for _, s := range fr.Sites {
		var named []*Card
		if s.Method != "" {
			named = byMethod[s.Method]
		}
		anyCards, ok := anyFor[s.Method]
		if !ok {
			for _, c := range anyMethod {
				if patAccepts(c.Match, s.Method) {
					anyCards = append(anyCards, c)
				}
			}
			anyFor[s.Method] = anyCards
		}
		for _, list := range [2][]*Card{named, anyCards} {
			for _, c := range list {
				if c.mark == s.ID+1 { // a card in both buckets: Python runs it twice, the second run emits nothing new
					continue
				}
				c.mark = s.ID + 1
				if !patAccepts(c.Match, s.Method) {
					continue
				}
				current = c
				if env, ok := cardEnvs(c, s, fr); ok {
					emit(c, s, env, "card")
				}
			}
		}
		// A constant written as an argument of a recorded call. When the
		// fragment has the reference itself (graph-fragment-1.17), the
		// reference loop below reports it at its own position instead.
		var argIdx []int
		for _, i := range s.ParamIdx {
			t := norm(s.Params[i].ArgumentExpression)
			if wordDotsMatch(t) && strings.Contains(t, ".") && fr.refAt(s, t) == nil {
				argIdx = append(argIdx, i)
			}
		}
		if len(argIdx) == 0 {
			continue // const_match is None for every argument: no constant card can emit here
		}
		for _, c := range constants {
			current = c
			if anyCall(c.NotIn, Expr{Site: s, Caller: s.Caller}, Env{}, fr) {
				continue
			}
			if !constAt(c.Constant, "arg") {
				continue
			}
			for _, i := range argIdx {
				if g := constMatch(c.Constant, s.Params[i].ArgumentExpression, fr, s.Caller); g != nil {
					emit(c, s, Env{}.withGroups(g), strConstant)
					break
				}
			}
		}
	}
	// Declarations (graph-fragment-1.18), reported at the declaration as
	// OpenGrep reports `T $X = $E;`, whatever the initializer is.
	for _, d := range fr.Decls {
		for _, c := range declarations {
			current = c
			if declarationMatches(c.Declaration, d, fr) {
				emit(c, d, Env{}, "declaration:"+d.RefContext)
			}
		}
	}
	// Attribute stores (Python), reported at the assignment.
	for _, st := range fr.Stores {
		for _, c := range stores {
			current = c
			if env, ok := finishEnv(c, st, storeEnvs(c.Store, st, fr), fr); ok {
				emit(c, st, env, "store")
			}
		}
	}
	// Constant references at any position (graph-fragment-1.17), reported at
	// the reference as OpenGrep reports `Owner.$C`. not_in excludes a
	// reference inside a matching call, at any depth.
	if len(constants) > 0 {
		for _, r := range fr.Refs {
			if fr.comparisonRef(r.RefContext) && !fr.reportComparison(r) {
				continue
			}
			for _, c := range constants {
				current = c
				if !constAt(c.Constant, r.RefContext) {
					continue
				}
				g := constMatch(c.Constant, r.Raw, fr, r.Caller)
				if g == nil || insideCall(c.NotIn, r, fr) {
					continue
				}
				emit(c, r, Env{}.withGroups(g), "constant:"+r.RefContext)
			}
		}
	}
	return findings
}

// insideCall: a call of the reference's function that contains it matches
// one of pats.
func insideCall(pats []any, ref *Site, fr *Frag) bool {
	if len(pats) == 0 {
		return false
	}
	for _, s := range fr.ByCaller[ref.Caller] {
		if s.contains(ref) && anyCall(pats, Expr{Site: s, Caller: s.Caller}, Env{}, fr) {
			return true
		}
	}
	if fr.Python {
		for _, p := range pats {
			if m, ok := p.(*OMap); ok && keySet(m, "call") {
				if name, ok := m.GetOr("call").(string); ok && (fr.refInBuiltinCall(ref, name) ||
					ref.RefContext == pyTypeCheck && pyTypeCheckCalls[name]) {
					return true
				}
			}
		}
	}
	return false
}

// atKey is the environment entry a call pattern's `cast` sets on a fragment
// that records casts: the cast (index in Frag.CastList) the finding reports.
const atKey = "__at"

// castAt: the first cast around the call whose type the card's `cast` names.
func castAt(want any, casts []*Site, fr *Frag) *Site {
	for _, c := range casts {
		for _, t := range asList(want) {
			if fr.typeNamed(mustStr(t, "cast"), c.Raw, c.Caller, false) {
				return c
			}
		}
	}
	return nil
}

func atoi(s string) int {
	n := lenient(strconv.Atoi(s))
	return n
}

// declarationMatches: the declaration has one of the card's types (as
// written, or the card's qualified name with package evidence for a short
// one) and, when the card gives `init`, an initializer as it says: true (any),
// false (none), or one kind or a list of kinds (call, cast, null, literal,
// other).
func declarationMatches(card *OMap, d *Site, fr *Frag) bool {
	hit := false
	for _, t := range asList(card.GetOr(strType)) {
		if fr.typeNamed(mustStr(t, "declaration type"), d.Raw, d.Caller, true) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	init, ok := card.Get("init")
	if !ok {
		return true
	}
	if b, isBool := init.(bool); isBool {
		return b == (d.RefContext != "")
	}
	for _, k := range asList(init) {
		if mustStr(k, "declaration init") == d.RefContext {
			return true
		}
	}
	return false
}
