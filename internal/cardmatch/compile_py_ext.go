// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cardmatch

// The compiler's Python extensions beyond the PoC's shapes (E2.7-py.10). Each
// turns a rule shape compile_rules_py.py skips into index data the matcher
// reads (index_py.go):
//
//   - a nested call argument with metavariables (`hashes.Hash(hashes.$A(...))`):
//     an argument {"kind": "call", "call": <entry>}, matched against the call
//     written there; a metavariable bound inside it carries its constraints;
//   - a dotted reference that is no call (`hashes.$ALG`, `ssl.PROTOCOL_TLSv1`):
//     a constant entry (receiver "constant"), matched against the fragment's
//     constant references; table pattern-insides (`{..., $K: $V, ...}`,
//     `(..., $X, ...)`, `[..., $X, ...]`) give its position kinds ("at");
//   - pattern-insides that say where a metavariable's object comes from
//     (`$X = F(...)`, `with F(...) as $X:`, `$X: T = ...`,
//     `def $F(..., $X: T, ...):`): an origin group ("insides"): the receiver or
//     argument bound to $X is typed T, or a local assigned from one of the
//     calls (the card engine's `from`, via var or chain);
//   - taint rules whose sources are factory calls (object flow): the sink's
//     receiver (or focused argument) gets the same origin group, with the
//     sources as the factories, and the entry is matched as a call
//     ("flow": "object") instead of by tainted values;
//   - pattern-not-inside a call: "not_inside" (the call, or the constant, is
//     not written inside a matching call); comparisons and subscripts around
//     a constant become positions it is not reported at ("not_at");
//   - an import pattern-inside is checked against the callee's dotted name;
//   - metavariable-pattern alternatives that are dotted names: a regex on the
//     argument also tried on its text qualified through the file's imports.

import (
	"strings"

	"github.com/dlclark/regexp2"
)

var (
	rxPyConstant   = rxFull(`(` + cQName + `)\.(\$[A-Z_0-9]+|` + cIdent + `)`)
	rxPyRecvMV     = rxStart(`^(\$[A-Z_0-9]+)\s*\.`)
	rxPyAssignFrom = regexp2.MustCompile(`\A(\$[A-Z_0-9]+)\s*=\s*([^\n]+?)\s*\n\s*\.\.\.\s*\z`, regexp2.None)
	rxPyWithAs     = regexp2.MustCompile(`\Awith\s+([^\n]+?)\s+as\s+(\$[A-Z_0-9]+)\s*:\s*\n\s*\.\.\.\s*\z`, regexp2.None)
	rxPyAnnotated  = regexp2.MustCompile(`\A(\$[A-Z_0-9]+)\s*:\s*(`+cQName+`)\s*=\s*\.\.\.\s*\n\s*\.\.\.\s*\z`, regexp2.None)
	rxPyDefParam   = regexp2.MustCompile(`\Adef\s+\$[A-Z_0-9]+\s*\(\s*\.\.\.\s*,\s*(\$[A-Z_0-9]+)\s*:\s*(`+cQName+`)\s*,\s*\.\.\.\s*\)\s*:\s*\n\s*\.\.\.\s*\z`, regexp2.None)
	rxPyImport     = regexp2.MustCompile(`\A(?:\.\.\.\s*\n\s*)?(?:import\s+(`+cQName+`)(?:\s+as\s+(\$[A-Z_0-9]+))?|from\s+(`+cQName+`)\s+import\s+(`+cIdent+`|\$[A-Z_0-9]+))\s*\n\s*\.\.\.\s*\z`, regexp2.None)
	rxPyStringRx   = rxFull(`"=~/(.*)/"`)
	rxPyTypeMVRecv = rxStart(`^(` + cQName + `)\.(\$[A-Z_0-9]+)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxPyDictTable  = rxFull(`\{\s*\.\.\.\s*,\s*\$[A-Z_0-9]+\s*:\s*\$[A-Z_0-9]+\s*,\s*\.\.\.\s*\}`)
	rxPySeqTable   = rxFull(`[\(\[]\s*\.\.\.\s*,\s*\$[A-Z_0-9]+\s*,\s*\.\.\.\s*[\)\]]`)
	rxPyCompare    = rxFull(`\$[A-Z_0-9]+\s*(==|!=|is not|is|not in|in)\s*\$[A-Z_0-9]+`)
	rxPySubscript  = rxFull(`\$[A-Z_0-9]+\s*\[\s*\.\.\.\s*\]`)
	rxPyMVOnly     = rxFull(`\$[A-Z_0-9]+`)
	rxPyStringMV   = rxFull(`["'](\$[A-Z_0-9]+)["']`)
	rxPyMVAll      = rxSearch(`\$[A-Z_0-9]+`)
	rxPyDictKey    = rxSearch(`(["'][^"'\n]+["'])\s*:`)
	rxPyDictEntry  = rxSearch(`(["'][^"'\n]+["'])\s*:\s*(\$[A-Z_0-9]+)\s*[,}]`)
	rxPySelfField  = rxSearch(`(?:self|cls)\.\$[A-Z_0-9]+\s*=\s*(?:\$[A-Z_0-9]+\s*=\s*)?(` + cQName + `)\s*\(\s*\.\.\.\s*\)`)
	rxPyReassign   = regexp2.MustCompile(`\A\$[A-Z_0-9]+\s*=\s*\$[A-Z_0-9]+\s*\n\s*\.\.\.\s*\z`, regexp2.None)
)

// nestedCall parses a nested call argument (ext): an entry with empty
// constraints, as a sink has.
func nestedCall(a string, ext bool) (*OMap, error) {
	if ext {
		if sub, err := parsePyCall(a, true); err == nil && getString(sub, "receiver") != strConstant {
			sub.Set("constraints", []any{})
			return sub, nil
		}
	}
	return nil, skip("argument is a sub-pattern with a metavariable")
}

// containerArg is a dict or list display argument holding metavariables
// (`{"alg": $ALGO, ...}`, `[$ALGO, ...]`), nil for another text: the
// argument is a display of that kind with the pattern's keys; its
// metavariables bind the whole argument (a focus reports it; a taint value
// is a string literal written in it).
func containerArg(a string, ext bool) *OMap {
	if !ext || len(a) < 2 || ((a[0] != '{' || a[len(a)-1] != '}') && (a[0] != '[' || a[len(a)-1] != ']')) {
		return nil
	}
	var names, keys []any
	for m := find(rxPyMVAll, a); m != nil; m = lenient(rxPyMVAll.FindNextMatch(m)) {
		names = append(names, m.String())
	}
	for m := find(rxPyDictKey, a); m != nil; m = lenient(rxPyDictKey.FindNextMatch(m)) {
		keys = append(keys, pyDQ(group(m, 1)))
	}
	if keys == nil {
		keys = []any{}
	}
	entries := &OMap{} // metavariable -> the dict key it is the value of
	for m := find(rxPyDictEntry, a); m != nil; m = lenient(rxPyDictEntry.FindNextMatch(m)) {
		entries.Set(group(m, 2), pyDQ(group(m, 1)))
	}
	return omap("kind", "container", "value", a[:1], "names", names, "keys", keys, "entries", entries)
}

// constantEntry is the entry of a dotted reference `owner.NAME` or
// `owner.$NAME`, nil for any other text.
func constantEntry(p string) *OMap {
	m := find(rxPyConstant, p)
	if m == nil {
		return nil
	}
	c := omap("receiver", strConstant, strType, group(m, 1), "method", group(m, 2), "min_arity", int64(0), "max_arity", int64(0),
		"args", []any{}, "method_regex", nil)
	if name := group(m, 2); strings.HasPrefix(name, "$") {
		c.Set("method_metavar", name)
		c.Set("method", nil)
	}
	return c
}

// receiverMetavar is the metavariable a Python call pattern binds to its
// receiver (`$X.m(...)`), or "".
func receiverMetavar(s *OMap) string {
	if getString(s, "receiver") != strAny {
		return ""
	}
	if m := find(rxPyRecvMV, getString(s, "pattern")); m != nil {
		return group(m, 1)
	}
	return ""
}

// metavarOwner is the entry in which name binds: the call itself or, with
// deep, a nested call argument at any depth.
func metavarOwner(call *OMap, name any, deep bool) (*OMap, *slot) {
	if sl := metavarSlot(call, name); sl != nil {
		return call, sl
	}
	if !deep {
		return nil, nil
	}
	for _, v := range listOf(call.GetOr("args")) {
		if sub, ok := v.(*OMap).GetOr("call").(*OMap); ok {
			if o, sl := metavarOwner(sub, name, true); sl != nil {
				return o, sl
			}
		}
	}
	return nil, nil
}

// boundInCall: name is the call's receiver or a top-level argument
// metavariable (where an origin is checked).
func boundInCall(s *OMap, name string) bool {
	if receiverMetavar(s) == name {
		return true
	}
	sl := metavarSlot(s, name)
	return sl != nil && !sl.method && !sl.container
}

// pyClassLike: a dotted callee whose last name starts with an upper-case
// letter is a class (an instantiation gives an object of that class).
func pyClassLike(name string) bool {
	i := strings.LastIndexByte(name, '.')
	last := name[i+1:]
	return i > 0 && last != "" && last[0] >= 'A' && last[0] <= 'Z'
}

// originOfCall is what a call pattern producing an object says about it: the
// card call pattern matching the call (`from`), and the class it
// instantiates (`types`), when it is one.
func originOfCall(call *OMap) (from *OMap, types []any) {
	pat := &OMap{}
	method := getString(call, "method")
	if method == "" {
		return nil, nil // a metavariable method name
	}
	switch getString(call, "receiver") {
	case strType:
		callee := getString(call, strType) + "." + method
		pat.Set("call", callee)
		if pyClassLike(callee) && !constrainingArgs(call) {
			// An object of the class, whatever made it, unless the
			// pattern says how it was made.
			types = append(types, callee)
		}
	case strAny, strNone:
		pat.Set("method", method)
	default:
		return nil, nil
	}
	args := &OMap{}
	for _, v := range listOf(call.GetOr("args")) {
		a := as[*OMap](v)
		key := a.GetOr("index")
		if s, ok := key.(string); ok {
			key = strings.TrimPrefix(s, "kw:")
		}
		switch getString(a, "kind") {
		case strLiteral:
			args.Set(key, omap(strLiteral, getString(a, "value")))
		case "any_string":
			args.Set(key, omap("string", true))
		case strMetavar:
			if _, kw := key.(string); kw {
				args.Set(key, omap("regex", ".")) // the keyword is passed
			}
		case strText:
			if text := getString(a, "value"); find(rxPyConstant, text) != nil {
				args.Set(key, omap("const", text))
			} else {
				args.Set(key, omap(strLiteral, text))
			}
		}
	}
	if args.Len() > 0 {
		pat.Set("args", args)
	}
	return pat, types
}

// constrainingArgs: the call pattern says something about an argument (a
// literal, a text, a nested call), beyond arity and metavariables.
func constrainingArgs(call *OMap) bool {
	for _, v := range listOf(call.GetOr("args")) {
		switch getString(as[*OMap](v), "kind") {
		case strEllipsis, strMetavar:
		default:
			return true
		}
	}
	return false
}

// originAlternative reads a pattern-inside that says where a metavariable's
// object comes from; nil when the text is no such shape.
func originAlternative(t string) *OMap {
	var mv, rhs string
	if m := find(rxPyAssignFrom, t); m != nil {
		mv, rhs = group(m, 1), group(m, 2)
	} else if m := find(rxPyWithAs, t); m != nil {
		mv, rhs = group(m, 2), group(m, 1)
	} else if m := find(rxPyAnnotated, t); m != nil {
		return omap(strMetavar, group(m, 1), "types", []any{group(m, 2)}, "from", []any{})
	} else if m := find(rxPyDefParam, t); m != nil {
		return omap(strMetavar, group(m, 1), "types", []any{group(m, 2)}, "from", []any{})
	} else {
		return nil
	}
	call, err := parsePyCall(rhs, false)
	if err != nil {
		return nil
	}
	from, types := originOfCall(call)
	if from == nil {
		return nil
	}
	if types == nil {
		types = []any{}
	}
	return omap(strMetavar, mv, "types", types, "from", []any{from})
}

// pyTableKind is the position kind a table pattern-inside gives a constant.
func pyTableKind(t string) string {
	switch {
	case find(rxPyDictTable, t) != nil:
		return "dict"
	case find(rxPySeqTable, t) != nil:
		return "array"
	}
	return ""
}

// compilePyInside compiles a pattern-inside (or an either of them) of a
// Python rule (ext): table positions, imports, origins.
func compilePyInside(val any, sinks []*OMap) error { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	vals, ok := val.([]any)
	if !ok {
		vals = []any{val}
	}
	var at, imports, origins []any
	unsupported := 0
	for _, v := range vals {
		text, err := asString(v, "pattern-inside")
		if err != nil {
			return err
		}
		t := pyStrip(text)
		if kind := pyTableKind(t); kind != "" { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
			at = append(at, kind)
		} else if m := find(rxPyImport, t); m != nil {
			if groupOK(m, 1) {
				imports = append(imports, pyImport{module: group(m, 1), alias: group(m, 2)})
			} else {
				imports = append(imports, pyImport{module: group(m, 3), name: group(m, 4)})
			}
		} else if o := originAlternative(t); o != nil {
			origins = append(origins, o)
		} else {
			unsupported++
		}
	}
	kinds := 0
	for _, l := range [][]any{at, imports, origins} {
		if len(l) > 0 {
			kinds++
		}
	}
	if kinds != 1 || unsupported > 0 && len(origins) == 0 {
		return skip("pattern-inside that is not an import or package")
	}
	for _, s := range sinks {
		constant := getString(s, "receiver") == strConstant
		switch {
		case len(at) > 0:
			if !constant {
				return skip("pattern-inside table around a call")
			}
			s.Set("at", append(listOf(s.GetOr("at")), at...))
		case len(imports) > 0:
			if err := applyImports(s, imports); err != nil {
				return err
			}
		default:
			if constant {
				return skip("pattern-inside origin around a constant")
			}
			var group []any
			for _, o := range origins {
				if boundInCall(s, getString(as[*OMap](o), strMetavar)) {
					group = append(group, o)
				}
			}
			if len(group) == 0 {
				return skip("pattern-inside on a metavariable not bound in the call")
			}
			if len(group) < len(origins) || unsupported > 0 {
				appendTo(s, "dropped_clauses", "pattern-inside alternative not compiled")
			}
			s.Set("insides", append(listOf(s.GetOr("insides")), group))
		}
	}
	return nil
}

// pyImport is an import pattern-inside: `import module [as $alias]` or
// `from module import name` (name may be a metavariable).
type pyImport struct{ module, alias, name string }

// applyImports applies import pattern-insides (alternatives) to a sink. The
// matcher qualifies the callee through the file's imports, so an import
// that names the callee's module is implied; one that gives the callee its
// spelling qualifies it: `from jose import jwt` + `jwt.encode(...)` is
// `jose.jwt.encode(...)`, `import rsa as $A` + `$A.newkeys(...)` is
// `rsa.newkeys(...)`, `from rsa import $N` + `$N(...)` is `rsa.$N(...)`.
// The first alternative that applies decides; when none does, the clause is
// dropped (a dotted callee) or the rule skipped.
func applyImports(s *OMap, imports []any) error { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	typ, recvMV := getString(s, strType), receiverMetavar(s)
	method := getString(s, "method_metavar")
	for _, v := range imports {
		im := as[pyImport](v)
		switch {
		case im.alias != "" && recvMV == im.alias:
			s.Set("receiver", strType)
			s.Set(strType, im.module)
			return nil
		case im.name != "" && strings.HasPrefix(im.name, "$"):
			if getString(s, "receiver") == strNone && method == im.name {
				s.Set("receiver", strType)
				s.Set(strType, im.module)
				return nil
			}
		case im.name != "":
			if typ == im.name || strings.HasPrefix(typ, im.name+".") {
				s.Set(strType, im.module+"."+typ)
				return nil
			}
			if getString(s, "receiver") == strNone && getString(s, "method") == im.name {
				s.Set("receiver", strType)
				s.Set(strType, im.module)
				return nil
			}
		case im.alias == "":
			if typ == im.module || strings.HasPrefix(typ, im.module+".") {
				return nil
			}
		}
	}
	if typ == "" {
		return skip("pattern-inside import around a call without a dotted callee")
	}
	appendTo(s, "dropped_clauses", "pattern-inside import not about the callee type")
	return nil
}

// compilePyNotInside compiles a pattern-not-inside of a Python rule (ext)
// that is a call, a comparison or a subscript; it is false for another shape.
func compilePyNotInside(text string, sinks []*OMap) bool {
	t := pyStrip(text)
	if m := find(rxPyCompare, t); m != nil {
		kind := "compare"
		if strings.HasSuffix(group(m, 1), "in") {
			kind = "in"
		}
		for _, s := range sinks {
			if getString(s, "receiver") == strConstant {
				s.Set("not_at", append(listOf(s.GetOr("not_at")), kind))
			} else {
				appendTo(s, "dropped_clauses", "pattern-not-inside comparison around a call")
			}
		}
		return true
	}
	if find(rxPySubscript, t) != nil {
		// $TYPE[...]: a type subscript holds no constant reference the
		// fragment records (annotations are left out) and no call.
		return true
	}
	neg, err := parsePyCall(t, false)
	if err != nil || getString(neg, "receiver") == strConstant {
		return false
	}
	neg.Set("constraints", []any{})
	for _, s := range sinks {
		s.Set("not_inside", append(listOf(s.GetOr("not_inside")), neg))
	}
	return true
}

// reassignedElsewhere: a pattern-not-inside `$X = $OTHER` + `...` with a
// metavariable-pattern excluding the factories (the object was reassigned
// from something else since); the compiler does not check it.
func reassignedElsewhere(v any) bool {
	m, ok := v.(*OMap)
	if !ok || !keySet(m, "patterns") {
		return false
	}
	l := asOr[[]any](m.GetOr("patterns"))
	if len(l) != 2 || !keySet(l[0], "pattern") || !keySet(l[1], "metavariable-pattern") {
		return false
	}
	return find(rxPyReassign, pyStrip(pyStr(as[*OMap](l[0]).GetOr("pattern")))) != nil
}

// pyNameAlternatives turns a metavariable-pattern made of dotted-name
// alternatives (through pattern-either / single-clause patterns) into a
// regex; ok is false for any other sub-pattern.
func pyNameAlternatives(node *OMap) (string, bool) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var names []string
	var walk func(v any) bool
	walk = func(v any) bool {
		m, isMap := v.(*OMap)
		if !isMap {
			return false
		}
		switch {
		case m.Has("metavariable") && m.Len() == 2 && (m.Has("pattern-either") || m.Has("patterns") || m.Has("pattern")):
			for i, k := range m.Keys {
				if k != any("metavariable") {
					return walk(omap(k, m.Vals[i]))
				}
			}
		case keySet(m, "pattern"):
			text := pyStrip(pyStr(m.GetOr("pattern")))
			if find(rxPyConstant, text) == nil || strings.Contains(text, "$") {
				return false
			}
			names = append(names, pyReEscape(text))
			return true
		case keySet(m, "pattern-either"):
			l := asOr[[]any](m.GetOr("pattern-either"))
			for _, x := range l {
				if !walk(x) {
					return false
				}
			}
			return len(l) > 0
		case keySet(m, "patterns"):
			l := asOr[[]any](m.GetOr("patterns"))
			return len(l) == 1 && walk(l[0])
		}
		return false
	}
	if !walk(node) || len(names) == 0 {
		return "", false
	}
	return "^(?:" + strings.Join(names, "|") + ")$", true
}

// objectSources reads taint sources that are factory calls (object flow):
// the origin alternative of the object they produce. An alternative that is
// none of the shapes is dropped and recorded; nil when none is read.
func objectSources(srcs []any, ctx *compileCtx) *OMap { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	types, froms, notFroms := []any{}, []any{}, []any{}
	dropped := 0
	var walk func(v any)
	walk = func(v any) {
		m, ok := v.(*OMap)
		if !ok {
			dropped++
			return
		}
		if l, ok := m.GetOr("pattern-either").([]any); ok && m.Len() == 1 {
			for _, x := range l {
				walk(x)
			}
			return
		}
		if keySet(m, "pattern") {
			call, err := parsePyCall(m.GetOr("pattern"), false)
			if err == nil {
				if from, ts := originOfCall(call); from != nil {
					froms, types = append(froms, from), append(types, ts...)
					return
				}
			}
			dropped++
			return
		}
		if l, ok := m.GetOr("patterns").([]any); ok && m.Len() == 1 {
			if f, nf, ok := negatedFactories(l); ok {
				froms, notFroms = append(froms, f...), append(notFroms, nf...)
				return
			}
			if ts := selfFieldTypes(l); len(ts) > 0 {
				types = append(types, ts...)
				return
			}
		}
		// def $F(..., $X: T, ...) + $X (+ focus $X): a parameter annotated T.
		if l, ok := m.GetOr("patterns").([]any); ok && m.Len() == 1 {
			var o *OMap
			mv := ""
			for _, c := range l {
				cm := asOr[*OMap](c)
				switch {
				case cm == nil:
				case keySet(cm, "pattern-inside"):
					o = originAlternative(pyStrip(pyStr(cm.GetOr("pattern-inside"))))
				case keySet(cm, "pattern") && find(rxPyMVOnly, pyStrip(pyStr(cm.GetOr("pattern")))) != nil:
					mv = pyStrip(pyStr(cm.GetOr("pattern")))
				case keySet(cm, "focus-metavariable"):
				default:
					o = nil
					mv = "?"
				}
			}
			if o != nil && getString(o, strMetavar) == mv && len(listOf(o.GetOr("from"))) == 0 {
				types = append(types, listOf(o.GetOr("types"))...)
				return
			}
		}
		dropped++
	}
	for _, s := range srcs {
		walk(s)
	}
	if len(types) == 0 && len(froms) == 0 {
		return nil
	}
	if dropped > 0 {
		ctx.dropped = append(ctx.dropped, "taint source alternative not compiled")
	}
	return omap("types", types, "from", froms, "not_from", notFroms)
}

// negatedFactories reads a source `patterns` of factory calls (a pattern or
// an either of them) minus pattern-not calls: the factories (no class
// typing: the pattern says how the object is made) and the excluded calls.
func negatedFactories(clauses []any) (from, notFrom []any, ok bool) { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	for _, c := range clauses {
		cm, isMap := c.(*OMap)
		if !isMap || cm.Len() != 1 {
			return nil, nil, false
		}
		var pats []any
		neg := false
		switch {
		case cm.Has("pattern"):
			pats = []any{cm.GetOr("pattern")}
		case cm.Has("pattern-not"):
			pats, neg = []any{cm.GetOr("pattern-not")}, true
		case cm.Has("pattern-either"):
			for _, x := range listOf(cm.GetOr("pattern-either")) {
				if !keySet(x, "pattern") {
					return nil, nil, false
				}
				pats = append(pats, as[*OMap](x).GetOr("pattern"))
			}
		default:
			return nil, nil, false
		}
		for _, p := range pats {
			call, err := parsePyCall(p, false)
			if err != nil {
				return nil, nil, false
			}
			pat, _ := originOfCall(call)
			if pat == nil {
				return nil, nil, false
			}
			if neg {
				notFrom = append(notFrom, pat)
			} else {
				from = append(from, pat)
			}
		}
	}
	return from, notFrom, len(from) > 0
}

// selfFieldTypes reads a source `self.$F` / `cls.$F` inside a class whose
// method assigns the field from a class instantiation with any arguments:
// the field's class (the fragment types self fields from their writes).
func selfFieldTypes(clauses []any) []any { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	var types []any
	field := false
	for _, c := range clauses {
		cm := asOr[*OMap](c)
		if cm == nil || !keySet(cm, "pattern-either") {
			return nil
		}
		for _, x := range listOf(cm.GetOr("pattern-either")) {
			xm := asOr[*OMap](x)
			switch {
			case keySet(xm, "pattern"):
				p := pyStrip(pyStr(xm.GetOr("pattern")))
				if !strings.HasPrefix(p, "self.$") && !strings.HasPrefix(p, "cls.$") {
					return nil
				}
				field = true
			case keySet(xm, "pattern-inside"):
				m := find(rxPySelfField, pyStr(xm.GetOr("pattern-inside")))
				if m == nil || !pyClassLike(group(m, 1)) {
					return nil
				}
				if !listHas(types, group(m, 1)) {
					types = append(types, group(m, 1))
				}
			default:
				return nil
			}
		}
	}
	if !field {
		return nil
	}
	return types
}

// objectFlowSinks makes the sinks of an object-flow taint rule: the origin
// of the sources on the focused argument, else on the receiver.
func objectFlowSinks(sinks []*OMap, origin *OMap) error {
	for _, s := range sinks {
		mv := ""
		if f, ok := s.GetOr("focus_arg").(int64); ok {
			for _, v := range listOf(s.GetOr("args")) {
				a := as[*OMap](v)
				if a.GetOr("index") == any(f) && getString(a, "kind") == strMetavar {
					mv = getString(a, "name")
				}
			}
		} else if s.GetOr("focus_arg") == nil {
			mv = receiverMetavar(s)
		}
		if mv == "" {
			return skip("taint sink without a receiver or focused argument")
		}
		o := omap(strMetavar, mv, "types", origin.GetOr("types"), "from", origin.GetOr("from"), "not_from", origin.GetOr("not_from"))
		if made, ok := origin.Get("made"); ok {
			o.Set("made", made)
		}
		s.Set("insides", append(listOf(s.GetOr("insides")), []any{o}))
		s.Set("flow", flowObject)
		s.Set("focus_arg", nil) // OpenGrep reports the sink call's line
	}
	return nil
}
