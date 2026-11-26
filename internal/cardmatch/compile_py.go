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

// The Python pattern shapes of the rule compiler: a port of the PoC's
// compile_rules_py.py, which replaces compile_rules.py's two shape parsers
// (parse_arg, parse_call) with Python ones and adds the Python spelling of
// the one pattern-not-inside shape the compiler understands. A rule is read
// with them when its languages name python.
//
//	a.b.f(...)       callee by dotted name: type a.b, method f (a class
//	                 instantiation has the same shape: no `new`)
//	$X.m(...)        method on any receiver
//	f(...)           bare name
//	kw=$X, kw="lit"  keyword argument: index "kw:<name>" (no position)
//	'lit'            a plain single-quoted literal is written with double quotes

import (
	"strings"

	"github.com/dlclark/regexp2"
)

const pyStringLit = `(?:[bBrRuUfF]{0,2})(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`

var (
	rxPyKeyword   = regexp2.MustCompile(`\A(?:^(`+cIdent+`)\s*=(?!=)\s*(.+)$)`, regexp2.Singleline)
	rxPyString    = rxFull(pyStringLit)
	rxPyOtherLit  = rxFull(`-?\d+(?:\.\d+)?|None|True|False`)
	rxPySingleQ   = rxFull(`([bBrRuUfF]{0,2})'([^'"\\]*)'`)
	rxPyAssign    = rxSearch(`(?<![=!<>(,\s\w])\s*=(?!=)`)
	rxPyStatement = rxStart(`^(with|for|if|def|class|import|from|return|async|await)\b`)
	rxPyAnyRecv   = rxStart(`^(\$[A-Z_0-9]+)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxPyTypeRecv  = rxStart(`^(` + cQName + `)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxPyNoRecv    = rxStart(`^(\$?` + cIdent + `)\s*\(`)
	rxPyReference = rxFull(`\$?` + cQName + `(\.\$[A-Z_0-9]+)?|-?\d+|` + pyStringLit)
	rxPyNotAssign = regexp2.MustCompile(`\A(?:(\$[A-Z_0-9]+)\s*=\s*["'](?:\.\.\.|\$[A-Z_0-9]+)["']\s*\n\s*\.\.\.\s*)\z`, regexp2.None)
)

// pyDQ is compile_rules_py.dq: 'abc' -> "abc" for a plain single-quoted
// literal (no quote or backslash inside).
func pyDQ(lit string) string {
	if m := find(rxPySingleQ, lit); m != nil {
		return group(m, 1) + `"` + group(m, 2) + `"`
	}
	return lit
}

// pyKeywordArg is the keyword index of a Python argument entry.
func pyKeywordIndex(kw string) string { return "kw:" + kw }

// parsePyArg is compile_rules_py.parse_arg. With ext, an argument that is a
// call pattern holding metavariables (`padding.PSS(mgf=$M, ...)`) is a nested
// call argument ({"kind": "call", "call": <entry>}) instead of a skip.
func parsePyArg(a string, ext bool) (*OMap, error) { //nolint:gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	kw := ""
	if m := find(rxPyKeyword, a); m != nil { // never a metavariable: a name starts no `$`
		kw, a = group(m, 1), pyStrip(group(m, 2))
	}
	if a == jsEllipsis {
		if kw != "" {
			// kw=...: the keyword must be present.
			return omap("kind", strMetavar, "name", nil, "kw", kw), nil
		}
		return omap("kind", strEllipsis), nil
	}
	var out *OMap
	switch {
	case find(rxArgEllipsisMV, a) != nil:
		out = omap("kind", strEllipsis, "name", strings.ReplaceAll(a, "...", ""))
	case find(rxMetavar, a) != nil:
		out = omap("kind", strMetavar, "name", a)
	case ext && find(rxPyStringMV, a) != nil:
		// "$X": a string literal whose content binds $X.
		out = omap("kind", strMetavar, "name", group(find(rxPyStringMV, a), 1), "unquote", true)
	case a == `"..."` || a == `'...'`:
		out = omap("kind", "any_string")
	case ext && find(rxPyStringRx, a) != nil:
		// "=~/re/": a string literal whose content the regex matches.
		out = omap("kind", "string_regex", "value", group(find(rxPyStringRx, a), 1))
	case find(rxPyString, a) != nil || find(rxPyOtherLit, a) != nil:
		out = omap("kind", strLiteral, "value", pyDQ(a))
	case strings.Contains(a, "$") || strings.Contains(a, "..."):
		sub, err := nestedCall(a, ext)
		if err != nil {
			c := containerArg(a, ext)
			if c == nil {
				return nil, err
			}
			out = c
			break
		}
		out = omap("kind", "call", "call", sub)
	default:
		out = omap("kind", strText, "value", norm(a))
	}
	if kw != "" {
		if getString(out, "kind") == strEllipsis {
			return nil, skip("keyword argument bound to an ellipsis metavariable")
		}
		out.Set("kw", kw)
	}
	return out, nil
}

// parsePyCall is compile_rules_py.parse_call: one Python call pattern into
// {receiver, type, method, args, ...}, or a skip. With ext (the compiler's
// extensions, off for parity with the PoC), a dotted reference that is no
// call (`ssl.PROTOCOL_TLSv1`, `hashes.$ALG`) is a constant entry and an
// argument may be a nested call pattern.
func parsePyCall(v any, ext bool) (*OMap, error) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	p, ok := v.(string)
	if !ok {
		return nil, skip("pattern given as a mapping")
	}
	p = pyStrip(p)
	head, _, _ := strings.Cut(p, "(")
	if strings.Contains(p, "\n") || find(rxPyAssign, head) != nil || find(rxPyStatement, p) != nil {
		return nil, skip("statement, block or declaration pattern")
	}
	var call *OMap
	var m *regexp2.Match
	if m = find(rxPyTypeMVRecv, p); ext && m != nil { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		// a.$C.m(...): a class of module a named by a metavariable.
		call = omap("receiver", strType, strType, group(m, 1)+"."+group(m, 2), "method", group(m, 3), "type_metavar", group(m, 2))
	} else if m = find(rxPyAnyRecv, p); m != nil {
		call = omap("receiver", strAny, strType, nil, "method", group(m, 2))
	} else if m = find(rxPyTypeRecv, p); m != nil {
		call = omap("receiver", strType, strType, group(m, 1), "method", group(m, 2))
	} else if m = find(rxPyNoRecv, p); m != nil {
		call = omap("receiver", strNone, strType, nil, "method", group(m, 1))
	} else {
		if ext {
			if c := constantEntry(p); c != nil {
				return c, nil
			}
		}
		if find(rxPyReference, p) != nil {
			return nil, skip("not a call (attribute, constant, name or literal reference)")
		}
		return nil, skip("unrecognised pattern shape") //nolint:misspell // verbatim compile-report text; respelling changes the report output
	}
	rs := []rune(p)
	openI := m.Index + m.Length - 1
	closeI, err := matchingParen(rs, openI)
	if err != nil {
		return nil, err
	}
	if pyStrip(string(rs[closeI+1:])) != "" {
		return nil, skip("chained call pattern")
	}
	var args []any
	for _, text := range splitArgs(string(rs[openI+1 : closeI])) {
		a, err := parsePyArg(text, ext)
		if err != nil {
			return nil, err
		}
		args = append(args, a)
	}
	seenEllipsis, pos, fixed := false, int64(0), int64(0)
	for _, v := range args {
		a := as[*OMap](v)
		if getString(a, "kind") != strEllipsis {
			fixed++
		}
		if kw := getString(a, "kw"); kw != "" {
			a.Set("index", pyKeywordIndex(kw)) // a keyword argument has no position
			continue
		}
		if getString(a, "kind") == strEllipsis {
			seenEllipsis = true
		} else if seenEllipsis {
			return nil, skip("argument after an ellipsis (index not fixed)")
		}
		a.Set("index", pos)
		pos++
	}
	if args == nil {
		args = []any{}
	}
	call.Set("min_arity", fixed)
	if seenEllipsis {
		call.Set("max_arity", nil)
	} else {
		call.Set("max_arity", fixed)
	}
	call.Set("args", args)
	call.Set("method_regex", nil)
	if method := getString(call, "method"); strings.HasPrefix(method, "$") {
		call.Set("method_metavar", method)
		call.Set("method", nil)
	}
	return call, nil
}

// pyConjClauses is compile_rules_py.compile_conj's rewrite: the Python
// spelling of `$V = "..."; ... call($V)` is `$V = "$VALUE"` (or "...") on one
// line and `...` on the next; it becomes the Java spelling the compiler
// knows.
func pyConjClauses(clauses []any) []any {
	out := make([]any, len(clauses))
	for i, v := range clauses {
		out[i] = v
		c, ok := v.(*OMap)
		if !ok || !keySet(c, "pattern-not-inside") {
			continue
		}
		if m := find(rxPyNotAssign, pyStr(c.GetOr("pattern-not-inside"))); m != nil {
			out[i] = omap("pattern-not-inside", group(m, 1)+` = "..."; ... $SINK`)
		}
	}
	return out
}

// pythonRule: the rule is read with the Python shapes (its languages name
// python).
func pythonRule(r *OMap) bool {
	langs := asOr[[]any](r.GetOr("languages"))
	for _, l := range langs {
		if s, ok := l.(string); ok && strings.EqualFold(s, "python") {
			return true
		}
	}
	return false
}

// keywordIndices turns the symbolic keyword indices of compiled Python
// entries ("kw:<name>" as argument index, constraint arg_index, focus_arg)
// into the parameter ids the Python matcher files keyword arguments under
// (kwKey), as pymatch.load_index does. The caller holds the matching lock.
func keywordIndices(entries []*OMap) {
	fix := func(m *OMap, key string) {
		if s, ok := m.GetOr(key).(string); ok && strings.HasPrefix(s, "kw:") {
			m.Set(key, int64(kwKey(s[3:])))
		}
	}
	var entry func(e *OMap)
	entry = func(e *OMap) {
		for _, v := range listOf(e.GetOr("args")) {
			a := as[*OMap](v)
			fix(a, "index")
			if sub, ok := a.GetOr("call").(*OMap); ok {
				entry(sub) // a nested call argument (compile_py_ext.go)
			}
		}
		for _, key := range []string{"not_calls", "not_inside"} {
			for _, n := range listOf(e.GetOr(key)) {
				entry(as[*OMap](n))
			}
		}
		for _, c := range listOf(e.GetOr("constraints")) {
			fix(as[*OMap](c), "arg_index")
		}
		fix(e, "focus_arg")
	}
	for _, e := range entries {
		entry(e)
	}
}
