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

// The rule compiler: a port of the PoC's compile_rules.py. It reads OpenGrep crypto rules (YAML)
// and compiles them into the symbol index the matcher loads, one entry per sink call pattern. A
// Python rule (languages: [python]) is read with the Python shapes of compile_rules_py.py
// (compile_py.go). A rule that cannot be compiled faithfully is recorded as skipped with a reason; a clause
// that is dropped is recorded on the entry.
//
// The index is compiled on the client from the rule YAML it is served, so no precompiled index
// has to ship. Entries are built as ordered maps with the key order compile_rules.py gives its
// dicts, written as JSON and decoded into an Index, so the result is the Index loadIndex returns
// for compile_rules.py's index.json. YAML goes through parseYAML (PyYAML semantics) and the shape
// tests through regexp2, which agrees with Python's re on the constructs used here.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
)

const (
	cIdent = `[A-Za-z_][\w]*`
	cQName = cIdent + `(?:\.` + cIdent + `)*`
)

// Python regex forms: re.fullmatch, re.match (anchored at the start) and re.search.
func rxFull(p string) *regexp2.Regexp   { return regexp2.MustCompile(`\A(?:`+p+`)\z`, regexp2.None) }
func rxStart(p string) *regexp2.Regexp  { return regexp2.MustCompile(`\A(?:`+p+`)`, regexp2.None) }
func rxSearch(p string) *regexp2.Regexp { return regexp2.MustCompile(p, regexp2.None) }

var (
	rxPcreNamed     = rxSearch(`\(\?<([A-Za-z_]\w*)>`)
	rxArgEllipsisMV = rxFull(`\$\.\.\.[A-Z_0-9]+`)
	rxMetavar       = rxFull(`\$[A-Z_0-9]+`)
	rxStringLit     = rxFull(`"(?:[^"\\]|\\.)*"`)
	rxOtherLit      = rxFull(`-?\d+[lLfFdD]?|null|true|false`)
	rxTypedArg      = rxFull(`\(\s*` + cQName + `(?:<[^>]*>)?(?:\[\])?\s+\$[A-Z_0-9]+\s*\)`)
	rxAssign        = rxSearch(`[^=!<>]=[^=]`)
	rxCast          = rxStart(`^\(\s*` + cQName + `\s*\)\s*(?!\$)`)
	rxTypedStart    = rxStart(`^\(\s*` + cQName + `\s+\$`)
	rxNew           = rxStart(`^new\s+(` + cQName + `)\s*\(`)
	rxTypedRecv     = rxStart(`^\(\s*(` + cQName + `)\s+\$[A-Z_0-9]+\s*\)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxAnyRecv       = rxStart(`^(\$[A-Z_0-9]+)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxTypeRecv      = rxStart(`^(` + cQName + `)\s*\.\s*(\$?` + cIdent + `)\s*\(`)
	rxNoRecv        = rxStart(`^(\$?` + cIdent + `)\s*\(`)
	rxReference     = rxFull(`\$?` + cQName + `(\.\$[A-Z_0-9]+)?|-?\d+`)
	rxLiteralAlt    = rxFull(`-?\d+|"[^"]*"`)
	rxImportInside  = rxFull(`import\s+(` + cQName + `)(\.\*)?\s*;\s*\.\.\.`)
	rxPackageInside = rxFull(`package\s+(` + cQName + `)\s*;\s*\.\.\.`)
	rxNotAssigned   = regexp2.MustCompile(`\A(?:(\$[A-Z_0-9]+)\s*=\s*\"\.\.\.\"\s*;\s*\.\.\.\s*(.+))\z`, regexp2.Singleline)
)

// find runs a regex; the patterns above have no timeout, so an error is a bug.
func find(re *regexp2.Regexp, s string) *regexp2.Match {
	m, err := re.FindStringMatch(s)
	if err != nil {
		panic(err)
	}
	return m
}

func group(m *regexp2.Match, n int) string { return m.GroupByNumber(n).String() }

// groupOK is bool(m.group(n)): the group took part and is not empty.
func groupOK(m *regexp2.Match, n int) bool {
	g := m.GroupByNumber(n)
	return g != nil && len(g.Captures) > 0 && g.String() != ""
}

// skipError is compile_rules.Skip: the rule (or one pattern-either alternative) is not compiled.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

func skip(reason string) error { return &skipError{reason} }

func asSkip(err error) (*skipError, bool) {
	var s *skipError
	ok := errors.As(err, &s)
	return s, ok
}

// pcreToPyText is compile_rules.pcre_to_py: PCRE named groups (?<name>...) become (?P<name>...),
// the spelling the index stores.
func pcreToPyText(rx string) string {
	out, err := rxPcreNamed.Replace(rx, "(?P<$1>", -1, -1)
	if err != nil {
		panic(err)
	}
	return out
}

// pyReEscape is Python 3.7+ re.escape.
func pyReEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("()[]{}?*+-|^$\\.&~# \t\n\r\v\f", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// omap builds an ordered map from key, value pairs.
func omap(kv ...any) *OMap {
	m := &OMap{}
	for i := 0; i < len(kv); i += 2 {
		m.Set(kv[i], kv[i+1])
	}
	return m
}

// keySet reports whether v is a mapping whose keys are exactly want (Python: set(v) == {want}).
func keySet(v any, want string) bool {
	m, ok := v.(*OMap)
	return ok && m.Len() == 1 && m.Has(want)
}

func asMap(v any, what string) (*OMap, error) {
	m, ok := v.(*OMap)
	if !ok {
		return nil, fmt.Errorf("%s is not a mapping: %s", what, pyRepr(v))
	}
	return m, nil
}

func asSeq(v any, what string) ([]any, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a list: %s", what, pyRepr(v))
	}
	return l, nil
}

func asString(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s is not a string: %s", what, pyRepr(v))
	}
	return s, nil
}

func getString(m *OMap, k string) string {
	s := asOr[string](m.GetOr(k))
	return s
}

// splitArgs splits a call's argument text on top-level commas.
func splitArgs(s string) []string {
	var out []string
	var cur []rune
	depth := 0
	var quote rune
	for _, ch := range s {
		if quote != 0 {
			cur = append(cur, ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch {
		case ch == '"' || ch == '\'':
			quote = ch
		case strings.ContainsRune("([{", ch):
			depth++
		case strings.ContainsRune(")]}", ch):
			depth--
		case ch == ',' && depth == 0:
			out = append(out, pyStrip(string(cur)))
			cur = cur[:0]
			continue
		}
		cur = append(cur, ch)
	}
	if t := pyStrip(string(cur)); t != "" {
		out = append(out, t)
	}
	return out
}

// matchingParen returns the index of the parenthesis closing the one at i.
func matchingParen(s []rune, i int) (int, error) {
	depth := 0
	var quote rune
	for j := i; j < len(s); j++ {
		ch := s[j]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j, nil
			}
		}
	}
	return 0, skip("unbalanced pattern")
}

func parseArg(a string) (*OMap, error) {
	switch {
	case a == jsEllipsis:
		return omap("kind", strEllipsis), nil
	case find(rxArgEllipsisMV, a) != nil:
		return omap("kind", strEllipsis, "name", strings.ReplaceAll(a, "...", "")), nil
	case find(rxMetavar, a) != nil:
		return omap("kind", strMetavar, "name", a), nil
	case a == `"..."`:
		return omap("kind", "any_string"), nil
	case find(rxStringLit, a) != nil || find(rxOtherLit, a) != nil:
		return omap("kind", strLiteral, "value", a), nil
	case find(rxTypedArg, a) != nil:
		return nil, skip("typed metavariable in argument")
	case strings.Contains(a, "$"):
		return nil, skip("argument is a sub-pattern with a metavariable")
	}
	return omap("kind", strText, "value", norm(a)), nil
}

// parseCallPattern parses one call pattern into {receiver, type, method, args, ...}, or skips it.
// Indices are code points, as in Python.
func parseCallPattern(p string) (*OMap, error) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	p = pyStrip(p)
	if strings.HasSuffix(p, ";") {
		p = pyStrip(p[:len(p)-1])
	}
	if strings.Contains(p, "\n") || strings.Contains(p, "{") || find(rxAssign, p) != nil {
		return nil, skip("statement, block or declaration pattern")
	}
	if strings.HasPrefix(p, "super(") || strings.HasPrefix(p, "this(") {
		return nil, skip("constructor delegation (super/this) pattern")
	}
	if find(rxCast, p) != nil && find(rxTypedStart, p) == nil {
		return nil, skip("cast expression pattern")
	}
	var call *OMap
	var m *regexp2.Match
	if m = find(rxNew, p); m != nil { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		call = omap("receiver", strType, strType, group(m, 1), "method", strInit)
	} else if m = find(rxTypedRecv, p); m != nil {
		call = omap("receiver", strTypedMetavar, strType, group(m, 1), "method", group(m, 2))
	} else if m = find(rxAnyRecv, p); m != nil {
		call = omap("receiver", strAny, strType, nil, "method", group(m, 2))
	} else if m = find(rxTypeRecv, p); m != nil {
		call = omap("receiver", strType, strType, group(m, 1), "method", group(m, 2))
	} else if m = find(rxNoRecv, p); m != nil {
		call = omap("receiver", strNone, strType, nil, "method", group(m, 1))
	} else {
		if find(rxReference, p) != nil {
			return nil, skip("not a call (field, constant, type or literal reference)")
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
	prefix := string(rs[:openI])
	receiver := getString(call, "receiver")
	maxParens := 0
	if receiver == strTypedMetavar {
		maxParens = 1
	}
	if strings.Count(prefix, "(") > maxParens {
		return nil, skip("chained call pattern")
	}
	if receiver == strType && strings.Contains(prefix, "(") {
		return nil, skip("chained call pattern")
	}
	var args []any
	seenEllipsis := false
	fixed := 0
	for i, text := range splitArgs(string(rs[openI+1 : closeI])) {
		a, err := parseArg(text)
		if err != nil {
			return nil, err
		}
		if getString(a, "kind") == strEllipsis {
			seenEllipsis = true
		} else {
			if seenEllipsis {
				return nil, skip("argument after an ellipsis (index not fixed)")
			}
			fixed++
		}
		a.Set("index", int64(i))
		args = append(args, a)
	}
	if args == nil {
		args = []any{}
	}
	call.Set("min_arity", int64(fixed))
	if seenEllipsis {
		call.Set("max_arity", nil)
	} else {
		call.Set("max_arity", int64(fixed))
	}
	call.Set("args", args)
	call.Set("method_regex", nil)
	if method := getString(call, "method"); strings.HasPrefix(method, "$") {
		call.Set("method_metavar", method)
		call.Set("method", nil)
	}
	return call, nil
}

// slot is where a metavariable binds in a call: an argument index (an int64,
// or a Python keyword's "kw:<name>"), or the method name.
type slot struct {
	method    bool
	arg       any
	typ       bool   // with method: a Python class name in the callee (`a.$C.m(...)`)
	container bool   // a Python dict / list display argument holding the metavariable
	dictKey   string // with container: the dict key whose value the metavariable is
	unquote   bool   // a Python "$X" argument: the string's content
}

func metavarSlot(call *OMap, name any) *slot {
	n, ok := name.(string)
	if !ok {
		return nil
	}
	for _, v := range as[[]any](call.GetOr("args")) {
		a := as[*OMap](v)
		if getString(a, "name") == n && a.Has("name") && getString(a, "kind") == strMetavar {
			return &slot{arg: a.GetOr("index"), unquote: a.GetOr("unquote") == true}
		}
		if getString(a, "kind") == "container" && listHas(listOf(a.GetOr("names")), n) {
			key := asOr[string](as[*OMap](a.GetOr("entries")).GetOr(n))
			return &slot{arg: a.GetOr("index"), container: true, dictKey: key}
		}
	}
	if mv, ok := call.Get("method_metavar"); ok && mv == n {
		return &slot{method: true}
	}
	if mv, ok := call.Get("type_metavar"); ok && mv == n {
		return &slot{method: true, typ: true}
	}
	return nil
}

// literalAlternatives turns a metavariable-pattern made of literal pattern alternatives into a
// regex; ok is false for any other sub-pattern.
func literalAlternatives(node *OMap) (string, bool, error) {
	items := []any{node}
	if v, has := node.Get("pattern-either"); has {
		l, err := asSeq(v, "metavariable-pattern pattern-either")
		if err != nil {
			return "", false, err
		}
		items = l
	}
	var pats []string
	for _, item := range items {
		if !keySet(item, "pattern") {
			return "", false, nil
		}
		text := pyStrip(pyStr(as[*OMap](item).GetOr("pattern")))
		if find(rxLiteralAlt, text) == nil {
			return "", false, nil
		}
		pats = append(pats, pyReEscape(text))
	}
	if len(pats) == 0 {
		return "", false, nil
	}
	return "^(?:" + strings.Join(pats, "|") + ")$", true, nil
}

// compileCtx carries the pattern-either alternatives dropped anywhere in a rule. It is not rolled
// back when an alternative is dropped later: a rule's entries record every drop seen. python: the
// rule is read with the Python shapes (compile_py.go).
type compileCtx struct {
	dropped []string
	python  bool
	golang  bool
	ruby    bool
	// ext: the compiler's Python extensions (compile_py_ext.go) apply; off
	// for parity with compile_rules_py.py.
	ext bool
}

// parseCall parses a call pattern with the rule's language shapes.
func (ctx *compileCtx) parseCall(v any) (*OMap, error) {
	if ctx.python {
		return parsePyCall(v, ctx.ext)
	}
	text, err := asString(v, "pattern")
	if err != nil {
		return nil, err
	}
	if ctx.golang {
		return parseGoCall(text)
	}
	if ctx.ruby {
		return parseRubyCall(text)
	}
	return parseCallPattern(text)
}

func appendTo(m *OMap, key string, v any) {
	m.Set(key, append(as[[]any](m.GetOr(key)), v))
}

// compileConj compiles a conjunction (a patterns list) into sinks.
func compileConj(clauses []any, ctx *compileCtx) ([]*OMap, error) { //nolint:funlen,gocognit,gocyclo // compileConj is the port of compile_rules.compile_conj, one case per pattern operator
	if ctx.python {
		clauses = pyConjClauses(clauses)
	}
	var producers *goProducerConj
	if ctx.golang {
		var err error
		if clauses, producers, err = goProducerClauses(clauses); err != nil {
			return nil, err
		}
	}
	var positives []*OMap
	var filters []*OMap
	for _, v := range clauses {
		c, err := asMap(v, "patterns clause")
		if err != nil {
			return nil, err
		}
		if either, has := c.Get("pattern-either"); has && allPatternInside(either) {
			var texts []any
			for _, i := range as[[]any](either) {
				texts = append(texts, as[*OMap](i).GetOr("pattern-inside"))
			}
			if texts == nil {
				texts = []any{}
			}
			filters = append(filters, omap("pattern-inside-any", texts))
		} else if c.Has("pattern") || c.Has("pattern-either") || c.Has("patterns") {
			positives = append(positives, c)
		} else {
			filters = append(filters, c)
		}
	}
	if len(positives) != 1 {
		return nil, skip(fmt.Sprintf("conjunction of %d positive patterns", len(positives)))
	}
	sinks, err := compileFormula(positives[0], ctx)
	if err != nil {
		return nil, err
	}
	var aliasNots []*goAliasNot
	for _, c := range filters {
		if c.Len() != 1 {
			return nil, fmt.Errorf("patterns clause with %d keys: %s", c.Len(), pyRepr(c))
		}
		key, val := pyStr(c.Keys[0]), c.Vals[0]
		switch key {
		case "focus-metavariable":
			for _, s := range sinks {
				sl := metavarSlot(s, val)
				if ctx.ext && sl == nil && receiverMetavar(s) == val {
					continue // the receiver: reported at the call
				}
				if ctx.golang && sl == nil && getString(s, goReceiverMetavarKey) == val {
					// The receiver: reported at the receiver's span, as OpenGrep does.
					s.Set(keyFocusReceiver, true)
					continue
				}
				if sl == nil || sl.method {
					return nil, skip("focus-metavariable not bound to an argument")
				}
				s.Set("focus_arg", sl.arg)
			}
		case "metavariable-regex", "metavariable-pattern":
			if err := compileMetavarFilter(key, val, sinks, ctx); err != nil {
				return nil, err
			}
		case "pattern-inside", "pattern-inside-any":
			inside := compileInside
			if ctx.ext {
				inside = compilePyInside
			}
			if ctx.golang {
				inside = compileGoInside
			}
			if err := inside(val, sinks); err != nil {
				return nil, err
			}
		case keyPatternNot:
			nots := []any{val}
			if a := goAliasScopedNot(val); ctx.golang && a != nil {
				aliasNots = append(aliasNots, a) // checked once the import guards typed the sinks
				continue
			}
			if ctx.golang {
				var err error
				if nots, err = goNotPatterns(val); err != nil {
					return nil, err
				}
			}
			for _, v := range nots {
				neg, err := ctx.parseCall(v)
				if err != nil {
					if s, ok := asSkip(err); ok {
						return nil, skip(fmt.Sprintf("pattern-not that is not a plain call (%s)", s.reason))
					}
					return nil, err
				}
				for _, s := range sinks {
					appendTo(s, "not_calls", neg)
				}
			}
		case "pattern-not-inside":
			if _, isText := val.(string); !isText && ctx.ext {
				if !reassignedElsewhere(val) {
					return nil, skip("pattern-not-inside of an unsupported shape")
				}
				for _, s := range sinks {
					appendTo(s, "dropped_clauses", "pattern-not-inside reassignment not checked")
				}
				continue
			}
			text, err := asString(val, "pattern-not-inside")
			if err != nil {
				return nil, err
			}
			m := find(rxNotAssigned, pyStrip(text))
			if m == nil && ctx.ext {
				if compilePyNotInside(text, sinks) {
					continue
				}
			}
			if m == nil {
				return nil, skip("pattern-not-inside of an unsupported shape")
			}
			name := group(m, 1)
			for _, s := range sinks {
				sl := metavarSlot(s, name)
				if sl == nil || sl.method {
					return nil, skip("pattern-not-inside on a metavariable not bound to an argument")
				}
				// $V = "..."; ... call($V): the argument is a variable assigned a string literal.
				appendTo(s, "constraints", omap(strMetavar, name, "arg_index", sl.arg,
					"kind", "not_assigned_string_literal", "polarity", "negative", "clause", key))
			}
		default:
			return nil, skip("unsupported clause " + key)
		}
	}
	for _, a := range aliasNots {
		for _, s := range sinks {
			if !a.impliedFor(getString(s, strType)) {
				return nil, skip("pattern-not of an unsupported sub-rule")
			}
			appendTo(s, "dropped_clauses", goAliasScopedNotDropped)
		}
	}
	if producers != nil {
		if err := producers.attach(sinks); err != nil {
			return nil, err
		}
	}
	return sinks, nil
}

// goNotPatterns lists the call patterns of a Go pattern-not. A pattern-not
// written as a sub-rule (`pattern-not: {pattern: ...}` or
// `pattern-not: {pattern-either: [{pattern: ...}, ...]}`) subtracts each of
// its calls, as OpenGrep does. A not_calls entry carries no constraints, so
// any other sub-rule is skipped instead of aborting the compile.
func goNotPatterns(val any) ([]any, error) {
	if _, ok := val.(string); ok {
		return []any{val}, nil
	}
	sub, ok := val.(*OMap)
	if !ok || sub.Len() != 1 {
		return nil, skip("pattern-not of an unsupported sub-rule")
	}
	switch pyStr(sub.Keys[0]) {
	case jsLeaf:
		return []any{sub.Vals[0]}, nil
	case "pattern-either":
		var out []any
		for _, alt := range as[[]any](sub.Vals[0]) {
			m, ok := alt.(*OMap)
			if !ok || m.Len() != 1 || pyStr(m.Keys[0]) != jsLeaf {
				return nil, skip("pattern-not of a pattern-either that is not plain patterns")
			}
			out = append(out, m.Vals[0])
		}
		if len(out) == 0 {
			return nil, skip("pattern-not of an empty pattern-either")
		}
		return out, nil
	}
	return nil, skip("pattern-not of an unsupported sub-rule")
}

// allPatternInside is all(set(i) == {"pattern-inside"} for i in either).
func allPatternInside(either any) bool {
	l, ok := either.([]any)
	if !ok {
		return false
	}
	for _, i := range l {
		if !keySet(i, "pattern-inside") {
			return false
		}
	}
	return true
}

// compileMetavarFilter compiles a metavariable-regex or a literal metavariable-pattern into a
// method regex or an argument constraint.
func compileMetavarFilter(key string, val any, sinks []*OMap, ctx *compileCtx) error { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	m, err := asMap(val, key)
	if err != nil {
		return err
	}
	name, has := m.Get("metavariable")
	if !has {
		return fmt.Errorf("%s without metavariable", key)
	}
	var rx string
	qualified := false               // dotted names: also tried on the text qualified through the imports
	if key == "metavariable-regex" { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		r, err := asString(m.GetOr("regex"), "metavariable-regex regex")
		if err != nil {
			return err
		}
		rx = pcreToPyText(r)
	} else {
		r, ok, err := literalAlternatives(m)
		if err != nil {
			return err
		}
		if !ok && ctx.ext {
			r, ok = pyNameAlternatives(m)
			qualified = ok
		}
		if !ok {
			return skip("metavariable-pattern with a non-literal sub-pattern")
		}
		rx = r
	}
	if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
		return fmt.Errorf("%s regex %q: %w", key, rx, err)
	}
	for _, s := range sinks {
		owner, sl := metavarOwner(s, name, ctx.ext)
		if sl == nil || sl.container && sl.dictKey == "" {
			return skip("metavariable-regex on a metavariable not bound to an argument or method name")
		}
		if sl.typ {
			owner.Set("type_regex", rx)
			continue
		}
		if sl.method {
			owner.Set("method_regex", rx)
			continue
		}
		polarity := "positive"
		if strings.HasPrefix(rx, "^(?!") && strings.HasSuffix(strings.TrimRight(rx, "$"), ".+") {
			polarity = "negative"
		}
		c := omap(strMetavar, name, "arg_index", sl.arg, "regex", rx, "polarity", polarity, "clause", key)
		if qualified {
			c.Set("qualified", true)
		}
		if sl.unquote {
			c.Set("unquote", true)
		}
		if sl.dictKey != "" {
			c.Set("dict_key", sl.dictKey)
		}
		appendTo(owner, "constraints", c)
	}
	return nil
}

// compileInside compiles pattern-inside clauses naming an import or a package into callee or
// caller package constraints.
func compileInside(val any, sinks []*OMap) error { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	vals, ok := val.([]any)
	if !ok {
		vals = []any{val}
	}
	type imp struct {
		name string
		wild bool
	}
	var pkgs []imp
	var callers []any
	for _, v := range vals {
		text, err := asString(v, "pattern-inside")
		if err != nil {
			return err
		}
		text = pyStrip(text)
		if m := find(rxImportInside, text); m != nil {
			pkgs = append(pkgs, imp{group(m, 1), groupOK(m, 2)})
		} else if m := find(rxPackageInside, text); m != nil {
			callers = append(callers, group(m, 1))
		} else {
			return skip("pattern-inside that is not an import or package")
		}
	}
	if len(callers) > 0 && len(pkgs) > 0 {
		return skip("pattern-inside mixing package and import")
	}
	for _, s := range sinks {
		if len(callers) > 0 {
			s.Set("caller_packages", callers)
			continue
		}
		// The fragment has no imports. An import clause becomes a constraint on the callee's
		// package only when the import names the callee's own type (or a wildcard package);
		// otherwise the clause is dropped and recorded.
		typ := getString(s, strType)
		simple := typ[strings.LastIndexByte(typ, '.')+1:]
		var okPkgs []any
		for _, p := range pkgs {
			if typ == "" || (!p.wild && p.name[strings.LastIndexByte(p.name, '.')+1:] != simple) {
				continue
			}
			if p.wild {
				okPkgs = append(okPkgs, p.name)
			} else if i := strings.LastIndexByte(p.name, '.'); i >= 0 {
				okPkgs = append(okPkgs, p.name[:i])
			} else {
				okPkgs = append(okPkgs, p.name)
			}
		}
		if len(okPkgs) > 0 {
			s.Set("callee_packages", okPkgs)
		} else {
			appendTo(s, "dropped_clauses", "pattern-inside import not about the callee type")
		}
	}
	return nil
}

func compileFormula(v any, ctx *compileCtx) ([]*OMap, error) { //nolint:gocognit // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	node, err := asMap(v, "formula")
	if err != nil {
		return nil, err
	}
	if pat, has := node.Get("pattern"); has {
		call, err := ctx.parseCall(pyStr(pat))
		if err != nil {
			return nil, err
		}
		call.Set("constraints", []any{})
		call.Set("not_calls", []any{})
		call.Set("focus_arg", nil)
		call.Set("dropped_clauses", []any{})
		call.Set("pattern", pyStrip(pyStr(pat)))
		return []*OMap{call}, nil
	}
	if either, has := node.Get("pattern-either"); has { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		items, err := asSeq(either, "pattern-either")
		if err != nil {
			return nil, err
		}
		var out []*OMap
		var errs []string
		for _, item := range items {
			sinks, err := compileFormula(item, ctx)
			if err != nil {
				s, ok := asSkip(err)
				if !ok {
					return nil, err
				}
				errs = append(errs, s.reason)
				continue
			}
			out = append(out, sinks...)
		}
		if len(out) == 0 {
			if len(errs) == 0 {
				return nil, fmt.Errorf("empty pattern-either")
			}
			return nil, skip(errs[0])
		}
		// Some alternatives compiled: keep them, record the dropped ones.
		for _, e := range errs {
			ctx.dropped = append(ctx.dropped, "pattern-either alternative: "+e)
		}
		return out, nil
	}
	if pats, has := node.Get("patterns"); has {
		clauses, err := asSeq(pats, "patterns")
		if err != nil {
			return nil, err
		}
		return compileConj(clauses, ctx)
	}
	keys := make([]string, len(node.Keys))
	for i, k := range node.Keys {
		keys[i] = pyStr(k)
	}
	return nil, skip("unsupported formula " + strings.Join(keys, ","))
}

// compileSource compiles a taint source into regexes on a value (nil = any expression).
func compileSource(v any) ([]any, error) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	node, err := asMap(v, "taint source")
	if err != nil {
		return nil, err
	}
	if either, has := node.Get("pattern-either"); has {
		items, err := asSeq(either, "pattern-either")
		if err != nil {
			return nil, err
		}
		var out []any
		for _, item := range items {
			rxs, err := compileSource(item)
			if err != nil {
				return nil, err
			}
			out = append(out, rxs...)
		}
		return out, nil
	}
	clauses := []any{node}
	if pats, has := node.Get("patterns"); has {
		if clauses, err = asSeq(pats, "patterns"); err != nil {
			return nil, err
		}
	}
	pat := ""
	var rx any
	for _, cv := range clauses {
		c, err := asMap(cv, "taint source clause")
		if err != nil {
			return nil, err
		}
		if p, has := c.Get("pattern"); has {
			pat = pyStrip(pyStr(p))
		} else if mr, has := c.Get("metavariable-regex"); has {
			m, err := asMap(mr, "metavariable-regex")
			if err != nil {
				return nil, err
			}
			r, err := asString(m.GetOr("regex"), "metavariable-regex regex")
			if err != nil {
				return nil, err
			}
			rx = pcreToPyText(r)
		} else {
			return nil, skip("taint source is not a bare metavariable")
		}
	}
	if pat == "" || find(rxMetavar, pat) == nil {
		return nil, skip("taint source is not a bare metavariable")
	}
	return []any{rx}, nil
}

func compileRule(r *OMap, poc bool) ([]*OMap, error) {
	if nodeRule(r) {
		return compileJSRule(r)
	}
	if rustRule(r) {
		return compileRustRule(r)
	}
	if cRule(r) {
		return compileCRule(r)
	}
	python := pythonRule(r)
	ctx := &compileCtx{python: python, golang: goRule(r), ruby: rubyRule(r), ext: python && !poc}
	sinks, err := compileRuleSinks(r, ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sinks {
		if ctx.golang {
			dropGoCompileKeys(s)
		}
		if ctx.ruby {
			rubyLooseReceiver(s)
		}
		own := as[[]any](s.GetOr("dropped_clauses"))
		all := make([]any, 0, len(own)+len(ctx.dropped))
		all = append(all, own...)
		for _, d := range ctx.dropped {
			all = append(all, d)
		}
		s.Set("dropped_clauses", all)
	}
	return sinks, nil
}

func compileRuleSinks(r *OMap, ctx *compileCtx) ([]*OMap, error) { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	if mode := asOr[string](r.GetOr("mode")); mode == strTaint { //nolint:nestif // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
		if pyTruthy(r.GetOr("pattern-sanitizers")) || pyTruthy(r.GetOr("pattern-propagators")) && !ctx.golang {
			return nil, skip("taint sanitizers/propagators")
		}
		if pyTruthy(r.GetOr("pattern-propagators")) {
			// Go: a propagator only adds flow, so leaving it out loses
			// findings and never adds one.
			ctx.dropped = append(ctx.dropped, "taint propagators")
		}
		srcs, err := asSeq(r.GetOr("pattern-sources"), "pattern-sources")
		if err != nil {
			return nil, err
		}
		sources := []any{}
		var object *OMap
		for _, src := range srcs {
			if ctx.golang {
				src = goCallSource(src)
			}
			rxs, err := compileSource(src)
			if isSkipError(err) && ctx.golang {
				if object = goObjectSources(srcs, ctx); object != nil {
					break
				}
			} else if isSkipError(err) && ctx.ext {
				if object = objectSources(srcs, ctx); object != nil {
					break
				}
			}
			if err != nil {
				return nil, err
			}
			sources = append(sources, rxs...)
		}
		snks, err := asSeq(r.GetOr("pattern-sinks"), "pattern-sinks")
		if err != nil {
			return nil, err
		}
		var sinks []*OMap
		for _, snk := range snks {
			out, err := compileFormula(snk, ctx)
			if err != nil {
				return nil, err
			}
			sinks = append(sinks, out...)
		}
		if object != nil {
			sources = []any{}
			if err := objectFlowSinks(sinks, object); err != nil {
				return nil, err
			}
		}
		for _, s := range sinks {
			s.Set("taint_sources", sources)
		}
		return sinks, nil
	}
	node := &OMap{}
	for _, k := range []string{"pattern", "pattern-either", "patterns"} {
		if v, has := r.Get(k); has {
			node.Set(k, v)
		}
	}
	if node.Len() != 1 {
		if r.Has("pattern-regex") || r.Has("pattern-not-regex") {
			return nil, skip("pattern-regex")
		}
		return nil, skip("unsupported top-level formula")
	}
	return compileFormula(node, ctx)
}

// compiledRules is compile_rules.py's output minus the report: the index entries and one record
// per rule (compiled with its dropped clauses and sink count, or skipped with the reason).
type compiledRules struct {
	Entries []*OMap
	Rules   []*OMap
}

// ruleFiles is glob(rulesDir/**/*.y*ml, recursive=True), sorted: hidden files and directories
// are left out, as Python's glob does.
func ruleFiles(rulesDir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != rulesDir && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if lenient(filepath.Match("*.y*ml", d.Name())) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func compileRulesDir(rulesDir string) (*compiledRules, error) {
	return compileRulesDirMode(rulesDir, false)
}

// compileRulesDirMode compiles the rules under rulesDir; poc leaves out the
// compiler's Python extensions (compile_py_ext.go), which gives
// compile_rules_py.py's output.
func compileRulesDirMode(rulesDir string, poc bool) (*compiledRules, error) {
	if _, err := os.Stat(rulesDir); err != nil {
		return nil, err
	}
	files, err := ruleFiles(rulesDir)
	if err != nil {
		return nil, err
	}
	out := &compiledRules{}
	for _, path := range files {
		doc, err := loadYAML(path)
		if err != nil {
			return nil, err
		}
		if !pyTruthy(doc) {
			doc = &OMap{}
		}
		dm, err := asMap(doc, path)
		if err != nil {
			return nil, err
		}
		rules, has := dm.Get("rules")
		if !has {
			continue
		}
		rl, err := asSeq(rules, path+": rules")
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(rulesDir, path)
		if err != nil {
			return nil, err
		}
		for _, rv := range rl {
			if err := compileOne(rv, filepath.ToSlash(rel), out, poc); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	return out, nil
}

// compileOne compiles one rule, appending its entries and its record.
func compileOne(rv any, file string, out *compiledRules, poc bool) error {
	r, err := asMap(rv, "rule")
	if err != nil {
		return err
	}
	id, has := r.Get("id")
	if !has {
		return fmt.Errorf("rule without id")
	}
	mode := asOr[string](r.GetOr("mode"))
	taint := mode == strTaint
	var meta any = &OMap{}
	if md := r.GetOr("metadata"); pyTruthy(md) {
		mm, err := asMap(md, "metadata")
		if err != nil {
			return err
		}
		if c := mm.GetOr("crypto"); pyTruthy(c) {
			meta = c
		}
	}
	rec := omap("rule_id", id, "file", file, strTaint, taint)
	sinks, err := compileRule(r, poc)
	if err != nil {
		s, ok := asSkip(err)
		if !ok {
			return fmt.Errorf("rule %s: %w", pyStr(id), err)
		}
		rec.Set("status", "skipped")
		rec.Set("reason", s.reason)
		out.Rules = append(out.Rules, rec)
		return nil
	}
	rec.Set("status", "compiled")
	seen := map[string]bool{}
	var dropped []string
	for _, s := range sinks {
		for _, d := range as[[]any](s.GetOr("dropped_clauses")) {
			if ds := as[string](d); !seen[ds] {
				seen[ds] = true
				dropped = append(dropped, ds)
			}
		}
	}
	sort.Strings(dropped)
	dl := make([]any, len(dropped))
	for i, d := range dropped {
		dl[i] = d
	}
	rec.Set("dropped_clauses", dl)
	for _, s := range sinks {
		s.Set("rule_id", id)
		s.Set(strTaint, taint)
		s.Set("metadata", meta)
		out.Entries = append(out.Entries, s)
	}
	rec.Set("sinks", int64(len(sinks)))
	out.Rules = append(out.Rules, rec)
	return nil
}

// entriesJSON writes the entries as compile_rules.py's index.json does ({"entries": [...]}).
func (c *compiledRules) entriesJSON() []byte {
	var b strings.Builder
	b.WriteString(`{"entries": [`)
	for i, e := range c.Entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(jsonValue(e))
	}
	b.WriteString("]}")
	return []byte(b.String())
}

// CompileIndex compiles the rules under rulesDir into the symbol index. It returns what loadIndex
// returns for compile_rules.py's index.json of the same rules.
func CompileIndex(rulesDir string) (*Index, error) {
	c, err := compileRulesDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("compile index: %w", err)
	}
	ix, err := c.index()
	if err != nil {
		return nil, fmt.Errorf("compile index: %w", err)
	}
	return ix, nil
}

// index is the Index the compiled entries make.
func (c *compiledRules) index() (*Index, error) {
	keywordIndices(c.Entries)
	var ix Index
	if err := json.Unmarshal(c.entriesJSON(), &ix); err != nil {
		return nil, err
	}
	if err := ix.validateNode(); err != nil {
		return nil, err
	}
	ix.prepare()
	return &ix, nil
}
