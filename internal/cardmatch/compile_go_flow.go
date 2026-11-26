// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"regexp"
	"strings"
)

// The Go object sources of a taint rule (go-port audit T4): the origin the
// sink's receiver must hold (go_flow.go). A source is
//
//   - a call `pkg.F(...)`: a factory, the object it returns;
//   - a typed metavariable `($X : pkg.T)` / `($X : *pkg.T)`: any value of
//     type pkg.T (types);
//   - a composite literal `pkg.T{...}` / `&pkg.T{...}` or a declaration
//     `var $X pkg.T`: an object of type pkg.T one makes (made);
//
// either alone or after pattern-inside import clauses, whose path qualifies
// the package name. Any other alternative is dropped and recorded.

var (
	rxGoSourceComposite = regexp.MustCompile(`^&?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\{\s*\.{3}\s*\}$`)
	rxGoSourceTyped     = regexp.MustCompile(`^\(\s*\$[A-Z_][A-Z0-9_]*\s*:\s*\*?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\)$`)
	rxGoSourceVar       = regexp.MustCompile(`^var\s+\$[A-Z_][A-Z0-9_]*\s+\*?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)$`)
)

// goObjectSources reads a Go taint rule's object sources; nil when it reads
// none.
func goObjectSources(srcs []any, ctx *compileCtx) *OMap {
	r := &goSourceReader{}
	for _, s := range srcs {
		r.walk(s, nil)
	}
	if len(r.types)+len(r.made)+len(r.froms) == 0 {
		return nil
	}
	if r.dropped > 0 {
		ctx.dropped = append(ctx.dropped, "taint source alternative not compiled")
	}
	return omap("types", r.types, "from", r.froms, "not_from", []any{}, "made", r.made)
}

type goSourceReader struct {
	types, made, froms []any
	dropped            int
}

// walk reads one source clause under the import bindings of the clauses
// around it.
func (r *goSourceReader) walk(v any, bindings map[string]map[string]bool) {
	m, ok := v.(*OMap)
	switch {
	case !ok || m.Len() != 1:
		r.dropped++
	case m.Has(keyPatternEither):
		for _, x := range listOf(m.GetOr(keyPatternEither)) {
			r.walk(x, bindings)
		}
	case m.Has(keyPatterns):
		r.patterns(listOf(m.GetOr(keyPatterns)), bindings)
	case m.Has(keyPattern):
		if !r.pattern(pyStrip(pyStr(m.GetOr(keyPattern))), bindings) {
			r.dropped++
		}
	default:
		r.dropped++
	}
}

// patterns reads import clauses (alone or as an either of them) and one
// positive clause.
func (r *goSourceReader) patterns(clauses []any, outer map[string]map[string]bool) {
	var positive any
	var insides []any
	for _, c := range clauses {
		cm, ok := c.(*OMap)
		switch {
		case !ok || cm.Len() != 1:
			r.dropped++
			return
		case cm.Has(keyPatternInside):
			insides = append(insides, cm.GetOr(keyPatternInside))
		case cm.Has(keyPatternEither) && goAllInsides(cm.GetOr(keyPatternEither)):
			for _, x := range listOf(cm.GetOr(keyPatternEither)) {
				insides = append(insides, asOr[*OMap](x).GetOr(keyPatternInside))
			}
		case positive == nil && (cm.Has(keyPattern) || cm.Has(keyPatternEither)):
			positive = cm
		default:
			r.dropped++
			return
		}
	}
	bindings := outer
	if len(insides) > 0 {
		b, err := goInsideBindings(insides)
		if err != nil {
			r.dropped++
			return
		}
		bindings = b
	}
	if positive == nil {
		r.dropped++
		return
	}
	r.walk(positive, bindings)
}

// goAllInsides: an either of pattern-inside clauses only.
func goAllInsides(v any) bool {
	l := listOf(v)
	for _, x := range l {
		if !keySet(x, keyPatternInside) || asOr[*OMap](x).Len() != 1 {
			return false
		}
	}
	return len(l) > 0
}

// pattern reads one source pattern; false when it is none of the shapes.
func (r *goSourceReader) pattern(text string, bindings map[string]map[string]bool) bool {
	if m := rxGoSourceTyped.FindStringSubmatch(text); m != nil {
		return r.addType(&r.types, m[1], bindings)
	}
	for _, rx := range []*regexp.Regexp{rxGoSourceComposite, rxGoSourceVar} {
		if m := rx.FindStringSubmatch(text); m != nil {
			return r.addType(&r.made, m[1], bindings)
		}
	}
	call, err := parseGoCall(text)
	if err != nil || getString(call, "receiver") != strType || constrainingArgs(call) {
		return false
	}
	callee, ok := goQualify(getString(call, strType)+"."+getString(call, "method"), bindings)
	if !ok {
		return false
	}
	r.froms = append(r.froms, omap("call", callee))
	return true
}

// addType adds the qualified type name to list; false when it has no
// package or binds several.
func (r *goSourceReader) addType(list *[]any, name string, bindings map[string]map[string]bool) bool {
	t, ok := goQualify(name, bindings)
	if ok && !listHas(*list, t) {
		*list = append(*list, t)
	}
	return ok
}

// goQualify writes a package-qualified name (`otr.Conversation`) with the
// import path the bindings give its package; the name as written when they
// bind nothing for it. ok is false for a name with no package, or bound to
// several paths.
func goQualify(name string, bindings map[string]map[string]bool) (string, bool) {
	dot := strings.IndexByte(name, '.')
	if dot <= 0 {
		return "", false
	}
	paths := bindings[name[:dot]]
	if len(paths) == 0 {
		paths = goOnlyPath(bindings)
	}
	switch len(paths) {
	case 0:
		return name, true
	case 1:
		for p := range paths {
			return p + name[dot:], true
		}
	}
	return "", false
}

// goCallSource reads a Go taint source written as a call of no arguments
// whose callee a metavariable-regex names (`$FUNC()` with
// `^(?<package>elliptic)\.P(?<curve>256|384)$`) as a value source on the
// call's text (goCallRegex). Its named groups fill the metadata as a value
// source's do. Any other source is returned as it is.
func goCallSource(src any) any {
	m, ok := src.(*OMap)
	if !ok || m.Len() != 1 || !m.Has(keyPatterns) {
		return src
	}
	clauses := listOf(m.GetOr(keyPatterns))
	if len(clauses) != 2 {
		return src
	}
	pat, rx := asOr[*OMap](clauses[0]), asOr[*OMap](clauses[1])
	if pat == nil || rx == nil || !pat.Has(keyPattern) || !rx.Has("metavariable-regex") {
		return src
	}
	call := rxGoCallSource.FindStringSubmatch(pyStrip(pyStr(pat.GetOr(keyPattern))))
	mr := asOr[*OMap](rx.GetOr("metavariable-regex"))
	if call == nil || mr == nil || getString(mr, "metavariable") != call[1] {
		return src
	}
	re := goCallRegex(getString(mr, "regex"))
	return omap(keyPatterns, []any{
		omap(keyPattern, call[1]),
		omap("metavariable-regex", omap("metavariable", call[1], "regex", re)),
	})
}

var rxGoCallSource = regexp.MustCompile(`^(\$[A-Z_][A-Z0-9_]*)\(\s*\)$`)

// goCallRegex turns a metavariable-regex on a callee into one on the text
// of a call of no arguments to it. OpenGrep's metavariable-regex matches
// from the start of the callee, not to its end, so: each `$` (unescaped,
// outside a character class) asserts that only `()` follows, and after the
// regex the rest of the callee may follow before the `()` that ends the
// text. A prefix regex (`^elliptic\.P`) and an alternation with a `$` per
// branch (`^a\.X$|^a\.Y$`) read as they do on the callee.
func goCallRegex(re string) string {
	var b strings.Builder
	escaped, class := false, false
	for _, r := range re {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '[' && !class:
			class = true
		case r == ']' && class:
			class = false
		case r == '$' && !class:
			b.WriteString(`(?=\(\s*\)$)`)
			continue
		}
		b.WriteRune(r)
	}
	return `(?:` + b.String() + `)[\w.]*\(\s*\)$`
}
