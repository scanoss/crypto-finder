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

// The C++ forms of the C matcher (c_match.go), as OpenGrep matches C++:
//
//   - A qualified name matches the name written with the same segments. A
//     pattern `ns::rest` also matches `rest` written in a file that has a
//     `using namespace ns;` outside function bodies, anywhere in the file;
//     and a pattern `ns::n` matches `n` written after a `using ns::n;`.
//     An unqualified pattern name never matches a qualified one, and `f`
//     never matches `f<T>`.
//   - A metavariable segment binds one segment, or, written first, the
//     leading segments: `$NS::f` binds `a::b` in `a::b::f`.
//   - `$X.m` matches `x.m`, `p->m` (binding `p->`, the dereference as
//     written) and `A::m` (binding the qualifier); `$X->m` matches `p->m`
//     and `(*p).m`, binding `p`.

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// cppUsing is a using directive or declaration of a C++ file: the segments
// it names, where it ends, and whether it is a declaration (`using ns::n;`)
// or a directive (`using namespace ns;`).
type cppUsing struct {
	segs  []string
	decl  bool
	local bool // written in a function body
	end   cPos
}

// cppUsingsOf reads the using directives and declarations a C++ fragment
// lists among its imports: an import whose text is `using namespace ns;` or
// `using ns::n;` (an alias `using T = ...;` is neither).
func cppUsingsOf(imports map[string][]graphfrag.GraphFragmentImport) map[string][]cppUsing { //nolint:gocognit // one pass over the imports
	out := map[string][]cppUsing{}
	for file, list := range imports {
		for _, im := range list {
			text := strings.TrimSpace(im.Text)
			body, ok := strings.CutPrefix(text, "using ")
			if !ok || !strings.HasSuffix(body, ";") || strings.Contains(body, "=") || im.Line < 1 {
				continue
			}
			body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
			u := cppUsing{local: im.Local, end: cPos{im.Line, im.StartCol + len(im.Text)}}
			if ns, isDirective := strings.CutPrefix(body, "namespace "); isDirective {
				body = strings.TrimSpace(ns)
			} else {
				u.decl = true
			}
			body = strings.TrimPrefix(body, cppScope)
			for _, s := range strings.Split(body, cppScope) {
				s = strings.TrimSpace(s)
				if s == "" || !isCIdentStart(s[0]) {
					u.segs = nil
					break
				}
				u.segs = append(u.segs, s)
			}
			if len(u.segs) > 0 && (!u.decl || len(u.segs) > 1) {
				out[file] = append(out[file], u)
			}
		}
	}
	return out
}

// cppCallees are the reads a C++ callee pattern can match: the calls whose
// callee ends with the pattern's last name; every call when it ends with a
// metavariable or is not a name.
func (m *cMatcher) cppCallees(callee *CExpr) []*cRead {
	if name := cppLastName(callee); name != "" {
		return m.byLast[name]
	}
	return m.reads
}

// cppSegments are the segments of a written name and whether it starts
// with `::`; ok is false for an expression that is not a name.
func cppSegments(e *CExpr) (segs []CExpr, global, ok bool) {
	switch e.Kind {
	case CExprIdent, CExprTemplate:
		return []CExpr{*e}, false, true
	case CExprScoped:
		return e.Args, e.Op == cppScope, true
	}
	return nil, false, false
}

// unifyName unifies a qualified name, a template or a type with a written
// expression.
func (m *cMatcher) unifyName(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool { //nolint:gocyclo // one case per name form and using kind
	switch pe.Kind {
	case CExprType:
		return se.Kind == CExprType && se.Text == pe.Text && k(env)
	case CExprTemplate:
		return se.Kind == CExprTemplate && m.unify(pe.Sub, se.Sub, rd, env, func(env cEnv) bool {
			return m.unifyArgs(pe.Args, se.Args, rd, env, k)
		})
	}
	ss, global, ok := cppSegments(se)
	if !ok {
		return false
	}
	if global == (pe.Op == cppScope) && m.unifySegs(pe.Args, ss, rd, env, k) {
		return true
	}
	if pe.Op == cppScope {
		return false
	}
	for _, u := range m.fr.CUsings[rd.site.File] {
		switch {
		case u.local && !u.decl:
			continue // OpenGrep reads no directive of a function body
		case u.decl:
			// `using ns::n;` names n after it: pattern ns::n, written n
			if len(ss) == 1 && ss[0].Kind == CExprIdent && ss[0].Name == u.segs[len(u.segs)-1] &&
				!(cPos{rd.site.Line, rd.site.Col}).before(u.end) && cppSegsAre(pe.Args, u.segs) && k(env) {
				return true
			}
		case len(pe.Args) > len(u.segs) && cppSegsAre(pe.Args[:len(u.segs)], u.segs):
			if m.unifySegs(pe.Args[len(u.segs):], ss, rd, env, k) {
				return true
			}
		}
	}
	return false
}

// cppSegsAre: the pattern segments are the names names.
func cppSegsAre(ps []CExpr, names []string) bool {
	if len(ps) != len(names) {
		return false
	}
	for i := range ps {
		if ps[i].Kind != CExprIdent || ps[i].Name != names[i] {
			return false
		}
	}
	return true
}

// unifySegs unifies pattern segments with written ones; a leading
// metavariable followed by more segments binds one or more segments.
func (m *cMatcher) unifySegs(ps, ss []CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if len(ps) == 0 || len(ss) == 0 {
		return len(ps) == 0 && len(ss) == 0 && k(env)
	}
	if ps[0].Kind == CExprMetavar && len(ps) > 1 && len(ss) > len(ps) {
		n := len(ss) - len(ps) + 1
		lead := &CExpr{Kind: CExprScoped, Args: ss[:n], Start: ss[0].Start, End: ss[n-1].End}
		env, ok := env.bind(ps[0].Var, m.binding(rd, lead))
		return ok && m.unifySegs(ps[1:], ss[n:], rd, env, k)
	}
	if len(ps) != len(ss) {
		return false
	}
	return m.unify(&ps[0], &ss[0], rd, env, func(env cEnv) bool {
		return m.unifySegs(ps[1:], ss[1:], rd, env, k)
	})
}

// unifyMember unifies a member access pattern with a written expression, as
// OpenGrep reads C++ members: `p->m` is `(*p).m`, and a qualified call
// `A::m` reads as a member m of A for a `$X.m` pattern.
func (m *cMatcher) unifyMember(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool { //nolint:gocognit,gocyclo // one case per written member form
	var recv *CExpr
	var name *CExpr // the member name as written
	switch se.Kind {
	case CExprMember:
		name = &CExpr{Kind: CExprIdent, Name: se.Name, Start: se.End - len(se.Name), End: se.End}
		switch {
		case pe.Op == "." && se.Op == ".":
			recv = se.Sub
		case pe.Op == "." && se.Op == "->": // binds the dereference as written, `p->`
			arrow := strings.Index(rd.text[se.Sub.End:], "->")
			if arrow < 0 {
				return false
			}
			recv = &CExpr{Kind: CExprUnary, Op: "*", Sub: se.Sub, Start: se.Sub.Start, End: se.Sub.End + arrow + 2}
		case pe.Op == "->" && se.Op == "->":
			recv = se.Sub
		case pe.Op == "->" && se.Op == "." && se.Sub.Kind == CExprUnary && se.Sub.Op == "*":
			recv = se.Sub.Sub
		default:
			return false
		}
	case CExprScoped:
		if pe.Op != "." || se.Op == cppScope {
			return false
		}
		n := len(se.Args)
		last := &se.Args[n-1]
		if last.Kind != CExprIdent {
			return false
		}
		name = last
		recv = &se.Args[0]
		if n > 2 {
			recv = &CExpr{Kind: CExprScoped, Args: se.Args[:n-1], Start: se.Args[0].Start, End: se.Args[n-2].End}
		}
	default:
		return false
	}
	if isMetavar(pe.Name) {
		var ok bool
		if env, ok = env.bind(pe.Name, m.binding(rd, name)); !ok {
			return false
		}
	} else if pe.Name != name.Name {
		return false
	}
	return m.unify(pe.Sub, recv, rd, env, k)
}

// cAnchorAt is where a call anchor is: file, line and columns.
type cAnchorAt struct {
	file              string
	line, col, endCol int
}

// cppAnchorKinds reads the AST kind of each call anchor of a C++ fragment
// (call_expression, new_expression, init_declarator, ...) by place.
func cppAnchorKinds(frag *FragmentJSON) map[cAnchorAt]string {
	anchors := frag.Anchors
	if anchors == nil && len(frag.CallAnchors) > 0 {
		if err := json.Unmarshal(frag.CallAnchors, &anchors); err != nil {
			return nil
		}
	}
	out := make(map[cAnchorAt]string, len(anchors))
	for _, a := range anchors {
		if a.Function < 0 || a.Function >= len(frag.Functions) {
			continue
		}
		out[cAnchorAt{frag.Functions[a.Function].FilePath, a.Line, a.StartCol, a.EndCol}] = a.Kind
	}
	return out
}

// The anchor kinds of the construction sites (reach graph-algo-cpp-2).
const (
	cppAnchorFunctionDecl = "function_declarator"
	cppAnchorInitDecl     = "init_declarator"
	cppAnchorIdentifier   = "identifier"
)

// readCPPDeclSite reads a declaration site: the declaration statement as
// OpenGrep reports it, from the qualifiers before its type to the `;`
// after it, its declarator form the one its anchor names. nil when the
// site is not a declaration of its assigned variable.
func (m *cMatcher) readCPPDeclSite(s *Site) *cRead { //nolint:gocyclo // one check per part of the statement
	if s.AssignedVar == "" || s.EndLine > s.Line {
		return nil
	}
	form := ""
	switch m.fr.CAnchorKinds[cAnchorAt{s.File, s.Line, s.Col, s.EndCol}] {
	case cppAnchorFunctionDecl:
		form = cppDeclFunction
	case cppAnchorInitDecl:
		form = cppDeclInit
	case cppAnchorIdentifier:
		form = cppDeclNone
	default:
		return nil
	}
	line, ok := m.fr.Lines[s.File][s.Line]
	if !ok || s.EndCol-1 > len(line) || s.Col < 1 {
		return nil
	}
	start := s.Col - 1
	for {
		head := strings.TrimRight(line[:start], " \t")
		j := len(head)
		for j > 0 && isCIdentByte(head[j-1]) {
			j--
		}
		if j == len(head) || !cppDeclQualifiers[head[j:]] {
			break
		}
		start = j
	}
	end := s.EndCol - 1
	rest := strings.TrimLeft(line[end:], " \t")
	if strings.HasPrefix(rest, ";") {
		end = len(line) - len(rest) + 1
	}
	text := line[start:end]
	d, ok := readCPPDecl(text, false)
	if !ok || d.Callee.Name != s.AssignedVar || (form == cppDeclNone) != (d.Op == "") {
		return nil
	}
	d.Text = form
	d.Multi = d.Multi || strings.HasPrefix(rest, ",")
	d.Start, d.End = 0, len(text)
	return &cRead{site: s, call: d, text: text, line: s.Line, col: start + 1}
}

// funcContextAt holds a C++ function context for a range written in rd's
// function: its return type, name and parameters.
func (m *cMatcher) funcContextAt(p *CFuncLine, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	fn := m.fr.CFuncs[rd.site.Caller]
	if fn == nil {
		return false
	}
	name := fn.Name
	if name == "" {
		name = rd.site.Caller[strings.LastIndexByte(rd.site.Caller, '.')+1:]
	}
	return m.cppFuncContext(p, fn, name, env, func(env cEnv) bool {
		return m.funcParams(p.Params, fn, rd, env, k)
	})
}

// cppFuncContext binds a C++ function context's return type (the graph
// lists none: a metavariable binds it empty) and name.
func (m *cMatcher) cppFuncContext(p *CFuncLine, fn *FunctionJSON, name string, env cEnv, k func(cEnv) bool) bool {
	for _, pair := range [][2]string{{p.Type, fn.ReturnType}, {p.Name, name}} {
		if !isMetavar(pair[0]) {
			if pair[0] != pair[1] {
				return false
			}
			continue
		}
		var ok bool
		if env, ok = env.bind(pair[0], cBinding{text: pair[1], norm: pair[1]}); !ok {
			return false
		}
	}
	return k(env)
}

// unifyConstruct unifies a construction pattern, `new T(...)`, `T{...}` or
// a declaration, with a written one. A `new T` pattern takes no arguments;
// a declaration matches one of its declarator form that declares one name.
func (m *cMatcher) unifyConstruct(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if se.Kind != pe.Kind {
		return false
	}
	args := func(env cEnv) bool {
		if pe.Kind == CExprNew && pe.Op == "" {
			return len(se.Args) == 0 && k(env)
		}
		return m.unifyArgs(pe.Args, se.Args, rd, env, k)
	}
	if pe.Kind == CExprDecl {
		// an init declarator pattern takes either brackets, as OpenGrep reads both as a constructor call
		if se.Multi || se.Text != pe.Text || (pe.Text != cppDeclInit && se.Op != pe.Op) {
			return false
		}
		return m.unify(pe.Sub, se.Sub, rd, env, func(env cEnv) bool {
			return m.unify(pe.Callee, se.Callee, rd, env, args)
		})
	}
	return m.unify(pe.Sub, se.Sub, rd, env, args)
}

// The kinds of the sites a C++ regex match is reported at.
const (
	siteRegex  = "regex"
	siteString = "string"
)

// cppLineMatch is one match of a line regex: its span and named groups.
type cppLineMatch struct {
	span   cSpan
	groups map[string]string
}

// cppLines are lines from..to of file: where a site regex is searched.
type cppLines struct {
	file     string
	from, to int
}

// lineMatches are the matches of a site regex in the lines from..to of
// file, searched as one text (each line followed by its line break), as
// OpenGrep searches the file there.
func (m *cMatcher) lineMatches(rx, file string, from, to int) []cppLineMatch {
	byLines := m.rxMatches[rx]
	if byLines == nil {
		byLines = map[cppLines][]cppLineMatch{}
		m.rxMatches[rx] = byLines
	}
	key := cppLines{file, from, to}
	if found, ok := byLines[key]; ok {
		return found
	}
	out := m.searchLines(rx, file, from, to)
	byLines[key] = out
	return out
}

// searchLines searches rx in the lines from..to of file; nil when a line
// is not in the fragment.
func (m *cMatcher) searchLines(rx, file string, from, to int) []cppLineMatch {
	var b strings.Builder
	for l := from; l <= to; l++ {
		text, ok := m.fr.Lines[file][l]
		if !ok {
			return nil
		}
		b.WriteString(text)
		b.WriteByte('\n')
	}
	text := b.String()
	pos := func(off int) cPos {
		head := text[:off]
		nl := strings.LastIndexByte(head, '\n')
		return cPos{from + strings.Count(head, "\n"), off - nl}
	}
	var out []cppLineMatch
	search := compileRx(rx).search
	match, err := search.FindStringMatch(text)
	for ; err == nil && match != nil; match, err = search.FindNextMatch(match) {
		if match.Length == 0 {
			continue
		}
		start := len(string([]rune(text)[:match.Index]))
		lm := cppLineMatch{span: cSpan{file, pos(start), pos(start + len(match.String()))}, groups: map[string]string{}}
		for _, g := range match.Groups() {
			if g.Name != "" && !isAllDigits(g.Name) && len(g.Captures) > 0 {
				lm.groups[g.Name] = g.String()
			}
		}
		out = append(out, lm)
	}
	return out
}

// matchLineRegex matches a pattern-regex positive confined by an around
// context: each match in the lines of a construct the context matches,
// inside it.
func (m *cMatcher) matchLineRegex(e *Entry, p *CPattern) { //nolint:gocognit // the context, each match, then the filters
	anchor := slices.IndexFunc(p.Inside, func(c CContext) bool { return c.Place == CAround && c.Call != nil })
	rest := slices.Delete(slices.Clone(p.Inside), anchor, anchor+1)
	for _, o := range m.sitesOf(p.Inside[anchor].Call, p.Where) {
		within := o.span(o.call)
		m.unify(p.Inside[anchor].Call, o.call, o, cEnv{}, func(env cEnv) bool {
			if !cWhereBound(p.Where, env) {
				return false
			}
			for _, lm := range m.lineMatches(p.LineRegex, within.file, within.start.line, within.end.line) {
				if !lm.span.within(within) {
					continue
				}
				next := env
				for _, k := range slices.Sorted(maps.Keys(lm.groups)) {
					next = next.set("$"+k, cBinding{text: lm.groups[k], norm: lm.groups[k], span: lm.span})
				}
				m.contexts(rest, o, lm.span, next, func(env cEnv) bool {
					env, ok := cWhere(p.Where, env)
					if !ok || m.notRegexed(p.NotRegex, lm.span) {
						return false
					}
					for i := range p.NotInside {
						c := &p.NotInside[i]
						if m.context(c, o, lm.span, env, func(env cEnv) bool { _, ok := cWhere(c.Where, env); return ok }) {
							return false
						}
					}
					m.emit(e, &Site{File: lm.span.file, Line: lm.span.start.line, LineOK: true, Col: lm.span.start.col, ColOK: true, Kind: siteRegex, Caller: o.site.Caller}, lm.span, env)
					return true
				})
			}
			return false
		})
	}
}

// notRegexed: a match of a pattern-not-regex holds span or lies in it, as
// OpenGrep drops a match a not-regex range includes or is included in.
func (m *cMatcher) notRegexed(rxs []string, span cSpan) bool {
	for _, rx := range rxs {
		for _, lm := range m.lineMatches(rx, span.file, span.start.line, span.end.line) {
			if lm.span.within(span) || span.within(lm.span) {
				return true
			}
		}
	}
	return false
}

// matchSiteRegex matches a site regex positive: each match that lies wholly
// in a call, a construction or a string literal, as written, under the
// alternative's #include contexts.
func (m *cMatcher) matchSiteRegex(e *Entry, p *CPattern) { //nolint:gocognit // the places, each match, then the filters
	type place struct {
		span cSpan
		site *Site
	}
	var places []place
	for _, s := range m.fr.Sites {
		if (s.Kind == siteExternal || s.Kind == siteInternal) && s.LineOK && s.ColOK && s.EndCol > 0 {
			places = append(places, place{cSpan{s.File, cPos{s.Line, s.Col}, cPos{max(s.EndLine, s.Line), s.EndCol}}, s})
		}
	}
	for _, file := range slices.Sorted(maps.Keys(m.fr.CStrings)) {
		for _, lit := range m.fr.CStrings[file] {
			s := &Site{File: file, Line: lit.Line, LineOK: true, Col: lit.StartCol, ColOK: true, Kind: siteString}
			places = append(places, place{cSpan{file, cPos{lit.Line, lit.StartCol}, cPos{max(lit.EndLine, lit.Line), lit.EndCol}}, s})
		}
	}
	for _, pl := range places {
		rd := &cRead{site: pl.site, line: pl.span.start.line, col: pl.span.start.col}
		for _, lm := range m.lineMatches(p.SiteRegex, pl.span.file, pl.span.start.line, pl.span.end.line) {
			if !lm.span.within(pl.span) {
				continue
			}
			env := cEnv{}
			for _, k := range slices.Sorted(maps.Keys(lm.groups)) {
				env = env.set("$"+k, cBinding{text: lm.groups[k], norm: lm.groups[k], span: lm.span})
			}
			m.contexts(p.Inside, rd, lm.span, env, func(env cEnv) bool {
				env, ok := cWhere(p.Where, env)
				if !ok || m.notRegexed(p.NotRegex, lm.span) {
					return false
				}
				m.emit(e, &Site{File: lm.span.file, Line: lm.span.start.line, LineOK: true, Col: lm.span.start.col, ColOK: true, Kind: siteRegex, Caller: pl.site.Caller}, lm.span, env)
				return true
			})
		}
	}
}
