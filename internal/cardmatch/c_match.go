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

// The C matcher. It reads each call site as written, from the fragment's
// source lines and the call's span, with the reader that reads a rule's
// pattern (c_syntax.go), and unifies the pattern with it into an environment
// of metavariable bindings. It never reads reach's resolved target: OpenGrep
// matches syntax, and C names an external function by itself.
//
// An #include context reads the directives the fragment lists per file
// (imports): the directive must come before the matched range in the same
// file. An enclosing-call context reads the other call sites of the file
// whose span holds the range. A pattern-regex positive is searched in each
// directive's text and reported at the columns it matches.

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// loadC keeps the facts only the C matcher reads: the fragment's includes,
// string literals and functions by key.
func (fr *Frag) loadC(frag *FragmentJSON) {
	fr.CIncludes = cIncludesOf(frag.Imports)
	if fr.CPP = frag.ScanMetadata.Ecosystem == ecosystemCPP; fr.CPP {
		fr.CUsings = cppUsingsOf(frag.Imports)
		fr.CAnchorKinds = cppAnchorKinds(frag)
	}
	fr.CStrings = frag.Strings
	fr.CFuncs = make(map[string]*FunctionJSON, len(frag.Functions))
	for i := range frag.Functions {
		fr.CFuncs[frag.Functions[i].Key] = &frag.Functions[i]
	}
}

// The kinds of the call sites a C fragment loads (Site.Kind).
const (
	siteExternal = "external"
	siteInternal = "internal"
)

// CMatchStats counts what the C matcher did with one fragment.
type CMatchStats struct {
	Entries int // C entries in the index
	// UnreadableSites are the call sites whose written call could not be
	// read (no source line or column, a preprocessor line inside the call).
	UnreadableSites int
}

// cRead is a call site's written call: the expression read from text, which
// starts at line, col of file.
type cRead struct {
	site      *Site
	call      *CExpr
	text      string
	line, col int
}

// cPos is a position in a file: 1-based line and column.
type cPos struct{ line, col int }

func (a cPos) before(b cPos) bool { return a.line < b.line || (a.line == b.line && a.col < b.col) }

// cSpan is a range of a file, end exclusive.
type cSpan struct {
	file       string
	start, end cPos
}

// startOff and endOff are the byte offsets of s in rd's text.
func (s cSpan) startOff(rd *cRead) int { return rd.offset(s.start) }
func (s cSpan) endOff(rd *cRead) int   { return rd.offset(s.end) }

// within: s lies inside o (or is o).
func (s cSpan) within(o cSpan) bool {
	return s.file == o.file && !s.start.before(o.start) && !o.end.before(s.end)
}

// pos is the position of byte offset off of the read text.
func (rd *cRead) pos(off int) cPos {
	head := rd.text[:off]
	nl := strings.LastIndexByte(head, '\n')
	if nl < 0 {
		return cPos{rd.line, rd.col + off}
	}
	return cPos{rd.line + strings.Count(head, "\n"), off - nl}
}

// offset is the byte offset of position p in the read text.
func (rd *cRead) offset(p cPos) int {
	if p.line == rd.line {
		return p.col - rd.col
	}
	off := 0
	for l := rd.line; l < p.line; l++ {
		off += strings.IndexByte(rd.text[off:], '\n') + 1
	}
	return off + p.col - 1
}

// span is where expression e of the read is written.
func (rd *cRead) span(e *CExpr) cSpan {
	return cSpan{rd.site.File, rd.pos(e.Start), rd.pos(e.End)}
}

// cBinding is what a metavariable binds: the text as written, its spelling
// with whitespace folded (what two bindings are compared by), and where it
// is written (where).
type cBinding struct {
	text, norm string
	// span is where a binding with no expression is written.
	span cSpan
	// expr is the expression bound, in the read rd; nil for a directive's
	// header or a regex group.
	expr *CExpr
	rd   *cRead
}

// where is where b is written. An expression's place is read only when a
// finding needs it: most bindings are dropped by a later filter.
func (b cBinding) where() cSpan {
	if b.expr != nil {
		return b.rd.span(b.expr)
	}
	return b.span
}

// cEnv binds metavariables, each name once; it is never changed in place. A
// match binds a handful, so a slice copied on each new binding costs less
// than a map cloned on each.
type cEnv []cVar

// cVar is one metavariable and what it binds.
type cVar struct {
	name string
	b    cBinding
}

// get is what name binds.
func (e cEnv) get(name string) (cBinding, bool) {
	for i := range e {
		if e[i].name == name {
			return e[i].b, true
		}
	}
	return cBinding{}, false
}

// bind extends the environment; false when the metavariable is bound to
// other text. `$_` matches anything and binds nothing.
func (e cEnv) bind(name string, b cBinding) (cEnv, bool) {
	if name == "$_" {
		return e, true
	}
	if old, ok := e.get(name); ok {
		return e, old.norm == b.norm
	}
	out := make(cEnv, len(e), len(e)+1)
	copy(out, e)
	return append(out, cVar{name, b}), true
}

// set binds name over what it bound.
func (e cEnv) set(name string, b cBinding) cEnv {
	i := slices.IndexFunc(e, func(v cVar) bool { return v.name == name })
	if i < 0 {
		out := make(cEnv, len(e), len(e)+1)
		copy(out, e)
		return append(out, cVar{name, b})
	}
	out := slices.Clone(e)
	out[i].b = b
	return out
}

// cInclude is one #include directive of a file.
type cInclude struct {
	system bool
	// local: the directive is written inside a function body; its text is
	// searched by a pattern-regex, but it opens no `#include ...` range.
	local  bool
	header string
	text   string
	line   int
	col    int // start column of the directive
	end    cPos
}

// binding is what `#include "$H"` binds $H to: `<h>` for the system form,
// `h` for the quote form, as OpenGrep binds it.
func (inc *cInclude) binding(file string) cBinding {
	text := inc.header
	if inc.system {
		text = "<" + inc.header + ">"
	}
	return cBinding{text: text, norm: text, span: cSpan{file, cPos{inc.line, inc.col}, inc.end}}
}

// cIncludesOf reads a fragment's directives by file. The form is read from
// the directive's text: the delimiter before the header.
func cIncludesOf(imports map[string][]graphfrag.GraphFragmentImport) map[string][]cInclude {
	out := make(map[string][]cInclude, len(imports))
	for file, list := range imports {
		for _, im := range list {
			i := strings.Index(im.Text, im.Module)
			if im.Module == "" || i < 1 || im.Line < 1 || im.StartCol < 1 {
				continue
			}
			open := im.Text[i-1]
			if open != '<' && open != '"' {
				continue
			}
			out[file] = append(out[file], cInclude{
				system: open == '<', local: im.Local, header: im.Module, text: im.Text, line: im.Line, col: im.StartCol,
				end: cPos{im.Line, im.StartCol + len(im.Text)},
			})
		}
	}
	return out
}

// cMatcher is the state of one match over a fragment.
type cMatcher struct {
	fr       *Frag
	reads    []*cRead            // the readable call sites, one per written call
	byCallee map[string][]*cRead // the reads whose callee is a name, by name
	// calleeNames are byCallee's names in reading order; otherCallee the
	// reads whose callee is not a name (`ctx->f(...)`, `(*fp)(...)`).
	calleeNames []string
	otherCallee []*cRead
	stmts       map[*cRead]bool // statementCall, once per read
	byFile      map[string][]*cRead
	byCaller    map[string][]*cRead  // the reads by the function they are written in
	declReads   map[*Site]*cDeclRead // declarations read, nil when unreadable
	// cpp: the fragment is C++ (cpp_match.go); byLast are its reads by the
	// name their callee ends with.
	cpp    bool
	byLast map[string][]*cRead
	// rxMatches are the matches of the site regexes searched, by regex and
	// lines. A regex's matches are dropped after the last entry that
	// searches it, so they never outlive their use.
	rxMatches map[string]map[cppLines][]cppLineMatch
	fnDecls   map[cPos2]bool // where a declaration is a function declarator
	stats     CMatchStats
	found     []*Finding
	seen      map[string]bool
}

// matchC matches a C or C++ fragment.
func matchC(a *Assets, fr *Frag) []*Finding {
	found, _ := matchCStats(a, fr)
	return found
}

func matchCStats(a *Assets, fr *Frag) ([]*Finding, CMatchStats) {
	m := newCMatcher(fr)
	m.matchEntries(a)
	return m.found, m.stats
}

// newCMatcher reads the call sites of fr.
func newCMatcher(fr *Frag) *cMatcher {
	m := &cMatcher{
		fr: fr, byCallee: map[string][]*cRead{}, byFile: map[string][]*cRead{}, byCaller: map[string][]*cRead{},
		declReads: map[*Site]*cDeclRead{}, stmts: map[*cRead]bool{}, seen: map[string]bool{},
		cpp: fr.CPP, byLast: map[string][]*cRead{}, rxMatches: map[string]map[cppLines][]cppLineMatch{},
	}
	m.readSites()
	if m.cpp {
		m.readAssigns()
	}
	return m
}

// matchEntries matches a's C entries.
func (m *cMatcher) matchEntries(a *Assets) {
	// An entry a hand card replaces is not matched here.
	matched := func(e *Entry) bool { return e.C != nil && !a.cards.RuleIDs[e.RuleID] }
	lastSearch := map[string]int{}
	for i, e := range a.index.Entries {
		if matched(e) {
			for _, rx := range e.C.siteRegexes() {
				lastSearch[rx] = i
			}
		}
	}
	for i, e := range a.index.Entries {
		if !matched(e) {
			continue
		}
		m.stats.Entries++
		m.matchEntry(e)
		for _, rx := range e.C.siteRegexes() {
			if lastSearch[rx] == i {
				delete(m.rxMatches, rx)
			}
		}
	}
}

// matchEntry matches one C entry by the kind of its pattern.
func (m *cMatcher) matchEntry(e *Entry) {
	switch p := e.C; {
	case p.Regex != "":
		m.matchRegex(e)
	case p.Call != nil:
		for _, rd := range m.sitesOf(p.Call, p.Where) {
			if !p.Stmt || m.statementCall(rd) {
				m.matchAt(e, p, rd, rd.call, cEnv{})
			}
		}
	case p.Expr != nil:
		m.matchExpr(e, p)
	case p.Store != nil:
		m.matchStores(e, p)
	case p.Str != nil:
		m.matchStrings(e, p)
	case p.LineRegex != "":
		m.matchLineRegex(e, p)
	case p.SiteRegex != "":
		m.matchSiteRegex(e, p)
	}
}

// siteRegexes are the site regexes matching p searches (lineMatches).
func (p *CPattern) siteRegexes() []string {
	var out []string
	for _, rx := range []string{p.LineRegex, p.SiteRegex} {
		if rx != "" {
			out = append(out, rx)
		}
	}
	out = append(out, p.NotRegex...)
	for i := range p.Not {
		out = append(out, p.Not[i].siteRegexes()...)
	}
	return out
}

// sitesOf are the reads a call or C++ construction pattern can match.
func (m *cMatcher) sitesOf(pe *CExpr, where []CWhere) []*cRead {
	if pe.Kind != CExprCall {
		return m.cppCallees(pe)
	}
	return m.callees(pe.Callee, where)
}

// callees are the reads a call pattern's callee can match: the calls of the
// name; for a metavariable that a metavariable-regex filters, the calls of
// the names the regex accepts (read once per name) and every call whose
// callee is not a name; else every call.
func (m *cMatcher) callees(callee *CExpr, where []CWhere) []*cRead {
	if callee.Kind == CExprIdent {
		return m.byCallee[callee.Name]
	}
	if callee.Kind != CExprMetavar {
		return m.cppCallees(callee)
	}
	var rxs []string
	for _, w := range where {
		if w.Metavar == callee.Var {
			rxs = append(rxs, w.Regex)
		}
	}
	if len(rxs) == 0 {
		return m.reads
	}
	out := slices.Clone(m.otherCallee)
	for _, name := range m.calleeNames {
		if !slices.ContainsFunc(rxs, func(rx string) bool { return !reMatchOK(rx, name) }) {
			out = append(out, m.byCallee[name]...)
		}
	}
	return out
}

// readSites reads every call site once; two sites of one written call (a
// call the graph links to several definitions) read as one.
func (m *cMatcher) readSites() {
	at := map[cSpan]bool{}
	for _, s := range m.fr.Sites {
		if s.Kind != siteExternal && s.Kind != siteInternal {
			continue
		}
		rd := m.readSite(s)
		if rd == nil {
			m.stats.UnreadableSites++
			continue
		}
		span := rd.span(rd.call)
		if at[span] {
			continue
		}
		at[span] = true
		m.reads = append(m.reads, rd)
		m.byFile[s.File] = append(m.byFile[s.File], rd)
		m.byCaller[s.Caller] = append(m.byCaller[s.Caller], rd)
		m.indexByName(rd)
	}
}

// indexByName files a read under the name of its callee (or, for C++, of the
// type it constructs).
func (m *cMatcher) indexByName(rd *cRead) {
	if m.cpp {
		last := cppLastName(rd.call) // a construction's type
		if rd.call.Kind == CExprCall {
			last = cppLastName(rd.call.Callee)
		}
		m.byLast[last] = append(m.byLast[last], rd)
	}
	if rd.call.Kind != CExprCall { // a C++ construction
		return
	}
	if name := rd.call.Callee.Name; rd.call.Callee.Kind == CExprIdent {
		if _, seen := m.byCallee[name]; !seen {
			m.calleeNames = append(m.calleeNames, name)
		}
		m.byCallee[name] = append(m.byCallee[name], rd)
	} else {
		m.otherCallee = append(m.otherCallee, rd)
	}
}

func (m *cMatcher) readSite(s *Site) *cRead {
	if !s.LineOK || !s.ColOK {
		return nil
	}
	text, ok := m.spanText(s.File, s.Line, s.Col, s.EndLine, s.EndCol)
	if !ok {
		return nil
	}
	read := readCExpr
	if m.cpp {
		read = readCPPExpr
	}
	e, ok := read(text, false)
	if m.cpp && (!ok || (e.Kind != CExprCall && e.Kind != CExprNew)) {
		return m.readCPPDeclSite(s)
	}
	if !ok || (e.Kind != CExprCall && e.Kind != CExprNew) {
		return nil
	}
	if m.cpp { // the call as written, its parentheses included: `(*p).f(x)`
		e.Start, e.End = 0, len(text)
	}
	return &cRead{site: s, call: e, text: text, line: s.Line, col: s.Col}
}

// spanText is the source text of a span from the fragment's source lines.
func (m *cMatcher) spanText(file string, line, col, endLine, endCol int) (string, bool) {
	if col < 1 || endCol < 1 {
		return "", false
	}
	endLine = max(endLine, line)
	lines := m.fr.Lines[file]
	var b strings.Builder
	for l := line; l <= endLine; l++ {
		text, ok := lines[l]
		if !ok {
			return "", false
		}
		from, to := 0, len(text)
		if l == line {
			from = col - 1
		}
		if l == endLine {
			to = endCol - 1
		}
		if from > to || to > len(text) {
			return "", false
		}
		if l > line {
			b.WriteByte('\n')
		}
		b.WriteString(text[from:to])
	}
	return b.String(), true
}

// matchRegex searches a pattern-regex positive in every directive's text.
func (m *cMatcher) matchRegex(e *Entry) {
	rx := compileRx(e.C.Regex).search
	for _, file := range slices.Sorted(maps.Keys(m.fr.CIncludes)) {
		for _, inc := range m.fr.CIncludes[file] {
			match, err := rx.FindStringMatch(inc.text)
			for err == nil && match != nil {
				if match.Length > 0 {
					from := len(string([]rune(inc.text)[:match.Index]))
					to := from + len(match.String())
					span := cSpan{file, cPos{inc.line, inc.col + from}, cPos{inc.line, inc.col + to}}
					s := &Site{File: file, Line: inc.line, LineOK: true, Col: inc.col + from, ColOK: true, Kind: "include"}
					m.emit(e, s, span, cEnv{})
				}
				match, err = rx.FindNextMatch(match)
			}
		}
	}
}

// matchExpr matches a bare metavariable positive: every expression written
// inside a call its around context matches.
func (m *cMatcher) matchExpr(e *Entry, p *CPattern) {
	anchor := slices.IndexFunc(p.Inside, func(c CContext) bool { return c.Call != nil })
	rest := *p
	rest.Inside = slices.Delete(slices.Clone(p.Inside), anchor, anchor+1)
	for _, rd := range m.sitesOf(p.Inside[anchor].Call, p.Where) {
		m.unify(p.Inside[anchor].Call, rd.call, rd, cEnv{}, func(env cEnv) bool {
			if !cWhereBound(p.Where, env) {
				return false
			}
			cWalk(rd.call, func(x *CExpr) bool {
				if x.Kind == CExprConcat {
					return false
				}
				if env2, ok := env.bind(p.Expr.Var, m.binding(rd, x)); ok {
					m.matchAt(e, &rest, rd, x, env2)
				}
				return false
			})
			return false
		})
	}
}

// matchStrings matches a string literal positive with each literal of the
// fragment: `"$X"` binds the content between the quotes; each pattern-regex
// beside it must match within the literal's text, and the finding is
// reported at that match, as OpenGrep reports the intersection of the two
// ranges.
func (m *cMatcher) matchStrings(e *Entry, p *CPattern) {
	for _, file := range slices.Sorted(maps.Keys(m.fr.CStrings)) {
		for _, lit := range m.fr.CStrings[file] {
			q := strings.IndexByte(lit.Text, '"')
			if q < 0 || len(lit.Text) < q+2 || lit.Text[len(lit.Text)-1] != '"' {
				continue
			}
			content := lit.Text[q+1 : len(lit.Text)-1]
			site := &Site{File: file, Line: lit.Line, LineOK: true, Col: lit.StartCol, ColOK: true, Kind: "string"}
			rd := &cRead{site: site, text: lit.Text, line: lit.Line, col: lit.StartCol}
			whole := &CExpr{Kind: CExprString, Text: content, Start: 0, End: len(lit.Text)}
			env := cEnv{}
			switch {
			case p.Str.Kind == CExprStrVar:
				env, _ = env.bind(p.Str.Var, cBinding{text: content, norm: content, expr: whole, rd: rd})
			case p.Str.Text != content:
				continue
			}
			env, ok := cWhere(p.Where, env)
			if !ok {
				continue
			}
			m.strRegexes(e, p.StrRegex, rd, rd.span(whole), env)
		}
	}
}

// strRegexes reports the literal of rd at each place every regex matches
// within it (the literal itself when there is none).
func (m *cMatcher) strRegexes(e *Entry, rxs []string, rd *cRead, span cSpan, env cEnv) {
	if len(rxs) == 0 {
		m.emit(e, rd.site, span, env)
		return
	}
	text := rd.text[span.startOff(rd):span.endOff(rd)]
	match, err := compileRx(rxs[0]).search.FindStringMatch(text)
	for ; err == nil && match != nil; match, err = compileRx(rxs[0]).search.FindNextMatch(match) {
		from := span.startOff(rd) + len(string([]rune(text)[:match.Index]))
		to := from + len(match.String())
		if to == from {
			continue
		}
		next := env
		for _, g := range match.Groups() {
			if g.Name != "" && !isAllDigits(g.Name) && len(g.Captures) > 0 {
				next = next.set("$"+g.Name, cBinding{text: g.String(), norm: g.String()})
			}
		}
		x := &CExpr{Start: from, End: to}
		m.strRegexes(e, rxs[1:], rd, rd.span(x), next)
	}
}

// matchStores matches a store positive with each field store of the
// fragment.
func (m *cMatcher) matchStores(e *Entry, p *CPattern) {
	for _, st := range m.fr.Stores {
		text, ok := m.spanText(st.File, st.Line, st.Col, st.EndLine, st.EndCol)
		if !ok {
			continue
		}
		x, ok := readCExpr(text, false)
		if !ok || x.Kind != CExprAssign {
			continue
		}
		rd := &cRead{site: st, call: x, text: text, line: st.Line, col: st.Col}
		m.unify(p.Store, x, rd, cEnv{}, func(env cEnv) bool {
			m.matchAt(e, p, rd, x, env)
			return p.Focus == ""
		})
	}
}

// matchAt finishes a match of pattern p whose positive matched expression x
// of read rd (the positive's own unification is done, or p.Call is unified
// here): the contexts, filters and negatives, then the finding.
func (m *cMatcher) matchAt(e *Entry, p *CPattern, rd *cRead, x *CExpr, env cEnv) {
	var span cSpan
	spanRead := false
	finish := func(env cEnv) bool {
		if !cWhereBound(p.Where, env) {
			return false
		}
		if !spanRead {
			span, spanRead = rd.span(x), true
		}
		return m.contexts(p.Inside, rd, span, env, func(env cEnv) bool {
			env, ok := cWhere(p.Where, env)
			if !ok || m.excluded(p, rd, x, span, env) || m.notRegexed(p.NotRegex, span) {
				return false
			}
			// a focus reports each place it binds
			return m.report(e, p, rd, x, env) && p.Focus == ""
		})
	}
	if p.Call != nil && x == rd.call {
		m.unify(p.Call, rd.call, rd, env, finish)
		return
	}
	finish(env)
}

// report emits the finding of a match: at its focus, or the matched
// expression x of rd; a taint sink only when what it reports is tainted.
// It reports whether it emitted.
func (m *cMatcher) report(e *Entry, p *CPattern, rd *cRead, x *CExpr, env cEnv) bool {
	at, atRead, atExpr := rd.span(x), rd, x
	if p.Focus != "" {
		b, _ := env.get(p.Focus)
		at, atRead, atExpr = b.where(), b.rd, b.expr
	}
	fill := env
	if p.Taint != nil {
		if atExpr == nil {
			return false
		}
		hit, tainted := m.tainted(p.Taint, atRead, atExpr)
		if !tainted {
			return false
		}
		fill = hit
		for _, v := range env {
			fill = fill.set(v.name, v.b)
		}
	}
	m.emit(e, rd.site, at, fill)
	return true
}

// contexts holds every context in turn, with the bindings each makes.
func (m *cMatcher) contexts(ctxs []CContext, rd *cRead, span cSpan, env cEnv, k func(cEnv) bool) bool {
	if len(ctxs) == 0 {
		return k(env)
	}
	return m.context(&ctxs[0], rd, span, env, func(env cEnv) bool {
		return m.contexts(ctxs[1:], rd, span, env, k)
	})
}

// context holds one context for the range at span, written in rd's
// function.
func (m *cMatcher) context(c *CContext, rd *cRead, span cSpan, env cEnv, k func(cEnv) bool) bool {
	switch {
	case c.Include != nil:
		return m.includeContext(c.Include, span, env, k)
	case c.Decl != nil:
		return m.declContext(c.Decl, rd.site.Caller, span, env, k)
	case c.Func != nil:
		if c.Func.Params != nil {
			return m.funcContextAt(c.Func, rd, env, k)
		}
		return m.funcContext(c.Func, rd.site.Caller, env, k)
	case c.Place == CBefore:
		for _, o := range m.byCaller[rd.site.Caller] {
			if o.span(o.call).end.before(span.start) || o.span(o.call).end == span.start {
				if m.statementCall(o) && m.unify(c.Call, o.call, o, env, k) {
					return true
				}
			}
		}
		return false
	}
	for _, o := range m.byFile[span.file] {
		if span.within(o.span(o.call)) && m.unify(c.Call, o.call, o, env, k) {
			return true
		}
	}
	return false
}

// statementCall: the call is written in an expression statement, a
// declaration or a return, at any depth, as OpenGrep reads a statement
// pattern `f(...);`, not in the header of an if, while, for or switch. The
// outermost call around it decides, read on its first line: an open
// parenthesis before it that a control keyword opens is a header.
func (m *cMatcher) statementCall(rd *cRead) bool {
	if v, ok := m.stmts[rd]; ok {
		return v
	}
	v := m.readStatementCall(rd)
	m.stmts[rd] = v
	return v
}

func (m *cMatcher) readStatementCall(rd *cRead) bool {
	outer := rd
	for _, o := range m.byFile[rd.site.File] {
		if rd.span(rd.call).within(o.span(o.call)) && o.span(o.call).within(outer.span(outer.call)) {
			outer = o
		}
	}
	line, ok := m.fr.Lines[outer.site.File][outer.line]
	if !ok || outer.col-1 > len(line) {
		return false
	}
	depth := 0
	for i := outer.col - 2; i >= 0; i-- {
		switch line[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			word := strings.TrimRight(line[:i], " \t")
			j := len(word)
			for j > 0 && isCIdentByte(word[j-1]) {
				j--
			}
			switch word[j:] {
			case "if", "while", "for", "switch":
				return false
			}
		}
	}
	return true
}

// declContext: a declaration of the function, before the range, matches
// the pattern. A function body reads as one block.
func (m *cMatcher) declContext(p *CDeclLine, caller string, span cSpan, env cEnv, k func(cEnv) bool) bool {
	for _, d := range m.fr.DeclsByCaller[caller] {
		if !(cPos{d.Line, d.Col}).before(span.start) {
			continue
		}
		decl := m.readDecl(d)
		if decl == nil {
			continue
		}
		for i := range decl.decl.Decls {
			if dc := &decl.decl.Decls[i]; dc.Name == d.AssignedVar && m.unifyDecl(p, decl, dc, env, k) {
				return true
			}
		}
	}
	return false
}

// cDeclRead is a declaration read from its source text.
type cDeclRead struct {
	decl *cDecl
	rd   *cRead // the text, for the bindings' spans
}

// readDecl reads a declaration site; nil when its text cannot be read.
func (m *cMatcher) readDecl(d *Site) *cDeclRead {
	if r, ok := m.declReads[d]; ok {
		return r
	}
	var out *cDeclRead
	if text, ok := m.spanText(d.File, d.Line, d.Col, d.EndLine, d.EndCol); ok {
		if decl, ok := readCDecl(text, false); ok {
			out = &cDeclRead{decl: decl, rd: &cRead{site: d, text: text, line: d.Line, col: d.Col}}
		}
	}
	m.declReads[d] = out
	return out
}

// unifyDecl unifies a declaration pattern with one declarator.
func (m *cMatcher) unifyDecl(p *CDeclLine, d *cDeclRead, dc *cDeclarator, env cEnv, k func(cEnv) bool) bool {
	if p.Ptr != dc.Ptr || p.Array != dc.Array || (p.Size == nil) != (dc.Size == nil) || (p.Init == nil) != (dc.Init == nil) {
		return false
	}
	var ok bool
	if len(p.Type) == 1 && isMetavar(p.Type[0]) {
		text := strings.Join(d.decl.Type, " ")
		env, ok = env.bind(p.Type[0], cBinding{text: text, norm: text})
	} else {
		ok = slices.Equal(p.Type, d.decl.Type)
	}
	if !ok {
		return false
	}
	if isMetavar(p.Name) {
		if env, ok = env.bind(p.Name, cBinding{text: dc.Name, norm: dc.Name}); !ok {
			return false
		}
	} else if p.Name != dc.Name {
		return false
	}
	init := func(env cEnv) bool {
		switch {
		case p.Init == nil:
			return k(env)
		case p.Init.Kind == CExprInit:
			return dc.Init.Kind == CExprInit && m.unifyArgs(p.Init.Args, dc.Init.Args, d.rd, env, k)
		}
		return m.unify(p.Init, dc.Init, d.rd, env, k)
	}
	if p.Size != nil {
		return m.unify(p.Size, dc.Size, d.rd, env, init)
	}
	return init(env)
}

// funcContext: the range is written in a function of the pattern's return
// type and name.
func (m *cMatcher) funcContext(p *CFuncLine, caller string, env cEnv, k func(cEnv) bool) bool {
	fn := m.fr.CFuncs[caller]
	if fn == nil {
		return false
	}
	name := fn.Name
	if name == "" {
		name = caller[strings.LastIndexByte(caller, '.')+1:]
	}
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

// includeContext: a directive of the pattern's form and header ends before
// the range, in its file.
func (m *cMatcher) includeContext(p *CIncludeLine, span cSpan, env cEnv, k func(cEnv) bool) bool {
	for i := range m.fr.CIncludes[span.file] {
		inc := &m.fr.CIncludes[span.file][i]
		if inc.local || span.start.before(inc.end) || !cIncludeFits(p, inc) {
			continue
		}
		next := env
		if p.Var != "" {
			var ok bool
			if next, ok = env.bind(p.Var, inc.binding(span.file)); !ok {
				continue
			}
		}
		if k(next) {
			return true
		}
	}
	return false
}

// cIncludeFits: the directive is of the pattern's form and header.
func cIncludeFits(p *CIncludeLine, inc *cInclude) bool {
	switch p.Form {
	case CIncludeSystem:
		return inc.system && inc.header == p.Header
	case CIncludeQuote:
		return !inc.system && inc.header == p.Header
	}
	return true
}

// excluded: a pattern-not-inside context holds for the range, or a
// pattern-not matches the positive, under the positive's bindings.
func (m *cMatcher) excluded(p *CPattern, rd *cRead, x *CExpr, span cSpan, env cEnv) bool {
	for i := range p.NotInside {
		c := &p.NotInside[i]
		if m.context(c, rd, span, env, func(env cEnv) bool { _, ok := cWhere(c.Where, env); return ok }) {
			return true
		}
	}
	for i := range p.Not {
		n := &p.Not[i]
		if x.Kind == n.Call.Kind && m.unify(n.Call, x, rd, env, func(env cEnv) bool { _, ok := cWhere(n.Where, env); return ok }) {
			return true
		}
	}
	return false
}

// cWhereBound: every metavariable-regex on a metavariable env already binds
// matches. It drops a match early, before the contexts are read; cWhere
// reads every filter again once all are bound.
func cWhereBound(ws []CWhere, env cEnv) bool {
	for _, w := range ws {
		if b, ok := env.get(w.Metavar); ok && !reMatchOK(w.Regex, b.text) {
			return false
		}
	}
	return true
}

// cWhere: every metavariable-regex matches the text its metavariable binds;
// the regex's named groups bind as metavariables, as OpenGrep binds them.
func cWhere(ws []CWhere, env cEnv) (cEnv, bool) {
	for _, w := range ws {
		b, ok := env.get(w.Metavar)
		if !ok {
			return env, false
		}
		groups := reMatch(w.Regex, b.text)
		if groups == nil {
			return env, false
		}
		for _, k := range slices.Sorted(maps.Keys(groups)) {
			env = env.set("$"+k, cBinding{text: groups[k], norm: groups[k], span: b.where()})
		}
	}
	return env, true
}

// binding is what a metavariable binds when it matches expression x of rd.
func (m *cMatcher) binding(rd *cRead, x *CExpr) cBinding {
	text := rd.text[x.Start:x.End]
	return cBinding{text: text, norm: foldSpace(text), expr: x, rd: rd}
}

// foldSpace is text with its whitespace runs folded to one space and none at
// either end, as strings.Fields reads whitespace. Text already so written,
// in ASCII, is returned as is.
func foldSpace(text string) string {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 0x80 || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' ||
			c == ' ' && (i == 0 || i == len(text)-1 || text[i+1] == ' ') {
			return strings.Join(strings.Fields(text), " ")
		}
	}
	return text
}

// unify unifies pattern expression pe with written expression se of rd,
// calling k with each environment that makes them equal until k accepts one.
func (m *cMatcher) unify(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool { //nolint:gocyclo // one case per pattern shape of the closed set
	switch pe.Kind {
	case CExprMetavar:
		env, ok := env.bind(pe.Var, m.binding(rd, se))
		return ok && k(env)
	case CExprIdent:
		return se.Kind == CExprIdent && se.Name == pe.Name && k(env)
	case CExprInt:
		pv, _ := cIntValue(pe.Text)
		sv, ok := cIntValue(se.Text)
		return se.Kind == CExprInt && ok && pv == sv && k(env)
	case CExprString:
		if m.cpp && pe.Text == rustEllipsis { // C++: `"..."` is any string literal
			return se.Kind == CExprString && k(env)
		}
		return se.Kind == CExprString && se.Text == pe.Text && k(env) // a prefixed literal (L"x") too, as OpenGrep reads it
	case CExprUnary:
		return se.Kind == CExprUnary && se.Op == pe.Op && m.unify(pe.Sub, se.Sub, rd, env, k)
	case CExprCall:
		return m.unifyCall(pe, se, rd, env, k)
	case CExprDeep:
		return cWalk(se, func(x *CExpr) bool { return m.unify(pe.Sub, x, rd, env, k) })
	case CExprScoped, CExprTemplate, CExprType:
		return m.unifyName(pe, se, rd, env, k)
	case CExprNew, CExprDecl:
		return m.unifyConstruct(pe, se, rd, env, k)
	case CExprTyped:
		return m.unifyTyped(pe, se, rd, env, k)
	case CExprInit: // C++: `{..., $X, ...}`
		return se.Kind == CExprInit && m.unifyArgs(pe.Args, se.Args, rd, env, k)
	case CExprMember:
		if m.cpp {
			return m.unifyMember(pe, se, rd, env, k)
		}
		return se.Kind == CExprMember && se.Op == pe.Op && se.Name == pe.Name && m.unify(pe.Sub, se.Sub, rd, env, k)
	case CExprAssign:
		return se.Kind == CExprAssign && se.Op == pe.Op && m.unify(&pe.Args[0], &se.Args[0], rd, env, func(env cEnv) bool {
			return m.unify(&pe.Args[1], &se.Args[1], rd, env, k)
		})
	case CExprBinary:
		return m.unifyBinary(pe, se, rd, env, k)
	}
	return false
}

// argsFit: pattern arguments ps can match n written ones (unifyArgs), each
// argument but `...` matching exactly one.
func argsFit(ps []CExpr, n int) bool {
	fixed, open := 0, false
	for i := range ps {
		if ps[i].Kind == CExprEllipsis {
			open = true
		} else {
			fixed++
		}
	}
	return fixed == n || open && fixed < n
}

// unifyCall unifies a call pattern with a written call: callee, then arguments.
func (m *cMatcher) unifyCall(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if se.Kind != CExprCall || se.Op != pe.Op || !argsFit(pe.Args, len(se.Args)) {
		return false
	}
	return m.unify(pe.Callee, se.Callee, rd, env, func(env cEnv) bool {
		return m.unifyArgs(pe.Args, se.Args, rd, env, k)
	})
}

// unifyBinary unifies a binary pattern with a written chain of the same operator.
func (m *cMatcher) unifyBinary(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if se.Kind != CExprBinary || se.Op != pe.Op {
		return false
	}
	return m.unifyOr(pe.Args, se.Args, make([]bool, len(se.Args)), rd, env, k)
}

// unifyArgs unifies argument lists; `...` matches any run of arguments.
func (m *cMatcher) unifyArgs(ps, ss []CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if len(ps) == 0 {
		return len(ss) == 0 && k(env)
	}
	if ps[0].Kind == CExprEllipsis {
		for i := 0; i <= len(ss); i++ {
			if m.unifyArgs(ps[1:], ss[i:], rd, env, k) {
				return true
			}
		}
		return false
	}
	if len(ss) == 0 {
		return false
	}
	return m.unify(&ps[0], &ss[0], rd, env, func(env cEnv) bool {
		return m.unifyArgs(ps[1:], ss[1:], rd, env, k)
	})
}

// unifyOr matches the operands of an `|` pattern with distinct operands of
// the written chain, in any order, as OpenGrep's matching modulo
// associativity and commutativity does: operands left over are allowed, and
// a `...` operand needs at least one.
func (m *cMatcher) unifyOr(ps, ss []CExpr, used []bool, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if len(ps) == 0 {
		return k(env)
	}
	if ps[0].Kind == CExprEllipsis {
		free := 0
		for _, u := range used {
			if !u {
				free++
			}
		}
		return free >= len(ps) && m.unifyOr(ps[1:], ss, used, rd, env, k)
	}
	for i := range ss {
		if used[i] {
			continue
		}
		used[i] = true
		ok := m.unify(&ps[0], &ss[i], rd, env, func(env cEnv) bool {
			return m.unifyOr(ps[1:], ss, used, rd, env, k)
		})
		used[i] = false
		if ok {
			return true
		}
	}
	return false
}

// emit keeps the finding of entry e at span, one per rule and span.
func (m *cMatcher) emit(e *Entry, s *Site, span cSpan, env cEnv) {
	key := e.RuleID + "\x00" + span.file + "\x00" + strconv.Itoa(span.start.line) + ":" + strconv.Itoa(span.start.col) +
		"\x00" + strconv.Itoa(span.end.line) + ":" + strconv.Itoa(span.end.col)
	if m.seen[key] {
		return
	}
	m.seen[key] = true
	fg := fillGroups{}
	for _, kv := range env {
		v := kv.b.text
		fg[strings.TrimPrefix(kv.name, "$")] = &v
	}
	f := &Finding{
		RuleID: e.RuleID, File: span.file, Line: span.start.line, LineOK: true, Col: span.start.col, ColOK: true,
		How: howSymbol, Resolution: s.Resolution, SiteKind: s.Kind, Callee: calleeOf(s),
		Metadata: fillCF(e.Metadata.M, fg, s, e), Caller: s.Caller, EndCol: span.end.col,
	}
	if span.end.line != span.start.line {
		f.EndLine = span.end.line
	}
	m.found = append(m.found, f)
}
