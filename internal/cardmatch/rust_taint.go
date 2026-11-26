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

// Rust taint rules. A sink compiles as any Rust pattern does; the sources
// ride on it (RustPattern.Taint). The match reads what reaches the sink at
// the level OpenGrep's --taint-intrafile reads it, within one file:
//
//   - a value source (a bare metavariable, with a metavariable-regex) holds
//     when an argument's value matches: the argument as written, the values
//     its source nodes trace to (literals, consts, lets), and the values the
//     callers of its function in the same file pass for a parameter
//     (taintHits, shared with Java and Python);
//   - an object source (a call pattern, or a path) holds when the sink's
//     receiver or an argument holds what a call matching it returns: a local
//     assigned from such a call, a call chained on one, an argument whose
//     source nodes trace to one, or a parameter a caller in the same file
//     passes one for. Taint passes through a call whose receiver or argument
//     holds it, as OpenGrep's does through a function it has no summary for.
//
// Sanitizers and propagators are not modeled: such a rule is skipped.

import (
	"strings"
)

// rustFlowDepth bounds how many calls, locals and callers a flow crosses.
const rustFlowDepth = 8

// compileRustTaint compiles a taint rule: one entry per sink alternative,
// each carrying every source.
func compileRustTaint(r *OMap) ([]*OMap, error) {
	if pyTruthy(r.GetOr("pattern-sanitizers")) || pyTruthy(r.GetOr("pattern-propagators")) {
		return nil, skipRustSanitizers.err()
	}
	taint := &RustTaint{}
	for _, src := range rustList(r.GetOr("pattern-sources")) {
		if err := taint.add(src); err != nil {
			return nil, err
		}
	}
	if len(taint.Values)+len(taint.Objects) == 0 {
		return nil, skipRustSource.err()
	}
	var out []*OMap
	for _, snk := range rustList(r.GetOr("pattern-sinks")) {
		sm, ok := snk.(*OMap)
		if !ok {
			return nil, skipRustFormula.err()
		}
		alts, err := rustAlternatives(sm)
		if err != nil {
			return nil, err
		}
		for _, a := range alts {
			e, err := rustSinkEntry(a, taint)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, skipRustNoPositive.err()
	}
	return out, nil
}

// rustSinkEntry gives the entry of a sink alternative: a call, and no
// second positive.
func rustSinkEntry(a *RustPattern, taint *RustTaint) (*OMap, error) {
	switch {
	case a.Call == nil:
		return nil, skipRustPositive.err()
	case len(a.Within) > 0:
		return nil, skipRustPositives.err()
	}
	a.Taint = taint
	return rustEntry(a)
}

// add reads one pattern-sources entry: a value source when it is a bare
// metavariable (compileSource), else object sources, one per alternative.
func (t *RustTaint) add(src any) error {
	node, ok := src.(*OMap)
	if !ok {
		return skipRustFormula.err()
	}
	if rxs, err := compileSource(node); err == nil {
		for i, name := range rustSourceMetavars(node) {
			v := RustTaintValue{Metavar: name}
			if rx, ok := rxs[i].(string); ok {
				v.Regex = &rx
			}
			t.Values = append(t.Values, v)
		}
		return nil
	}
	alts, err := rustAlternatives(node)
	if err != nil {
		return err
	}
	for _, a := range alts {
		if (a.Call == nil && a.Ref == nil) || a.Focus != "" || len(a.Within) > 0 {
			return skipRustSource.err()
		}
		if err := a.check(map[string]bool{}); err != nil {
			return err
		}
		t.Objects = append(t.Objects, *a)
	}
	return nil
}

// rustSourceMetavars are the metavariables of a value source, one per
// regex compileSource gives for it, in the same order.
func rustSourceMetavars(node *OMap) []string {
	if either, ok := node.Get(keyPatternEither); ok {
		var out []string
		for _, b := range rustList(either) {
			if bm, ok := b.(*OMap); ok {
				out = append(out, rustSourceMetavars(bm)...)
			}
		}
		return out
	}
	clauses := []any{node}
	if pats, ok := node.Get(keyPatterns); ok {
		clauses = rustList(pats)
	}
	name := ""
	for _, c := range clauses {
		if cm, ok := c.(*OMap); ok {
			if p, ok := cm.Get(keyPattern); ok {
				name = pyStrip(pyStr(p))
			}
		}
	}
	return []string{name}
}

// rustTaintHit is how a source reaches a sink: how, the value (or the
// source call's text), and what the source binds.
type rustTaintHit struct {
	how, value string
	env        rustEnv
}

// tainted reports whether a source of e reaches the sink at s matched under
// env: the focused argument or receiver, else the receiver and every argument.
func (m *rustMatcher) tainted(e *Entry, s *Site, rd *rustRead, env rustEnv) (rustTaintHit, bool) {
	t := e.Rust.Taint
	idxs, recv := s.ParamIdx, true
	if f := e.Rust.Focus; f != "" {
		// The focused argument, else the focused receiver.
		if i, ok := env.arg[f]; ok {
			idxs, recv = []int{i}, false
		} else {
			idxs = nil
		}
	}
	if len(t.Values) > 0 {
		rxs := make([]*string, len(t.Values))
		for i := range t.Values {
			rxs[i] = t.Values[i].Regex
		}
		if hits := taintHits(rxs, idxs, s, m.fr.Incoming, m.fr.ResolveParams); len(hits) > 0 {
			return t.valueHit(hits[0]), true
		}
	}
	if len(m.sources(e)) == 0 {
		return rustTaintHit{}, false
	}
	saved := m.undecided
	defer func() { m.undecided = saved }()
	fl := &rustFlow{m: m, srcs: m.sources(e), done: map[*Site]*rustTaintHit{}}
	if recv && rd.call.Receiver != nil {
		if h := fl.expr(s, rd, *rd.call.Receiver, 0); h != nil {
			return *h, true
		}
	}
	for _, i := range idxs {
		if p := s.Params[i]; p != nil {
			if h := fl.nodes(s, p.SourceNodes, 0); h != nil {
				return *h, true
			}
		}
	}
	return rustTaintHit{}, false
}

// sources are the object sources of e no missing fact or shape holds.
func (m *rustMatcher) sources(e *Entry) []RustPattern {
	if out, ok := m.srcs[e]; ok {
		return out
	}
	var out []RustPattern
	for i := range e.Rust.Taint.Objects {
		if len(rustSourceHolds(&e.Rust.Taint.Objects[i], m.fr.RustFacts)) == 0 {
			out = append(out, e.Rust.Taint.Objects[i])
		}
	}
	m.srcs[e] = out
	return out
}

// rustSourceHolds are the reasons an object source is held. A path source
// is read where the flow meets it (a receiver), not from the constant
// references, so neither their table nor their shapes hold it.
func rustSourceHolds(p *RustPattern, facts bool) []string {
	q := *p
	q.Ref = nil
	return rustHolds(&q, facts, false)
}

// valueHit binds the metavariable of the first value source the hit's
// value matches, and the regex's named groups.
func (t *RustTaint) valueHit(h taintHit) rustTaintHit {
	out := rustTaintHit{how: h.How, value: h.Value}
	for _, v := range t.Values {
		if v.Regex != nil {
			if _, ok := reMatchFull(*v.Regex, h.Value); !ok {
				continue
			}
		}
		out.env, _ = out.env.bind(v.Metavar, h.Value)
		break
	}
	for k, g := range h.Groups {
		if g != nil {
			out.env, _ = out.env.bind("$"+k, *g)
		}
	}
	return out
}

// rustFlow follows what a sink holds back to object sources, within one
// fragment; done memoizes each call site's result (nil: no source).
type rustFlow struct {
	m    *rustMatcher
	srcs []RustPattern
	done map[*Site]*rustTaintHit
}

// site: the call at site returns what a source returns, as a call matching
// one or a call whose receiver or argument holds it.
func (fl *rustFlow) site(site *Site, depth int) *rustTaintHit {
	if h, ok := fl.done[site]; ok {
		return h
	}
	fl.done[site] = nil // a cycle holds nothing
	rd := fl.m.read(site)
	var h *rustTaintHit
	if text, ok := fl.m.spanText(site.File, site.Line, site.Col, site.EndLine, site.EndCol); ok && rd != nil {
		h = fl.source(site, rd, text)
	}
	if h == nil && depth < rustFlowDepth {
		switch {
		case rd != nil && rd.call.Receiver != nil:
			h = fl.expr(site, rd, *rd.call.Receiver, depth+1)
		case rd == nil:
			// A call the reader has no shape for (`f(..).await.unwrap()`):
			// what it is chained on still flows into it.
			if inner := fl.m.chained(site); inner != nil {
				h = fl.site(inner, depth+1)
			}
		}
		for _, i := range site.ParamIdx {
			if h != nil {
				break
			}
			if p := site.Params[i]; p != nil {
				h = fl.nodes(site, p.SourceNodes, depth+1)
			}
		}
	}
	fl.done[site] = h
	return h
}

// source: a source pattern matches what rd reads at site.
func (fl *rustFlow) source(site *Site, rd *rustRead, text string) *rustTaintHit {
	m := fl.m
	file := m.file
	defer func() { m.file = file }()
	m.file = site.File
	for i := range fl.srcs {
		p := &fl.srcs[i]
		if (p.Call != nil) != (rd.call != nil) {
			continue
		}
		var hit *rustTaintHit
		m.matchPattern(p, site, rd, rustEnv{}, func(env rustEnv) bool {
			hit = &rustTaintHit{how: "object", value: text, env: env}
			return true
		})
		if hit != nil {
			return hit
		}
	}
	return nil
}

// expr: a written receiver holds what a source returns. A local reads the
// call it was last assigned from before site, a call the site chained on
// (it starts where site starts), a path an object source naming it.
func (fl *rustFlow) expr(site *Site, rd *rustRead, e RustExpr, depth int) *rustTaintHit {
	switch e.Kind { //nolint:exhaustive // the other kinds hold nothing a flow reads
	case RustExprRef, RustExprTry, RustExprField, RustExprIndex:
		// `&x`, `x?`, `x.await`, a field or an element of x hold what x holds.
		return fl.expr(site, rd, *e.Sub, depth)
	case RustExprCall:
		if inner := fl.m.chained(site); inner != nil {
			return fl.site(inner, depth)
		}
	case RustExprPath:
		if h := fl.source(site, &rustRead{ref: e.Path, span: rd.span}, e.Path.String()); h != nil {
			return h
		}
		if name, ok := rustLocalName(e.Path); ok {
			if t := fl.m.assigned(site, name); t != nil {
				return fl.site(t, depth)
			}
		}
	}
	return nil
}

// nodes: an argument's source nodes trace to what a source returns.
func (fl *rustFlow) nodes(site *Site, nodes []SourceNode, depth int) *rustTaintHit {
	if depth > rustFlowDepth {
		return nil
	}
	for i := range nodes {
		n := &nodes[i]
		switch n.Type {
		case srcCallResult:
			if t := fl.m.callAt(site, n); t != nil {
				if h := fl.site(t, depth); h != nil {
					return h
				}
				continue
			}
		case srcParameter:
			if h := fl.callers(site, n, depth); h != nil {
				return h
			}
			continue
		}
		if h := fl.nodes(site, n.SourceNodes, depth); h != nil {
			return h
		}
	}
	return nil
}

// callers: a caller written in the same file passes, for the parameter n,
// what a source returns (OpenGrep's taint follows no other file).
func (fl *rustFlow) callers(site *Site, n *SourceNode, depth int) *rustTaintHit {
	if !fl.m.fr.ResolveParams || n.ParameterIndex == nil {
		return nil
	}
	for _, cs := range fl.m.fr.Incoming[site.Caller] {
		if cs.File != site.File {
			continue
		}
		if cp := callerArgument(cs, n); cp != nil {
			if h := fl.nodes(cs, cp.SourceNodes, depth+1); h != nil {
				return h
			}
		}
	}
	return nil
}

// rustLocalName is the name of a path that reads a local: one plain segment.
func rustLocalName(p *RustPath) (string, bool) {
	if p.Global || p.QSelf != nil || len(p.Segs) != 1 || p.Segs[0].Var != "" || p.Segs[0].Generics != nil {
		return "", false
	}
	return p.Segs[0].Name, true
}

// chained is the call a method call at s is chained on: the longest call
// of the same function that starts where s starts and ends before it.
func (m *rustMatcher) chained(s *Site) *Site {
	var best *Site
	for _, t := range m.fr.ByCaller[s.Caller] {
		if t == s || t.File != s.File || t.Line != s.Line || t.Col != s.Col || !t.ColOK || !s.ColOK {
			continue
		}
		if !rustEndsBefore(t, s) {
			continue
		}
		if best == nil || rustEndsBefore(best, t) {
			best = t
		}
	}
	return best
}

// rustEndsBefore: a ends before b.
func rustEndsBefore(a, b *Site) bool {
	al, bl := max(a.EndLine, a.Line), max(b.EndLine, b.Line)
	return al < bl || (al == bl && a.EndCol < b.EndCol)
}

// assigned is the call the local name was last assigned from before s, in
// the same function, when no later let of the name, ended before s, binds it
// from something else (a parameter, a field, a call of no site): the last
// binding before the sink decides, as OpenGrep's taint reads it. A let in a
// block that has closed before s still counts, as OpenGrep reads it (pinned
// by testdata/rust_taint/rebind.rs). A plain reassignment (`key = loaded;`)
// is no declaration of the fragment and is not seen.
func (m *rustMatcher) assigned(s *Site, name string) *Site {
	var best *Site
	for _, t := range m.fr.ByCaller[s.Caller] {
		if t.AssignedVar != name || t.File != s.File || !rustPosLE(t.Line, t.Col, s.Line, s.Col) || t == s {
			continue
		}
		if best == nil || rustPosLE(best.Line, best.Col, t.Line, t.Col) {
			best = t
		}
	}
	if best == nil {
		return nil
	}
	at := rustPos{s.Line, s.Col}
	for _, d := range m.fr.DeclsByCaller[s.Caller] {
		if d.AssignedVar != name || d.File != s.File {
			continue
		}
		span := rustSpanOf(d.Line, d.Col, d.EndCol, d.EndLine)
		if at.before(span.to) || span.contains(rustPos{best.Line, best.Col}) {
			continue // not ended before s, or the let of best's own call
		}
		if !rustPosLE(d.Line, d.Col, best.Line, best.Col) {
			return nil
		}
	}
	return best
}

// callAt is the call a CALL_RESULT node of an argument at s names: a call of
// the same function on the node's line whose written text is the node's.
func (m *rustMatcher) callAt(s *Site, n *SourceNode) *Site {
	if n.Location == nil {
		return nil
	}
	want := strings.Join(strings.Fields(n.Value), "")
	for _, t := range m.fr.ByCaller[s.Caller] {
		if t.File != s.File || t.Line != n.Location.Line {
			continue
		}
		if text, ok := m.spanText(t.File, t.Line, t.Col, t.EndLine, t.EndCol); ok && strings.Join(strings.Fields(text), "") == want {
			return t
		}
	}
	return nil
}
