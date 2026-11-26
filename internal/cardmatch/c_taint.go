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

// C taint rules. A sink compiles as any C pattern does; the sources ride on
// it (CPattern.Taint). The sink's focused expression (the whole call when it
// has no focus) is tainted when it, or an expression written inside it,
// matches a source: OpenGrep's taint passes through a call it has no
// summary for, so `f(SRC)` and `&SRC` carry SRC.
//
// A name in it that is a local reads as the value its declaration
// initializes it with (the last declaration before it in its function,
// through further locals); a name that is a parameter of its function reads
// as the argument each call of that function written in the same file passes
// for it, as OpenGrep's --taint-intrafile does. Locals and callers together
// are followed cFlowDepth deep. What reaches the sink otherwise (a plain
// assignment, a struct field, a function's return, a caller in another file)
// is not read: such a sink finds nothing. Sanitizers and propagators are not
// modeled: such a rule is skipped.

import (
	"slices"
)

// CTaint is what a taint rule's sink must hold.
type CTaint struct {
	Sources []CTaintSource `json:"sources"`
}

// CTaintSource is one source: an expression pattern (a metavariable, a
// name, a call), Bind a bare metavariable written beside it that binds the
// same expression, and the metavariable-regex filters on what it binds.
type CTaintSource struct {
	Expr  *CExpr   `json:"expr"`
	Bind  string   `json:"bind,omitempty"`
	Where []CWhere `json:"where,omitempty"`
}

// compileCTaint compiles a taint rule: one entry per sink alternative, each
// carrying every source.
func compileCTaint(r *OMap) ([]*OMap, error) {
	if pyTruthy(r.GetOr("pattern-sanitizers")) || pyTruthy(r.GetOr("pattern-propagators")) {
		return nil, skipCTaintSanitizers.err()
	}
	taint := &CTaint{}
	for _, src := range cList(r.GetOr("pattern-sources")) {
		node, ok := src.(*OMap)
		if !ok {
			return nil, skipCTaintSource.err()
		}
		srcs, err := cTaintSources(node)
		if err != nil {
			return nil, err
		}
		taint.Sources = append(taint.Sources, srcs...)
	}
	if len(taint.Sources) == 0 {
		return nil, skipCTaintSource.err()
	}
	out, err := cTaintSinks(cList(r.GetOr("pattern-sinks")), taint)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, skipCFocus.err()
	}
	return out, nil
}

// cTaintSinks compiles the sinks, each alternative a call carrying taint.
func cTaintSinks(sinks []any, taint *CTaint) ([]*OMap, error) {
	var out []*OMap
	for _, snk := range sinks {
		sm, ok := snk.(*OMap)
		if !ok {
			return nil, skipCFormula.err()
		}
		alts, err := cDialect{}.cAlternatives(sm)
		if err != nil {
			return nil, err
		}
		for _, a := range cFocused(alts) {
			if a.Call == nil {
				return nil, skipCTaintSink.err()
			}
			a.Taint = taint
			e, err := cEntry(a)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// cTaintSources reads one pattern-sources entry: a pattern, a pattern-either
// of sources, or a patterns of one source (or a source and a bare
// metavariable binding the same expression) and metavariable-regex filters.
func cTaintSources(node *OMap) ([]CTaintSource, error) {
	if node.Len() != 1 {
		return nil, skipCTaintSource.err()
	}
	val := node.Vals[0]
	switch asOr[string](node.Keys[0]) {
	case keyPattern:
		text, ok := val.(string)
		if !ok {
			return nil, skipCTaintSource.err()
		}
		e, ok := readCExpr(text, true)
		if !ok || cTaintSourceShape(e) != nil {
			return nil, skipCTaintSource.err()
		}
		return []CTaintSource{{Expr: e}}, nil
	case keyPatternEither:
		var out []CTaintSource
		for _, b := range cList(val) {
			bm, ok := b.(*OMap)
			if !ok {
				return nil, skipCTaintSource.err()
			}
			srcs, err := cTaintSources(bm)
			if err != nil {
				return nil, err
			}
			out = append(out, srcs...)
		}
		return out, nil
	case keyPatterns:
		return cTaintConjunction(cList(val))
	}
	return nil, skipCTaintSource.err()
}

// cTaintConjunction reads a source's `patterns`: one source (a pattern or a
// pattern-either), or one and a bare metavariable binding the same
// expression, and metavariable-regex filters.
func cTaintConjunction(items []any) ([]CTaintSource, error) { //nolint:gocognit,gocyclo // one pass over the clauses, then the source shapes
	var positives [][]CTaintSource
	var where []CWhere
	for _, it := range items {
		m, ok := it.(*OMap)
		if !ok || m.Len() != 1 {
			return nil, skipCTaintSource.err()
		}
		switch asOr[string](m.Keys[0]) {
		case keyPattern, keyPatternEither:
			got, err := cTaintSources(m)
			if err != nil {
				return nil, err
			}
			positives = append(positives, got)
		case keyMetavarRegex:
			w, err := cWhereOf(m.Vals[0])
			if err != nil {
				return nil, err
			}
			where = append(where, w)
		default:
			return nil, skipCTaintSource.err()
		}
	}
	bare := func(srcs []CTaintSource) bool { return len(srcs) == 1 && srcs[0].Expr.Kind == CExprMetavar }
	var srcs []CTaintSource
	bind := ""
	switch {
	case len(positives) == 1:
		srcs = positives[0]
	case len(positives) == 2 && bare(positives[1]):
		srcs, bind = positives[0], positives[1][0].Expr.Var
	case len(positives) == 2 && bare(positives[0]):
		srcs, bind = positives[1], positives[0][0].Expr.Var
	default:
		return nil, skipCTaintSource.err()
	}
	out := make([]CTaintSource, len(srcs))
	for i, s := range srcs {
		s.Bind, s.Where = bind, slices.Concat(s.Where, where)
		bound := map[string]bool{}
		cVars(s.Expr, bound, map[string]bool{}, false)
		if bind != "" {
			bound[bind] = true
		}
		for _, w := range s.Where {
			if !bound[w.Metavar] {
				return nil, skipCUnbound.err()
			}
		}
		out[i] = s
	}
	return out, nil
}

// cTaintSourceShape checks a source expression: a metavariable, a name, a
// literal or a call of the call shapes.
func cTaintSourceShape(e *CExpr) error {
	switch e.Kind {
	case CExprMetavar, CExprIdent, CExprInt, CExprString:
		return nil
	case CExprCall:
		return cDialect{}.cPatternCall(e)
	}
	return skipCTaintSource.err()
}

// cFlowDepth bounds how many declarations and callers a taint flow crosses.
const cFlowDepth = 4

// tainted reads whether expression x of rd holds a source, and what the
// source binds: x or an expression written in it matches one, or a name in it
// is a local whose declaration, the last before it in its function,
// initializes it with a tainted value.
func (m *cMatcher) tainted(t *CTaint, rd *cRead, x *CExpr) (cEnv, bool) {
	return m.taintedAt(t, rd, x, 0)
}

func (m *cMatcher) taintedAt(t *CTaint, rd *cRead, x *CExpr, depth int) (cEnv, bool) {
	var hit cEnv
	found := cWalk(x, func(y *CExpr) bool {
		if env, ok := m.source(t, rd, y); ok {
			hit = env
			return true
		}
		if y.Kind != CExprIdent || depth >= cFlowDepth {
			return false
		}
		d, init, declared := m.localInit(rd, y)
		if init != nil {
			if env, ok := m.taintedAt(t, d, init, depth+1); ok {
				hit = env
				return true
			}
		}
		if !declared {
			if env, ok := m.taintedByCallers(t, rd, y.Name, depth+1); ok {
				hit = env
				return true
			}
		}
		return false
	})
	return hit, found
}

// taintedByCallers: name is a parameter of rd's function and a call of that
// function written in the same file passes a tainted argument for it.
func (m *cMatcher) taintedByCallers(t *CTaint, rd *cRead, name string, depth int) (cEnv, bool) {
	fn := m.fr.CFuncs[rd.site.Caller]
	if fn == nil {
		return nil, false
	}
	index := slices.Index(fn.ParameterNames, name)
	if index < 0 {
		return nil, false
	}
	for _, cs := range m.fr.Incoming[rd.site.Caller] {
		if cs.File != rd.site.File {
			continue
		}
		crd := m.readSite(cs)
		if crd == nil || index >= len(crd.call.Args) {
			continue
		}
		if env, ok := m.taintedAt(t, crd, &crd.call.Args[index], depth); ok {
			return env, true
		}
	}
	return nil, false
}

// source: expression y of rd matches a source, with what it binds.
func (m *cMatcher) source(t *CTaint, rd *cRead, y *CExpr) (cEnv, bool) {
	var hit cEnv
	for i := range t.Sources {
		s := &t.Sources[i]
		if m.unify(s.Expr, y, rd, cEnv{}, func(env cEnv) bool {
			if s.Bind != "" {
				var ok bool
				if env, ok = env.bind(s.Bind, m.binding(rd, y)); !ok {
					return false
				}
			}
			env, ok := cWhere(s.Where, env)
			hit = env
			return ok
		}) {
			return hit, true
		}
	}
	return nil, false
}

// localInit is the initializer of the local name y of rd is, from its last
// declaration before y in rd's function; nil when it has none. declared is
// whether such a declaration exists.
func (m *cMatcher) localInit(rd *cRead, y *CExpr) (*cRead, *CExpr, bool) {
	at := rd.pos(y.Start)
	var last *Site
	for _, d := range m.fr.DeclsByCaller[rd.site.Caller] {
		if d.AssignedVar == y.Name && d.File == rd.site.File && (cPos{d.Line, d.Col}).before(at) &&
			(last == nil || (cPos{last.Line, last.Col}).before(cPos{d.Line, d.Col})) {
			last = d
		}
	}
	if last == nil {
		return nil, nil, false
	}
	decl := m.readDecl(last)
	if decl == nil {
		return nil, nil, true
	}
	for i := range decl.decl.Decls {
		if dc := &decl.decl.Decls[i]; dc.Name == y.Name {
			return decl.rd, dc.Init, true
		}
	}
	return nil, nil, true
}
