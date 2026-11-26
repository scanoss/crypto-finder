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

// The C++ shapes that read the declared types of the fragment
// (graph-algo-cpp-3): typed metavariables, typed parameters of a function
// context and `T $X = ...;` declarations, as OpenGrep matches them:
//
//   - `(T $X)` matches a name whose type is T: the type of the latest
//     declaration of the name written before it in the function (blocks are
//     not scopes), else of the function's parameter of that name. A
//     declaration tree-sitter reads as a function declarator (`T x(a);`)
//     declares no variable.
//   - A type matches when its name matches T (qualified as names are), its
//     declarator suffix (`*`, `&`) is T's, and it is const when T is.
//   - `T $X = ...;` matches a declaration of one name with an initializer
//     that is not a function declarator: `T x = e;`, `T x(1);`, `T x{a};`.

import (
	"strings"
)

// cppDeclAssign is the declarator form of a `T $X = ...;` pattern and of
// the declarations it matches.
const cppDeclAssign = "assign"

// typeFits: the written type fits the typed pattern pe; k is called with
// the bindings of its name.
func (m *cMatcher) typeFits(pe *CExpr, written string, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	t, ok := readCPPType(written)
	if !ok || t.suffix != pe.Op || (pe.Text == cppConst && !t.cnst) {
		return false
	}
	tr := &cRead{site: rd.site, text: t.text, line: rd.line, col: rd.col}
	return m.unify(pe.Sub, t.name, tr, env, k)
}

// unifyTyped unifies a typed metavariable with a written name of its type.
func (m *cMatcher) unifyTyped(pe, se *CExpr, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	if se.Kind == CExprInt && pe.Sub.Kind == CExprIdent && pe.Sub.Name == "int" {
		env, ok := env.bind(pe.Var, m.binding(rd, se))
		return ok && k(env)
	}
	if se.Kind != CExprIdent {
		return false
	}
	written, ok := m.declaredType(rd, se.Name)
	if !ok {
		return false
	}
	return m.typeFits(pe, written, rd, env, func(env cEnv) bool {
		env, ok := env.bind(pe.Var, m.binding(rd, se))
		return ok && k(env)
	})
}

// declaredType is the type the name has where rd is written: its latest
// declaration before rd in rd's function, else its parameter.
func (m *cMatcher) declaredType(rd *cRead, name string) (string, bool) {
	at := cPos{rd.site.Line, rd.site.Col}
	var best *Site
	for _, d := range m.fr.DeclsByCaller[rd.site.Caller] {
		dp := cPos{d.Line, d.Col}
		if d.AssignedVar != name || !dp.before(at) || m.cppFunctionDecl(d) {
			continue
		}
		if best == nil || (cPos{best.Line, best.Col}).before(dp) {
			best = d
		}
	}
	if best != nil {
		return best.Raw, true
	}
	if fn := m.fr.CFuncs[rd.site.Caller]; fn != nil {
		for _, p := range fn.WrittenParameters {
			if p.Name == name {
				return p.Type, true
			}
		}
	}
	return "", false
}

// cppFunctionDecl: the declaration is one tree-sitter reads as a function
// declarator, `T x(a);`: a construction site of that anchor starts there.
func (m *cMatcher) cppFunctionDecl(d *Site) bool {
	if m.fnDecls == nil {
		m.fnDecls = map[cPos2]bool{}
		for at, kind := range m.fr.CAnchorKinds {
			if kind == cppAnchorFunctionDecl {
				m.fnDecls[cPos2{at.file, at.line, at.col}] = true
			}
		}
	}
	return m.fnDecls[cPos2{d.File, d.Line, d.Col}]
}

// cPos2 is a position in a file.
type cPos2 struct {
	file      string
	line, col int
}

// funcParams unifies a function context's parameter patterns (`...` and
// typed parameters) with the function's parameters as written.
func (m *cMatcher) funcParams(ps []CExpr, fn *FunctionJSON, rd *cRead, env cEnv, k func(cEnv) bool) bool {
	params := fn.WrittenParameters
	var walk func(ps []CExpr, i int, env cEnv) bool
	walk = func(ps []CExpr, i int, env cEnv) bool {
		if len(ps) == 0 {
			return i == len(params) && k(env)
		}
		if ps[0].Kind == CExprEllipsis {
			for j := i; j <= len(params); j++ {
				if walk(ps[1:], j, env) {
					return true
				}
			}
			return false
		}
		if i == len(params) || params[i].Name == "" {
			return false
		}
		p := params[i]
		return m.typeFits(&ps[0], p.Type, rd, env, func(env cEnv) bool {
			env, ok := env.bind(ps[0].Var, cBinding{text: p.Name, norm: p.Name})
			return ok && walk(ps[1:], i+1, env)
		})
	}
	return walk(ps, 0, env)
}

// readAssigns reads the declarations a `T $X = ...;` pattern can match:
// one name of a type without declarator suffix, an initializer, not a
// function declarator; each reads as the statement OpenGrep reports, from
// its qualifiers to its `;`.
func (m *cMatcher) readAssigns() {
	starts := map[cPos2]int{}
	for _, d := range m.fr.Decls {
		starts[cPos2{d.File, d.Line, d.Col}]++
	}
	for _, d := range m.fr.Decls {
		if d.RefContext == "" || starts[cPos2{d.File, d.Line, d.Col}] > 1 || d.EndLine > d.Line || m.cppFunctionDecl(d) {
			continue
		}
		t, ok := readCPPType(d.Raw)
		if !ok || t.suffix != "" {
			continue
		}
		line, ok := m.fr.Lines[d.File][d.Line]
		if !ok || d.Col < 1 || d.EndCol-1 > len(line) || d.EndCol <= d.Col {
			continue
		}
		start := cppQualifiersStart(line, d.Col-1)
		text := line[start : d.EndCol-1]
		at := strings.Index(text[d.Col-1-start:], " "+d.AssignedVar)
		if at < 0 {
			continue
		}
		nameStart := d.Col - 1 - start + at + 1
		name := &CExpr{Kind: CExprIdent, Name: d.AssignedVar, Start: nameStart, End: nameStart + len(d.AssignedVar)}
		typ := &CExpr{Kind: CExprType, Text: t.text}
		if e, ok := readCPPExpr(t.text, false); ok {
			typ = e
		}
		decl := &CExpr{Kind: CExprDecl, Text: cppDeclAssign, Sub: typ, Callee: name, Start: 0, End: len(text)}
		rd := &cRead{site: d, call: decl, text: text, line: d.Line, col: start + 1}
		last := cppLastName(decl)
		m.byLast[last] = append(m.byLast[last], rd)
		m.byCaller[d.Caller] = append(m.byCaller[d.Caller], rd)
	}
}

// cppQualifiersStart is the offset where the qualifiers written before the
// type at offset at of line start.
func cppQualifiersStart(line string, at int) int {
	start := at
	for {
		head := strings.TrimRight(line[:start], " \t")
		j := len(head)
		for j > 0 && isCIdentByte(head[j-1]) {
			j--
		}
		if j == len(head) || !cppDeclQualifiers[head[j:]] {
			return start
		}
		start = j
	}
}
