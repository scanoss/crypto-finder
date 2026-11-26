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

// The C++ forms of the C expression reader (c_syntax.go): qualified names
// `a::b::c` (a leading `::` too), template arguments `f<T, U>`, `new T(...)`
// and the brace initialization `T{...}`. The reader reads them only in C++
// mode (cParser.cpp); C text reads as before.

import (
	"slices"
	"strings"
)

// The C++ expression kinds.
const (
	// CExprScoped is a qualified name: its segments in Args (each an ident,
	// a metavariable or a template), Op "::" when it starts with `::`.
	CExprScoped = "scoped"
	// CExprTemplate is a name with template arguments: Sub the name, Args
	// the arguments.
	CExprTemplate = "template"
	// CExprType is a template argument that is not a name or a literal,
	// `const char *`: Text its tokens joined by spaces.
	CExprType = "type"
	// CExprNew is `new T(...)`, `new T{...}` or `new T`: Sub the type, Args
	// the arguments, Op "(" or "{" (none for `new T`).
	CExprNew = "new"
)

// CExprTyped is a typed metavariable `(T $X)` of a pattern (or a typed
// parameter `T &$X`): Var the metavariable, Sub the type's name, Op its
// declarator suffix (`*`, `&`, `&&` or none), Text cppConst when the type is
// const.
const CExprTyped = "typed"

// cppConst is the const qualifier, and the Text of a const typed pattern.
const cppConst = "const"

// CExprBrace is the Op of a call written as a brace initialization, `T{a}`.
const CExprBrace = "{"

// cppScope is the C++ scope token.
const cppScope = "::"

// cppNamePrimary: the cursor is at a C++ name (a word, a metavariable or
// `::`) the C++ reader reads, or at `new`.
func (p *cParser) cppNamePrimary() bool {
	if !p.cpp || p.eof() {
		return false
	}
	t := p.toks[p.i]
	return t.kind == ctIdent || (t.kind == ctPunct && t.text == cppScope) || (t.kind == ctVar && p.peekNext().text == cppScope)
}

// parseCPPPrimary reads a qualified name, a template or a new expression.
func (p *cParser) parseCPPPrimary() (*CExpr, error) {
	if t := p.toks[p.i]; t.kind == ctIdent && t.text == "new" {
		return p.parseNew()
	}
	return p.parseCPPName()
}

// parseCPPName reads `[::]a<...>::b::c<...>`; a lone name reads as the
// ident (or the metavariable) itself.
func (p *cParser) parseCPPName() (*CExpr, error) { //nolint:gocognit,gocyclo // one pass over the segments
	if p.eof() { // `new` as the last token of a site's text
		return nil, errCLex
	}
	start := p.toks[p.i].off
	global := p.accept(cppScope)
	var segs []CExpr
	for {
		if p.eof() || (p.toks[p.i].kind != ctIdent && p.toks[p.i].kind != ctVar) {
			return nil, errCLex
		}
		t := p.toks[p.i]
		p.i++
		seg := CExpr{Kind: CExprIdent, Name: t.text, Start: t.off, End: t.end()}
		if t.kind == ctVar {
			seg = CExpr{Kind: CExprMetavar, Var: t.text, Start: t.off, End: t.end()}
		} else if cppKeywords[t.text] {
			return nil, errCLex
		}
		if t.kind == ctIdent && p.is("<") {
			if args, ok, err := p.templateArgs(); err != nil {
				return nil, err
			} else if ok {
				name := seg
				seg = CExpr{Kind: CExprTemplate, Sub: &name, Args: args, Start: name.Start, End: p.prevEnd()}
			}
		}
		segs = append(segs, seg)
		if p.is(cppScope) && (p.peekNext().kind == ctIdent || p.peekNext().kind == ctVar) {
			p.i++
			continue
		}
		if p.is(cppScope) { // `a::~a`, `a::operator=`, `a::template f`
			return nil, errCLex
		}
		break
	}
	if !global && len(segs) == 1 {
		return &segs[0], nil
	}
	e := &CExpr{Kind: CExprScoped, Args: segs, Start: start, End: segs[len(segs)-1].End}
	if global {
		e.Op = cppScope
	}
	return e, nil
}

// cppKeywords are the words that never name a value or a type in an
// expression the reader reads.
var cppKeywords = setOf("template", "typename", "operator", "delete", "throw", "co_await", "co_yield")

// cppAfterTemplate are the tokens that can follow a template argument list.
var cppAfterTemplate = setOf("(", "{", cppScope, ")", "]", "}", ",", ";")

// templateArgs reads `<...>` at the cursor as template arguments when it
// closes and what follows can follow a template name (`(`, `{`, `::`, a
// closing bracket, `,`, `;` or the end); ok is false, the cursor
// unmoved, when the `<` is a less-than. A `>>` that closes it is split.
func (p *cParser) templateArgs() ([]CExpr, bool, error) {
	end, ok := p.templateClose()
	if !ok {
		return nil, false, nil
	}
	if end+1 < len(p.toks) {
		next := p.toks[end+1]
		declared := p.typeName && (next.kind == ctIdent || next.kind == ctVar) // `T<A> x`
		if !declared && (next.kind != ctPunct || !cppAfterTemplate[next.text]) {
			return nil, false, nil
		}
	}
	inner := p.toks[p.i+1 : end]
	p.i = end + 1
	args := []CExpr{}
	for len(inner) > 0 {
		n := cppArgLen(inner)
		a, err := p.templateArg(inner[:n])
		if err != nil {
			return nil, false, err
		}
		args = append(args, *a)
		inner = inner[n:]
		if len(inner) > 0 { // the comma
			inner = inner[1:]
			if len(inner) == 0 {
				return nil, false, errCLex
			}
		}
	}
	return args, true, nil
}

// templateClose finds the `>` that closes the `<` at the cursor; brackets
// nest, and a statement or block token ends the search. A `>>` closing two
// levels is split into two `>`.
func (p *cParser) templateClose() (int, bool) {
	depth, nest := 0, 0
	for j := p.i; j < len(p.toks); j++ {
		t := p.toks[j]
		if t.kind != ctPunct {
			continue
		}
		switch t.text {
		case "<":
			if nest == 0 {
				depth++
			}
		case ">", ">>":
			if nest > 0 {
				continue
			}
			if t.text == ">>" {
				p.splitShift(j)
			}
			depth--
			if depth == 0 {
				return j, true
			}
		case "(", "[":
			nest++
		case ")", "]":
			if nest == 0 {
				return 0, false
			}
			nest--
		case ";", "{", "}", "&&", "||":
			return 0, false
		}
	}
	return 0, false
}

// splitShift splits the `>>` token at j into two `>`.
func (p *cParser) splitShift(j int) {
	t := p.toks[j]
	p.toks = append(p.toks[:j+1], p.toks[j:]...)
	p.toks[j] = cTok{ctPunct, ">", t.off}
	p.toks[j+1] = cTok{ctPunct, ">", t.off + 1}
}

// cppArgLen is the number of tokens of the first template argument of toks:
// up to a comma outside brackets.
func cppArgLen(toks []cTok) int {
	depth := 0
	for i, t := range toks {
		if t.kind != ctPunct {
			continue
		}
		switch t.text {
		case "(", "[", "<":
			depth++
		case ")", "]", ">":
			depth--
		case ",":
			if depth == 0 {
				return i
			}
		}
	}
	return len(toks)
}

// templateArg reads one template argument: a name, a metavariable or a
// literal reads as an expression; anything else (a type with qualifiers or
// declarators) reads as a type, its tokens joined.
func (p *cParser) templateArg(toks []cTok) (*CExpr, error) {
	if len(toks) == 0 {
		return nil, errCLex
	}
	sub := &cParser{toks: slices.Clone(toks), pattern: p.pattern, cpp: true}
	if e, err := sub.parseExpr(); err == nil && sub.eof() {
		switch e.Kind {
		case CExprIdent, CExprScoped, CExprTemplate, CExprMetavar, CExprInt:
			return e, nil
		}
	}
	words := make([]string, 0, len(toks))
	for _, t := range toks {
		if t.kind == ctVar || (t.kind == ctPunct && t.text == rustEllipsis) {
			return nil, errCLex // a pattern binds or skips only a whole argument
		}
		words = append(words, t.text)
	}
	last := toks[len(toks)-1]
	return &CExpr{Kind: CExprType, Text: strings.Join(words, " "), Start: toks[0].off, End: last.end()}, nil
}

// parseNew reads `new T(...)`, `new T{...}` or `new T`.
func (p *cParser) parseNew() (*CExpr, error) {
	start := p.toks[p.i].off
	p.i++
	if p.is("(") { // placement new
		return nil, errCLex
	}
	typ, err := p.parseCPPName()
	if err != nil {
		return nil, err
	}
	e := &CExpr{Kind: CExprNew, Sub: typ, Start: start, End: typ.End}
	switch {
	case p.is("("):
		args, err := p.parseArgs()
		if err != nil {
			return nil, err
		}
		e.Op, e.Args, e.End = "(", args, p.prevEnd()
	case p.is("{"):
		init, err := p.parseBraceArgs()
		if err != nil {
			return nil, err
		}
		e.Op, e.Args, e.End = CExprBrace, init, p.prevEnd()
	case p.is("[") || p.is("*") || p.is("&"):
		return nil, errCLex
	}
	return e, nil
}

// parseBraceArgs reads `{a, b}` at the cursor as arguments.
func (p *cParser) parseBraceArgs() ([]CExpr, error) {
	p.i++ // {
	args := []CExpr{}
	if p.accept("}") {
		return args, nil
	}
	for {
		a, err := p.parseArg()
		if err != nil {
			return nil, err
		}
		args = append(args, *a)
		if p.accept("}") {
			return args, nil
		}
		if !p.accept(",") {
			return nil, errCLex
		}
	}
}

// cppBraceCallee: a brace initialization can follow e, a type name.
func cppBraceCallee(e *CExpr) bool {
	switch e.Kind {
	case CExprIdent, CExprScoped, CExprTemplate:
		return true
	}
	return false
}

// readCPPExpr reads text as one whole C++ expression.
func readCPPExpr(text string, pattern bool) (*CExpr, bool) {
	toks, err := lexC(text, pattern)
	if err != nil || len(toks) == 0 {
		return nil, false
	}
	p := &cParser{toks: toks, pattern: pattern, cpp: true}
	e, err := p.parseExpr()
	if err != nil || !p.eof() {
		return nil, false
	}
	return e, true
}

// cppLastName is the name a callee ends with: an ident's, a qualified
// name's last segment's, a template's or a member's (empty for a
// metavariable or another expression).
func cppLastName(e *CExpr) string {
	switch e.Kind {
	case CExprIdent:
		return e.Name
	case CExprScoped:
		return cppLastName(&e.Args[len(e.Args)-1])
	case CExprTemplate:
		return cppLastName(e.Sub)
	case CExprMember:
		if !isMetavar(e.Name) {
			return e.Name
		}
	case CExprNew, CExprDecl:
		return cppLastName(e.Sub)
	}
	return ""
}

// CExprDecl is a C++ variable declaration that constructs its variable:
// Sub the type, Callee the declared name, Op "(" or "{" for the
// initializer's brackets (none for `T x;`), Args its arguments, Text the
// declarator form (cppDeclFunction, cppDeclInit or cppDeclNone) and Multi
// whether the declaration declares more than one name.
const CExprDecl = "decl"

// The declarator forms of a declaration, as tree-sitter reads them:
// `T x(a, b)` whose arguments read as parameter types is a function
// declarator, `T x(1)` or `T x{a}` an init declarator, `T x;` a bare one.
// OpenGrep matches a declaration pattern only with a declaration of its own
// form, the pattern being read the same way.
const (
	cppDeclFunction = "function"
	cppDeclInit     = "init"
	cppDeclNone     = "none"
)

// cppDeclQualifiers are the words a declaration statement may start with
// before its type.
var cppDeclQualifiers = setOf(cppConst, "static", "volatile", "constexpr", "thread_local", "inline", "mutable", "register")

// readCPPDecl reads a C++ declaration `[const] T a(...), b{...}, c` (with
// or without its `;`): its last declarator. A pointer, reference or array
// declarator, or an `= v` initializer, does not read.
func readCPPDecl(text string, pattern bool) (*CExpr, bool) { //nolint:gocognit,gocyclo // one pass over the declarators
	toks, err := lexC(text, pattern)
	if err != nil || len(toks) == 0 {
		return nil, false
	}
	p := &cParser{toks: toks, pattern: pattern, cpp: true}
	for !p.eof() && p.toks[p.i].kind == ctIdent && cppDeclQualifiers[p.toks[p.i].text] {
		p.i++
	}
	if p.eof() || (p.toks[p.i].kind != ctIdent && !p.is(cppScope)) || (p.toks[p.i].kind == ctIdent && cppKeywords[p.toks[p.i].text]) {
		return nil, false
	}
	p.typeName = true
	typ, err := p.parseCPPName()
	p.typeName = false
	if err != nil || typ.Kind == CExprMetavar {
		return nil, false
	}
	var last *CExpr
	n := 0
	for {
		if p.eof() || (p.toks[p.i].kind != ctIdent && p.toks[p.i].kind != ctVar) {
			return nil, false
		}
		t := p.toks[p.i]
		p.i++
		name := &CExpr{Kind: CExprIdent, Name: t.text, Start: t.off, End: t.end()}
		if t.kind == ctVar {
			name = &CExpr{Kind: CExprMetavar, Var: t.text, Start: t.off, End: t.end()}
		}
		d := &CExpr{Kind: CExprDecl, Sub: typ, Callee: name, Text: cppDeclNone, Start: typ.Start}
		switch {
		case p.is("("):
			args, err := p.parseArgs()
			if err != nil {
				return nil, false
			}
			d.Op, d.Args, d.Text = "(", args, cppDeclInit
			if len(args) == 0 || cppParamLike(args) { // `T x()` declares a function too
				d.Text = cppDeclFunction
			}
		case p.is("{"):
			args, err := p.parseBraceArgs()
			if err != nil {
				return nil, false
			}
			d.Op, d.Args, d.Text = CExprBrace, args, cppDeclInit
		}
		d.End = p.prevEnd()
		last, n = d, n+1
		if !p.accept(",") {
			break
		}
	}
	p.accept(";")
	if !p.eof() {
		return nil, false
	}
	last.Multi = n > 1
	return last, true
}

// cppParamLike: every argument reads as a parameter type, as tree-sitter
// reads `T x(a, b)` as a function declarator: a name, a qualified name, a
// template, a metavariable or `...`.
func cppParamLike(args []CExpr) bool {
	if len(args) == 0 {
		return false
	}
	for i := range args {
		switch args[i].Kind {
		case CExprIdent, CExprScoped, CExprTemplate, CExprMetavar, CExprEllipsis:
		default:
			return false
		}
	}
	return true
}

// parseTypedMetavar reads `(T $X)` at the cursor: `const`, a type name, a
// declarator suffix and a metavariable in parentheses. ok is false, the
// cursor unmoved, for anything else.
func (p *cParser) parseTypedMetavar() (*CExpr, bool) {
	start := p.i
	p.i++
	e, ok := p.typedParam()
	if !ok || !p.accept(")") {
		p.i = start
		return nil, false
	}
	e.Start, e.End = p.toks[start].off, p.prevEnd()
	return e, true
}

// typedParam reads `[const] T [*|&|&&] $X` at the cursor.
func (p *cParser) typedParam() (*CExpr, bool) { //nolint:gocyclo // one pass over the parameter's parts
	e := &CExpr{Kind: CExprTyped}
	if !p.eof() {
		e.Start = p.toks[p.i].off
	}
	for !p.eof() && p.toks[p.i].kind == ctIdent && (p.toks[p.i].text == cppConst || p.toks[p.i].text == "volatile") {
		if p.toks[p.i].text == cppConst {
			e.Text = cppConst
		}
		p.i++
	}
	if p.eof() || (p.toks[p.i].kind != ctIdent && !p.is(cppScope)) {
		return nil, false
	}
	p.typeName = true
	typ, err := p.parseCPPName()
	p.typeName = false
	if err != nil || typ.Kind == CExprMetavar {
		return nil, false
	}
	if !p.eof() && p.toks[p.i].kind == ctIdent && p.toks[p.i].text == cppConst { // `T const &`
		e.Text = cppConst
		p.i++
	}
	for p.is("*") || p.is("&") || p.is("&&") {
		e.Op += p.toks[p.i].text
		p.i++
	}
	if p.eof() || p.toks[p.i].kind != ctVar {
		return nil, false
	}
	e.Sub, e.Var = typ, p.toks[p.i].text
	p.i++
	e.End = p.prevEnd()
	return e, true
}

// cppType is a type as a declaration or a parameter writes it: its name,
// its declarator suffix (`*`, `&`, `&&`, `[]`, ...) and whether it is const.
type cppType struct {
	name   *CExpr
	text   string // the name's text
	suffix string
	cnst   bool
}

// readCPPType reads a written type, `const seal::KeyGenerator &`; ok is
// false for a type with no name read (`auto`, a function pointer, ...).
func readCPPType(text string) (cppType, bool) {
	var t cppType
	s := strings.TrimSpace(text)
	for {
		switch {
		case strings.HasSuffix(s, "[]"):
			t.suffix, s = "[]"+t.suffix, s[:len(s)-2]
		case strings.HasSuffix(s, "&&"):
			t.suffix, s = "&&"+t.suffix, s[:len(s)-2]
		case strings.HasSuffix(s, "&") || strings.HasSuffix(s, "*"):
			t.suffix, s = s[len(s)-1:]+t.suffix, s[:len(s)-1]
		case strings.HasSuffix(s, " const"):
			t.cnst, s = true, s[:len(s)-len(" const")]
		default:
			s = strings.TrimSpace(s)
			for _, q := range []string{"const ", "volatile "} {
				if rest, ok := strings.CutPrefix(s, q); ok {
					t.cnst = t.cnst || q == "const "
					s = strings.TrimSpace(rest)
				}
			}
			e, ok := readCPPExpr(s, false)
			if !ok || (e.Kind != CExprIdent && e.Kind != CExprScoped && e.Kind != CExprTemplate) || e.Name == "auto" {
				return t, false
			}
			t.name, t.text = e, s
			return t, true
		}
		s = strings.TrimRight(s, " \t")
	}
}

// cppCast reads a C++ cast at the cursor, `(const ns::T *)x`, whose type
// has a qualified name or a template (the C reader reads the others): the
// type, `)` and an operand that cannot continue an expression. ok is false,
// the cursor unmoved, for anything else.
func (p *cParser) cppCast() (*CExpr, bool) { //nolint:gocyclo // one check per part of the cast
	if !p.cpp {
		return nil, false
	}
	start := p.i
	p.i++
	j := p.i
	for j < len(p.toks) && p.toks[j].kind == ctIdent && cTypeWords[p.toks[j].text] {
		j++
	}
	qualified := j < len(p.toks) && (p.toks[j].text == cppScope || (j+1 < len(p.toks) && (p.toks[j+1].text == cppScope || p.toks[j+1].text == "<")))
	if !qualified {
		p.i = start
		return nil, false
	}
	p.i = j
	p.typeName = true
	typ, err := p.parseCPPName()
	p.typeName = false
	for err == nil && !p.eof() && (p.is("*") || p.is("&") || (p.toks[p.i].kind == ctIdent && p.toks[p.i].text == cppConst)) {
		p.i++
	}
	if err != nil || typ.Kind == CExprIdent || !p.accept(")") || p.eof() {
		p.i = start
		return nil, false
	}
	if next := p.toks[p.i]; next.kind != ctIdent && next.kind != ctNum && next.kind != ctStr && next.kind != ctChar && next.text != "(" {
		p.i = start
		return nil, false
	}
	typeText := p.typeText(start+1, p.i-1)
	sub, err := p.parseUnary()
	if err != nil {
		p.i = start
		return nil, false
	}
	return &CExpr{Kind: CExprCast, Name: typeText, Sub: sub, Start: p.toks[start].off, End: sub.End}, true
}
