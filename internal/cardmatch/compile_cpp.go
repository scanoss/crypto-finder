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

// The C++ shapes of the C rule compiler. A rule whose languages name C++ and
// not C is read in the C++ dialect: its patterns read with the C++ reader
// (cpp_syntax.go), and a call's callee and arguments may also be a qualified
// name, a template, a member of an expression (`$R.m`, `$R->m`) or a call
// (`H()(x)`). A rule that names C keeps the C shapes, so C rules compile as
// they did. The constructions (`T x(...);`, `new T(...)`, `T{...}`) are
// skipped with their own reason: the C++ graph lists no construction sites.

import (
	"slices"
	"strings"

	"github.com/dlclark/regexp2"
)

// The C++ skip reasons.
const (
	skipCPPConstruct cSkip = "c++: construction"
	skipCPPTyped     cSkip = "c++: typed metavariable"
	skipCPPRegex     cSkip = "c++: pattern-regex anchor or multi-line lookbehind"
)

// cDialect is the language a rule's patterns are read in.
type cDialect struct {
	cpp bool
}

// cppOnlyRule: the rule's languages name C++ and not C.
func cppOnlyRule(r *OMap) bool {
	cpp := false
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		s, isStr := l.(string)
		if !isStr {
			continue
		}
		switch strings.ToLower(s) {
		case ecosystemC:
			return false
		case ecosystemCPP, "c++":
			cpp = true
		}
	}
	return cpp
}

// read reads a pattern's text as one expression.
func (d cDialect) read(text string) (*CExpr, bool) {
	if d.cpp {
		return readCPPExpr(text, true)
	}
	return readCExpr(text, true)
}

// unreadable is the reason a pattern text that does not read as an
// expression is skipped: a C++ construction or typed metavariable has its
// own; else fallback.
func (d cDialect) unreadable(text string, fallback cSkip) cSkip {
	if !d.cpp {
		return fallback
	}
	switch {
	case cppTypedMetavar(text):
		return skipCPPTyped
	case cppDeclaration(text):
		return skipCPPConstruct
	}
	return fallback
}

// cppTypedMetavar: the text starts with a typed metavariable, `(T $X)`.
func cppTypedMetavar(text string) bool {
	toks, err := lexC(text, true)
	if err != nil || len(toks) < 4 || toks[0].text != "(" {
		return false
	}
	for i := 1; i < len(toks); i++ {
		if toks[i].text == ")" {
			return toks[i-1].kind == ctVar && i >= 3
		}
	}
	return false
}

// cppDeclaration: the text is a declaration of a variable of a named type,
// `T x;`, `T x(...);`, `T x{...};` or `T x = v;` (a statement followed by
// `...` included).
func cppDeclaration(text string) bool { //nolint:gocyclo // one check per part of the declaration
	toks, err := lexC(text, true)
	if err != nil {
		return false
	}
	p := &cParser{toks: toks, pattern: true, cpp: true}
	for !p.eof() && p.toks[p.i].kind == ctIdent && cTypeQualifiers[p.toks[p.i].text] {
		p.i++
	}
	if p.eof() || (p.toks[p.i].kind != ctIdent && !p.is(cppScope)) {
		return false
	}
	if _, err := p.parseCPPName(); err != nil {
		return false
	}
	for p.is("*") || p.is("&") {
		p.i++
	}
	if p.eof() || (p.toks[p.i].kind != ctVar && p.toks[p.i].kind != ctIdent) {
		return false
	}
	p.i++
	return p.eof() || p.is("(") || p.is("{") || p.is("=") || p.is(";")
}

// cppPatternCall checks a C++ call pattern: its callee one of the C++
// callee shapes, its arguments each in the argument shapes.
func (d cDialect) cppPatternCall(e *CExpr) error {
	if e.Op == CExprBrace {
		return skipCPPConstruct.err()
	}
	if err := d.cppCallee(e.Callee); err != nil {
		return err
	}
	for i := range e.Args {
		if e.Args[i].Kind == CExprEllipsis {
			continue
		}
		if err := d.cPatternArg(&e.Args[i]); err != nil {
			return err
		}
	}
	return nil
}

// cppCallee checks a callee: a name, a metavariable, a qualified name, a
// template, a member of an argument-shaped expression or a call.
func (d cDialect) cppCallee(e *CExpr) error {
	switch e.Kind {
	case CExprIdent, CExprMetavar:
		return nil
	case CExprScoped, CExprTemplate:
		return d.cppName(e)
	case CExprMember:
		return d.cPatternArg(e.Sub)
	case CExprCall:
		return d.cPatternCall(e)
	}
	return skipCExpr.err()
}

// cppName checks a qualified name or a template: segments that are names,
// metavariables or templates of names, whose arguments are each a name, a
// metavariable, an integer, a type or a template of the same shape.
func (d cDialect) cppName(e *CExpr) error {
	switch e.Kind {
	case CExprIdent, CExprMetavar, CExprInt, CExprType:
		return nil
	case CExprScoped:
		for i := range e.Args {
			if err := d.cppName(&e.Args[i]); err != nil {
				return err
			}
		}
		return nil
	case CExprTemplate:
		if e.Sub.Kind != CExprIdent {
			return skipCExpr.err()
		}
		for i := range e.Args {
			if err := d.cppName(&e.Args[i]); err != nil {
				return err
			}
		}
		return nil
	}
	return skipCExpr.err()
}

// cppPatternArg checks the C++ argument shapes beside the C ones: a
// qualified name, a template and a member access.
func (d cDialect) cppPatternArg(e *CExpr) (bool, error) {
	switch e.Kind {
	case CExprScoped, CExprTemplate:
		return true, d.cppName(e)
	case CExprMember:
		return true, d.cPatternArg(e.Sub)
	case CExprNew:
		return true, d.cppConstruct(e)
	case CExprCall:
		return true, d.cppPatternCall(e)
	case CExprTyped:
		return true, d.cppTyped(e)
	case CExprInit:
		for i := range e.Args {
			if e.Args[i].Kind == CExprEllipsis {
				continue
			}
			if err := d.cPatternArg(&e.Args[i]); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	return false, nil
}

// cppConstruct checks a construction pattern: `new T(...)`, `new T`,
// `T{...}` of a type name, or a declaration `T $X(...);` or `T $X;` of
// one name. `T $X = v;`, `T $X{...};` and `T $X();` are skipped: the graph
// lists no `T x = v;` or `T x();` site, so they would not match all OpenGrep
// matches.
func (d cDialect) cppConstruct(e *CExpr) error {
	if e.Sub.Kind == CExprMetavar {
		return skipCPPConstruct.err()
	}
	if err := d.cppName(e.Sub); err != nil {
		return err
	}
	if e.Kind == CExprDecl && e.Multi {
		return skipCPPConstruct.err()
	}
	for i := range e.Args {
		if e.Args[i].Kind == CExprEllipsis {
			continue
		}
		if err := d.cPatternArg(&e.Args[i]); err != nil {
			return err
		}
	}
	return nil
}

// cppDeclPattern reads a declaration pattern (its `;` included) and
// checks it.
func (d cDialect) cppDeclPattern(text string) (*CExpr, error) {
	if head, ok := strings.CutSuffix(strings.Join(strings.Fields(text), " "), "= ...;"); ok {
		decl, ok := readCPPDecl(strings.TrimSpace(head)+";", true)
		if !ok || decl.Op != "" || decl.Multi {
			return nil, skipCPPConstruct.err()
		}
		decl.Text = cppDeclAssign
		return decl, d.cppName(decl.Sub)
	}
	decl, ok := readCPPDecl(text, true)
	if !ok {
		return nil, d.unreadable(text, skipCStatement).err()
	}
	if err := d.cppConstruct(decl); err != nil {
		return nil, err
	}
	return decl, nil
}

// cppDeclPositive is a declaration positive, `T $X(...);`.
func (d cDialect) cppDeclPositive(text string) (*CPattern, error) {
	decl, err := d.cppDeclPattern(text)
	if err != nil {
		return nil, err
	}
	return &CPattern{Call: decl}, nil
}

// cppAroundContext is a construction a site is written in: `new T(...)`,
// `T{...}` or a declaration statement `T $X(...);`.
func (d cDialect) cppAroundContext(text string, e *CExpr) (CContext, error) {
	if e == nil {
		if !strings.HasSuffix(text, ";") {
			return CContext{}, d.unreadable(text, skipCContext).err()
		}
		decl, err := d.cppDeclPattern(text)
		if err != nil {
			return CContext{}, err
		}
		e = decl
	} else if err := d.cppConstruct(e); err != nil {
		return CContext{}, err
	}
	return CContext{Place: CAround, Call: e}, nil
}

// cppSiteRegex: a regex the C++ matcher searches in the lines a construct
// or a literal is written on, keeping each match that lies wholly in it:
// one with no line or text anchor (`^`, `$`, `\A`, `\Z`, `\z`, `\G`) and
// no lookbehind that can see past a line break, whose matches there depend
// on the text around the construct only through those lines.
func cppSiteRegex(rx string) bool { //nolint:gocyclo // one case per regex construct the check rejects
	inClass := false
	for i := 0; i < len(rx); i++ {
		c := rx[i]
		switch {
		case c == '\\':
			if i+1 < len(rx) && !inClass && strings.IndexByte("AZzG", rx[i+1]) >= 0 {
				return false
			}
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
			if strings.HasPrefix(rx[i+1:], "^]") {
				i += 2
			} else if strings.HasPrefix(rx[i+1:], "]") {
				i++
			}
		case c == '^' || c == '$':
			return false
		case strings.HasPrefix(rx[i:], "(?<=") || strings.HasPrefix(rx[i:], "(?<!"):
			end := cppGroupEnd(rx, i)
			if end < 0 || !cppNoBreak(rx[i+4:end]) {
				return false
			}
		}
	}
	return true
}

// cppGroupEnd is the index of the `)` closing the group opened at i; -1
// when it does not close.
func cppGroupEnd(rx string, i int) int {
	depth, inClass := 0, false
	for j := i; j < len(rx); j++ {
		switch c := rx[j]; {
		case c == '\\':
			j++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// cppNoBreak: nothing in the regex can match a line break (no `\s`, `\W`,
// `\D`, `\n`, negated class, `.` or inline flag), so a lookbehind of it sees
// the line it is written on only.
func cppNoBreak(rx string) bool {
	for i := 0; i < len(rx); i++ {
		switch c := rx[i]; {
		case c == '\\':
			if i+1 < len(rx) && strings.IndexByte("sWDHVRNnrfv", rx[i+1]) >= 0 {
				return false
			}
			i++
		case c == '.' || c == '(' || strings.HasPrefix(rx[i:], "[^"):
			return false
		}
	}
	return true
}

// cppRegexes places a C++ alternative's pattern-regex: beside a string
// literal positive it filters the literal (a bounded regex only); with no
// positive it is the positive: searched in the construct an around context
// matches (LineRegex), or with no other context than #include ones, in every
// call, construction and string literal of the file (SiteRegex).
func (p *CPattern) cppRegexes() error { //nolint:gocyclo // one check per clause the regex positive allows
	if len(p.NotRegex) > 0 && (p.Str != nil || p.Regex != "") {
		return skipCPatternRegex.err() // a literal's or directive's match is not filtered
	}
	if p.SiteRegex != "" {
		if len(p.StrRegex) > 0 {
			return skipCPatternRegex.err()
		}
		return p.siteRegex(p.SiteRegex)
	}
	if len(p.StrRegex) == 0 {
		return nil
	}
	if p.Str != nil {
		for _, rx := range p.StrRegex {
			if !cBoundedRegex(rx) {
				return skipCPatternRegex.err()
			}
		}
		return nil
	}
	if p.positive() || len(p.StrRegex) != 1 || p.Focus != "" {
		return skipCPatternRegex.err()
	}
	if !cppSiteRegex(p.StrRegex[0]) {
		return skipCPPRegex.err()
	}
	if slices.ContainsFunc(p.Inside, func(c CContext) bool { return c.Place == CAround && c.Call != nil }) {
		p.LineRegex, p.StrRegex = p.StrRegex[0], nil
		return nil
	}
	return p.siteRegex(p.StrRegex[0])
}

// siteRegex makes rx the alternative's positive, searched in every site and
// literal: its contexts must all be #include ones.
func (p *CPattern) siteRegex(rx string) error {
	if len(p.NotInside)+len(p.Not) > 0 || p.Focus != "" || slices.ContainsFunc(p.Inside, func(c CContext) bool { return c.Include == nil }) {
		return skipCPatternRegex.err()
	}
	p.SiteRegex, p.StrRegex = rx, nil
	return nil
}

// cppSiteRegexAlt is a pattern-regex alternative of its own (a rule's
// formula or a pattern-either branch): a site regex positive.
func (d cDialect) cppSiteRegexAlt(rx string) ([]*CPattern, error) {
	if !cppSiteRegex(rx) {
		return nil, skipCPPRegex.err()
	}
	rx = pcreToPyText(rx)
	if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
		return nil, skipCPatternRegex.err()
	}
	return []*CPattern{{SiteRegex: rx}}, nil
}

// cppTyped checks a typed metavariable: a class type, read from the
// declarations and parameters, or `int`, which an integer literal also has
// (the other built-in types' literals are not read).
func (d cDialect) cppTyped(e *CExpr) error {
	if e.Sub.Kind == CExprIdent && cTypeWords[e.Sub.Name] && (e.Sub.Name != "int" || e.Op != "" || e.Text != "") {
		return skipCPPTyped.err()
	}
	return d.cppName(e.Sub)
}

// cppFuncContextOf reads a C++ function context `$RET $FN(params) { ... }`:
// the parameters are `...` or typed parameters `[const] T [&|*] $X`. The
// graph lists no C++ return type, so a written one is skipped.
func (d cDialect) cppFuncContextOf(text string) (CContext, error) { //nolint:gocognit,gocyclo // the words, the parameters, then the body
	toks, err := lexC(text, true)
	if err != nil {
		return CContext{}, skipCFunction.err()
	}
	open := slices.IndexFunc(toks, func(t cTok) bool { return t.text == "(" })
	if open < 2 {
		return CContext{}, skipCFunction.err()
	}
	words := make([]string, 0, open)
	for _, t := range toks[:open] {
		if t.kind != ctIdent && t.kind != ctVar {
			return CContext{}, skipCFunction.err()
		}
		if !cTypeQualifiers[t.text] {
			words = append(words, t.text)
		}
	}
	closeAt := cppParenClose(toks, open)
	rest := make([]string, 0, 3)
	for _, t := range toks[closeAt+1:] {
		rest = append(rest, t.text)
	}
	if len(words) != 2 || !isMetavar(words[0]) || !slices.Equal(rest, []string{"{", rustEllipsis, "}"}) {
		return CContext{}, skipCFunction.err()
	}
	params := []CExpr{}
	for inner := toks[open+1 : closeAt]; len(inner) > 0; {
		n := cppArgLen(inner)
		param := inner[:n]
		if len(param) == 1 && param[0].text == rustEllipsis {
			params = append(params, CExpr{Kind: CExprEllipsis})
		} else {
			p := &cParser{toks: slices.Clone(param), pattern: true, cpp: true}
			e, ok := p.typedParam()
			if !ok || !p.eof() {
				return CContext{}, skipCFunction.err()
			}
			if err := d.cppTyped(e); err != nil {
				return CContext{}, skipCFunction.err()
			}
			params = append(params, *e)
		}
		inner = inner[n:]
		if len(inner) > 0 {
			inner = inner[1:]
		}
	}
	return CContext{Place: CAround, Func: &CFuncLine{Type: words[0], Name: words[1], Params: params}}, nil
}

// cppParenClose is the index of the `)` closing the `(` at open.
func cppParenClose(toks []cTok, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		switch toks[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(toks) - 1
}
