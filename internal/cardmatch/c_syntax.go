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

// The C expression reader: one reader for a rule's pattern text
// (metavariables, `...` and `<... e ...>` allowed) and for the source text of
// a call the fragment ships. Parentheses are dropped, as OpenGrep drops them:
// `(*fp)` reads as `*fp`, `(A | B)` as `A | B`. A `|` chain reads as one
// node with every operand, the shape OpenGrep matches modulo associativity
// and commutativity.

import (
	"errors"
	"strings"
)

var errCLex = errors.New("c: unreadable text")

// The expression kinds. A pattern uses the first block only; a source read
// uses every kind but the pattern-only ones.
const (
	CExprEllipsis = "ellipsis" // pattern: `...`
	CExprDeep     = "deep"     // pattern: `<... e ...>`
	CExprMetavar  = "metavar"  // pattern: `$X`
	CExprStrVar   = "strvar"   // pattern: `"$X"`, a string literal binding its content
	CExprIdent    = "ident"
	CExprInt      = "int"
	CExprString   = "string" // one string literal; Text is its content
	CExprCall     = "call"
	CExprUnary    = "unary"  // Op and Sub
	CExprBinary   = "binary" // Op and the operands in Args (a `|` chain is flattened)

	CExprChar    = "char"
	CExprFloat   = "float"
	CExprConcat  = "concat" // adjacent string literals, each in Args
	CExprMember  = "member" // Sub, Op (`.` or `->`) and Name, the field
	CExprIndex   = "index"  // Sub and Args[0]
	CExprCast    = "cast"   // Name, the type as written, and Sub
	CExprSizeof  = "sizeof" // Sub, or Name for a type
	CExprTernary = "ternary"
	CExprAssign  = "assign" // Op, Args[0] and Args[1]
	CExprPostfix = "postfix"
	CExprInit    = "init" // `{...}`, the elements in Args
)

// CExpr is a C expression. Start and End are byte offsets in the text read
// (End exclusive); a pattern's are not serialized.
type CExpr struct {
	Kind   string  `json:"kind"`
	Name   string  `json:"name,omitempty"` // ident name, member field, cast type
	Var    string  `json:"var,omitempty"`  // metavar, strvar
	Op     string  `json:"op,omitempty"`
	Text   string  `json:"text,omitempty"` // literal as written; a string's content
	Callee *CExpr  `json:"callee,omitempty"`
	Sub    *CExpr  `json:"sub,omitempty"`
	Args   []CExpr `json:"args,omitempty"`
	Multi  bool    `json:"multi,omitempty"` // C++ declaration: it declares more than one name
	Start  int     `json:"-"`
	End    int     `json:"-"`
}

type cTokKind uint8

const (
	ctIdent cTokKind = iota + 1
	ctVar            // $X (pattern)
	ctNum
	ctStr  // "..." with an optional L, u, U or u8 prefix
	ctChar // '.'
	ctPunct
)

type cTok struct {
	kind cTokKind
	text string
	off  int
}

func (t cTok) end() int { return t.off + len(t.text) }

// The deep-expression tokens of a pattern, `<... e ...>`.
const (
	cDeepOpen  = "<..."
	cDeepClose = "...>"
)

// cPuncts are the multi-character punctuation tokens, longest first. `<...`
// and `...>` are pattern tokens.
var cPuncts = []string{
	cDeepOpen, cDeepClose, rustEllipsis, "<<=", ">>=", cppScope, "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
}

func isCIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isCIdentByte(c byte) bool { return isCIdentStart(c) || (c >= '0' && c <= '9') }

// lexC splits C text into tokens, dropping whitespace and comments. pattern
// allows metavariables and the deep-expression tokens; a source text with a
// preprocessor line, or a pattern token, does not read.
func lexC(src string, pattern bool) ([]cTok, error) { //nolint:gocognit,gocyclo,funlen // one lexer: a case per token class reads clearer than helpers per class
	var out []cTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
			continue
		case c == '\\' && i+1 < len(src) && (src[i+1] == '\n' || src[i+1] == '\r'):
			i += 2
			continue
		case strings.HasPrefix(src[i:], "//"):
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
			continue
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				return nil, errCLex
			}
			i += j + 4
			continue
		case c == '#': // a preprocessor line, or a pattern's directive (read apart)
			return nil, errCLex
		}
		switch {
		case c == '$' && pattern:
			j := i + 1
			for j < len(src) && isCIdentByte(src[j]) {
				j++
			}
			if j == i+1 {
				return nil, errCLex
			}
			out = append(out, cTok{ctVar, src[i:j], i})
			i = j
		case isCIdentStart(c):
			j := i
			for j < len(src) && isCIdentByte(src[j]) {
				j++
			}
			word := src[i:j]
			if j < len(src) && (src[j] == '"' || src[j] == '\'') && (word == "L" || word == "u" || word == "U" || word == "u8") {
				end, ok := cQuoted(src, j)
				if !ok {
					return nil, errCLex
				}
				kind := ctStr
				if src[j] == '\'' {
					kind = ctChar
				}
				out = append(out, cTok{kind, src[i:end], i})
				i = end
				continue
			}
			out = append(out, cTok{ctIdent, word, i})
			i = j
		case c >= '0' && c <= '9' || (c == '.' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9'):
			hex := strings.HasPrefix(src[i:], "0x") || strings.HasPrefix(src[i:], "0X")
			j := i + 1
			for j < len(src) {
				d, prev := src[j], src[j-1]
				exponent := prev == 'p' || prev == 'P' || (!hex && (prev == 'e' || prev == 'E'))
				if isCIdentByte(d) || d == '.' || ((d == '+' || d == '-') && exponent) {
					j++
					continue
				}
				break
			}
			out = append(out, cTok{ctNum, src[i:j], i})
			i = j
		case c == '"' || c == '\'':
			end, ok := cQuoted(src, i)
			if !ok {
				return nil, errCLex
			}
			kind := ctStr
			if c == '\'' {
				kind = ctChar
			}
			out = append(out, cTok{kind, src[i:end], i})
			i = end
		default:
			matched := false
			for _, p := range cPuncts {
				if !strings.HasPrefix(src[i:], p) || ((p == cDeepOpen || p == cDeepClose) && !pattern) {
					continue
				}
				out = append(out, cTok{ctPunct, p, i})
				i += len(p)
				matched = true
				break
			}
			if !matched {
				if !strings.ContainsRune("()[]{},;:?.=+-*/%&|^!~<>", rune(c)) {
					return nil, errCLex
				}
				out = append(out, cTok{ctPunct, string(c), i})
				i++
			}
		}
	}
	return out, nil
}

// cQuoted is the offset past the string or char literal opening at i.
func cQuoted(src string, i int) (int, bool) {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '\n':
			return 0, false
		case q:
			return j + 1, true
		}
	}
	return 0, false
}

// cParser reads tokens into expressions.
type cParser struct {
	toks    []cTok
	i       int
	pattern bool
	cpp     bool // C++: qualified names, templates, new, brace initialization (cpp_syntax.go)
	// typeName: the C++ name read is a declaration's type, which a declared
	// name follows.
	typeName bool
}

func (p *cParser) eof() bool { return p.i >= len(p.toks) }

// peekNext is the token after the cursor, or the zero token past the end.
func (p *cParser) peekNext() cTok {
	if p.i+1 < len(p.toks) {
		return p.toks[p.i+1]
	}
	return cTok{}
}

func (p *cParser) is(text string) bool {
	return !p.eof() && p.toks[p.i].kind == ctPunct && p.toks[p.i].text == text
}

func (p *cParser) accept(text string) bool {
	if p.is(text) {
		p.i++
		return true
	}
	return false
}

func (p *cParser) prevEnd() int { return p.toks[p.i-1].end() }

// memberName: the token at the cursor names a member: a word, or in C++ a
// pattern metavariable (`$X.$M`) and not a keyword (`x.template f`).
func (p *cParser) memberName() bool {
	t := p.toks[p.i]
	if !p.cpp {
		return t.kind == ctIdent
	}
	return (t.kind == ctIdent || t.kind == ctVar) && !cppKeywords[t.text]
}

// cBinaryPrec is the precedence of each binary operator; assignment and the
// conditional are read apart.
var cBinaryPrec = map[string]int{
	"||": 3, "&&": 4, "|": 5, "^": 6, "&": 7, "==": 8, "!=": 8,
	"<": 9, ">": 9, "<=": 9, ">=": 9, "<<": 10, ">>": 10, "+": 11, "-": 11, "*": 12, "/": 12, "%": 12,
}

var cAssignOps = setOf("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=")

// parseExpr reads an assignment expression (no comma operator).
func (p *cParser) parseExpr() (*CExpr, error) {
	lhs, err := p.parseCond()
	if err != nil {
		return nil, err
	}
	if !p.eof() && p.toks[p.i].kind == ctPunct && cAssignOps[p.toks[p.i].text] {
		op := p.toks[p.i].text
		p.i++
		rhs, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &CExpr{Kind: CExprAssign, Op: op, Args: []CExpr{*lhs, *rhs}, Start: lhs.Start, End: rhs.End}, nil
	}
	return lhs, nil
}

func (p *cParser) parseCond() (*CExpr, error) {
	c, err := p.parseBinary(3)
	if err != nil {
		return nil, err
	}
	if !p.accept("?") {
		return c, nil
	}
	a, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if !p.accept(":") {
		return nil, errCLex
	}
	b, err := p.parseCond()
	if err != nil {
		return nil, err
	}
	return &CExpr{Kind: CExprTernary, Args: []CExpr{*c, *a, *b}, Start: c.Start, End: b.End}, nil
}

func (p *cParser) parseBinary(minPrec int) (*CExpr, error) {
	lhs, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for !p.eof() && p.toks[p.i].kind == ctPunct {
		op := p.toks[p.i].text
		prec, ok := cBinaryPrec[op]
		if !ok || prec < minPrec {
			break
		}
		p.i++
		rhs, err := p.parseBinary(prec + 1)
		if err != nil {
			return nil, err
		}
		lhs = cJoin(op, lhs, rhs)
	}
	return lhs, nil
}

// cJoin builds a binary node; a `|` chain, parenthesized or not, keeps every
// operand in one node.
func cJoin(op string, lhs, rhs *CExpr) *CExpr {
	out := &CExpr{Kind: CExprBinary, Op: op, Start: lhs.Start, End: rhs.End}
	for _, side := range []*CExpr{lhs, rhs} {
		if op == "|" && side.Kind == CExprBinary && side.Op == "|" {
			out.Args = append(out.Args, side.Args...)
		} else {
			out.Args = append(out.Args, *side)
		}
	}
	return out
}

// cTypeWords are the words a cast's type is written with besides type names.
var cTypeWords = setOf("const", "volatile", "unsigned", "signed", "struct", "union", "enum", "int", "char", "short",
	"long", "float", "double", "void", "_Bool", "bool", "restrict")

// castAhead: the `(` at the cursor opens a cast: a type (words and `*`) and
// `)` followed by an operand. A lone name in parentheses is a cast only when
// an operand that cannot continue a binary expression follows.
func (p *cParser) castAhead() (end int, ok bool) { //nolint:gocognit,gocyclo // one scan of the parenthesized tokens
	j := p.i + 1
	words, stars, keyword := 0, 0, false
	for ; j < len(p.toks); j++ {
		t := p.toks[j]
		switch {
		case t.kind == ctIdent && stars == 0:
			words++
			keyword = keyword || cTypeWords[t.text]
		case t.kind == ctPunct && t.text == "*":
			stars++
		case t.kind == ctPunct && t.text == ")":
			if words == 0 || j+1 >= len(p.toks) {
				return 0, false
			}
			next := p.toks[j+1]
			operand := next.kind == ctIdent || next.kind == ctNum || next.kind == ctStr || next.kind == ctChar ||
				(next.kind == ctPunct && (next.text == "(" || next.text == "~" || next.text == "!"))
			if keyword || stars > 0 || words > 1 {
				operand = operand || (next.kind == ctPunct && (next.text == "&" || next.text == "*" || next.text == "-" || next.text == "+" || next.text == "{"))
			}
			return j, operand
		default:
			return 0, false
		}
	}
	return 0, false
}

func (p *cParser) parseUnary() (*CExpr, error) {
	if p.eof() {
		return nil, errCLex
	}
	t := p.toks[p.i]
	if t.kind == ctPunct {
		if e, ok, err := p.parseUnaryPunct(t); ok || err != nil {
			return e, err
		}
	}
	if t.kind == ctIdent && t.text == "sizeof" {
		p.i++
		if p.is("(") {
			if end, ok := p.typeParen(); ok {
				typ := p.typeText(p.i+1, end)
				p.i = end + 1
				return &CExpr{Kind: CExprSizeof, Name: typ, Start: t.off, End: p.prevEnd()}, nil
			}
		}
		sub, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &CExpr{Kind: CExprSizeof, Sub: sub, Start: t.off, End: sub.End}, nil
	}
	return p.parsePostfix()
}

// parseUnaryPunct reads a prefix operator or a cast at the cursor, which is
// the punctuation token t; ok is false when t starts neither.
func (p *cParser) parseUnaryPunct(t cTok) (e *CExpr, ok bool, err error) {
	switch t.text {
	case "&", "*", "-", "+", "!", "~", "++", "--":
		p.i++
		sub, err := p.parseUnary()
		if err != nil {
			return nil, true, err
		}
		return &CExpr{Kind: CExprUnary, Op: t.text, Sub: sub, Start: t.off, End: sub.End}, true, nil
	case "(":
		if e, ok := p.cppCast(); ok {
			return e, true, nil
		}
		if end, ok := p.castAhead(); ok {
			typ := p.typeText(p.i+1, end)
			p.i = end + 1
			sub, err := p.parseUnary()
			if err != nil {
				return nil, true, err
			}
			return &CExpr{Kind: CExprCast, Name: typ, Sub: sub, Start: t.off, End: sub.End}, true, nil
		}
	}
	return nil, false, nil
}

// typeParen: the `(` at the cursor holds only type words and `*`.
func (p *cParser) typeParen() (int, bool) {
	keyword := false
	for j := p.i + 1; j < len(p.toks); j++ {
		t := p.toks[j]
		switch {
		case t.kind == ctIdent:
			keyword = keyword || cTypeWords[t.text]
		case t.kind == ctPunct && t.text == "*":
			keyword = true
		case t.kind == ctPunct && t.text == ")":
			return j, keyword
		default:
			return 0, false
		}
	}
	return 0, false
}

// typeText joins the tokens from..to-1 as a type.
func (p *cParser) typeText(from, to int) string {
	parts := make([]string, 0, to-from)
	for _, t := range p.toks[from:to] {
		parts = append(parts, t.text)
	}
	return strings.Join(parts, " ")
}

func (p *cParser) parsePostfix() (*CExpr, error) {
	e, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for !p.eof() {
		next, ok, err := p.parsePostfixOp(e)
		if err != nil {
			return nil, err
		}
		if !ok {
			return e, nil
		}
		e = next
	}
	return e, nil
}

// parsePostfixOp reads one call, index, brace construction, member access or
// increment applied to e at the cursor; ok is false when none starts there.
func (p *cParser) parsePostfixOp(e *CExpr) (next *CExpr, ok bool, err error) {
	switch {
	case p.is("("):
		args, err := p.parseArgs()
		if err != nil {
			return nil, false, err
		}
		return &CExpr{Kind: CExprCall, Callee: e, Args: args, Start: e.Start, End: p.prevEnd()}, true, nil
	case p.is("["):
		p.i++
		idx, err := p.parseExpr()
		if err != nil {
			return nil, false, err
		}
		if !p.accept("]") {
			return nil, false, errCLex
		}
		return &CExpr{Kind: CExprIndex, Sub: e, Args: []CExpr{*idx}, Start: e.Start, End: p.prevEnd()}, true, nil
	case p.cpp && p.is("{") && cppBraceCallee(e): // `T{a}` constructs a T, as `new T{a}` does
		args, err := p.parseBraceArgs()
		if err != nil {
			return nil, false, err
		}
		return &CExpr{Kind: CExprNew, Op: CExprBrace, Sub: e, Args: args, Start: e.Start, End: p.prevEnd()}, true, nil
	case p.is(".") || p.is("->"):
		next, err := p.parseMember(e)
		return next, err == nil, err
	case p.is("++") || p.is("--"):
		next := &CExpr{Kind: CExprPostfix, Op: p.toks[p.i].text, Sub: e, Start: e.Start, End: p.toks[p.i].end()}
		p.i++
		return next, true, nil
	}
	return nil, false, nil
}

// parseMember reads `.name` or `->name` applied to e at the cursor.
func (p *cParser) parseMember(e *CExpr) (*CExpr, error) {
	op := p.toks[p.i].text
	p.i++
	if p.eof() || !p.memberName() {
		return nil, errCLex
	}
	next := &CExpr{Kind: CExprMember, Op: op, Name: p.toks[p.i].text, Sub: e, Start: e.Start, End: p.toks[p.i].end()}
	p.i++
	return next, nil
}

// parseArgs reads `(a, b, ...)` at the cursor.
func (p *cParser) parseArgs() ([]CExpr, error) {
	p.i++ // (
	args := []CExpr{}
	if p.accept(")") {
		return args, nil
	}
	for {
		a, err := p.parseArg()
		if err != nil {
			return nil, err
		}
		args = append(args, *a)
		if p.accept(")") {
			return args, nil
		}
		if !p.accept(",") {
			return nil, errCLex
		}
	}
}

// parseArg reads one argument or initializer element: an expression, or in
// a pattern `...`.
func (p *cParser) parseArg() (*CExpr, error) {
	if p.pattern && p.is(rustEllipsis) && (p.peekNext().text == "," || p.peekNext().text == ")" || p.peekNext().text == "}") {
		t := p.toks[p.i]
		p.i++
		return &CExpr{Kind: CExprEllipsis, Start: t.off, End: t.end()}, nil
	}
	return p.parseExpr()
}

func (p *cParser) parsePrimary() (*CExpr, error) { //nolint:gocyclo // one case per primary form
	if p.eof() {
		return nil, errCLex
	}
	t := p.toks[p.i]
	if p.cppNamePrimary() {
		return p.parseCPPPrimary()
	}
	if p.cpp && p.pattern && t.kind == ctPunct && t.text == "(" {
		if e, ok := p.parseTypedMetavar(); ok {
			return e, nil
		}
	}
	switch t.kind {
	case ctVar:
		p.i++
		return &CExpr{Kind: CExprMetavar, Var: t.text, Start: t.off, End: t.end()}, nil
	case ctIdent:
		p.i++
		return &CExpr{Kind: CExprIdent, Name: t.text, Start: t.off, End: t.end()}, nil
	case ctNum:
		p.i++
		kind := CExprInt
		if _, ok := cIntValue(t.text); !ok {
			kind = CExprFloat
		}
		return &CExpr{Kind: kind, Text: t.text, Start: t.off, End: t.end()}, nil
	case ctChar:
		p.i++
		return &CExpr{Kind: CExprChar, Text: t.text, Start: t.off, End: t.end()}, nil
	case ctStr:
		return p.parseStrings(), nil
	case ctPunct:
	}
	switch {
	case t.text == "(":
		return p.parseParen()
	case t.text == "{" && (!p.pattern || p.cpp):
		return p.parseInit()
	case t.text == cDeepOpen && p.pattern:
		return p.parseDeep()
	case t.text == rustEllipsis && p.pattern:
		p.i++
		return &CExpr{Kind: CExprEllipsis, Start: t.off, End: t.end()}, nil
	}
	return nil, errCLex
}

// parseParen reads a parenthesized expression, or a comma expression, at the
// cursor.
func (p *cParser) parseParen() (*CExpr, error) {
	p.i++
	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	for p.accept(",") { // a comma expression reads as its last operand's parent
		r, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		e = &CExpr{Kind: CExprBinary, Op: ",", Args: []CExpr{*e, *r}, Start: e.Start, End: r.End}
	}
	if !p.accept(")") {
		return nil, errCLex
	}
	return e, nil
}

// parseInit reads an initializer list `{a, b}` at the cursor.
func (p *cParser) parseInit() (*CExpr, error) {
	init := &CExpr{Kind: CExprInit, Start: p.toks[p.i].off}
	p.i++
	for !p.accept("}") {
		if p.accept(".") || p.is("[") { // designator
			return nil, errCLex
		}
		e, err := p.parseArg()
		if err != nil {
			return nil, err
		}
		init.Args = append(init.Args, *e)
		if !p.accept(",") && !p.is("}") {
			return nil, errCLex
		}
	}
	init.End = p.prevEnd()
	return init, nil
}

// parseDeep reads `<... e ...>` at the cursor.
func (p *cParser) parseDeep() (*CExpr, error) {
	start := p.toks[p.i].off
	p.i++
	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if !p.accept(cDeepClose) {
		return nil, errCLex
	}
	return &CExpr{Kind: CExprDeep, Sub: e, Start: start, End: p.prevEnd()}, nil
}

// parseStrings reads one string literal or adjacent ones; a pattern string
// whose whole content is a metavariable reads as a strvar.
func (p *cParser) parseStrings() *CExpr {
	var parts []CExpr
	for !p.eof() && p.toks[p.i].kind == ctStr {
		t := p.toks[p.i]
		p.i++
		q := strings.IndexByte(t.text, '"')
		content := t.text[q+1 : len(t.text)-1]
		s := CExpr{Kind: CExprString, Text: content, Start: t.off, End: t.end()}
		if p.pattern && q == 0 && isMetavar(content) && isCMetavarName(content) {
			s = CExpr{Kind: CExprStrVar, Var: content, Start: t.off, End: t.end()}
		}
		parts = append(parts, s)
	}
	if len(parts) == 1 {
		return &parts[0]
	}
	return &CExpr{Kind: CExprConcat, Args: parts, Start: parts[0].Start, End: parts[len(parts)-1].End}
}

// isCMetavarName: s is `$` and an identifier.
func isCMetavarName(s string) bool {
	if len(s) < 2 || s[0] != '$' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isCIdentByte(s[i]) {
			return false
		}
	}
	return true
}

// cIntValue is the value of an integer literal (decimal, hex, octal or
// binary, any u/l suffix); false for anything else.
func cIntValue(text string) (uint64, bool) {
	s := strings.TrimRight(strings.ToLower(text), "ul")
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x"):
		base, s = 16, s[2:]
	case strings.HasPrefix(s, "0b"):
		base, s = 2, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c == '\'':
			continue
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		v = v*uint64(base) + uint64(d)
	}
	return v, true
}

// readCExpr reads text as one whole expression.
func readCExpr(text string, pattern bool) (*CExpr, bool) {
	toks, err := lexC(text, pattern)
	if err != nil || len(toks) == 0 {
		return nil, false
	}
	p := &cParser{toks: toks, pattern: pattern}
	e, err := p.parseExpr()
	if err != nil || !p.eof() {
		return nil, false
	}
	return e, true
}

// cWalk calls f on e and each of its subexpressions, outer first; it stops
// when f returns true.
func cWalk(e *CExpr, f func(*CExpr) bool) bool {
	if f(e) {
		return true
	}
	if e.Kind == CExprScoped || e.Kind == CExprTemplate { // a C++ name is one expression
		return false
	}
	if e.Callee != nil && cWalk(e.Callee, f) {
		return true
	}
	if e.Sub != nil && cWalk(e.Sub, f) {
		return true
	}
	for i := range e.Args {
		if cWalk(&e.Args[i], f) {
			return true
		}
	}
	return false
}

// cDecl is a declaration statement read: its type words (qualifiers and
// storage classes left out, as OpenGrep compares types) and declarators.
type cDecl struct {
	Type  []string
	Decls []cDeclarator
}

// cDeclarator is one declared name: `**name[size] = init`.
type cDeclarator struct {
	Name  string
	Ptr   int
	Array bool
	Size  *CExpr // nil for `[]` or no array
	Init  *CExpr // nil for none; an initializer list reads as CExprInit
}

// cTypeQualifiers are the words a type comparison leaves out.
var cTypeQualifiers = setOf("const", "volatile", "restrict", "static", "extern", "register", "auto", "inline", "_Thread_local")

// readCDecl reads a declaration statement `T a = v, *b[2];`; pattern allows
// metavariables for the type and names and `...` in an initializer list.
func readCDecl(text string, pattern bool) (*cDecl, bool) { //nolint:gocognit,gocyclo // one pass over the declaration's parts
	toks, err := lexC(text, pattern)
	if err != nil || len(toks) < 3 || toks[len(toks)-1].text != ";" {
		return nil, false
	}
	p := &cParser{toks: toks[:len(toks)-1], pattern: pattern}
	var words []string
	for !p.eof() && (p.toks[p.i].kind == ctIdent || p.toks[p.i].kind == ctVar) {
		words = append(words, p.toks[p.i].text)
		p.i++
	}
	d := &cDecl{}
	first := true
	for {
		var dc cDeclarator
		for p.accept("*") {
			dc.Ptr++
		}
		switch {
		case first && dc.Ptr == 0:
			if len(words) < 2 {
				return nil, false
			}
			dc.Name, words = words[len(words)-1], words[:len(words)-1]
		case !p.eof() && (p.toks[p.i].kind == ctIdent || p.toks[p.i].kind == ctVar):
			dc.Name = p.toks[p.i].text
			p.i++
		default:
			return nil, false
		}
		first = false
		if p.accept("[") {
			dc.Array = true
			if !p.accept("]") {
				size, err := p.parseExpr()
				if err != nil || !p.accept("]") {
					return nil, false
				}
				dc.Size = size
			}
		}
		if p.accept("=") {
			var init *CExpr
			var err error
			if p.is("{") {
				init, err = p.parseInit()
			} else {
				init, err = p.parseExpr()
			}
			if err != nil {
				return nil, false
			}
			dc.Init = init
		}
		d.Decls = append(d.Decls, dc)
		if p.eof() {
			break
		}
		if !p.accept(",") {
			return nil, false
		}
	}
	for _, w := range words {
		if !cTypeQualifiers[w] {
			d.Type = append(d.Type, w)
		}
	}
	return d, len(d.Type) > 0
}
