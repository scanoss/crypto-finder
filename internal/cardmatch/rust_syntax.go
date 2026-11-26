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

// The Rust syntax reader: one reader for a rule's pattern text (metavariables
// and `...` allowed) and for the source text a fragment ships (callees,
// argument expressions). A pattern and a site written the same way read into
// equal values, and every value prints in one canonical spelling (rustJoin),
// which is what a metavariable binds and a metavariable-regex reads.

import (
	"errors"
	"strings"
	"unicode/utf8"
)

var errRustLex = errors.New("rust: unreadable text")

// rustEllipsis is the `...` token.
const rustEllipsis = "..."

type rustTokKind uint8

const (
	rtIdent    rustTokKind = iota + 1 // identifiers and keywords
	rtVar                             // $X
	rtLit                             // string, byte string, char, number
	rtLifetime                        // 'a
	rtPunct
)

type rustTok struct {
	kind rustTokKind
	text string
	off  int // byte offset of the token in the text lexed
}

// end is the byte offset just past the token.
func (t rustTok) end() int { return t.off + len(t.text) }

// rustPuncts are the multi-character punctuation tokens, longest first. `>`
// and `&` stay single so `Vec<Vec<u8>>` and `&&x` read as nested.
var rustPuncts = []string{rustEllipsis, "..=", "::", "..", "->", "=>", "==", "!=", "<=", ">=", "||", "+=", "-="}

func isRustIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isRustIdentByte(c byte) bool { return isRustIdentStart(c) || (c >= '0' && c <= '9') }

// lexRust splits Rust text into tokens, dropping whitespace and comments.
func lexRust(src string) ([]rustTok, error) { //nolint:gocognit,gocyclo,funlen // one lexer: a case per token class reads clearer than helpers per class
	var out []rustTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(src[i:], "//"):
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
		case strings.HasPrefix(src[i:], "/*"):
			j := strings.Index(src[i+2:], "*/")
			if j < 0 {
				return nil, errRustLex
			}
			i += j + 4
		case c == '$':
			j := i + 1
			for j < len(src) && isRustIdentByte(src[j]) {
				j++
			}
			if !rxMetavarName(src[i+1 : j]) {
				return nil, errRustLex
			}
			out = append(out, rustTok{rtVar, src[i:j], i})
			i = j
		case isRustIdentStart(c):
			if n := rustPrefixedLiteral(src[i:]); n > 0 {
				out = append(out, rustTok{rtLit, src[i : i+n], i})
				i += n
				continue
			}
			j := i
			if strings.HasPrefix(src[i:], "r#") && i+2 < len(src) && isRustIdentStart(src[i+2]) {
				j += 2 // raw identifier r#type
			}
			for j < len(src) && isRustIdentByte(src[j]) {
				j++
			}
			out = append(out, rustTok{rtIdent, src[i:j], i})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (isRustIdentByte(src[j]) || (src[j] == '.' && j+1 < len(src) && src[j+1] >= '0' && src[j+1] <= '9')) {
				j++
			}
			out = append(out, rustTok{rtLit, src[i:j], i})
			i = j
		case c == '"':
			n := rustQuoted(src[i:], '"')
			if n < 0 {
				return nil, errRustLex
			}
			out = append(out, rustTok{rtLit, src[i : i+n], i})
			i += n
		case c == '\'':
			if n := rustCharLit(src[i:]); n > 0 {
				out = append(out, rustTok{rtLit, src[i : i+n], i})
				i += n
				continue
			}
			j := i + 1
			for j < len(src) && isRustIdentByte(src[j]) {
				j++
			}
			if j == i+1 {
				return nil, errRustLex
			}
			out = append(out, rustTok{rtLifetime, src[i:j], i})
			i = j
		default:
			p := string(c)
			for _, m := range rustPuncts {
				if strings.HasPrefix(src[i:], m) {
					p = m
					break
				}
			}
			out = append(out, rustTok{rtPunct, p, i})
			i += len(p)
		}
	}
	return out, nil
}

// rxMetavarName: a semgrep metavariable name ($X, $ALG_2, $_).
func rxMetavarName(name string) bool {
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// rustQuoted is the length of a quoted literal starting at s[0] == q, or -1.
func rustQuoted(s string, q byte) int {
	for j := 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j + 1
		}
	}
	return -1
}

// rustCharLit is the length of a char literal at s[0] == '\”, or 0 when s
// starts a lifetime.
func rustCharLit(s string) int {
	if len(s) >= 2 && s[1] == '\\' {
		return max(rustQuoted(s, '\''), 0)
	}
	_, size := utf8.DecodeRuneInString(s[1:])
	if 1+size < len(s) && s[1+size] == '\'' {
		return 2 + size
	}
	return 0
}

// rustPrefixedLiteral is the length of a b"..", b'..', c"..", r".." or
// r#".."# literal (with br/cr) at the start of s, or 0.
func rustPrefixedLiteral(s string) int {
	j := 0
	if s[0] == 'b' || s[0] == 'c' {
		j++
	}
	if j < len(s) && s[j] == 'r' {
		return rustRawString(s, j+1)
	}
	if j == 0 || j >= len(s) {
		return 0
	}
	n := 0
	switch {
	case s[j] == '"':
		n = rustQuoted(s[j:], '"')
	case s[j] == '\'' && s[0] == 'b':
		n = rustCharLit(s[j:])
	}
	if n <= 0 {
		return 0
	}
	return j + n
}

// rustRawString is the length of a raw string whose hashes start at s[k], or 0.
func rustRawString(s string, k int) int {
	hashes := 0
	for k < len(s) && s[k] == '#' {
		k++
		hashes++
	}
	if k >= len(s) || s[k] != '"' {
		return 0
	}
	closing := "\"" + strings.Repeat("#", hashes)
	end := strings.Index(s[k+1:], closing)
	if end < 0 {
		return 0
	}
	return k + 1 + end + len(closing)
}

// rustWordLike: tokens that need a space between them when adjacent.
func rustWordLike(t rustTok) bool { return t.kind != rtPunct }

// rustJoin prints tokens in the canonical spelling: no space around
// punctuation, one space between two words and after a comma or a semicolon. Every
// String method below prints the same spelling for the same text.
func rustJoin(toks []rustTok) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			prev := toks[i-1]
			if (rustWordLike(prev) && rustWordLike(t)) || prev.text == "," || prev.text == ";" {
				b.WriteByte(' ')
			}
		}
		b.WriteString(t.text)
	}
	return b.String()
}

// RustPath is a written path: `a::B::<C>::f`, `<T as tr::Tr>::f`, `$X::f`.
type RustPath struct {
	// Global: the path is written with a leading `::`.
	Global bool `json:"global,omitempty"`
	// QSelf is the `<T as Trait>` head of a qualified path.
	QSelf *RustQSelf `json:"qself,omitempty"`
	Segs  []RustSeg  `json:"segs"`
}

// RustQSelf is `<Self as Trait>`; Trait is nil for `<T>::f`.
type RustQSelf struct {
	Self  RustType  `json:"self"`
	Trait *RustPath `json:"trait,omitempty"`
}

// RustSeg is one path segment: a name or a metavariable, with the generic
// arguments written on it. Generics are identity, never dropped: in
// OpenGrep 1.22.0 `Kdf::new(...)` does not match `Kdf::<Sha256>::new(...)`,
// so a segment without generics is not a wildcard for one with them.
type RustSeg struct {
	Name     string     `json:"name,omitempty"`
	Var      string     `json:"var,omitempty"`
	Generics []RustType `json:"generics,omitempty"`
}

// RustType is a generic argument, a qualified self type, a let's or a fn
// parameter's type: a path, a metavariable, a reference, or any other type
// as canonical text (`[u8; 32]`, `dyn Tr`).
type RustType struct {
	Path  *RustPath  `json:"path,omitempty"`
	Var   string     `json:"var,omitempty"`
	Tuple []RustType `json:"tuple,omitempty"` // (A, B)
	// Ref is the referenced type of `&T` or `&mut T` (Mut); a lifetime is
	// dropped.
	Ref  *RustType `json:"ref,omitempty"`
	Mut  bool      `json:"mut,omitempty"`
	Text string    `json:"text,omitempty"`
	// Trait is the bound of a `dyn` or `impl` trait type that is one path
	// of names (`dyn acme::rand::Tr`); Text still holds the whole type.
	Trait *RustPath `json:"trait,omitempty"`
}

// Qualified reports whether the path is written qualified: more than one
// segment, a leading `::` or a `<T as Tr>` head. OpenGrep 1.22.0 compares a
// qualified pattern path with the site's written path and with that path
// qualified through the `use` leaves in scope, aliases included
// (`acme_kdf::Kdf::new(...)` matches `K2::new` after `use acme_kdf::Kdf as
// K2`, `Kdf::new(...)` does not); an unqualified one with the written path
// only.
func (p *RustPath) Qualified() bool {
	return p.Global || p.QSelf != nil || len(p.Segs) > 1
}

// Last is the path's last segment.
func (p *RustPath) Last() RustSeg { return p.Segs[len(p.Segs)-1] }

func (p *RustPath) String() string {
	var b strings.Builder
	if p.QSelf != nil {
		b.WriteString("<" + p.QSelf.Self.String())
		if p.QSelf.Trait != nil {
			b.WriteString(" as " + p.QSelf.Trait.String())
		}
		b.WriteString(">::")
	} else if p.Global {
		b.WriteString("::")
	}
	for i, s := range p.Segs {
		if i > 0 {
			b.WriteString("::")
		}
		b.WriteString(s.Name + s.Var)
		if s.Generics != nil {
			b.WriteString("::<" + joinTypes(s.Generics) + ">")
		}
	}
	return b.String()
}

func (t RustType) String() string {
	switch {
	case t.Path != nil:
		return t.Path.typeString()
	case t.Var != "":
		return t.Var
	case t.Tuple != nil:
		return "(" + joinTypes(t.Tuple) + ")"
	case t.Ref != nil && t.Mut:
		return "&mut " + t.Ref.String()
	case t.Ref != nil:
		return "&" + t.Ref.String()
	}
	return t.Text
}

// typeString prints a path in type position: generics without the turbofish.
func (p *RustPath) typeString() string {
	return strings.ReplaceAll(p.String(), "::<", "<")
}

func joinTypes(ts []RustType) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.String()
	}
	return strings.Join(parts, ", ")
}

// RustExprKind is the closed set of expression shapes a pattern can write.
type RustExprKind string

// The expression shapes.
const (
	RustExprVar      RustExprKind = "metavar"  // $X
	RustExprEllipsis RustExprKind = "ellipsis" // ... (in argument lists)
	RustExprDeep     RustExprKind = "deep"     // <... E ...>: E anywhere inside
	RustExprLit      RustExprKind = "literal"  // "x", b"x", 32, 'c', true
	RustExprPath     RustExprKind = "path"     // a::B::C, $A::C
	RustExprRef      RustExprKind = "ref"      // &E, &mut E
	RustExprCall     RustExprKind = "call"     // Path::f(..), $X.m(..)
	RustExprField    RustExprKind = "field"    // E.name
	RustExprTry      RustExprKind = "try"      // E?
	RustExprIndex    RustExprKind = "index"    // E[I]
	RustExprRange    RustExprKind = "range"    // .. (the full range, as in E[..])
	RustExprBinary   RustExprKind = "binary"   // A * B: Sub, Op and Right
	RustExprParen    RustExprKind = "paren"    // (E) before a `.`: Sub; read from source text only
	// RustExprText is source text the reader has no shape for (a closure, a
	// binary operation): only a metavariable or `...` matches it. Never
	// produced from a pattern.
	RustExprText RustExprKind = "text"
)

// RustExpr is a pattern argument, receiver or initializer, or a site's
// argument read from its source text (no metavariables there).
type RustExpr struct {
	Kind  RustExprKind `json:"kind"`
	Var   string       `json:"var,omitempty"`
	Lit   string       `json:"lit,omitempty"`
	Path  *RustPath    `json:"path,omitempty"`
	Sub   *RustExpr    `json:"sub,omitempty"` // ref, field, try, index and deep operand, a binary's left
	Index *RustExpr    `json:"index,omitempty"`
	// Op and Right are a binary expression's operator, as written, and right
	// operand.
	Op    string    `json:"op,omitempty"`
	Right *RustExpr `json:"right,omitempty"`
	Mut   bool      `json:"mut,omitempty"`
	Field string    `json:"field,omitempty"`
	Call  *RustCall `json:"call,omitempty"`
}

// RustCall is a call: a path call (Callee) or a method call (Receiver and
// Method, the method name or a metavariable).
type RustCall struct {
	Callee    *RustPath  `json:"callee,omitempty"`
	Receiver  *RustExpr  `json:"receiver,omitempty"`
	Method    string     `json:"method,omitempty"`
	Turbofish []RustType `json:"turbofish,omitempty"` // .collect::<T>()
	Args      []RustExpr `json:"args"`
	// RecvSpan, in source text read, is where what `$X` of a pattern
	// `$X.m(...)` binds is written: the receiver of a method call, the path
	// before the last segment of a path call (byte offsets, end exclusive;
	// zero when unknown).
	RecvSpan [2]int `json:"-"`
}

// Arity is the call's argument count range: max -1 when an argument is `...`.
func (c *RustCall) Arity() (minArity, maxArity int) {
	for _, a := range c.Args {
		if a.Kind == RustExprEllipsis {
			maxArity = -1
			continue
		}
		minArity++
	}
	if maxArity == 0 {
		maxArity = minArity
	}
	return minArity, maxArity
}

func (c *RustCall) String() string {
	var b strings.Builder
	b.WriteString(c.CalleeString())
	parts := make([]string, len(c.Args))
	for i := range c.Args {
		parts[i] = c.Args[i].String()
	}
	b.WriteString("(" + strings.Join(parts, ", ") + ")")
	return b.String()
}

// CalleeString is the call without its argument list: the callee path, or
// the receiver, the method and its turbofish.
func (c *RustCall) CalleeString() string {
	if c.Callee != nil {
		return c.Callee.String()
	}
	s := c.Receiver.String() + "." + c.Method
	if c.Turbofish != nil {
		s += "::<" + joinTypes(c.Turbofish) + ">"
	}
	return s
}

// bound is the text a metavariable binds on the expression: the written
// text, but a parenthesized plain name (`(key)`) binds the name, as OpenGrep
// 1.33.1 reads it; any other group keeps its parentheses (`(a + b)`,
// `(self)`, `(a::b)`).
func (e *RustExpr) bound() string {
	if e.Kind == RustExprParen {
		in := e.Sub
		for in.Kind == RustExprParen {
			in = in.Sub
		}
		if in.Kind == RustExprPath && !in.Path.Global && in.Path.QSelf == nil && len(in.Path.Segs) == 1 {
			if s := in.Path.Segs[0]; s.Name != "" && s.Name != "self" && s.Generics == nil {
				return s.Name
			}
		}
	}
	return e.String()
}

func (e *RustExpr) String() string {
	switch e.Kind {
	case RustExprVar:
		return e.Var
	case RustExprEllipsis:
		return rustEllipsis
	case RustExprDeep:
		return "<..." + e.Sub.String() + "...>"
	case RustExprPath:
		return e.Path.String()
	case RustExprRef:
		if e.Mut {
			return "&mut " + e.Sub.String()
		}
		return "&" + e.Sub.String()
	case RustExprCall:
		return e.Call.String()
	case RustExprField:
		return e.Sub.String() + "." + e.Field
	case RustExprTry:
		return e.Sub.String() + "?"
	case RustExprIndex:
		return e.Sub.String() + "[" + e.Index.String() + "]"
	case RustExprRange:
		return ".."
	case RustExprBinary:
		return e.Sub.String() + e.Op + e.Right.String()
	case RustExprParen:
		return "(" + e.Sub.String() + ")"
	case RustExprLit, RustExprText:
	}
	return e.Lit
}

// rustParser reads tokens; pattern allows metavariables, `...` and `<... E ...>`.
type rustParser struct {
	toks    []rustTok
	i       int
	pattern bool
	// group: the tokens are the inside of a parenthesized receiver, so a
	// group at their end is one too (`((a)).m()`).
	group bool
}

func (p *rustParser) eof() bool { return p.i >= len(p.toks) }

func (p *rustParser) peekAt(n int) rustTok {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return rustTok{}
}

// is: the current token is text (punctuation or keyword).
func (p *rustParser) is(text string) bool {
	t := p.peekAt(0)
	return (t.kind == rtPunct || t.kind == rtIdent) && t.text == text
}

func (p *rustParser) accept(text string) bool {
	if p.is(text) {
		p.i++
		return true
	}
	return false
}

func (p *rustParser) expect(text string, reason rustSkip) error {
	if !p.accept(text) {
		return reason.err()
	}
	return nil
}

// rustReserved are keywords that never start a path segment.
var rustReserved = setOf("as", "break", "const", "continue", "else", "enum", "extern", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "trait", "type", "unsafe", "use", "where", "while", "dyn", "async", "await")

// segStart: the current token can start a path segment.
func (p *rustParser) segStart() bool {
	t := p.peekAt(0)
	return (t.kind == rtVar && p.pattern) || (t.kind == rtIdent && !rustReserved[t.text])
}

// parsePath reads a path; typePos reads generics as `T<A>` (type position)
// instead of `T::<A>` (expression position).
func (p *rustParser) parsePath(typePos bool) (*RustPath, error) {
	path := &RustPath{}
	switch {
	case p.accept("::"):
		path.Global = true
	case p.is("<"):
		q, err := p.parseQSelf()
		if err != nil {
			return nil, err
		}
		path.QSelf = q
	}
	for {
		seg, err := p.parseSeg(typePos)
		if err != nil {
			return nil, err
		}
		path.Segs = append(path.Segs, seg)
		if n := p.peekAt(1); !p.is("::") || (n.kind != rtVar && (n.kind != rtIdent || rustReserved[n.text])) {
			return path, nil
		}
		p.i++
	}
}

// parseQSelf reads `<T as Trait>::` from the `<`.
func (p *rustParser) parseQSelf() (*RustQSelf, error) {
	p.i++
	self, err := p.parseType()
	if err != nil {
		return nil, err
	}
	q := &RustQSelf{Self: self}
	if p.accept("as") {
		if q.Trait, err = p.parsePath(true); err != nil {
			return nil, err
		}
	}
	if err := p.expect(">", skipRustSyntax); err != nil {
		return nil, err
	}
	return q, p.expect("::", skipRustSyntax)
}

// parseSeg reads one path segment with the generics written on it.
func (p *rustParser) parseSeg(typePos bool) (RustSeg, error) {
	if !p.segStart() {
		return RustSeg{}, skipRustSyntax.err()
	}
	t := p.toks[p.i]
	p.i++
	seg := RustSeg{}
	if t.kind == rtVar {
		seg.Var = t.text
	} else {
		seg.Name = t.text
	}
	turbofish := !typePos && p.is("::") && p.peekAt(1).text == "<"
	if !turbofish && (!typePos || !p.is("<")) {
		return seg, nil
	}
	if turbofish {
		p.i++
	}
	g, err := p.parseGenerics()
	seg.Generics = g
	return seg, err
}

// parseGenerics reads `<A, B>` from the `<`.
func (p *rustParser) parseGenerics() ([]RustType, error) {
	if err := p.expect("<", skipRustSyntax); err != nil {
		return nil, err
	}
	out := []RustType{}
	for !p.accept(">") {
		t, err := p.parseType()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		if !p.accept(",") && !p.is(">") {
			return nil, skipRustType.err()
		}
	}
	if len(out) == 0 {
		return nil, skipRustSyntax.err()
	}
	return out, nil
}

// parseType reads a type: a path or a metavariable, else canonical text up to
// the next top-level `,` or closing `>`. A pattern type that is text holding a
// metavariable or `...` has no shape here.
func (p *rustParser) parseType() (RustType, error) {
	if t := p.peekAt(0); t.kind == rtVar && rustTypeEnd(p.peekAt(1).text) {
		p.i++
		return RustType{Var: t.text}, nil
	}
	save := p.i
	if p.accept("&") {
		if p.peekAt(0).kind == rtLifetime {
			p.i++
		}
		mut := p.accept("mut")
		if elem, err := p.parseType(); err == nil {
			return RustType{Ref: &elem, Mut: mut}, nil
		}
		p.i = save
	}
	if p.is("(") && p.peekAt(1).text != ")" {
		if tuple, err := p.parseTuple(); err == nil && rustTypeEnd(p.peekAt(0).text) {
			return RustType{Tuple: tuple}, nil
		}
		p.i = save
	}
	if p.segStart() || p.is("::") || p.is("<") {
		if path, err := p.parsePath(true); err == nil && rustTypeEnd(p.peekAt(0).text) {
			return RustType{Path: path}, nil
		}
		p.i = save
	}
	return p.parseTypeText()
}

// parseTraitType reads `dyn P` or `impl P` with P a path of names (no
// metavariable, generics or qualified self), as text with its trait path.
func (p *rustParser) parseTraitType() (RustType, bool) {
	save := p.i
	if !p.accept("dyn") && !p.accept("impl") {
		return RustType{}, false
	}
	if p.segStart() || p.is("::") {
		path, err := p.parsePath(true)
		if err == nil && rustTypeEnd(p.peekAt(0).text) && rustNamesPath(path) {
			return RustType{Text: rustJoin(p.toks[save:p.i]), Trait: path}, true
		}
	}
	p.i = save
	return RustType{}, false
}

// rustNamesPath: p is written with names only, a leading `::` allowed.
func rustNamesPath(p *RustPath) bool {
	if p.QSelf != nil {
		return false
	}
	for _, s := range p.Segs {
		if s.Name == "" || s.Generics != nil {
			return false
		}
	}
	return true
}

// parseTypeText reads any other type as canonical text, up to the next
// top-level token that ends a type, with its trait path for a `dyn` or
// `impl` type parseTraitType reads.
func (p *rustParser) parseTypeText() (RustType, error) {
	if t, ok := p.parseTraitType(); ok {
		return t, nil
	}
	start := p.i
	depth := 0
	for !p.eof() && depth >= 0 {
		t := p.peekAt(0).text
		if depth == 0 && rustTypeEnd(t) {
			break
		}
		switch t {
		case "<", "(", "[", "{":
			depth++
		case ">", ")", "]", "}":
			depth--
		}
		if depth >= 0 {
			p.i++
		}
	}
	if p.i == start {
		return RustType{}, skipRustType.err()
	}
	text := rustJoin(p.toks[start:p.i])
	if p.pattern && (strings.Contains(text, "$") || strings.Contains(text, rustEllipsis)) {
		return RustType{}, skipRustType.err()
	}
	return RustType{Text: text}, nil
}

// parseTuple reads a tuple type `(A, B)` from the `(`.
func (p *rustParser) parseTuple() ([]RustType, error) {
	p.i++
	out := []RustType{}
	for !p.accept(")") {
		t, err := p.parseType()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		if !p.accept(",") && !p.is(")") {
			return nil, skipRustType.err()
		}
	}
	return out, nil
}

// rustTypeEnd: the token ends a type ("" is the end of the text).
func rustTypeEnd(t string) bool {
	switch t {
	case "", ",", ">", "=", ";", "as", ")", "{":
		return true
	}
	return false
}

// rustBinaryPrec are the binary operators the reader knows, by precedence
// (higher binds tighter). `&`, `<`, `>`, `&&` and the shifts are left out:
// their tokens are also a reference, generics or two `&`, so a text holding
// one reads as text.
var rustBinaryPrec = map[string]int{
	"||": 1,
	"==": 2, "!=": 2, "<=": 2, ">=": 2,
	"|": 3, "^": 4,
	"+": 5, "-": 5,
	"*": 6, "/": 6, "%": 6,
}

// parseExpr reads one expression in the closed shape set, a binary
// expression of them included.
func (p *rustParser) parseExpr() (*RustExpr, error) {
	return p.parseBinary(1)
}

// parseBinary reads operands joined by operators of precedence min or more,
// left-associative.
func (p *rustParser) parseBinary(minPrec int) (*RustExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peekAt(0)
		prec, isOp := rustBinaryPrec[t.text]
		if t.kind != rtPunct || !isOp || prec < minPrec {
			return left, nil
		}
		p.i++
		right, err := p.parseBinary(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &RustExpr{Kind: RustExprBinary, Op: t.text, Sub: left, Right: right}
	}
}

// parseUnary reads one operand: an expression of the closed shape set
// without a binary operator outside it.
func (p *rustParser) parseUnary() (*RustExpr, error) { //nolint:gocognit,gocyclo,funlen // one case per expression shape of the closed set
	var e *RustExpr
	t := p.peekAt(0)
	first := p.i
	switch {
	case p.eof():
		return nil, skipRustSyntax.err()
	case p.is("&"):
		p.i++
		mut := p.accept("mut")
		sub, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &RustExpr{Kind: RustExprRef, Mut: mut, Sub: sub}, nil
	case p.pattern && p.is(rustEllipsis):
		p.i++
		return &RustExpr{Kind: RustExprEllipsis}, nil
	case p.pattern && p.is("<") && p.peekAt(1).text == rustEllipsis:
		p.i += 2
		sub, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(rustEllipsis, skipRustSyntax); err != nil {
			return nil, err
		}
		if err := p.expect(">", skipRustSyntax); err != nil {
			return nil, err
		}
		e = &RustExpr{Kind: RustExprDeep, Sub: sub}
	case !p.pattern && p.is("("):
		g, err := p.parseGroupReceiver()
		if err != nil {
			return nil, err
		}
		e = g
	case t.kind == rtLit || t.kind == rtIdent && (t.text == "true" || t.text == "false"):
		p.i++
		e = &RustExpr{Kind: RustExprLit, Lit: t.text}
	case p.is("-") && p.peekAt(1).kind == rtLit:
		p.i += 2
		e = &RustExpr{Kind: RustExprLit, Lit: "-" + p.toks[p.i-1].text}
	case t.kind == rtVar && p.pattern && p.peekAt(1).text != "::" && p.peekAt(1).text != "(":
		p.i++
		e = &RustExpr{Kind: RustExprVar, Var: t.text}
	case p.segStart() || p.is("::") || p.is("<"):
		start := p.i
		path, err := p.parsePath(false)
		if err != nil {
			return nil, err
		}
		switch {
		case p.is("!") && !p.pattern:
			// A macro in source text has no shape: its text is the expression.
			if !p.skipGroup() {
				return nil, skipRustMacro.err()
			}
			e = &RustExpr{Kind: RustExprText, Lit: rustJoin(p.toks[start:p.i])}
		case p.is("!"):
			return nil, skipRustMacro.err()
		case p.is("("):
			pathEnd := p.i
			args, err := p.parseArgs()
			if err != nil {
				return nil, err
			}
			call := &RustCall{Callee: path, Args: args}
			if last := rustLastSep(p.toks[start:pathEnd]); last > 0 {
				call.RecvSpan = [2]int{p.toks[start].off, p.toks[start+last-1].end()}
			}
			e = &RustExpr{Kind: RustExprCall, Call: call}
		default:
			e = &RustExpr{Kind: RustExprPath, Path: path}
		}
	default:
		return nil, skipRustExpr.err()
	}
	for {
		switch {
		case p.is("."):
			recv := p.recvSpan(e, first)
			p.i++
			n := p.peekAt(0)
			if n.kind != rtIdent && n.kind != rtVar && n.kind != rtLit {
				return nil, skipRustSyntax.err()
			}
			p.i++
			var turbofish []RustType
			if p.is("::") && p.peekAt(1).text == "<" {
				p.i++
				g, err := p.parseGenerics()
				if err != nil {
					return nil, err
				}
				turbofish = g
			}
			if !p.is("(") {
				if turbofish != nil {
					return nil, skipRustSyntax.err()
				}
				e = &RustExpr{Kind: RustExprField, Sub: e, Field: n.text}
				continue
			}
			args, err := p.parseArgs()
			if err != nil {
				return nil, err
			}
			e = &RustExpr{Kind: RustExprCall, Call: &RustCall{Receiver: e, Method: n.text, Turbofish: turbofish, Args: args, RecvSpan: recv}}
		case p.is("?"):
			p.i++
			e = &RustExpr{Kind: RustExprTry, Sub: e}
		case p.is("["):
			p.i++
			idx := &RustExpr{Kind: RustExprRange}
			if !p.accept("..") {
				var err error
				if idx, err = p.parseExpr(); err != nil {
					return nil, err
				}
			}
			if err := p.expect("]", skipRustExpr); err != nil {
				return nil, err
			}
			e = &RustExpr{Kind: RustExprIndex, Sub: e, Index: idx}
		default:
			return e, nil
		}
	}
}

// recvSpan is where the receiver e, read from toks[first:p.i], is written: a
// parenthesized plain name binds the name (RustExpr.bound), and OpenGrep
// 1.33.1 focuses it there too (`(key).m()` at `key`); any other receiver
// spans its tokens, parentheses included.
func (p *rustParser) recvSpan(e *RustExpr, first int) [2]int {
	a, b := first, p.i-1
	if e.Kind == RustExprParen && e.bound() != e.String() {
		for a < b && p.toks[a].text == "(" && p.toks[b].text == ")" {
			a, b = a+1, b-1
		}
	}
	return [2]int{p.toks[a].off, p.toks[b].end()}
}

// parseGroupReceiver reads the parenthesized receiver of a method call or a
// field access in source text: `(a + b).decrypt(k)`, `("kid", claims).sign(s)`.
// OpenGrep 1.33.1 matches a parenthesized expression as the expression
// (`a.decrypt(...)` matches `(a).decrypt(1)`), but a metavariable binds its
// text with the parentheses (RustExpr.bound); a tuple is only text, which a
// metavariable binds (pinned by invented rules). An expression outside the
// shape set is its text, `()` too; a group no `.` follows (an argument, a
// `let` initializer) is not read, as before.
func (p *rustParser) parseGroupReceiver() (*RustExpr, error) {
	start, depth, end := p.i, 0, -1
	for i := start; i < len(p.toks) && end < 0; i++ {
		switch p.toks[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				end = i
			}
		}
	}
	if end < 0 || (end+1 < len(p.toks) && p.toks[end+1].text != ".") || (end+1 >= len(p.toks) && !p.group) {
		return nil, skipRustExpr.err()
	}
	inner := p.toks[start+1 : end]
	p.i = end + 1
	if len(inner) == 0 {
		return &RustExpr{Kind: RustExprText, Lit: "()"}, nil
	}
	sub := &rustParser{toks: inner, group: true}
	if x, err := sub.parseExpr(); err == nil && sub.eof() {
		return &RustExpr{Kind: RustExprParen, Sub: x}, nil
	}
	if rustTopLevelComma(inner) {
		return &RustExpr{Kind: RustExprText, Lit: rustJoin(p.toks[start : end+1])}, nil
	}
	return &RustExpr{Kind: RustExprParen, Sub: &RustExpr{Kind: RustExprText, Lit: rustJoin(inner)}}, nil
}

// rustTopLevelComma: toks holds a `,` outside any bracket.
func rustTopLevelComma(toks []rustTok) bool {
	depth := 0
	for _, t := range toks {
		switch t.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// rustLastSep is the index in toks (a path) of the `::` before its last
// segment, outside generics; 0 when there is none.
func rustLastSep(toks []rustTok) int {
	last, depth := 0, 0
	for i, t := range toks {
		switch t.text {
		case "<":
			depth++
		case ">":
			depth--
		case "::":
			// A `::` in front of a turbofish (`A::verify::<u8>`) separates
			// no segment.
			if depth == 0 && (i+1 >= len(toks) || toks[i+1].text != "<") {
				last = i
			}
		}
	}
	return last
}

// parseArgs reads `(a, b, ...)` from the `(`.
func (p *rustParser) parseArgs() ([]RustExpr, error) {
	if err := p.expect("(", skipRustSyntax); err != nil {
		return nil, err
	}
	args := []RustExpr{}
	for !p.accept(")") {
		save := p.i
		a, err := p.parseExpr()
		if !p.pattern && (err != nil || (!p.is(",") && !p.is(")"))) {
			// Source text only: an argument outside the shape set (a closure, an
			// operation) is its text.
			p.i = save
			if a, err = p.textArg(); err != nil {
				return nil, err
			}
		}
		if err != nil {
			return nil, err
		}
		args = append(args, *a)
		if !p.accept(",") && !p.is(")") {
			return nil, skipRustExpr.err()
		}
	}
	return args, nil
}

// parseRustPatternExpr reads a pattern's expression text, all of it.
func parseRustPatternExpr(text string) (*RustExpr, error) {
	toks, err := lexRust(text)
	if err != nil {
		return nil, skipRustSyntax.err()
	}
	p := &rustParser{toks: toks, pattern: true}
	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	p.accept(";")
	if !p.eof() {
		return nil, skipRustExpr.err()
	}
	return e, nil
}

// readRustExpr reads source text (an argument, an initializer, a callee
// through its argument list) into an expression. Text outside the shape set
// reads as RustExprText in the canonical spelling, which only a metavariable
// or `...` matches; ok is false when the text does not lex.
func readRustExpr(text string) (e RustExpr, ok bool) {
	toks, err := lexRust(text)
	if err != nil {
		return RustExpr{Kind: RustExprText, Lit: strings.Join(strings.Fields(text), " ")}, false
	}
	p := &rustParser{toks: toks}
	if x, err := p.parseExpr(); err == nil && p.eof() {
		return *x, true
	}
	return RustExpr{Kind: RustExprText, Lit: rustJoin(toks)}, true
}

// skipGroup skips `!` and the balanced group after it; false when there is none.
func (p *rustParser) skipGroup() bool {
	if !p.is("!") {
		return false
	}
	p.i++
	if !p.is("(") && !p.is("[") && !p.is("{") {
		return false
	}
	depth := 0
	for !p.eof() {
		switch p.toks[p.i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
		p.i++
		if depth == 0 {
			return true
		}
	}
	return false
}

// textArg reads an argument of source text as its canonical text, up to the
// next top-level `,` or the `)` that closes the list. A comma inside a
// closure's parameters (`|a, b| ..`) or inside generics (`::<K, V>`,
// `as HashMap<K, V>`) belongs to the argument.
func (p *rustParser) textArg() (*RustExpr, error) {
	start := p.i
	if !p.skipClosureParams() {
		return nil, skipRustExpr.err()
	}
	var sc argScan
	for !p.eof() {
		t := p.toks[p.i]
		if sc.ends(t) {
			break
		}
		sc.step(t, p.i > start && p.toks[p.i-1].text == "::")
		p.i++
	}
	if p.i == start || sc.depth != 0 || sc.angle != 0 {
		return nil, skipRustExpr.err()
	}
	return &RustExpr{Kind: RustExprText, Lit: rustJoin(p.toks[start:p.i])}, nil
}

// skipClosureParams skips `[move] |..|`, the parameters of a closure
// argument; false when the closing `|` is missing.
func (p *rustParser) skipClosureParams() bool {
	save := p.i
	p.accept("move")
	if !p.is("|") {
		p.i = save
		return true
	}
	p.i++
	for !p.eof() && !p.is("|") {
		p.i++
	}
	if p.eof() {
		return false
	}
	p.i++
	return true
}

// argScan tracks the nesting of an argument's source text: brackets, and
// generics after `::` or `as`.
type argScan struct {
	depth, angle int
	typ          bool // after `as`, where generics are written `T<A>`
}

// ends: t ends the argument.
func (a *argScan) ends(t rustTok) bool {
	return t.kind == rtPunct && a.depth == 0 && a.angle == 0 && (t.text == "," || t.text == ")")
}

// step reads t; afterPath is true when t follows a `::`.
func (a *argScan) step(t rustTok, afterPath bool) {
	if t.kind == rtIdent && t.text == "as" {
		a.typ = true
	}
	if t.kind != rtPunct {
		return
	}
	switch t.text {
	case "(", "[", "{":
		a.depth++
	case ")", "]", "}":
		a.depth--
	case "<":
		if a.angle > 0 || a.typ || afterPath {
			a.angle++
		}
	case ">":
		if a.angle > 0 {
			a.angle--
		}
	case "::", "&":
	default:
		if a.angle == 0 {
			a.typ = false
		}
	}
}
