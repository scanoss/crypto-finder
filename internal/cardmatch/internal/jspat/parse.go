// Package jspat is a small JavaScript expression parser and unifier. It reads the patterns
// OpenGrep/Semgrep JavaScript rules use (metavariables, `...`, deep `<... e ...>`) and the
// argument text a call-graph fragment carries for a call site, and unifies the two.
//
// It models only expressions: calls, `new`, member chains, string and number literals,
// object and array literals, a few operators and sequences. Everything else on the concrete
// side becomes an Opaque node, and on the pattern side is ErrUnsupported.
package jspat

import (
	"errors"
	"fmt"
)

// Kind is the syntactic class of a Node.
type Kind uint8

// The node kinds.
const (
	Ident    Kind = iota // name
	Metavar              // $NAME (pattern only)
	Ellipsis             // `...` in an argument list, object or array (pattern only)
	Deep                 // <... e ...> (pattern only)
	String               // string literal; Name is the decoded value, Text the canonical double-quoted form
	Number               // Name and Text are the source text, with a folded leading minus
	Member               // Kids[0].Name, a["b"] included; Meta marks a metavariable Name; Op "?." for optional chaining
	Call                 // Kids[0](Kids[1:]...)
	New                  // new Kids[0](Kids[1:]...)
	Object               // Props
	Array                // Kids
	Binary               // Kids[0] Op Kids[1]
	Unary                // Op Kids[0]; Op is "!", "-", "+", "~", "typeof", "void", "delete" or kwAwait
	Sequence             // (a, b)
	Index                // Kids[0][Kids[1]] with a non-literal index
	// Opaque is concrete text the parser does not model (arrow function, template with
	// interpolation, regex, TS cast, spread element ...). Name says why: "fn" (a function or
	// class, which cannot be a plain value), "regex" or "expr" (an expression whose value the
	// text does not settle). It unifies with a metavariable, an ellipsis or an Opaque of the
	// same Text; against anything else it is No for "fn" and "regex" and Unknown for "expr".
	Opaque
)

// Node is one expression. The same type holds a rule pattern and a concrete argument; only a
// pattern holds Metavar, Ellipsis, Deep nodes and Meta members. In concrete mode `$X` is a
// plain Ident, because `$` is a legal identifier character.
type Node struct {
	Kind  Kind
	Text  string // source text of the node, whitespace-normalised
	Name  string
	Op    string
	Meta  bool // Member: Name is a metavariable
	Kids  []*Node
	Props []Prop
}

// Prop is one object-literal entry.
type Prop struct {
	Key       string // identifier or unquoted string key; "" for Spread, Ellipsis, Computed and KeyVar
	KeyVar    string // `$K: v` in a pattern
	Value     *Node  // nil for a pattern's bare ellipsis; the spread operand for Spread
	Spread    bool   // `...expr` on the concrete side: absence of a key becomes Unknown
	Computed  bool   // `[expr]: v` on the concrete side
	Ellipsis  bool
	Shorthand bool // `{a}` or `{$X}`: Value is the Ident or Metavar
}

// ErrUnsupported is returned for a PATTERN the parser cannot classify. Concrete text never
// fails: what is not modeled becomes Opaque.
var ErrUnsupported = errors.New("jspat: unsupported pattern")

type parseError struct{ msg string }

func (e parseError) Error() string { return e.msg }

func unsupported(err error) error { return fmt.Errorf("%w: %s", ErrUnsupported, err.Error()) }

// IsMetavar reports whether s is a metavariable name: `$` then uppercase letters, digits or `_`,
// starting with a letter or `_`.
func IsMetavar(s string) bool {
	if len(s) < 2 || s[0] != '$' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '_' || c >= 'A' && c <= 'Z' || i > 1 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

type parser struct {
	toks    []token
	i, end  int
	pattern bool
}

func (p *parser) fail(format string, a ...any) {
	panic(parseError{fmt.Sprintf(format, a...)})
}

func (p *parser) peek() token { return p.peekAt(0) }

func (p *parser) peekAt(n int) token {
	if p.i+n >= p.end {
		return token{}
	}
	return p.toks[p.i+n]
}

func (p *parser) next() token {
	t := p.peek()
	if t.kind == tEOF {
		p.fail("unexpected end")
	}
	p.i++
	return t
}

func (p *parser) isP(s string) bool {
	t := p.peek()
	return t.kind == tPunct && t.s == s
}

func (p *parser) expectP(s string) {
	if !p.isP(s) {
		p.fail("expected %q, found %q", s, p.peek().s)
	}
	p.i++
}

func (p *parser) mk(from int, n *Node) *Node {
	n.Text = joinToks(p.toks[from:p.i])
	return n
}

func (p *parser) try(f func() *Node) (n *Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(parseError)
			if !ok {
				panic(r)
			}
			n, err = nil, pe
		}
	}()
	return f(), nil
}

func opaque(toks []token, text string) *Node {
	if text == "" {
		text = joinToks(toks)
	}
	name := reasonExpr
	switch {
	case len(toks) == 1 && toks[0].kind == tRegex:
		name = "regex"
	case len(toks) > 0 && toks[0].kind == tIdent && (toks[0].s == kwFunction || toks[0].s == "class" || toks[0].s == "async"):
		name = "fn"
	default:
		depth := 0
		for _, t := range toks {
			if t.kind != tPunct {
				continue
			}
			switch t.s {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			case "=>":
				if depth == 0 {
					name = "fn"
				}
			}
		}
	}
	return &Node{Kind: Opaque, Name: name, Text: text}
}

// sliceEnd is the index of the first depth-0 `,` or closing bracket at or after p.i, or p.end.
func (p *parser) sliceEnd() int {
	depth := 0
	for j := p.i; j < p.end; j++ {
		t := p.toks[j]
		if t.kind != tPunct {
			continue
		}
		switch t.s {
		case "(", "[", "{", tokDeepOpen:
			depth++
		case ")", "]", "}", tokDeepClose:
			if depth == 0 {
				return j
			}
			depth--
		case ",":
			if depth == 0 {
				return j
			}
		}
	}
	return p.end
}

// element parses one list element (argument, array item, property value). In concrete mode
// an element it cannot model is an Opaque node spanning it; in pattern mode it is an error.
func (p *parser) element() *Node {
	start := p.i
	stop := p.sliceEnd()
	if p.pattern && stop-start == 1 && p.toks[start].kind == tPunct && p.toks[start].s == tokEllipsis {
		p.i = stop
		return &Node{Kind: Ellipsis, Text: tokEllipsis}
	}
	saved := p.end
	p.end = stop
	var n *Node
	var err error
	if stop == start {
		err = parseError{"empty element"}
	} else {
		n, err = p.try(func() *Node {
			n := p.expr()
			if p.i != stop {
				p.fail("unexpected %q", p.peek().s)
			}
			return n
		})
	}
	p.end = saved
	if err != nil {
		if p.pattern {
			panic(err)
		}
		p.i = stop
		return opaque(p.toks[start:stop], "")
	}
	return n
}

func (p *parser) expr() *Node { return p.binary(1) }

func binPrec(t token) int { //nolint:gocyclo // one case per grammar construct; splitting it hides the grammar
	if t.kind == tIdent {
		if t.s == "instanceof" || t.s == "in" {
			return 8
		}
		return 0
	}
	if t.kind != tPunct {
		return 0
	}
	switch t.s {
	case "??":
		return 1
	case "||":
		return 2
	case "&&":
		return 3
	case "|":
		return 4
	case "^":
		return 5
	case "&":
		return 6
	case "==", "!=", "===", "!==":
		return 7
	case "<", ">", "<=", ">=":
		return 8
	case "<<", ">>", ">>>":
		return 9
	case "+", "-":
		return 10
	case "*", "/", "%":
		return 11
	case "**":
		return 12
	}
	return 0
}

func (p *parser) binary(minPrec int) *Node {
	start := p.i
	left := p.unary()
	for {
		t := p.peek()
		prec := binPrec(t)
		if prec == 0 || prec < minPrec {
			return left
		}
		p.next()
		right := p.binary(prec + 1)
		left = p.mk(start, &Node{Kind: Binary, Op: t.s, Kids: []*Node{left, right}})
	}
}

func (p *parser) unary() *Node { //nolint:gocyclo // one case per grammar construct; splitting it hides the grammar
	start := p.i
	t := p.peek()
	switch {
	case t.kind == tPunct && (t.s == "!" || t.s == "~" || t.s == "+" || t.s == "-"):
		p.next()
		k := p.unary()
		if t.s == "-" && k.Kind == Number && k.Name[0] != '-' {
			return p.mk(start, &Node{Kind: Number, Name: "-" + k.Name})
		}
		return p.mk(start, &Node{Kind: Unary, Op: t.s, Kids: []*Node{k}})
	case t.kind == tPunct && (t.s == "++" || t.s == "--"):
		p.fail("update expression")
	case t.kind == tIdent && (t.s == "typeof" || t.s == "void" || t.s == "delete" || t.s == kwAwait):
		p.next()
		k := p.unary()
		return p.mk(start, &Node{Kind: Unary, Op: t.s, Kids: []*Node{k}})
	}
	return p.postfix(p.primary(), start, true)
}

func (p *parser) args() []*Node {
	p.expectP("(")
	var out []*Node
	for !p.isP(")") {
		if p.peek().kind == tEOF {
			p.fail("unterminated argument list")
		}
		out = append(out, p.element())
		if p.isP(",") {
			p.next()
		} else {
			break
		}
	}
	p.expectP(")")
	return out
}

func (p *parser) member(start int, obj *Node, name, op string) *Node {
	return p.mk(start, &Node{Kind: Member, Name: name, Op: op, Meta: p.pattern && IsMetavar(name), Kids: []*Node{obj}})
}

func (p *parser) index(start int, obj *Node, op string) *Node {
	p.expectP("[")
	idx := p.element()
	p.expectP("]")
	if idx.Kind == String {
		return p.member(start, obj, idx.Name, op)
	}
	return p.mk(start, &Node{Kind: Index, Kids: []*Node{obj, idx}})
}

func (p *parser) postfix(n *Node, start int, calls bool) *Node {
	for {
		t := p.peek()
		if t.kind != tPunct {
			return n
		}
		switch t.s {
		case ".":
			p.next()
			id := p.next()
			if id.kind != tIdent {
				p.fail("expected member name, found %q", id.s)
			}
			n = p.member(start, n, id.s, "")
		case "?.":
			p.next()
			switch {
			case p.isP("(") && calls:
				n = p.mk(start, &Node{Kind: Call, Op: "?.", Kids: append([]*Node{n}, p.args()...)})
			case p.isP("["):
				n = p.index(start, n, "?.")
			default:
				id := p.next()
				if id.kind != tIdent {
					p.fail("expected member name, found %q", id.s)
				}
				n = p.member(start, n, id.s, "?.")
			}
		case "[":
			n = p.index(start, n, "")
		case "(":
			if !calls {
				return n
			}
			n = p.mk(start, &Node{Kind: Call, Kids: append([]*Node{n}, p.args()...)})
		default:
			return n
		}
	}
}

func (p *parser) primary() *Node { //nolint:gocyclo // one case per grammar construct; splitting it hides the grammar
	t := p.peek()
	start := p.i
	switch t.kind { //nolint:exhaustive // the remaining kinds share the default behavior
	case tStr:
		p.next()
		return &Node{Kind: String, Name: t.v, Text: canon(t.v)}
	case tNum:
		p.next()
		return &Node{Kind: Number, Name: t.s, Text: t.s}
	case tTmpl:
		p.next()
		return &Node{Kind: Opaque, Name: reasonExpr, Text: t.s}
	case tRegex:
		p.next()
		return &Node{Kind: Opaque, Name: "regex", Text: t.s}
	case tIdent:
		switch t.s {
		case "new":
			return p.newExpr()
		case kwFunction, "class":
			p.fail("function or class expression")
		case "async":
			if p.peekAt(1).kind == tIdent && p.peekAt(1).s == kwFunction {
				p.fail("async function")
			}
		}
		p.next()
		if p.isP("=>") {
			p.fail("arrow function")
		}
		if p.pattern && IsMetavar(t.s) {
			return &Node{Kind: Metavar, Name: t.s, Text: t.s}
		}
		return &Node{Kind: Ident, Name: t.s, Text: t.s}
	case tPunct:
		switch t.s {
		case "(":
			return p.paren()
		case "[":
			return p.array()
		case "{":
			return p.object()
		case tokDeepOpen:
			if !p.pattern {
				break
			}
			p.next()
			inner := p.expr()
			p.expectP(tokDeepClose)
			return p.mk(start, &Node{Kind: Deep, Kids: []*Node{inner}})
		case tokEllipsis:
			if !p.pattern {
				break
			}
			p.next()
			return &Node{Kind: Ellipsis, Text: tokEllipsis}
		}
	}
	p.fail("unexpected %q", t.s)
	return nil
}

func (p *parser) matchClose(open int) int {
	depth := 0
	for j := open; j < p.end; j++ {
		t := p.toks[j]
		if t.kind != tPunct {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

func (p *parser) paren() *Node {
	if m := p.matchClose(p.i); m >= 0 && m+1 < p.end && p.toks[m+1].kind == tPunct && p.toks[m+1].s == "=>" {
		p.fail("arrow function")
	}
	start := p.i
	p.next()
	var kids []*Node
	for !p.isP(")") {
		if p.peek().kind == tEOF {
			p.fail("unterminated parenthesis")
		}
		kids = append(kids, p.element())
		if p.isP(",") {
			p.next()
		} else {
			break
		}
	}
	p.expectP(")")
	switch len(kids) {
	case 0:
		p.fail("empty parentheses")
	case 1:
		return kids[0]
	}
	return p.mk(start, &Node{Kind: Sequence, Kids: kids})
}

func (p *parser) array() *Node {
	start := p.i
	p.next()
	var kids []*Node
	for !p.isP("]") {
		if p.peek().kind == tEOF {
			p.fail("unterminated array")
		}
		if p.isP(",") {
			p.next()
			continue
		}
		kids = append(kids, p.element())
		if p.isP(",") {
			p.next()
		} else {
			break
		}
	}
	p.expectP("]")
	return p.mk(start, &Node{Kind: Array, Kids: kids})
}

func (p *parser) skipBalanced() {
	m := p.matchClose(p.i)
	if m < 0 {
		p.fail("unbalanced")
	}
	p.i = m + 1
}

func (p *parser) object() *Node {
	start := p.i
	p.next()
	var props []Prop
	for !p.isP("}") {
		t := p.peek()
		if t.kind == tEOF {
			p.fail("unterminated object")
		}
		if t.kind == tPunct && t.s == "," {
			p.next()
			continue
		}
		props = append(props, p.prop())
		if p.isP(",") {
			p.next()
		} else {
			break
		}
	}
	p.expectP("}")
	return p.mk(start, &Node{Kind: Object, Props: props})
}

func (p *parser) prop() Prop { //nolint:gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	t := p.peek()
	if t.kind == tPunct && t.s == tokEllipsis {
		p.next()
		if p.pattern && p.sliceEnd() == p.i {
			return Prop{Ellipsis: true}
		}
		// `...$X` in a pattern is a spread, as in the source: it matches an
		// object that spreads a value.
		return Prop{Spread: true, Value: p.element()}
	}
	var pr Prop
	switch {
	case t.kind == tPunct && t.s == "[":
		if p.pattern {
			p.fail("computed key in a pattern")
		}
		p.next()
		pr.Computed = true
		_ = p.element()
		p.expectP("]")
	case t.kind == tStr:
		p.next()
		pr.Key = t.v
	case t.kind == tNum:
		p.next()
		pr.Key = t.s
	case t.kind == tIdent:
		p.next()
		if p.pattern && IsMetavar(t.s) {
			pr.KeyVar = t.s
		} else {
			pr.Key = t.s
		}
	default:
		p.fail("unexpected %q in object", t.s)
	}
	switch {
	case p.isP(":"):
		p.next()
		pr.Value = p.element()
	case p.isP("(") && !p.pattern:
		p.skipBalanced()
		if p.isP("{") {
			p.skipBalanced()
		}
		pr.Value = &Node{Kind: Opaque, Name: "fn", Text: "(){}"}
	case t.kind == tIdent && (p.isP(",") || p.isP("}")):
		pr.Shorthand = true
		if pr.KeyVar != "" {
			pr.Value = &Node{Kind: Metavar, Name: t.s, Text: t.s}
		} else {
			pr.Value = &Node{Kind: Ident, Name: t.s, Text: t.s}
		}
	default:
		p.fail("unexpected %q in object", p.peek().s)
	}
	return pr
}

func (p *parser) newExpr() *Node {
	start := p.i
	p.next()
	if p.isP(".") {
		p.fail("new.target")
	}
	calleeStart := p.i
	callee := p.postfix(p.primary(), calleeStart, false)
	kids := []*Node{callee}
	if p.isP("(") {
		kids = append(kids, p.args()...)
	}
	return p.mk(start, &Node{Kind: New, Kids: kids})
}

func newParser(text string, pattern bool) (*parser, error) {
	toks, err := lex(text, pattern)
	if err != nil {
		return nil, errors.New("unterminated literal")
	}
	return &parser{toks: toks, end: len(toks), pattern: pattern}, nil
}

// ParseExpr parses one expression. pattern=false is tolerant: it never fails, and text it
// cannot model comes back as an Opaque node.
func ParseExpr(text string, pattern bool) (*Node, error) {
	p, err := newParser(text, pattern)
	if err != nil {
		if pattern {
			return nil, unsupported(err)
		}
		return &Node{Kind: Opaque, Name: reasonExpr, Text: text}, nil
	}
	if len(p.toks) == 0 {
		if pattern {
			return nil, unsupported(errors.New("empty pattern"))
		}
		return &Node{Kind: Opaque, Name: reasonExpr}, nil
	}
	n, err := p.try(func() *Node {
		n := p.expr()
		if p.i != p.end {
			p.fail("unexpected %q", p.peek().s)
		}
		return n
	})
	if err != nil {
		if pattern {
			return nil, unsupported(err)
		}
		return opaque(p.toks, ""), nil
	}
	return n, nil
}

func parseList(text string, pattern bool) ([]*Node, error) {
	p, err := newParser(text, pattern)
	if err != nil {
		return nil, unsupported(err)
	}
	var out []*Node
	_, err = p.try(func() *Node {
		for p.i < p.end {
			out = append(out, p.element())
			if p.isP(",") {
				p.next()
			} else if p.i < p.end {
				p.fail("unexpected %q", p.peek().s)
			}
		}
		return nil
	})
	if err != nil {
		return nil, unsupported(err)
	}
	return out, nil
}

// ParseArgs parses the text between a call's parentheses as an argument-list pattern:
// `$K, ..., {..., mode: $M, ...}`.
func ParseArgs(text string) ([]*Node, error) { return parseList(text, true) }

// ParseConcreteArgs parses the text between a call's parentheses as concrete arguments. It
// never fails: an argument it cannot model is Opaque.
func ParseConcreteArgs(text string) []*Node {
	out, err := parseList(text, false)
	if err != nil {
		return nil // unreachable: concrete lists never fail
	}
	return out
}

// Arity is the least and most arguments an argument-list pattern accepts; max is -1 when the
// list holds an ellipsis.
func Arity(pattern []*Node) (minArgs, maxArgs int) {
	for _, n := range pattern {
		if n.Kind == Ellipsis {
			maxArgs = -1
			continue
		}
		minArgs++
		if maxArgs >= 0 {
			maxArgs++
		}
	}
	return minArgs, maxArgs
}

// Head is the first identifier of a callee text (`A` of `A.encrypt`, `(0, A.encrypt)`),
// "" when the callee does not start with one (`require("m").f`).
func Head(calleeText string) string {
	n, err := ParseExpr(calleeText, false)
	if err != nil {
		return ""
	}
	for {
		switch n.Kind { //nolint:exhaustive // the remaining kinds share the default behavior
		case Ident:
			return n.Name
		case Member, Index:
			n = n.Kids[0]
		case Sequence:
			n = n.Kids[len(n.Kids)-1]
		default:
			return ""
		}
	}
}
