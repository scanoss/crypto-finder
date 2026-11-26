package jspat

import (
	"errors"
	"fmt"
)

// Binding is one name a guard statement introduces.
type Binding struct {
	Metavar string // the pattern metavariable bound ($NS, $F, $R)
	Fixed   string // or a literal local name (`const { pbkdf2 } = require("m")`)
	// Imported is the member of the source the local names: "" is the source itself
	// (namespace, default or whole-value binding), a literal name (`{ a: $X }`,
	// `import { a as $X }`), "$" the same name as the local one (`{..., $F, ...}`), or a
	// metavariable name such as "$K" (`{..., $K: $X, ...}`).
	Imported string
	// Source is what the local is taken from: a String node for an import statement, a
	// Metavar node for `from $M`, otherwise the right-hand side of the statement with any
	// `await` and `<... ...>` wrapper removed (a `require("m")`, `import("m")` or `$E("m")`
	// call, an alias path `$NS.ec`, a call or `new`).
	Source    *Node
	ModuleVar string // `require($M)` / `from $M`: the module is this metavariable
}

// Module is the module string a binding reads from: an import statement's module, or the
// single string argument of a require/import/wrapper call.
func (b Binding) Module() (string, bool) {
	s := b.Source
	switch {
	case s == nil:
		return "", false
	case s.Kind == String:
		return s.Name, true
	case isModuleCall(s) && s.Kids[1].Kind == String:
		return s.Kids[1].Name, true
	}
	return "", false
}

// Guard is one pattern-inside read as a list of binding statements, in order. A later
// statement may read a metavariable an earlier one binds.
type Guard struct{ Bindings []Binding }

// isModuleCall reports whether n is `require(x)`, `import(x)` or `$E(x)` with one argument
// that is a string or a metavariable.
func isModuleCall(n *Node) bool {
	if n.Kind != Call || len(n.Kids) != 2 {
		return false
	}
	c := n.Kids[0]
	if c.Kind != Metavar && (c.Kind != Ident || c.Name != "require" && c.Name != "import") {
		return false
	}
	return n.Kids[1].Kind == String || n.Kids[1].Kind == Metavar
}

func unwrapSource(n *Node) *Node {
	for {
		switch {
		case n.Kind == Deep:
			n = n.Kids[0]
		case n.Kind == Unary && n.Op == kwAwait:
			n = n.Kids[0]
		default:
			return n
		}
	}
}

func sourceBinding(local, imported string, src *Node) Binding {
	b := Binding{Imported: imported, Source: src}
	if IsMetavar(local) {
		b.Metavar = local
	} else {
		b.Fixed = local
	}
	if isModuleCall(src) && src.Kids[1].Kind == Metavar {
		b.ModuleVar = src.Kids[1].Name
	}
	return b
}

type guardParser struct {
	toks []token
	g    *Guard
}

// ParseGuard reads a pattern-inside (or pattern-not-inside) text made only of import /
// require / alias / construction statements and `...`, with the try/catch and block wrappers
// the generators emit. Anything else is ErrUnsupported.
func ParseGuard(text string) (*Guard, error) {
	toks, err := lex(text, true)
	if err != nil {
		return nil, unsupported(err)
	}
	gp := &guardParser{toks: toks, g: &Guard{}}
	if err := gp.stmts(0, len(toks)); err != nil {
		return nil, unsupported(err)
	}
	if len(gp.g.Bindings) == 0 {
		return nil, unsupported(errors.New("guard binds nothing"))
	}
	return gp.g, nil
}

func (gp *guardParser) at(i int) token {
	if i < 0 || i >= len(gp.toks) {
		return token{}
	}
	return gp.toks[i]
}

func (gp *guardParser) isP(i int, s string) bool {
	t := gp.at(i)
	return t.kind == tPunct && t.s == s
}

func (gp *guardParser) isW(i int, s string) bool {
	t := gp.at(i)
	return t.kind == tIdent && t.s == s
}

func (gp *guardParser) matchClose(open, hi int) int {
	depth := 0
	for j := open; j < hi; j++ {
		t := gp.toks[j]
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

func (gp *guardParser) stmtEnd(i, hi int) int {
	depth := 0
	for j := i; j < hi; j++ {
		t := gp.toks[j]
		if j > i && depth == 0 && t.nl {
			return j
		}
		if t.kind != tPunct {
			continue
		}
		switch t.s {
		case ";":
			if depth == 0 {
				return j
			}
		case "(", "[", "{", tokDeepOpen:
			depth++
		case ")", "]", "}", tokDeepClose:
			depth--
		}
	}
	return hi
}

func (gp *guardParser) stmts(lo, hi int) error {
	i := lo
	for i < hi {
		switch {
		case gp.isP(i, ";"), gp.isP(i, tokEllipsis):
			i++
		case gp.isW(i, "try"):
			next, err := gp.tryStmt(i, hi)
			if err != nil {
				return err
			}
			i = next
		case gp.isP(i, "{"):
			m := gp.matchClose(i, hi)
			if m < 0 {
				return errors.New("unbalanced block")
			}
			if err := gp.stmts(i+1, m); err != nil {
				return err
			}
			i = m + 1
		default:
			end := gp.stmtEnd(i, hi)
			if err := gp.stmt(i, end); err != nil {
				return err
			}
			i = end
		}
	}
	return nil
}

func (gp *guardParser) block(i, hi int) (int, error) {
	if !gp.isP(i, "{") {
		return 0, fmt.Errorf("expected block, found %q", gp.at(i).s)
	}
	m := gp.matchClose(i, hi)
	if m < 0 {
		return 0, errors.New("unbalanced block")
	}
	if err := gp.stmts(i+1, m); err != nil {
		return 0, err
	}
	return m + 1, nil
}

func (gp *guardParser) tryStmt(i, hi int) (int, error) {
	j, err := gp.block(i+1, hi)
	if err != nil {
		return 0, err
	}
	sawHandler := false
	if gp.isW(j, "catch") {
		sawHandler = true
		j++
		if gp.isP(j, "(") {
			m := gp.matchClose(j, hi)
			if m < 0 {
				return 0, errors.New("unbalanced catch")
			}
			j = m + 1
		}
		if j, err = gp.block(j, hi); err != nil {
			return 0, err
		}
	}
	if gp.isW(j, "finally") {
		sawHandler = true
		if j, err = gp.block(j+1, hi); err != nil {
			return 0, err
		}
	}
	if !sawHandler {
		return 0, errors.New("try without catch or finally")
	}
	return j, nil
}

func (gp *guardParser) stmt(i, end int) error {
	switch {
	case gp.isW(i, "import") && !gp.isP(i+1, "("):
		return gp.importStmt(i, end)
	case gp.isW(i, "var"), gp.isW(i, "let"), gp.isW(i, "const"):
		return gp.decl(i+1, end)
	}
	return gp.decl(i, end)
}

func (gp *guardParser) moduleNode(j int) (*Node, string, error) {
	t := gp.at(j)
	switch {
	case t.kind == tStr:
		return &Node{Kind: String, Name: t.v, Text: canon(t.v)}, "", nil
	case t.kind == tIdent && IsMetavar(t.s):
		return &Node{Kind: Metavar, Name: t.s, Text: t.s}, t.s, nil
	}
	return nil, "", fmt.Errorf("expected module, found %q", t.s)
}

type importLocal struct{ local, imported string }

func (gp *guardParser) importStmt(i, end int) error { //nolint:gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	j := i + 1
	var locals []importLocal
	if t := gp.at(j); t.kind == tStr {
		mod, mv, err := gp.moduleNode(j)
		if err != nil {
			return err
		}
		if j+1 != end {
			return errors.New("trailing tokens after import")
		}
		gp.g.Bindings = append(gp.g.Bindings, Binding{Source: mod, ModuleVar: mv})
		return nil
	}
	if t := gp.at(j); t.kind == tIdent && t.s != "from" {
		locals = append(locals, importLocal{t.s, ""})
		j++
		if gp.isP(j, ",") {
			j++
		}
	} else if gp.isP(j, "*") {
		if !gp.isW(j+1, "as") || gp.at(j+2).kind != tIdent {
			return errors.New("malformed namespace import")
		}
		locals = append(locals, importLocal{gp.at(j + 2).s, ""})
		j += 3
	}
	if gp.isP(j, "{") {
		m := gp.matchClose(j, end)
		if m < 0 {
			return errors.New("unbalanced import list")
		}
		for k := j + 1; k < m; {
			t := gp.at(k)
			switch {
			case t.kind == tPunct && (t.s == "," || t.s == tokEllipsis):
				k++
			case t.kind == tIdent && gp.isW(k+1, "as") && gp.at(k+2).kind == tIdent:
				locals = append(locals, importLocal{gp.at(k + 2).s, t.s})
				k += 3
			case t.kind == tIdent:
				locals = append(locals, importLocal{t.s, "$"})
				k++
			default:
				return fmt.Errorf("unexpected %q in import list", t.s)
			}
		}
		j = m + 1
	}
	if !gp.isW(j, "from") {
		return errors.New("import without from")
	}
	mod, mv, err := gp.moduleNode(j + 1)
	if err != nil {
		return err
	}
	if j+2 != end {
		return errors.New("trailing tokens after import")
	}
	if len(locals) == 0 {
		gp.g.Bindings = append(gp.g.Bindings, Binding{Source: mod, ModuleVar: mv})
		return nil
	}
	for _, l := range locals {
		b := sourceBinding(l.local, l.imported, mod)
		b.ModuleVar = mv
		gp.g.Bindings = append(gp.g.Bindings, b)
	}
	return nil
}

func (gp *guardParser) decl(i, end int) error { //nolint:gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	p := &parser{toks: gp.toks, end: end, pattern: true}
	var target *Node
	var local token
	var pos int
	switch t := gp.at(i); {
	case i >= end:
		return errors.New("empty statement")
	case t.kind == tPunct && t.s == "{":
		m := gp.matchClose(i, end)
		if m < 0 {
			return errors.New("unbalanced destructuring")
		}
		p.i, p.end = i, m+1
		n, err := p.try(p.object)
		if err != nil {
			return err
		}
		target, pos = n, m+1
	case t.kind == tIdent:
		local, pos = t, i+1
	default:
		return fmt.Errorf("unsupported statement starting with %q", t.s)
	}
	if !gp.isP(pos, "=") {
		return fmt.Errorf("unsupported statement starting with %q", gp.at(i).s)
	}
	p.i, p.end = pos+1, end
	rhs, err := p.try(func() *Node {
		n := p.expr()
		if p.i != p.end {
			p.fail("unexpected %q", p.peek().s)
		}
		return n
	})
	if err != nil {
		return err
	}
	src := unwrapSource(rhs)
	if target == nil {
		gp.g.Bindings = append(gp.g.Bindings, sourceBinding(local.s, "", src))
		return nil
	}
	named := false
	for _, pr := range target.Props {
		if !pr.Ellipsis {
			named = true
		}
		switch {
		case pr.Ellipsis:
		case pr.Spread || pr.Computed || pr.Value == nil:
			return errors.New("unsupported destructuring entry")
		default:
			imported := pr.Key
			if pr.KeyVar != "" {
				imported = pr.KeyVar
			}
			if pr.Shorthand {
				imported = "$"
			}
			if pr.Value.Kind != Metavar && pr.Value.Kind != Ident {
				return errors.New("nested destructuring")
			}
			gp.g.Bindings = append(gp.g.Bindings, sourceBinding(pr.Value.Name, imported, src))
		}
	}
	if !named {
		b := sourceBinding("", "", src)
		gp.g.Bindings = append(gp.g.Bindings, Binding{Source: src, ModuleVar: b.ModuleVar})
	}
	return nil
}
