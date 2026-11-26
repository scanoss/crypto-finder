package jspat

import (
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
)

// Value is what a metavariable bound: the matched node, and for a top-level call argument the
// value reach resolved for it ("" when none).
type Value struct {
	Node     *Node
	Resolved string
}

// Env is metavariable -> value. Unify never mutates its input.
type Env map[string]Value

// Concrete is one argument of a call site: its text parsed, and reach's resolved value.
type Concrete struct {
	Node     *Node
	Resolved string
}

// Verdict of a unification. Unknown is neither a match nor a mismatch: the concrete side has
// a spread, a computed key or an expression the text cannot settle. The matcher treats
// Unknown as no match for a positive pattern and as no hit for a negative one.
type Verdict uint8

// The verdicts.
const (
	No Verdict = iota
	Yes
	Unknown
)

func (v Verdict) String() string {
	switch v { //nolint:exhaustive // the remaining kinds share the default behavior
	case Yes:
		return "yes"
	case Unknown:
		return "unknown"
	}
	return "no"
}

func (e Env) with(name string, v Value) Env {
	out := make(Env, len(e)+1)
	for k, x := range e {
		out[k] = x
	}
	out[name] = v
	return out
}

func valueString(v Value) string {
	if v.Node != nil && v.Node.Kind == String {
		return v.Node.Name
	}
	return v.Resolved
}

func equalValues(a, b Value) bool {
	if a.Node != nil && b.Node != nil && a.Node.Text == b.Node.Text {
		return true
	}
	s := valueString(a)
	return s != "" && s == valueString(b)
}

func bind(env Env, name string, v Value) (Env, bool) {
	if name == "$_" {
		return env, true
	}
	if prev, ok := env[name]; ok {
		return env, equalValues(prev, v)
	}
	return env.with(name, v), true
}

func isSpread(n *Node) bool { return n.Kind == Opaque && strings.HasPrefix(n.Text, tokEllipsis) }

// UnifyArgs matches an argument-list pattern against a call's arguments, OpenGrep's way: an
// ellipsis takes any run of arguments, a repeated metavariable must bind equal text, and a
// string-literal pattern also matches an identifier whose Resolved is that literal (top level
// only: reach resolves nothing below it). It returns the first environment that unifies.
func UnifyArgs(pattern []*Node, args []Concrete, env Env) (Env, Verdict) {
	return unifyList(pattern, args, env, true)
}

// Unify matches one pattern node against one concrete node.
func Unify(pattern, concrete *Node, env Env) (Env, Verdict) {
	return uni(pattern, Concrete{Node: concrete}, env, false)
}

func unifyList(ps []*Node, cs []Concrete, env Env, top bool) (Env, Verdict) {
	e, v := listRec(ps, cs, 0, 0, env, top)
	if v == No {
		for _, c := range cs {
			if isSpread(c.Node) {
				return nil, Unknown
			}
		}
	}
	return e, v
}

func listRec(ps []*Node, cs []Concrete, pi, ci int, env Env, top bool) (Env, Verdict) {
	if pi == len(ps) {
		if ci == len(cs) {
			return env, Yes
		}
		return nil, No
	}
	p := ps[pi]
	if p.Kind == Ellipsis {
		best := No
		for k := ci; k <= len(cs); k++ {
			e, v := listRec(ps, cs, pi+1, k, env, top)
			if v == Yes {
				return e, Yes
			}
			if v == Unknown {
				best = Unknown
			}
		}
		return nil, best
	}
	if ci >= len(cs) {
		return nil, No
	}
	e, v := uni(p, cs[ci], env, top)
	switch v { //nolint:exhaustive // the remaining kinds share the default behavior
	case Yes:
		return listRec(ps, cs, pi+1, ci+1, e, top)
	case Unknown:
		if _, v2 := listRec(ps, cs, pi+1, ci+1, env, top); v2 != No {
			return nil, Unknown
		}
	}
	return nil, No
}

func uni(p *Node, c Concrete, env Env, top bool) (Env, Verdict) { //nolint:gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	cn := c.Node
	switch p.Kind { //nolint:exhaustive // the remaining kinds share the default behavior
	case Ellipsis:
		return env, Yes
	case Metavar:
		if isSpread(cn) {
			return nil, Unknown
		}
		e, ok := bind(env, p.Name, Value{Node: cn, Resolved: c.Resolved})
		if !ok {
			return nil, No
		}
		return e, Yes
	case Deep:
		return deep(p.Kids[0], cn, env)
	}
	if top && p.Kind == String && cn.Kind != String && c.Resolved != "" {
		return yesIf(stringMatches(p, c.Resolved), env)
	}
	if cn.Kind == Opaque {
		switch {
		case p.Kind == Opaque && p.Text == cn.Text:
			return env, Yes
		case cn.Name == reasonExpr && p.Kind != Opaque:
			return nil, Unknown
		}
		return nil, No
	}
	if p.Kind != cn.Kind {
		return nil, No
	}
	switch p.Kind { //nolint:exhaustive // the remaining kinds share the default behavior
	case Ident:
		return yesIf(p.Name == cn.Name, env)
	case String:
		return yesIf(stringMatches(p, cn.Name), env)
	case Number:
		return yesIf(p.Name == cn.Name, env)
	case Member:
		e := env
		if p.Meta {
			var ok bool
			e, ok = bind(env, p.Name, Value{Node: &Node{Kind: Ident, Name: cn.Name, Text: cn.Name}})
			if !ok {
				return nil, No
			}
		} else if p.Name != cn.Name {
			return nil, No
		}
		return uni(p.Kids[0], Concrete{Node: cn.Kids[0]}, e, false)
	case Binary, Unary:
		if p.Op != cn.Op {
			return nil, No
		}
		return unifyList(p.Kids, wrap(cn.Kids), env, false)
	case Call, New, Sequence, Array, Index:
		return unifyList(p.Kids, wrap(cn.Kids), env, false)
	case Object:
		return object(p, cn, env)
	}
	return nil, No
}

// stringMatches: a string pattern matches the string value v. A pattern
// written `"..."` is any string; one written `"=~/re/"` is OpenGrep's regex
// string: re (Python syntax) is searched in v.
func stringMatches(p *Node, v string) bool {
	if p.Name == tokEllipsis {
		return true
	}
	rx, ok := stringRegex(p.Name)
	if !ok {
		return p.Name == v
	}
	re, err := compiledRegex(rx)
	if err != nil {
		return false
	}
	m, err := re.MatchString(v)
	return err == nil && m
}

// regexes memoises compiled regex strings: text -> *compiled.
var regexes sync.Map

type compiled struct {
	re  *regexp2.Regexp
	err error
}

func compiledRegex(rx string) (*regexp2.Regexp, error) {
	if v, ok := regexes.Load(rx); ok {
		if c, ok := v.(*compiled); ok {
			return c.re, c.err
		}
	}
	re, err := regexp2.Compile(rx, regexp2.None)
	regexes.Store(rx, &compiled{re: re, err: err})
	return re, err
}

// stringRegex is the regex of a `=~/re/` string pattern.
func stringRegex(s string) (string, bool) {
	body, ok := strings.CutPrefix(s, "=~/")
	if !ok || !strings.HasSuffix(body, "/") || len(body) < 1 {
		return "", false
	}
	return strings.ReplaceAll(body[:len(body)-1], "(?P<", "(?<"), true
}

func yesIf(ok bool, env Env) (Env, Verdict) {
	if ok {
		return env, Yes
	}
	return nil, No
}

func wrap(ns []*Node) []Concrete {
	out := make([]Concrete, len(ns))
	for i, n := range ns {
		out[i] = Concrete{Node: n}
	}
	return out
}

// deep matches inner against n or any of its descendants. A concrete subtree the parser did
// not open (an Opaque node) may hide a match, so it makes the answer Unknown.
func deep(inner, n *Node, env Env) (Env, Verdict) {
	best := No
	var walk func(n *Node) (Env, bool)
	walk = func(n *Node) (Env, bool) {
		e, v := uni(inner, Concrete{Node: n}, env, false)
		switch v { //nolint:exhaustive // the remaining kinds share the default behavior
		case Yes:
			return e, true
		case Unknown:
			best = Unknown
		}
		if n.Kind == Opaque {
			best = Unknown
		}
		for _, k := range n.Kids {
			if e, ok := walk(k); ok {
				return e, true
			}
		}
		for _, pr := range n.Props {
			if pr.Value == nil {
				continue
			}
			if e, ok := walk(pr.Value); ok {
				return e, true
			}
		}
		return nil, false
	}
	if e, ok := walk(n); ok {
		return e, Yes
	}
	return nil, best
}

func object(p, c *Node, env Env) (Env, Verdict) { //nolint:funlen,gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	open := false
	for _, cp := range c.Props {
		if cp.Spread || cp.Computed {
			open = true
		}
	}
	hasEllipsis := false
	var pps []Prop
	for _, pp := range p.Props {
		if pp.Ellipsis {
			hasEllipsis = true
			continue
		}
		pps = append(pps, pp)
	}
	keyed := func(cp Prop) bool { return !cp.Spread && !cp.Computed && !cp.Ellipsis }
	// A pattern spread (`...$X`) takes a spread of the object; a key takes a
	// keyed property.
	takes := func(pp, cp Prop) bool {
		if pp.Spread {
			return cp.Spread
		}
		return keyed(cp)
	}
	used := make([]bool, len(c.Props))

	var rec func(i int, env Env) (Env, Verdict)
	rec = func(i int, env Env) (Env, Verdict) {
		if i == len(pps) {
			if hasEllipsis {
				return env, Yes
			}
			rest := Yes
			for j, cp := range c.Props {
				switch {
				case used[j]:
				case keyed(cp):
					return nil, No
				case cp.Spread || cp.Computed:
					rest = Unknown // a spread no pattern spread took may hold more keys
				}
			}
			if rest == Unknown {
				return nil, Unknown
			}
			return env, Yes
		}
		pp := pps[i]
		best := No
		seen := false
		for j, cp := range c.Props {
			if used[j] || !takes(pp, cp) {
				continue
			}
			e := env
			switch {
			case pp.Spread: // no key to compare
			case pp.KeyVar != "":
				var ok bool
				e, ok = bind(env, pp.KeyVar, Value{Node: &Node{Kind: Ident, Name: cp.Key, Text: cp.Key}})
				if !ok {
					continue
				}
			case pp.Key != cp.Key:
				continue
			}
			seen = true
			e2, v := uni(pp.Value, Concrete{Node: cp.Value}, e, false)
			if v == No {
				continue
			}
			used[j] = true
			e3, v2 := rec(i+1, e2)
			used[j] = false
			if v == Yes && v2 == Yes {
				return e3, Yes
			}
			if v2 != No {
				best = Unknown
			}
		}
		if !seen && open {
			if _, v := rec(i+1, env); v != No {
				best = Unknown
			}
		}
		return nil, best
	}
	return rec(0, env)
}
