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

// The JavaScript/TypeScript rule compiler. A node rule is mostly import
// plumbing: an import guard (pattern-either of pattern-inside: require,
// import default / star / named, dynamic import, interop wrappers) and the
// terminal call in several spellings. reach resolves every source spelling of
// an imported call to one callee key (`<module>.<member path>`), so the
// compiler resolves every rule spelling to that same key: the guards to a
// scope (resolveGuards), the terminal's callee through the scope (ref,
// callees), its argument list kept as a jspat pattern (lowerBranch), and
// equal sinks merged (mergeJSSinks). An alternative the compiler cannot read
// is dropped and recorded as a lossy clause; a rule is skipped only when no
// alternative compiles.

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/scanoss/crypto-finder/internal/cardmatch/internal/jspat"
)

const (
	jsBranchMax  = 4096 // most conjunctions a rule's formula may expand to
	jsPathAltMax = 64   // most fixed paths enumerated metavariables may give one callee
	jsDefault    = "default"
	jsInit       = "<init>"
	jsCrypto     = "crypto"
	jsEllipsis   = "..."
)

// jsGlobalHeads are the names a WebCrypto spelling starts with when no import
// binds them.
var jsGlobalHeads = map[string]bool{jsCrypto: true, "globalThis": true, "window": true, "self": true, "webcrypto": true}

// nodeRule: the rule's languages name javascript or typescript.
func nodeRule(r *OMap) bool {
	for _, l := range listOf(r.GetOr("languages")) {
		if s, ok := l.(string); ok && (s == "javascript" || s == "typescript") {
			return true
		}
	}
	return false
}

// ---------- formula -> branches ----------

// jsClause is one leaf clause of a rule's formula.
type jsClause struct {
	op   string // jsLeaf, jsInside, ...
	text string // the pattern text; for jsFail and jsDrop, the reason
	mv   string // metavariable-regex, metavariable-pattern, focus-metavariable
	// except: of a pattern-not written as a nested formula (`patterns:` of a
	// pattern and pattern-nots), the pattern-nots: the negation holds only
	// where none of them matches.
	except []string
	// regexes: of such a pattern-not, its metavariable-regex clauses: the
	// negation holds only where they hold.
	regexes []jsConstraint
	// exceptRules: of such a pattern-not, its pattern-nots written as nested
	// formulas themselves, read the same way (exceptions with exceptions).
	exceptRules []jsClause
	// formula: of a jsNotRule, the negated formula, compiled as a rule of
	// its own (not_entries).
	formula any
}

const (
	jsLeaf         = "pattern"
	jsPatterns     = "patterns"
	jsEither       = "pattern-either"
	jsInside       = "pattern-inside"
	jsNotInside    = "pattern-not-inside"
	jsNotRegex     = "pattern-not-regex"
	jsNot          = "pattern-not"
	jsRegex        = "metavariable-regex"
	jsPatternRegex = "pattern-regex"
	jsGeneric      = "metavariable-pattern"
	jsFocus        = "focus-metavariable"
	jsMVPattern    = "metavariable-pattern (formula)"
	jsFail         = "fail" // the branch cannot be compiled
	jsDrop         = "drop" // a clause left out: the branch matches more
	jsNotRule      = "pattern-not (rule)"
)

// jsDNF expands a formula into its conjunctions (disjunctive normal form).
func jsDNF(v any) ([][]jsClause, error) {
	m, ok := v.(*OMap)
	if !ok || m.Len() != 1 {
		return nil, skip("formula item is not a one-key mapping")
	}
	k, val := pyStr(m.Keys[0]), m.Vals[0]
	switch k {
	case jsPatterns:
		items, err := asSeq(val, k)
		if err != nil {
			return nil, err
		}
		return jsConj(items)
	case jsEither:
		items, err := asSeq(val, k)
		if err != nil {
			return nil, err
		}
		return jsEitherOf(items)
	}
	clauses, err := jsLeafClauses(k, val)
	if err != nil {
		return nil, err
	}
	return [][]jsClause{clauses}, nil
}

// jsConj is the product of a conjunction's items' alternatives.
func jsConj(items []any) ([][]jsClause, error) {
	out := [][]jsClause{{}}
	for _, it := range items {
		alts, err := jsDNF(it)
		if err != nil {
			return nil, err
		}
		if len(out)*len(alts) > jsBranchMax {
			return nil, skip("branch explosion")
		}
		next := make([][]jsClause, 0, len(out)*len(alts))
		for _, a := range out {
			for _, b := range alts {
				next = append(next, append(append([]jsClause{}, a...), b...))
			}
		}
		out = next
	}
	return out, nil
}

// jsEitherOf is the union of a pattern-either's alternatives.
func jsEitherOf(items []any) ([][]jsClause, error) {
	var out [][]jsClause
	for _, it := range items {
		alts, err := jsDNF(it)
		if err != nil {
			return nil, err
		}
		out = append(out, alts...)
		if len(out) > jsBranchMax {
			return nil, skip("branch explosion")
		}
	}
	return out, nil
}

// jsLeafClauses reads one operator that is not a conjunction or a
// disjunction.
func jsLeafClauses(k string, val any) ([]jsClause, error) { //nolint:gocyclo // one case per operator
	text, isText := val.(string)
	switch k {
	case jsLeaf, jsInside, jsNotInside, jsNot:
		switch {
		case isText:
			return []jsClause{{op: k, text: text}}, nil
		case k == jsNot:
			if nots, ok := jsNestedNot(val); ok {
				return nots, nil
			}
			return []jsClause{{op: jsNotRule, formula: val}}, nil
		case k == jsNotInside:
			return []jsClause{{op: jsDrop, text: k + ": nested formula"}}, nil
		}
		return []jsClause{{op: jsFail, text: k + ": nested formula"}}, nil
	case jsNotRegex:
		if isText {
			return []jsClause{{op: jsNotRegex, text: text}}, nil
		}
		return []jsClause{{op: jsDrop, text: k}}, nil
	case jsPatternRegex, "metavariable-comparison":
		return []jsClause{{op: jsFail, text: k}}, nil
	case jsRegex, jsGeneric:
		mm, ok := val.(*OMap)
		if !ok {
			return nil, skip(k + " is not a mapping")
		}
		mv := pyStr(mm.GetOr("metavariable"))
		if k == jsRegex {
			return []jsClause{{op: jsRegex, mv: mv, text: pyStr(mm.GetOr("regex"))}}, nil
		}
		p, isStr := mm.GetOr("pattern").(string)
		if mm.GetOr("language") != any("generic") || !isStr {
			return []jsClause{{op: jsMVPattern, mv: mv}}, nil
		}
		return []jsClause{{op: jsGeneric, mv: mv, text: strings.TrimSpace(p)}}, nil
	case jsFocus:
		if isText {
			return []jsClause{{op: jsFocus, mv: text}}, nil
		}
		var out []jsClause
		for _, f := range listOf(val) {
			out = append(out, jsClause{op: jsFocus, mv: pyStr(f)})
		}
		return out, nil
	}
	return []jsClause{{op: jsFail, text: "unsupported operator " + k}}, nil
}

// jsNestedNot reads a pattern-not written as a formula, in the shapes that
// stay a set of calls less a set of calls:
//
//	pattern: P                                 -> not P
//	pattern-either: [pattern: A, pattern: B]   -> not A, not B
//	patterns: [pattern: P, pattern-not: Q, ..] -> not P, except where a Q matches
//
// The `patterns:` form may also hold metavariable-regex clauses on P's
// metavariables, which the negation must satisfy. ok is false for any other
// shape.
func jsNestedNot(val any) ([]jsClause, bool) { //nolint:gocognit,gocyclo // one case per shape
	m, isMap := val.(*OMap)
	if !isMap || len(m.Keys) != 1 {
		return nil, false
	}
	k, v := pyStr(m.Keys[0]), m.Vals[0]
	switch k {
	case jsLeaf:
		text, isText := v.(string)
		return []jsClause{{op: jsNot, text: text}}, isText
	case jsEither:
		var out []jsClause
		for _, it := range listOf(v) {
			alt, ok := jsNestedNot(it)
			if !ok {
				return nil, false
			}
			out = append(out, alt...)
		}
		return out, len(out) > 0
	case jsPatterns:
		var pos *string
		var except []string
		var regexes []jsConstraint
		var exceptRules []jsClause
		for _, it := range listOf(v) {
			im, isMap := it.(*OMap)
			if !isMap || len(im.Keys) != 1 {
				return nil, false
			}
			if pyStr(im.Keys[0]) == jsRegex {
				rm, isMap := im.Vals[0].(*OMap)
				if !isMap {
					return nil, false
				}
				regexes = append(regexes, jsConstraint{metavar: pyStr(rm.GetOr("metavariable")), regex: pcreToPyText(pyStr(rm.GetOr("regex")))})
				continue
			}
			text, isText := im.Vals[0].(string)
			if !isText {
				if pyStr(im.Keys[0]) != jsNot {
					return nil, false
				}
				nested, ok := jsNestedNot(im.Vals[0])
				if !ok {
					return nil, false
				}
				exceptRules = append(exceptRules, nested...)
				continue
			}
			switch pyStr(im.Keys[0]) {
			case jsLeaf:
				if pos != nil {
					return nil, false
				}
				pos = &text
			case jsNot:
				except = append(except, text)
			default:
				return nil, false
			}
		}
		if pos == nil {
			return nil, false
		}
		return []jsClause{{op: jsNot, text: *pos, except: except, regexes: regexes, exceptRules: exceptRules}}, true
	}
	return nil, false
}

// ---------- references: what a name stands for after the guards ----------

type jsRefKind uint8

const (
	refModule jsRefKind = iota // a member path under one of several modules (empty: the module itself)
	refFree                    // a name no import binds: a global, or a written spelling
	refObject                  // the value a call produced
)

// jsSeg is one member segment: a fixed name or a metavariable. class marks a
// constructed class, written `(Name)` in a callee key.
type jsSeg struct {
	name, mv string
	class    bool
}

func (s jsSeg) text() string {
	if s.class {
		return "(" + s.name + ")"
	}
	return s.name
}

type jsRef struct {
	kind       jsRefKind
	modules    []string
	segs       []jsSeg
	localRegex string
	// localFirst: bound by a destructuring binder with a metavariable name
	// (`{..., $NS, ...} = require(m)`): a call through it is written with
	// that local name.
	localFirst bool
	from       []*jsSink // refObject: the producers
	via        string    // refObject: viaVar or viaChain
	ctorArgs   bool      // an instance whose constructor arguments the rule constrains
	// namespace: the head is a binding of the module itself (`import * as
	// $NS`, `$NS = require(m)`, a default import): a call of its member is
	// written as a member access (`$NS.f()`), never a bare name.
	namespace bool
	// wrapped: the value an interop wrapper `$W($NS)` returns for a bound
	// module: a variable other than the module's own binding holds it.
	wrapped bool
	// inline: the module is required where it is used (`require("m").f()`),
	// not through a binding.
	inline bool
	// readSrc: a guard assigned the name a read of a module member (`$O =
	// $NS.defaults.encryption`): as an argument it is that read's value.
	readSrc *jspat.Node
}

func (r *jsRef) extend(s jsSeg) *jsRef {
	out := *r
	out.segs = append(append([]jsSeg{}, r.segs...), s)
	return &out
}

// jsUnbound is an unbound metavariable: a guard reading it waits for the
// guard that binds it.
type jsUnbound struct{ mv string }

func (e *jsUnbound) Error() string { return "unbound metavariable " + e.mv }

// ---------- sinks ----------

type jsConstraint struct{ metavar, regex string }

// jsCallee is a resolved callee: NodeCallee before emission.
type jsCallee struct {
	bind        NodeBind
	modules     []string
	path        string
	pathRegex   string
	isNew       bool
	localRegex  string
	method      string // "" when the last segment is a metavariable
	from        []*jsSink
	via         []string
	constraints []jsConstraint // regexes of metavariables the path regex binds
	lossy       []string
	written     string // a global callee the rule writes with no import, as written
	localFirst  bool
	props       string // object callee: the property chain before the method
	member      bool   // written as a member access of a namespace binding
	wrapped     bool   // called through a variable an interop wrapper set
	inline      bool   // written on the require/import call itself
	assigned    bool   // a literal assigned to a variable (`$O = {...}`)
}

// jsSink is one entry before emission.
type jsSink struct {
	callee       jsCallee
	args         *string
	minArity     int
	maxArity     *int
	constraints  []jsConstraint
	notCalls     []*jsSink    // argument patterns, each with its own exceptions in notCalls
	notEntries   []*jsSink    // pattern-nots written as sub-rules
	notEnclosed  []string     // pattern-not-insides placing the match (not_enclosed)
	within       []*jsSink    // a literal's context calls (within)
	read         bool         // a property read (read)
	notProducers []jsProducer // pattern-not-insides `$V = <expr>; ...` on an argument metavariable
	consumers    []jsConsumer
	producers    []jsProducer
	notRegexes   []string
	notImports   []string
	focus        string
	dropped      []string
	bound        map[string]bool // the metavariables args binds
}

// jsProducer is an argument metavariable bound to a call's result by a
// context (NodeProducer).
type jsProducer struct {
	use, via string
	from     []*jsSink
}

func (p jsProducer) omap(modules bool) *OMap {
	from := make([]any, len(p.from))
	for i, f := range p.from {
		from[i] = f.fromEntry(modules)
	}
	return omap("use", p.use, "via", p.via, "from", from)
}

// ---------- branch lowering ----------

// jsCache memoises the parses of one rule: its alternatives repeat the same
// texts many times.
type jsCache struct {
	guards map[string]jsGuardParse
	exprs  map[string]jsExprParse
}

type jsGuardParse struct {
	g   *jspat.Guard
	err error
}

type jsExprParse struct {
	n   *jspat.Node
	err error
}

func (c *jsCache) guard(text string) (*jspat.Guard, error) {
	if p, ok := c.guards[text]; ok {
		return p.g, p.err
	}
	g, err := jspat.ParseGuard(text)
	c.guards[text] = jsGuardParse{g, err}
	return g, err
}

func (c *jsCache) expr(text string) (*jspat.Node, error) {
	if p, ok := c.exprs[text]; ok {
		return p.n, p.err
	}
	n, err := jspat.ParseExpr(text, true)
	c.exprs[text] = jsExprParse{n, err}
	return n, err
}

// jsBranch is one conjunction being lowered.
type jsBranch struct {
	cache   *jsCache
	regexes map[string][]string // metavariable -> metavariable-regex regexes
	generic map[string]string   // metavariable -> literal of a generic metavariable-pattern
	scope   map[string]*jsRef
	dropped []string
	// lenient: an unbound metavariable reads as a free name (`$C.webcrypto`)
	// instead of waiting for a guard that binds it.
	lenient bool
	// assignedLiteral: the terminal object literal is written as an
	// assignment's value (`$O = {...}`).
	assignedLiteral bool
}

// lowerBranch turns one conjunction into sinks.
func lowerBranch(clauses []jsClause, cache *jsCache) ([]*jsSink, error) { //nolint:gocognit,gocyclo,funlen // the clause kinds of one conjunction, in order: guards, terminal, negations
	b := &jsBranch{cache: cache, regexes: map[string][]string{}, generic: map[string]string{}, scope: map[string]*jsRef{}}
	var insides, leaves, notInsides []string
	var nots []jsClause
	var focus, mvPatterns, notRegexes []string
	var notRules []any
	for _, c := range clauses {
		switch c.op {
		case jsFail:
			return nil, skip(c.text)
		case jsDrop:
			b.drop(c.text)
		case jsRegex:
			b.regexes[c.mv] = append(b.regexes[c.mv], c.text)
		case jsGeneric:
			b.generic[c.mv] = c.text
		case jsFocus:
			focus = append(focus, c.mv)
		case jsMVPattern:
			mvPatterns = append(mvPatterns, c.mv)
		case jsInside:
			insides = append(insides, c.text)
		case jsLeaf:
			leaves = append(leaves, c.text)
		case jsNot:
			nots = append(nots, c)
		case jsNotInside:
			notInsides = append(notInsides, c.text)
		case jsNotRegex:
			notRegexes = append(notRegexes, pcreToPyText(c.text))
		case jsNotRule:
			notRules = append(notRules, c.formula)
		}
	}
	notEntries := b.notRules(notRules)
	var consumers []jsConsumer
	if !b.objectTerminal(leaves) {
		// Around an object literal a context call encloses it (fuse).
		insides, consumers, focus = b.consumerContexts(insides, focus, leaves)
	}
	contexts, err := b.resolveGuards(insides)
	if err != nil {
		return nil, err
	}
	for i := range consumers {
		if consumers[i].producers, err = b.producers(consumers[i].bound); err != nil {
			return nil, err
		}
	}
	b.lenient = true
	term, args, err := b.terminals(leaves)
	if err != nil {
		return nil, err
	}
	var sinks []*jsSink
	switch term.Kind { //nolint:exhaustive // the remaining kinds are not terminals
	case jspat.Call, jspat.New:
		if sinks, err = b.callSinks(term.Kids[0], args, term.Kind == jspat.New); err != nil {
			return nil, err
		}
		if len(contexts) > 0 {
			b.drop("pattern-inside: enclosing call")
		}
	case jspat.Object, jspat.Array:
		if len(contexts) == 0 && term.Kind == jspat.Object {
			if sinks, err = b.literalSinks(term); err != nil {
				return nil, err
			}
			break
		}
		if len(contexts) != 1 {
			return nil, skip("object literal outside a call")
		}
		if sinks, err = b.fuse(contexts[0], term); err != nil {
			return nil, err
		}
		if term.Kind == jspat.Object {
			// OpenGrep reports the object, within the context call.
			if lits, err := b.literalSinks(term); err == nil {
				for _, l := range lits {
					l.within = sinks
				}
				sinks = lits
			}
		}
	case jspat.Member, jspat.Ident, jspat.Index:
		if sinks, err = b.readSinks(term); err != nil {
			return nil, err
		}
	case jspat.Metavar:
		return nil, skip("bare metavariable terminal")
	default:
		return nil, skip("terminal is not a call")
	}
	enclosed, notInsides := b.enclosures(notInsides, term)
	notProds, notInsides := b.notProducers(notInsides)
	notMods := b.notImports(notInsides)
	for _, s := range sinks {
		for _, p := range notProds {
			if s.bound[p.use] {
				s.notProducers = append(s.notProducers, p)
			} else {
				s.dropped = append(s.dropped, jsNotInside)
			}
		}
		s.consumers = consumers
		s.notRegexes = notRegexes
		s.notEntries = notEntries
		s.notEnclosed = enclosed
		b.lowerNots(s, nots)
		s.notImports = filterNotImports(notMods, s.callee.modules)
		bound := s.bound
		for _, mv := range mvPatterns {
			// On an argument it only narrows what the argument is: left out.
			// Anywhere else (a receiver) it decides what the call is.
			if !bound[mv] {
				return nil, skip("metavariable-pattern")
			}
			s.dropped = append(s.dropped, "metavariable-pattern "+mv)
		}
		for _, f := range focus {
			if s.focus == "" && bound[f] {
				s.focus = f
			} else {
				s.dropped = append(s.dropped, "focus-metavariable "+f)
			}
		}
		s.dropped = uniqueSorted(append(append(append([]string{}, b.dropped...), s.callee.lossy...), s.dropped...))
	}
	return sinks, nil
}

func (b *jsBranch) drop(clause string) { b.dropped = append(b.dropped, clause) }

// objectTerminal: a pattern of the branch is an object literal.
func (b *jsBranch) objectTerminal(leaves []string) bool {
	for _, l := range leaves {
		if n, err := b.cache.expr(strings.TrimSpace(l)); err == nil && jsUnwrapTerm(n).Kind == jspat.Object {
			return true
		}
	}
	return false
}

// notRules compiles each pattern-not written as a sub-rule into the entries
// that negate a call where one of them matches it. A sub-rule that does not
// compile exactly (a skipped alternative, a dropped clause) is left out, as
// a dropped clause: a negation that matched more would remove findings
// OpenGrep keeps.
func (b *jsBranch) notRules(formulas []any) []*jsSink {
	var out []*jsSink
	for _, f := range formulas {
		subs, ok := b.notRule(f)
		if !ok {
			b.drop(jsNot + ": nested formula")
			continue
		}
		out = append(out, subs...)
	}
	return out
}

func (b *jsBranch) notRule(formula any) ([]*jsSink, bool) {
	branches, err := jsDNF(formula)
	if err != nil || len(branches) > jsBranchMax {
		return nil, false
	}
	var out []*jsSink
	for _, br := range branches {
		subs, err := lowerBranch(br, b.cache)
		if err != nil {
			return nil, false
		}
		for _, s := range subs {
			if len(s.dropped) > 0 {
				return nil, false
			}
		}
		out = append(out, subs...)
	}
	return mergeJSSinks(out), len(out) > 0
}

// jsNamesMetavar: one of texts names the metavariable mv.
func jsNamesMetavar(texts []string, mv string) bool {
	rx := regexp.MustCompile(regexp.QuoteMeta(mv) + `\b`)
	for _, t := range texts {
		if rx.MatchString(t) {
			return true
		}
	}
	return false
}

// jsConsumer is a NodeConsumer before emission.
type jsConsumer struct {
	via, calleeRegex, methodRegex, use string
	args                               *string
	constraints                        []jsConstraint
	bound                              map[string]bool // the metavariables args binds
	producers                          []jsProducer
}

func (c jsConsumer) omap() *OMap {
	m := omap("via", c.via)
	if c.calleeRegex != "" {
		m.Set("callee_regex", c.calleeRegex)
	}
	if c.methodRegex != "" {
		m.Set("method_regex", c.methodRegex)
	}
	if c.args != nil {
		m.Set("arg_pattern", *c.args)
	}
	if c.use != "" {
		m.Set("use", c.use)
	}
	if len(c.constraints) > 0 {
		m.Set("constraints", jsConstraints(c.constraints))
	}
	if len(c.producers) > 0 {
		ps := make([]any, len(c.producers))
		for i, p := range c.producers {
			ps[i] = p.omap(true)
		}
		m.Set("producers", ps)
	}
	return m
}

var rxJSAssignTo = regexp.MustCompile(`^(\$[A-Z_][A-Z0-9_]*)\s*=\s*(.+?);?$`)

// consumerContexts takes out of insides the contexts that pass the matched
// call on to another call, and reads them as consumers (NodeConsumer):
//
//	$SINK(.., $DRAW, ..)                    focus $DRAW -> inline
//	$MAT = $DRAW ... $S.$M({.., iv: $MAT})  focus $DRAW -> var
//	$OBJ = <call> ... $OBJ.sign(..)                     -> receiver
//	$CHAIN.sign(..)                                     -> receiver
//
// It returns the other insides and the focus metavariables left to apply.
func (b *jsBranch) consumerContexts(insides, focus, leaves []string) ([]string, []jsConsumer, []string) {
	var rest []string
	var out []jsConsumer
	used := map[string]bool{}
	for i, text := range insides {
		others := append(append(append([]string{}, insides[:i]...), insides[i+1:]...), leaves...)
		c, draw, ok := b.consumer(text, focus, others)
		if !ok {
			rest = append(rest, text)
			continue
		}
		out = append(out, c)
		if draw != "" {
			used[draw] = true
		}
	}
	var left []string
	for _, f := range focus {
		if !used[f] {
			left = append(left, f)
		}
	}
	return rest, out, left
}

// consumer reads one context as a consumer, and the focus metavariable that
// stands for the matched call ("" for a receiver). A receiver metavariable
// that another clause (others) names is a binding, not the matched call.
func (b *jsBranch) consumer(text string, focus, others []string) (jsConsumer, string, bool) {
	assigned, rhs, n, ok := b.consumerShape(text)
	if !ok {
		return jsConsumer{}, "", false
	}
	c, receiver, ok := b.consumerCallee(jsUnwrap(n.Kids[0]))
	if !ok {
		return jsConsumer{}, "", false
	}
	args, _, _, bound, err := jsArgPattern(n.Kids[1:])
	if err != nil {
		return jsConsumer{}, "", false
	}
	c.args, c.bound = args, bound
	draw := ""
	c.via, c.use, draw = consumerVia(assigned, rhs, receiver, focus, others, bound)
	if c.via == "" {
		return jsConsumer{}, "", false
	}
	for _, mv := range sortedKeys(bound) {
		if mv == c.use {
			continue
		}
		for _, rx := range b.regexes[mv] {
			c.constraints = append(c.constraints, jsConstraint{metavar: mv, regex: pcreToPyText(rx)})
		}
	}
	return c, draw, true
}

// consumerVia is how a consumer takes the matched call: through the
// assigned variable, as its receiver (the assigned value, or a link of the
// receiver's chain), or inline as the focused argument; "" for none. use and
// draw name the argument metavariable and the matched call's.
func consumerVia(assigned, rhs, receiver string, focus, others []string, bound map[string]bool) (via, use, draw string) {
	switch {
	case assigned != "" && jspat.IsMetavar(rhs) && inList(rhs, focus) && bound[assigned]:
		return ConsumeVar, assigned, rhs
	case assigned != "" && receiver == assigned && !jspat.IsMetavar(rhs):
		return ConsumeReceiver, "", ""
	case assigned != "":
		return "", "", ""
	}
	for _, f := range focus {
		if bound[f] {
			return ConsumeInline, f, f
		}
	}
	if receiver != "" && !bound[receiver] && !jsNamesMetavar(others, receiver) {
		return ConsumeReceiver, "", ""
	}
	return "", "", ""
}

// consumerShape splits a context into an optional leading assignment
// (`$X = <rhs>` then `...`) and its last statement, a call.
func (b *jsBranch) consumerShape(text string) (assigned, rhs string, call *jspat.Node, ok bool) {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == jsEllipsis {
		lines = lines[:len(lines)-1]
	}
	switch {
	case len(lines) == 1:
	case len(lines) == 3 && lines[1] == jsEllipsis:
		m := rxJSAssignTo.FindStringSubmatch(lines[0])
		if m == nil {
			return "", "", nil, false
		}
		assigned, rhs = m[1], strings.TrimSpace(m[2])
	default:
		return "", "", nil, false
	}
	n, err := b.cache.expr(strings.TrimSuffix(lines[len(lines)-1], ";"))
	if err != nil {
		return "", "", nil, false
	}
	if n = jsUnwrap(n); n.Kind != jspat.Call {
		return "", "", nil, false
	}
	return assigned, rhs, n, true
}

// consumerCallee reads a consumer's callee: a metavariable the rule gives a
// regex, or a method (fixed, or a metavariable with a regex) on a
// metavariable receiver, which it returns.
func (b *jsBranch) consumerCallee(callee *jspat.Node) (jsConsumer, string, bool) {
	switch {
	case callee.Kind == jspat.Metavar:
		if len(b.regexes[callee.Name]) != 1 {
			return jsConsumer{}, "", false
		}
		return jsConsumer{calleeRegex: pcreToPyText(b.regexes[callee.Name][0])}, "", true
	case callee.Kind != jspat.Member || jsUnwrap(callee.Kids[0]).Kind != jspat.Metavar:
		return jsConsumer{}, "", false
	}
	receiver := jsUnwrap(callee.Kids[0]).Name
	switch {
	case !callee.Meta:
		return jsConsumer{methodRegex: "^" + regexp.QuoteMeta(callee.Name) + "$"}, receiver, true
	case len(b.regexes[callee.Name]) == 1:
		return jsConsumer{methodRegex: pcreToPyText(b.regexes[callee.Name][0])}, receiver, true
	}
	return jsConsumer{}, "", false
}

// resolveGuards applies the branch's pattern-inside guards to the scope, in
// order, a guard that reads a metavariable a later guard binds waiting for
// it. A pattern-inside that is a call, not a binding, is a context call.
func (b *jsBranch) resolveGuards(insides []string) ([]*jspat.Node, error) {
	var contexts []*jspat.Node
	pending := insides
	for len(pending) > 0 {
		var wait []string
		var lastErr error
		for _, text := range pending {
			ctx, err := b.applyGuard(text)
			var unbound *jsUnbound
			switch {
			case errors.As(err, &unbound):
				wait = append(wait, text)
				lastErr = err
			case err != nil:
				return nil, err
			case ctx != nil:
				contexts = append(contexts, ctx)
			}
		}
		if len(wait) == len(pending) {
			if b.lenient {
				return nil, skip("guard: " + lastErr.Error())
			}
			b.lenient = true // what no guard binds is a free name
		}
		pending = wait
	}
	return contexts, nil
}

func (b *jsBranch) applyGuard(text string) (*jspat.Node, error) {
	g, err := b.cache.guard(text)
	if err != nil {
		if ctx := b.contextCall(text); ctx != nil {
			return ctx, nil
		}
		return nil, skip("guard: " + jsReason(err))
	}
	scope := make(map[string]*jsRef, len(b.scope)+len(g.Bindings))
	for k, v := range b.scope {
		scope[k] = v
	}
	bound := map[string]bool{}
	for _, bd := range g.Bindings {
		// `$X = a; ... $X = b`: a value replaced later in the context, which
		// no producer says; the alternative is left out, not widened.
		if bd.Metavar != "" && bound[bd.Metavar] {
			return nil, skip("guard: metavariable reassigned")
		}
		bound[bd.Metavar] = bd.Metavar != ""
		if err := b.bind(scope, bd); err != nil {
			return nil, err
		}
	}
	b.scope = scope
	return nil, nil
}

// contextCall reads a pattern-inside that is a call (`$NS.sign(<... $K ...>, ...)`).
func (b *jsBranch) contextCall(text string) *jspat.Node {
	t := strings.TrimSpace(text)
	t = strings.TrimSpace(strings.TrimSuffix(t, jsEllipsis))
	t = strings.TrimSuffix(t, ";")
	n, err := b.cache.expr(t)
	if err != nil {
		return nil
	}
	n = jsUnwrap(n)
	if n.Kind == jspat.Call || n.Kind == jspat.New {
		return n
	}
	return nil
}

// jsReason is a parse error as a short skip reason.
func jsReason(err error) string {
	s := strings.TrimPrefix(err.Error(), jspat.ErrUnsupported.Error()+": ")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// bind adds one guard binding to scope.
func (b *jsBranch) bind(scope map[string]*jsRef, bd jspat.Binding) error {
	local := bd.Metavar
	if local == "" {
		local = bd.Fixed
	}
	if local == "" {
		return nil // `import "m"`, `{...} = require("m")`: binds nothing
	}
	// `$V = {..., name: $ALG, ...}`: the variable holds an assigned object
	// literal of that shape (a producer).
	if src := bd.Source; src != nil && bd.Imported == "" && bd.Metavar != "" && jsUnwrapTerm(src).Kind == jspat.Object {
		return b.bindObjectLiteral(scope, local, src)
	}
	base, err := b.sourceRef(scope, bd)
	if err != nil {
		return err
	}
	ref, err := jsImported(base, bd, local)
	if err != nil {
		return err
	}
	b.markBound(ref, bd)
	scope[local] = ref
	return nil
}

// bindObjectLiteral binds local to the assigned object literal src (a
// producer): `$V = {..., name: $ALG, ...}`.
func (b *jsBranch) bindObjectLiteral(scope map[string]*jsRef, local string, src *jspat.Node) error {
	saved := b.assignedLiteral
	b.assignedLiteral = true
	lits, err := b.literalSinks(jsUnwrapTerm(src))
	b.assignedLiteral = saved
	if err != nil {
		return err
	}
	scope[local] = &jsRef{kind: refObject, from: lits, via: viaVar}
	return nil
}

// markBound sets what a reference carries once it is bound to a local name:
// its read source, local regex or first-local flag, and its variable origin.
func (b *jsBranch) markBound(ref *jsRef, bd jspat.Binding) {
	ref.inline = false // bound to a name now
	markReadSource(ref, bd)
	b.markLocalName(ref, bd)
	if ref.kind == refObject && ref.via != viaDestructure {
		ref.via = viaVar
	}
}

// markReadSource records the member or index read a module reference was
// bound from.
func markReadSource(ref *jsRef, bd jspat.Binding) {
	if src := bd.Source; bd.Imported == "" && bd.Metavar != "" && src != nil && ref.kind == refModule && len(ref.segs) > 0 {
		if k := jsUnwrapTerm(src).Kind; k == jspat.Member || k == jspat.Index {
			ref.readSrc = src
		}
	}
}

// markLocalName records how a module reference's call is written: by the
// metavariable's regex, first-local, or the named binder's local name.
func (b *jsBranch) markLocalName(ref *jsRef, bd jspat.Binding) {
	if rx := b.regexes[bd.Metavar]; bd.Metavar != "" && bd.Imported != "$" && len(rx) > 0 && ref.kind == refModule {
		ref.localRegex = pcreToPyText(rx[0])
	}
	if bd.Imported == "$" && bd.Metavar != "" && ref.kind == refModule {
		ref.localFirst = true
	}
	// A named binder (`{ encrypt }`, `{ a: enc }`): the call is written with
	// its local name; reach keys `ns.encrypt()` the same.
	if bd.Metavar == "" && bd.Fixed != "" && bd.Imported != "" && bd.Imported != jsDefault && ref.kind == refModule && ref.localRegex == "" {
		ref.localRegex = "^" + pyReEscape(bd.Fixed) + "$"
	}
}

// jsImported is the member a binding takes from its source, as a fresh
// reference: the source itself, a named member, or the member a metavariable
// names.
func jsImported(base *jsRef, bd jspat.Binding, local string) (*jsRef, error) {
	switch imp := bd.Imported; {
	case imp == "" || imp == jsDefault:
		cp := *base
		cp.namespace = base.kind == refModule && len(base.segs) == 0
		return &cp, nil
	case base.kind == refObject && imp == "$" && bd.Metavar != "" && len(base.segs) == 0:
		return &jsRef{kind: refObject, from: base.from, via: viaDestructure}, nil
	case base.kind == refObject:
		return nil, skip("guard: destructuring a call result")
	case imp == "$" && bd.Metavar != "":
		return base.member(jsSeg{mv: local}), nil
	case imp == "$":
		return base.member(jsSeg{name: local}), nil
	case jspat.IsMetavar(imp):
		return base.member(jsSeg{mv: imp}), nil
	}
	return base.member(jsSeg{name: bd.Imported}), nil
}

// member is the binding a destructuring takes out of r: its own name, no
// longer reached through a namespace.
func (r *jsRef) member(s jsSeg) *jsRef {
	out := r.extend(s)
	out.namespace = false
	return out
}

func (b *jsBranch) sourceRef(scope map[string]*jsRef, bd jspat.Binding) (*jsRef, error) {
	src := bd.Source
	switch {
	case src == nil:
		return nil, skip("guard: binding without a source")
	case src.Kind == jspat.String:
		return &jsRef{kind: refModule, modules: []string{src.Name}}, nil
	case src.Kind == jspat.Metavar && bd.ModuleVar == src.Name && scope[src.Name] == nil:
		return b.moduleVar(src.Name)
	}
	return b.ref(scope, src)
}

// moduleVar enumerates a module metavariable's regex (quotes stripped).
func (b *jsBranch) moduleVar(mv string) (*jsRef, error) {
	if len(b.regexes[mv]) == 0 {
		return nil, skip("module metavariable without regex")
	}
	vals, ok := b.enumerate(mv)
	if !ok {
		return nil, skip("module regex not finite")
	}
	seen := map[string]bool{}
	var mods []string
	for _, v := range vals {
		v = strings.Trim(v, `"'`)
		if v != "" && !seen[v] {
			seen[v] = true
			mods = append(mods, v)
		}
	}
	if len(mods) == 0 {
		return nil, skip("module regex not finite")
	}
	sort.Strings(mods)
	return &jsRef{kind: refModule, modules: mods}, nil
}

// enumerate lists the values a metavariable's regexes accept, when the first
// finite one is a short list (the others filter it).
func (b *jsBranch) enumerate(mv string) ([]string, bool) {
	rxs := b.regexes[mv]
	for i, rx := range rxs {
		vals, ok := enumRegex(rx, enumMax)
		if !ok {
			continue
		}
		var out []string
		for _, v := range vals {
			keep := true
			for j, other := range rxs {
				if j != i && !jsRegexAccepts(other, v) {
					keep = false
				}
			}
			if keep {
				out = append(out, v)
			}
		}
		return out, len(out) > 0
	}
	return nil, false
}

// jsUnwrap removes what does not change the value of an expression for a
// callee: `<... e ...>`, `await e`, `(0, e)`.
// jsRegexAccepts is re.match(rx, v) for a regex that may not compile (false).
func jsRegexAccepts(rx, v string) bool {
	re, err := regexp2.Compile(`\A(?:`+pyToNet(rx)+`)`, regexp2.None)
	if err != nil {
		return false
	}
	ok, err := re.MatchString(v)
	return err == nil && ok
}

func jsUnwrap(n *jspat.Node) *jspat.Node {
	for {
		switch {
		case n.Kind == jspat.Deep, n.Kind == jspat.Unary && n.Op == "await":
			n = n.Kids[0]
		case n.Kind == jspat.Sequence:
			n = n.Kids[len(n.Kids)-1]
		default:
			return n
		}
	}
}

// ref is what an expression denotes in the scope, read the way reach reads a
// call site's callee.
func (b *jsBranch) ref(scope map[string]*jsRef, n *jspat.Node) (*jsRef, error) { //nolint:gocognit,gocyclo // one case per expression kind
	n = jsUnwrap(n)
	switch n.Kind { //nolint:exhaustive // the remaining kinds denote nothing a callee can be
	case jspat.Ident:
		if r := scope[n.Name]; r != nil {
			return r, nil
		}
		return &jsRef{kind: refFree, segs: []jsSeg{{name: n.Name}}}, nil
	case jspat.Metavar:
		if r := scope[n.Name]; r != nil {
			return r, nil
		}
		if lit, ok := b.generic[n.Name]; ok && jsIdent(lit) {
			if r := scope[lit]; r != nil {
				return r, nil
			}
			return &jsRef{kind: refFree, segs: []jsSeg{{name: lit}}}, nil
		}
		if _, ok := b.enumerate(n.Name); ok || b.lenient {
			return &jsRef{kind: refFree, segs: []jsSeg{{mv: n.Name}}}, nil
		}
		return nil, &jsUnbound{n.Name}
	case jspat.Member:
		base, err := b.ref(scope, n.Kids[0])
		if err != nil {
			return nil, err
		}
		switch {
		case n.Meta:
			return base.extend(jsSeg{mv: n.Name}), nil
		case n.Name == jsDefault && base.kind != refFree:
			return base, nil // reach drops `.default`
		}
		return base.extend(jsSeg{name: n.Name}), nil
	case jspat.Call:
		if r, ok, err := b.moduleCall(scope, n); ok || err != nil {
			return r, err
		}
		sinks, err := b.callSinks(n.Kids[0], n.Kids[1:], false)
		if err != nil {
			return nil, err
		}
		return &jsRef{kind: refObject, from: sinks, via: viaChain}, nil
	case jspat.New:
		r, err := b.ref(scope, n.Kids[0])
		if err != nil {
			return nil, err
		}
		if r.kind == refModule && len(r.segs) > 0 && r.segs[len(r.segs)-1].class {
			return nil, skip("new of an instance")
		}
		if r.kind == refModule {
			// An instance: reach keys its methods <module>.x.(Y).meth.
			inst := *r
			inst.segs = append([]jsSeg{}, r.segs...)
			if len(inst.segs) == 0 {
				inst.segs = []jsSeg{{name: jsDefault}}
			}
			inst.segs[len(inst.segs)-1].class = true
			inst.localRegex = ""
			inst.ctorArgs = len(n.Kids) != 2 || n.Kids[1].Kind != jspat.Ellipsis
			return &inst, nil
		}
		sinks, err := b.callSinks(n.Kids[0], n.Kids[1:], true)
		if err != nil {
			return nil, err
		}
		return &jsRef{kind: refObject, from: sinks, via: viaChain}, nil
	case jspat.Index:
		return nil, skip("computed member")
	}
	return nil, skip("expression a callee cannot be")
}

// moduleCall reads `require("m")`, `import("m")`, a wrapper `$E("m")`, the
// same with a module metavariable, and an interop wrapper `$W($NS)` of a bound
// name (the name itself).
func (b *jsBranch) moduleCall(scope map[string]*jsRef, n *jspat.Node) (*jsRef, bool, error) {
	if len(n.Kids) != 2 {
		return nil, false, nil
	}
	c, a := n.Kids[0], n.Kids[1]
	named := c.Kind == jspat.Ident && (c.Name == "require" || c.Name == "import") && scope[c.Name] == nil
	wrapper := c.Kind == jspat.Metavar && scope[c.Name] == nil
	if !named && !wrapper {
		return nil, false, nil
	}
	switch a.Kind { //nolint:exhaustive // only a module string or a metavariable is a module argument
	case jspat.String:
		return &jsRef{kind: refModule, modules: []string{a.Name}, inline: named}, true, nil
	case jspat.Metavar:
		if r := scope[a.Name]; r != nil {
			if named {
				return nil, true, skip("require of a bound name")
			}
			cp := *r
			cp.wrapped = true
			return &cp, true, nil
		}
		r, err := b.moduleVar(a.Name)
		return r, true, err
	}
	return nil, false, nil
}

func jsIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9'
		if !ok {
			return false
		}
	}
	return true
}

// ---------- rendering a reference as callees ----------

// jsPlatform reads a WebCrypto spelling as reach names it: every `subtle`
// path is the SubtleCrypto interface, the global getRandomValues and
// randomUUID are Crypto's.
func jsPlatform(segs []jsSeg) ([]jsSeg, bool) {
	for i, s := range segs {
		if s.mv == "" && s.name == "subtle" && i < len(segs)-1 {
			return append([]jsSeg{{name: "SubtleCrypto", class: true}}, segs[i+1:]...), true
		}
	}
	if jsGlobalRandom(segs) {
		return []jsSeg{{name: "Crypto", class: true}, segs[len(segs)-1]}, true
	}
	return nil, false
}

// jsGlobalRandom: segs is getRandomValues or randomUUID on the global crypto
// object (`crypto.f`, `globalThis.crypto.f`, `self.f`, `$X.webcrypto.f`).
func jsGlobalRandom(segs []jsSeg) bool {
	n := len(segs)
	if n < 2 || segs[n-1].mv != "" || segs[n-1].name != "getRandomValues" && segs[n-1].name != "randomUUID" {
		return false
	}
	prev := segs[n-2]
	switch {
	case prev.mv == "" && prev.name != jsCrypto && jsGlobalHeads[prev.name]:
		return true
	case prev.name != jsCrypto:
		return false
	case n == 2:
		return true
	}
	return segs[0].name != jsCrypto && jsGlobalHeads[segs[0].name]
}

// callees renders a reference as the callees of a call (isNew: `new` of it).
func (b *jsBranch) callees(r *jsRef, isNew bool) ([]jsCallee, error) {
	var lossy []string
	if r.ctorArgs {
		lossy = append(lossy, "constructor arguments of the receiver")
	}
	switch r.kind {
	case refObject:
		return objectCallees(r, isNew, lossy)
	case refModule:
		return b.moduleCallees(r, isNew, lossy)
	case refFree:
		return b.freeCallees(r, isNew, lossy)
	}
	return nil, skip("unknown reference")
}

// objectCallees renders a reference to an object (a call result or a
// variable holding one) as the callees of a method call on it.
func objectCallees(r *jsRef, isNew bool, lossy []string) ([]jsCallee, error) {
	if r.via == viaDestructure {
		return nil, skip("method on a destructured call result")
	}
	if !isNew && len(r.segs) > 1 && r.via == viaVar && !jsHasVar(r.segs) {
		names := make([]string, len(r.segs)-1)
		for i, s := range r.segs[:len(r.segs)-1] {
			names[i] = s.name
		}
		method := r.segs[len(r.segs)-1].name
		return []jsCallee{{bind: BindObject, path: method, method: method, props: strings.Join(names, "."), from: r.from, via: []string{r.via}, lossy: lossy}}, nil
	}
	if isNew || len(r.segs) != 1 || r.segs[0].mv != "" {
		return nil, skip("method on a call result's property")
	}
	return []jsCallee{{bind: BindObject, path: r.segs[0].name, method: r.segs[0].name, from: r.from, via: []string{r.via}, lossy: lossy}}, nil
}

// moduleCallees renders a reference to a module member as the callees of a
// call: a platform global or an import.
func (b *jsBranch) moduleCallees(r *jsRef, isNew bool, lossy []string) ([]jsCallee, error) {
	if g, ok := jsPlatform(r.segs); ok {
		if isNew {
			return nil, skip("new of a platform interface")
		}
		return b.render(BindGlobal, nil, g, false, "", lossy)
	}
	segs, err := jsCallPath(r.segs, isNew)
	if err != nil {
		return nil, err
	}
	cs, err := b.render(BindImport, r.modules, segs, isNew, r.localRegex, lossy)
	for i := range cs {
		cs[i].localFirst = r.localFirst
		cs[i].member = r.namespace && len(r.segs) > 0
		cs[i].wrapped = r.wrapped
		cs[i].inline = r.inline
	}
	return cs, err
}

// freeCallees renders a free (unimported) reference as the callees of a
// call: a platform global or a written spelling.
func (b *jsBranch) freeCallees(r *jsRef, isNew bool, lossy []string) ([]jsCallee, error) {
	if g, ok := jsPlatform(r.segs); ok && !isNew {
		return b.render(BindGlobal, nil, g, false, "", lossy)
	}
	cs, err := b.render(BindWritten, nil, r.segs, isNew, "", lossy)
	// The branch's import guard still holds around a written spelling.
	if mods, ok := b.scopeModules(); ok && err == nil {
		for i := range cs {
			if cs[i].bind == BindWritten {
				cs[i].modules = mods
			}
		}
	}
	return cs, err
}

// jsCallPath is the key path of a call (isNew: a `new`) of a member path
// under a module: `x.(Y).<init>` for `new x.Y`, `default` for a call of the
// module itself, `(default).<init>` for a `new` of it.
func jsCallPath(path []jsSeg, isNew bool) ([]jsSeg, error) {
	switch {
	case isNew && len(path) == 0:
		return []jsSeg{{name: jsDefault, class: true}, {name: jsInit}}, nil
	case len(path) == 0:
		return []jsSeg{{name: jsDefault}}, nil
	case !isNew:
		return path, nil
	case path[len(path)-1].class:
		return nil, skip("new of an instance")
	}
	segs := make([]jsSeg, len(path), len(path)+1)
	copy(segs, path)
	segs[len(segs)-1].class = true
	return append(segs, jsSeg{name: jsInit}), nil
}

// render expands the metavariable segments whose regexes are finite lists
// into fixed paths, and writes the others as a path regex.
func (b *jsBranch) render(bind NodeBind, modules []string, segs []jsSeg, isNew bool, local string, lossy []string) ([]jsCallee, error) {
	alts := b.expand(segs)
	out := make([]jsCallee, 0, len(alts))
	for _, a := range alts {
		c := jsCallee{bind: bind, modules: modules, isNew: isNew, localRegex: local, lossy: lossy}
		if last := a[len(a)-1]; last.mv == "" {
			c.method = last.name
		}
		if !jsHasVar(a) {
			texts := make([]string, len(a))
			for i, s := range a {
				texts[i] = s.text()
			}
			c.path = strings.Join(texts, ".")
			out = append(out, c)
			continue
		}
		if bind == BindWritten {
			if a[0].mv != "" {
				tc, ok := b.textCallee(jsSegsText(a), a[0].mv, isNew)
				if !ok {
					return nil, skip("unbound metavariable callee " + a[0].mv)
				}
				tc.lossy = lossy
				out = append(out, tc)
				continue
			}
			return nil, skip("metavariable in an unimported callee")
		}
		c.pathRegex, c.constraints = b.pathRegex(a)
		out = append(out, c)
	}
	return out, nil
}

// expand writes each metavariable segment with a short list of values as
// each of them, while the paths stay few.
func (b *jsBranch) expand(segs []jsSeg) [][]jsSeg {
	alts := [][]jsSeg{segs}
	for i, s := range segs {
		if s.mv == "" {
			continue
		}
		vals, ok := b.segValues(s.mv)
		if !ok || len(alts)*len(vals) > jsPathAltMax {
			continue
		}
		next := make([][]jsSeg, 0, len(alts)*len(vals))
		for _, a := range alts {
			for _, v := range vals {
				c := append([]jsSeg{}, a...)
				c[i] = jsSeg{name: v, class: s.class}
				next = append(next, c)
			}
		}
		alts = next
	}
	return alts
}

// segValues are a member metavariable's values: its generic literal, or its
// enumerated regex when every value is an identifier.
func (b *jsBranch) segValues(mv string) ([]string, bool) {
	if lit, ok := b.generic[mv]; ok && jsIdent(lit) {
		return []string{lit}, true
	}
	vals, ok := b.enumerate(mv)
	if !ok {
		return nil, false
	}
	for _, v := range vals {
		if !jsIdent(v) {
			return nil, false
		}
	}
	return vals, true
}

// jsSegsText is a member path as written: metavariables by name; a class
// segment gives text no callee regex reads (`(C)`).
func jsSegsText(segs []jsSeg) string {
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = s.text()
		if s.mv != "" {
			parts[i] = s.mv
		}
	}
	return strings.Join(parts, ".")
}

func jsHasVar(segs []jsSeg) bool {
	for _, s := range segs {
		if s.mv != "" {
			return true
		}
	}
	return false
}

// pathRegex writes a path with metavariable segments as a regex whose named
// groups bind them; their own regexes become constraints on the bindings.
func (b *jsBranch) pathRegex(segs []jsSeg) (string, []jsConstraint) {
	seen := map[string]bool{}
	var cons []jsConstraint
	parts := make([]string, len(segs))
	for i, s := range segs {
		var p string
		switch {
		case s.mv == "":
			p = pyReEscape(s.name)
		case seen[s.mv]:
			p = "(?P=" + s.mv[1:] + ")"
		default:
			seen[s.mv] = true
			p = "(?P<" + s.mv[1:] + ">[^.()]+)"
			for _, rx := range b.regexes[s.mv] {
				cons = append(cons, jsConstraint{metavar: s.mv, regex: pcreToPyText(rx)})
			}
		}
		if s.class {
			p = `\(` + p + `\)`
		}
		parts[i] = p
	}
	return "^" + strings.Join(parts, `\.`) + "$", cons
}

// ---------- calls ----------

// callSinks lowers one call pattern: its callee through the scope, its
// argument list as a pattern, the regexes of the metavariables it binds.
func (b *jsBranch) callSinks(callee *jspat.Node, args []*jspat.Node, isNew bool) ([]*jsSink, error) {
	r, err := b.ref(b.scope, callee)
	if err != nil {
		var unbound *jsUnbound
		if !errors.As(err, &unbound) {
			return nil, err
		}
		c, ok := b.textCallee(jsUnwrap(callee).Text, unbound.mv, isNew)
		if !ok {
			return nil, skip("unbound metavariable callee " + unbound.mv)
		}
		return b.sinks(args, []jsCallee{c})
	}
	cs, err := b.callees(r, isNew)
	if err != nil {
		return nil, err
	}
	// reach gives every spelling of a global object one key; OpenGrep
	// matches the callee as the pattern writes it.
	for i := range cs {
		if cs[i].bind == BindGlobal {
			cs[i].written = jsUnwrap(callee).Text
		}
	}
	return b.sinks(args, cs)
}

// textCallee is the callee of a call written as a chain headed by an
// unbound metavariable: `$GEN($TYPE)` (with a metavariable-regex), `$R.sign`,
// `$MDNS.$H.create`. OpenGrep reads it on the callee text as written,
// whatever it calls: a regex over that text whose head group takes any
// expression and whose inner metavariables take one name each, their
// metavariable-regexes constraints. A bare metavariable with no regex would
// take every call: none.
func (b *jsBranch) textCallee(text, mv string, isNew bool) (jsCallee, bool) {
	text = norm(text)
	if strings.ContainsAny(text, "()[]'\"`") || !strings.HasPrefix(text, mv) {
		return jsCallee{}, false
	}
	segs := strings.Split(text, ".")
	if len(segs) == 1 && len(b.regexes[mv]) == 0 {
		return jsCallee{}, false
	}
	modules, ok := b.scopeModules()
	if !ok {
		return jsCallee{}, false
	}
	c := jsCallee{bind: BindText, isNew: isNew, modules: modules}
	seen := map[string]bool{}
	parts := make([]string, len(segs))
	for i, seg := range segs {
		switch {
		case !jspat.IsMetavar(seg):
			if !jsIdent(seg) {
				return jsCallee{}, false
			}
			parts[i] = pyReEscape(seg)
		case seen[seg]:
			parts[i] = "(?P=" + seg[1:] + ")"
		default:
			seen[seg] = true
			one := "[^.()]+"
			if i == 0 {
				one = ".+"
			}
			parts[i] = "(?P<" + seg[1:] + ">" + one + ")"
			for _, rx := range b.regexes[seg] {
				c.constraints = append(c.constraints, jsConstraint{metavar: seg, regex: pcreToPyText(rx)})
			}
		}
	}
	if last := segs[len(segs)-1]; !jspat.IsMetavar(last) {
		c.method = last
	}
	c.pathRegex = "^" + strings.Join(parts, `\.`) + "$"
	return c, true
}

// sinks are the entries of a call pattern with callees cs and arguments args.
func (b *jsBranch) sinks(args []*jspat.Node, cs []jsCallee) ([]*jsSink, error) {
	text, minArgs, maxArgs, bound, err := jsArgPattern(args)
	if err != nil {
		return nil, err
	}
	var cons []jsConstraint
	for _, mv := range sortedKeys(bound) {
		for _, rx := range b.regexes[mv] {
			cons = append(cons, jsConstraint{metavar: mv, regex: pcreToPyText(rx)})
		}
		if lit, ok := b.generic[mv]; ok {
			cons = append(cons, jsConstraint{metavar: mv, regex: `.*\b` + pyReEscape(lit) + `\b`})
		}
	}
	for _, c := range cons {
		if checkRegex(c.regex) != nil {
			return nil, skip("metavariable-regex does not compile")
		}
	}
	producers, err := b.producers(bound)
	if err != nil {
		return nil, err
	}
	out := make([]*jsSink, len(cs))
	for i, c := range cs {
		out[i] = &jsSink{
			callee: c, args: text, minArity: minArgs, maxArity: maxArgs, bound: bound,
			constraints: append(append([]jsConstraint{}, c.constraints...), cons...),
			producers:   producers,
		}
	}
	return out, nil
}

// producers are the argument metavariables of bound a context binds to a
// call's result: OpenGrep matches the argument only where it reads that
// variable.
func (b *jsBranch) producers(bound map[string]bool) ([]jsProducer, error) {
	var out []jsProducer
	for _, mv := range sortedKeys(bound) {
		r := b.scope[mv]
		if r != nil && r.readSrc != nil {
			from, err := b.readSinks(r.readSrc)
			if err != nil {
				return nil, err
			}
			out = append(out, jsProducer{use: mv, via: viaVar, from: from})
			continue
		}
		if r == nil || r.kind != refObject {
			continue
		}
		if len(r.segs) > 0 || r.via == viaChain {
			return nil, skip("argument bound to a call result's property")
		}
		out = append(out, jsProducer{use: mv, via: r.via, from: r.from})
	}
	return out, nil
}

// jsArgPattern is an argument list as pattern text (nil for `...`), checked by
// parsing it back, with its arity and the metavariables it binds.
func jsArgPattern(args []*jspat.Node) (*string, int, *int, map[string]bool, error) {
	if jsAnyArgs(args) {
		return nil, 0, nil, map[string]bool{}, nil
	}
	text := jsArgsText(args)
	back, err := jspat.ParseArgs(text)
	if err != nil || len(back) != len(args) {
		return nil, 0, nil, nil, skip("argument pattern does not parse back")
	}
	for i := range back {
		if back[i].Text != args[i].Text {
			return nil, 0, nil, nil, skip("argument pattern does not parse back")
		}
	}
	minArgs, maxArgs := jspat.Arity(back)
	var maxp *int
	if maxArgs >= 0 {
		maxp = &maxArgs
	}
	return &text, minArgs, maxp, jsMetavars(back), nil
}

// rxJSAssignNotInside is a pattern-not-inside that only assigns a
// metavariable: `$V = <expr>;` with an optional `...` after it.
var rxJSAssignNotInside = regexp.MustCompile(`^\s*(\$[A-Z_][A-Z0-9_]*)\s*=\s*([^\n;]+?)\s*;?\s*(?:\n\s*\.\.\.\s*)?$`)

// notProducers takes out of texts the pattern-not-insides `$V = <expr>;
// ...`: no finding where the argument $V binds reads a variable an earlier
// read or call matching <expr> assigned (not_producers). The rest stay.
func (b *jsBranch) notProducers(texts []string) (out []jsProducer, rest []string) {
	for _, text := range texts {
		m := rxJSAssignNotInside.FindStringSubmatch(text)
		if m == nil {
			rest = append(rest, text)
			continue
		}
		from, ok := b.valueSinks(m[2])
		if !ok {
			rest = append(rest, text)
			continue
		}
		out = append(out, jsProducer{use: m[1], via: viaVar, from: from})
	}
	return out, rest
}

// valueSinks are the entries of the read or call that produces a value.
func (b *jsBranch) valueSinks(text string) ([]*jsSink, bool) {
	n, err := b.cache.expr(text)
	if err != nil {
		return nil, false
	}
	n = jsUnwrapTerm(n)
	var sinks []*jsSink
	switch n.Kind { //nolint:exhaustive // only reads and calls produce a value a negation can name
	case jspat.Member, jspat.Ident, jspat.Index:
		sinks, err = b.readSinks(n)
	case jspat.Call, jspat.New:
		sinks, err = b.callSinks(n.Kids[0], n.Kids[1:], n.Kind == jspat.New)
	default:
		return nil, false
	}
	return sinks, err == nil && len(sinks) > 0
}

// readSinks lowers a property read (`$NS.enums.hash.md5`, `$C.fingerprint`):
// entries keyed as a call of the property would be, matched on the
// fragment's property reads.
func (b *jsBranch) readSinks(term *jspat.Node) ([]*jsSink, error) {
	r, err := b.ref(b.scope, term)
	var cs []jsCallee
	switch {
	case err == nil:
		cs, err = b.callees(r, false)
		if err != nil {
			return nil, err
		}
	case errors.As(err, new(*jsUnbound)):
		var unbound *jsUnbound
		errors.As(err, &unbound)
		c, ok := b.textCallee(jsUnwrap(term).Text, unbound.mv, false)
		if !ok {
			return nil, skip("property read of an unbound metavariable")
		}
		cs = []jsCallee{c}
	default:
		return nil, err
	}
	sinks, err := b.sinks(nil, cs)
	for _, s := range sinks {
		s.read, s.args, s.minArity, s.maxArity = true, nil, 0, nil // a read has no argument list
	}
	return sinks, err
}

// literalSinks lowers an object literal written with no call around it: a
// literal entry, under the module the rule's import guard binds.
func (b *jsBranch) literalSinks(lit *jspat.Node) ([]*jsSink, error) {
	modules, ok := b.scopeModules()
	if !ok {
		return nil, skip("object literal under imports of several modules")
	}
	return b.sinks([]*jspat.Node{lit}, []jsCallee{{bind: BindLiteral, modules: modules, assigned: b.assignedLiteral}})
}

// scopeModules is the module the branch's import guards bind, for an entry
// whose callee names none of them (a literal, a text callee): OpenGrep
// matches it only in a file the guard holds in. ok is false when the guards
// bind several different modules.
func (b *jsBranch) scopeModules() ([]string, bool) {
	var modules []string
	names := make([]string, 0, len(b.scope))
	for mv := range b.scope {
		names = append(names, mv)
	}
	sort.Strings(names)
	for _, mv := range names {
		r := b.scope[mv]
		if r.kind != refModule || len(r.modules) == 0 {
			continue
		}
		switch {
		case modules == nil:
			modules = r.modules
		case !slices.Equal(modules, r.modules):
			return nil, false
		}
	}
	return modules, true
}

// fuse lowers an object literal written inside a context call: the call,
// with the literal required somewhere in the run of arguments its first `...`
// stands for.
func (b *jsBranch) fuse(ctx, lit *jspat.Node) ([]*jsSink, error) {
	args := ctx.Kids[1:]
	at := -1
	for i, a := range args {
		if a.Kind == jspat.Ellipsis {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, skip("object literal in a call without ...")
	}
	texts := make([]string, 0, len(args)+2)
	for i, a := range args {
		if i == at {
			texts = append(texts, jsEllipsis, "<... "+lit.Text+" ...>", jsEllipsis)
			continue
		}
		texts = append(texts, a.Text)
	}
	fused, err := jspat.ParseArgs(strings.Join(texts, ", "))
	if err != nil {
		return nil, skip("object literal does not fuse into its call")
	}
	return b.callSinks(ctx.Kids[0], fused, ctx.Kind == jspat.New)
}

// terminals reads the branch's patterns: one terminal, and the others
// calls of a free callee (`$F($JWK)`) that only shape the same call's
// arguments. args are the terminal's arguments, or a shape's when the
// terminal's are `...`.
func (b *jsBranch) terminals(leaves []string) (*jspat.Node, []*jspat.Node, error) {
	if len(leaves) == 0 {
		return nil, nil, skip("no terminal pattern")
	}
	var term *jspat.Node
	var shapes []*jspat.Node
	for _, l := range leaves {
		n, err := b.terminal(l)
		if err != nil {
			return nil, nil, err
		}
		if len(leaves) > 1 && b.shapeOnly(n) {
			shapes = append(shapes, n)
			continue
		}
		if term != nil {
			return nil, nil, skip("several terminal patterns")
		}
		term = n
	}
	if term == nil {
		if len(shapes) != 1 {
			return nil, nil, skip("several terminal patterns")
		}
		term, shapes = shapes[0], nil
	}
	if term.Kind != jspat.Call && term.Kind != jspat.New {
		if len(shapes) > 0 {
			return nil, nil, skip("several terminal patterns")
		}
		return term, nil, nil
	}
	args, ok := jsShapeArgs(term, shapes)
	if !ok {
		return nil, nil, skip("several terminal patterns")
	}
	return term, args, nil
}

// jsShapeArgs are the terminal's arguments narrowed by the shapes'.
func jsShapeArgs(term *jspat.Node, shapes []*jspat.Node) ([]*jspat.Node, bool) {
	args := term.Kids[1:]
	for _, sh := range shapes {
		if sh.Kind != term.Kind || !jsSameName(sh.Kids[0], term.Kids[0]) {
			return nil, false
		}
		var ok bool
		if args, ok = jsIntersectArgs(args, sh.Kids[1:]); !ok {
			return nil, false
		}
	}
	return args, true
}

// jsIntersectArgs is one argument-list pattern that holds where both hold,
// when the two differ only by `...` lists, metavariables against patterns,
// and open object patterns (whose entries are united).
func jsIntersectArgs(a, b []*jspat.Node) ([]*jspat.Node, bool) {
	switch {
	case jsAnyArgs(a):
		return b, true
	case jsAnyArgs(b), jsArgsText(a) == jsArgsText(b):
		return a, true
	case len(a) != len(b):
		return nil, false
	}
	texts := make([]string, len(a))
	for i := range a {
		x, y := a[i], b[i]
		switch {
		case x.Text == y.Text, y.Kind == jspat.Metavar:
			texts[i] = x.Text
		case x.Kind == jspat.Metavar:
			texts[i] = y.Text
		case x.Kind == jspat.Object && y.Kind == jspat.Object:
			t, ok := jsUniteObjects(x, y)
			if !ok {
				return nil, false
			}
			texts[i] = t
		default:
			return nil, false
		}
	}
	out, err := jspat.ParseArgs(strings.Join(texts, ", "))
	if err != nil || len(out) != len(a) {
		return nil, false
	}
	return out, true
}

// jsUniteObjects writes two open object patterns (`{..., k: v, ...}`) as one
// holding the entries of both.
func jsUniteObjects(x, y *jspat.Node) (string, bool) {
	var parts []string
	seen := map[string]bool{}
	for _, o := range []*jspat.Node{x, y} {
		open := false
		for _, p := range o.Props {
			var t string
			switch {
			case p.Ellipsis:
				open = true
				continue
			case p.Spread || p.Computed || p.Value == nil:
				return "", false
			case p.Shorthand:
				t = p.Value.Text
			case p.KeyVar != "":
				t = p.KeyVar + ": " + p.Value.Text
			default:
				t = p.Key + ": " + p.Value.Text
			}
			if !seen[t] {
				seen[t] = true
				parts = append(parts, t)
			}
		}
		if !open {
			return "", false
		}
	}
	return "{" + strings.Join(append(append([]string{jsEllipsis}, parts...), jsEllipsis), ", ") + "}", true
}

// shapeOnly: n is a call whose callee starts at a metavariable nothing binds
// (`$F(...)`, `$RECV.encrypt(...)`): on the terminal's call it only shapes
// the arguments.
func (b *jsBranch) shapeOnly(n *jspat.Node) bool {
	if n.Kind != jspat.Call && n.Kind != jspat.New {
		return false
	}
	c := jsUnwrap(n.Kids[0])
	for c.Kind == jspat.Member {
		c = jsUnwrap(c.Kids[0])
	}
	if c.Kind != jspat.Metavar || b.scope[c.Name] != nil {
		return false
	}
	_, generic := b.generic[c.Name]
	return !generic && len(b.regexes[c.Name]) == 0
}

// jsSameName: two callees can be one call's: same last member name, or one a
// bare metavariable.
func jsSameName(a, b *jspat.Node) bool {
	a, b = jsUnwrap(a), jsUnwrap(b)
	if a.Kind != jspat.Member || b.Kind != jspat.Member || a.Meta || b.Meta {
		return true
	}
	return a.Name == b.Name
}

func jsAnyArgs(args []*jspat.Node) bool { return len(args) == 1 && args[0].Kind == jspat.Ellipsis }

func jsArgsText(args []*jspat.Node) string {
	texts := make([]string, len(args))
	for i, a := range args {
		texts[i] = a.Text
	}
	return strings.Join(texts, ", ")
}

// terminal reads the branch's pattern: bindings written before it are
// guards, an assignment's right side is the call.
func (b *jsBranch) terminal(text string) (*jspat.Node, error) {
	t := strings.TrimSuffix(strings.TrimSpace(text), ";")
	if n, err := b.cache.expr(t); err == nil {
		return jsUnwrapTerm(n), nil
	}
	var lines []string
	for _, l := range strings.Split(t, "\n") {
		if l = strings.TrimSpace(l); l != "" && l != jsEllipsis {
			lines = append(lines, l)
		}
	}
	if len(lines) > 1 {
		if _, err := b.resolveGuards([]string{strings.Join(lines[:len(lines)-1], "\n")}); err != nil {
			return nil, err
		}
		t = strings.TrimSuffix(lines[len(lines)-1], ";")
	}
	stripped := jsStripAssign(t)
	n, err := b.cache.expr(stripped)
	if err != nil {
		return nil, skip("terminal: " + jsReason(err))
	}
	n = jsUnwrapTerm(n)
	if stripped != t && n.Kind == jspat.Object {
		b.assignedLiteral = true // `$O = {...}`: an object assigned to a variable
	}
	return n, nil
}

func jsUnwrapTerm(n *jspat.Node) *jspat.Node {
	for n.Kind == jspat.Deep || n.Kind == jspat.Unary && n.Op == "await" {
		n = n.Kids[0]
	}
	return n
}

var rxJSAssign = regexp.MustCompile(`^(?:(?:var|let|const)\s+)?\$?[A-Za-z_][\w$]*\s*=`)

// jsStripAssign drops `[var|let|const] name =` from a pattern.
func jsStripAssign(t string) string {
	loc := rxJSAssign.FindStringIndex(t)
	if len(loc) < 2 || loc[1] >= len(t) || t[loc[1]] == '=' || t[loc[1]] == '>' {
		return t
	}
	return strings.TrimSpace(t[loc[1]:])
}

// ---------- negations ----------

// lowerNots adds the pattern-not calls on the sink's own callee as argument
// patterns. A pattern-not on another callee, or on an object or a name, can
// never match the sink's call: it is vacuous. A nested pattern-not's own
// pattern-nots become the exceptions of its not_calls entry; when one cannot
// be read the negation cannot be bounded and is dropped.
func (b *jsBranch) lowerNots(s *jsSink, nots []jsClause) {
	for _, c := range nots {
		n, ok := b.lowerNested(s, c)
		if !ok {
			s.dropped = append(s.dropped, c.dropReason())
			continue
		}
		if n == nil {
			continue
		}
		key := jsonValue(n.notEntry())
		dup := false
		for _, o := range s.notCalls {
			dup = dup || jsonValue(o.notEntry()) == key
		}
		if !dup {
			s.notCalls = append(s.notCalls, n)
		}
	}
}

// lowerNested is one pattern-not with its constraints and exceptions as a
// not_calls entry of s, nil when it is vacuous; ok is false when any part of
// it cannot be read.
func (b *jsBranch) lowerNested(s *jsSink, c jsClause) (*jsSink, bool) {
	n, ok := b.lowerNot(s, c.text)
	if !ok || n == nil {
		return nil, ok
	}
	if !n.constrain(c.regexes) {
		return nil, false
	}
	for _, text := range c.except {
		x, ok := b.lowerNot(s, text)
		if !ok {
			return nil, false
		}
		if x != nil {
			n.notCalls = append(n.notCalls, x)
		}
	}
	for _, r := range c.exceptRules {
		x, ok := b.lowerNested(s, r)
		if !ok {
			return nil, false
		}
		if x != nil {
			n.notCalls = append(n.notCalls, x)
		}
	}
	return n, true
}

// dropReason is how a pattern-not that cannot be read is recorded.
func (c jsClause) dropReason() string {
	if len(c.except) > 0 || len(c.regexes) > 0 || len(c.exceptRules) > 0 {
		return "pattern-not: nested formula"
	}
	return "pattern-not"
}

// lowerNot is one pattern-not as a not_calls entry of s, nil when it is
// vacuous; ok is false when it cannot be read.
func (b *jsBranch) lowerNot(s *jsSink, text string) (*jsSink, bool) {
	n, err := b.cache.expr(jsStripAssign(strings.TrimSuffix(strings.TrimSpace(text), ";")))
	if err != nil {
		return nil, false
	}
	n = jsUnwrapTerm(n)
	if s.callee.bind == BindLiteral {
		return literalNot(n)
	}
	switch n.Kind { //nolint:exhaustive // the remaining kinds cannot be read
	case jspat.Call, jspat.New:
	case jspat.Object, jspat.Array, jspat.Member, jspat.Ident:
		return nil, true
	default:
		return nil, false
	}
	if !b.sameCallee(n, &s.callee) {
		return nil, true
	}
	args, minArgs, maxArgs, bound, err := jsArgPattern(n.Kids[1:])
	if err != nil {
		return nil, false
	}
	return &jsSink{args: args, minArity: minArgs, maxArity: maxArgs, bound: bound}, true
}

// literalNot is a pattern-not of a literal entry: an object pattern
// negates the object (its one argument); anything else cannot match an
// object literal's range and is vacuous.
func literalNot(n *jspat.Node) (*jsSink, bool) {
	if n.Kind != jspat.Object {
		return nil, true
	}
	args, minArgs, maxArgs, bound, err := jsArgPattern([]*jspat.Node{n})
	if err != nil {
		return nil, false
	}
	return &jsSink{args: args, minArity: minArgs, maxArity: maxArgs, bound: bound}, true
}

// sameCallee: the negated call n is a call of c. A callee the scope cannot
// resolve (an unbound metavariable) is one when it is a bare metavariable or
// names the same method: OpenGrep matches it textually on the same call.
func (b *jsBranch) sameCallee(n *jspat.Node, c *jsCallee) bool {
	isNew := n.Kind == jspat.New
	if isNew != c.isNew {
		return false
	}
	if same, decided := b.sameResolvedCallee(n.Kids[0], c, isNew); decided {
		return same
	}
	callee := jsUnwrap(n.Kids[0])
	switch {
	case callee.Kind == jspat.Metavar:
		return true
	case callee.Kind == jspat.Member && !callee.Meta:
		return c.method == callee.Name || isNew && strings.HasSuffix(c.path, "("+callee.Name+")."+jsInit)
	case callee.Kind == jspat.Ident:
		// A name the scope does not bind is written text: OpenGrep matches it
		// on a call written with that name, which is the callee's when the
		// name is one it may be written with.
		return c.method == callee.Name || c.localRegex != "" && reMatch(c.localRegex, callee.Name) != nil
	}
	return false
}

// sameResolvedCallee compares the callee the scope resolves the negated
// call's callee to with c. decided is false when the scope cannot resolve
// it, or resolves it to a free name that matches no callee of c: the
// written text decides then.
func (b *jsBranch) sameResolvedCallee(callee *jspat.Node, c *jsCallee, isNew bool) (same, decided bool) {
	r, err := b.ref(b.scope, callee)
	if err != nil {
		return false, false
	}
	cs, err := b.callees(r, isNew)
	if err != nil {
		return false, false
	}
	for _, o := range cs {
		if o.bind == c.bind && o.path == c.path && o.pathRegex == c.pathRegex && (len(c.modules) == 0 || jsIntersect(o.modules, c.modules)) {
			return true, true
		}
	}
	return false, r.kind != refFree
}

func jsIntersect(a, b []string) bool {
	for _, x := range a {
		if inList(x, b) {
			return true
		}
	}
	return false
}

// notImports reads the pattern-not-inside guards that exclude files importing
// another library: their modules. A guard importing a named member (`import
// {p256 as $X} from "m"`) only keeps OpenGrep from reading a renamed import
// twice, which identity semantics already read as one call: it is vacuous. A
// guard that is not an import is left out (lossy).
func (b *jsBranch) notImports(texts []string) []string {
	var out []string
	for _, text := range texts {
		g, err := b.cache.guard(text)
		if err != nil {
			b.drop(jsNotInside)
			continue
		}
		mods, ok := b.guardModules(g)
		if !ok {
			b.drop(jsNotInside)
			continue
		}
		out = append(out, mods...)
	}
	return out
}

// enclosures takes out of texts the pattern-not-insides that place the
// terminal term in a call's argument list (`$FN(..., X, ...)`, `new
// $C(..., X, ...)`) or in an object literal's property (`{..., $K: X,
// ...}`), X of term's shape, as not_enclosed places; the rest stay.
func (b *jsBranch) enclosures(texts []string, term *jspat.Node) (places, rest []string) {
	for _, text := range texts {
		if k := b.enclosure(text, term); k != "" {
			places = append(places, k)
			continue
		}
		rest = append(rest, text)
	}
	return uniqueSorted(places), rest
}

func (b *jsBranch) enclosure(text string, term *jspat.Node) string {
	n, err := b.cache.expr(strings.TrimSpace(text))
	if err != nil || term == nil {
		return ""
	}
	n = jsUnwrapTerm(n)
	switch n.Kind { //nolint:exhaustive // the other kinds place nothing
	case jspat.Call, jspat.New:
		if b.enclosingCall(n, term) {
			return enclosedArgument
		}
	case jspat.Object:
		if value := jsOnlyValue(n); value != nil && jsSameShape(value, term) {
			return enclosedProperty
		}
	}
	return ""
}

// enclosingCall: n is `$FN(..., X, ...)` (or a new) with $FN unbound and X
// of term's shape.
func (b *jsBranch) enclosingCall(n, term *jspat.Node) bool {
	callee, args := jsUnwrap(n.Kids[0]), n.Kids[1:]
	return callee.Kind == jspat.Metavar && b.scope[callee.Name] == nil && len(args) == 3 &&
		args[0].Kind == jspat.Ellipsis && args[2].Kind == jspat.Ellipsis && jsSameShape(args[1], term)
}

// jsOnlyValue is the value of an object pattern's one property besides
// ellipses (`{..., $K: X, ...}`), nil for any other object.
func jsOnlyValue(n *jspat.Node) *jspat.Node {
	var value *jspat.Node
	for _, p := range n.Props {
		switch {
		case p.Ellipsis:
		case value == nil && p.Value != nil && !p.Spread:
			value = p.Value
		default:
			return nil
		}
	}
	return value
}

// jsSameShape: x stands for the terminal term: an object for an object; for
// a call, the same call kind whose callee, its leading metavariable left
// out, ends the terminal's callee (`$MDNS.sha256.create` for
// `$F.md.sha256.create`).
func jsSameShape(x, term *jspat.Node) bool {
	x = jsUnwrapTerm(x)
	if x.Kind != term.Kind {
		return false
	}
	if x.Kind != jspat.Call && x.Kind != jspat.New {
		return x.Kind == jspat.Object
	}
	xc, tc := norm(jsUnwrap(x.Kids[0]).Text), norm(jsUnwrap(term.Kids[0]).Text)
	head, rest, ok := strings.Cut(xc, ".")
	if !ok || !jspat.IsMetavar(head) {
		return xc == tc
	}
	return strings.HasSuffix(tc, "."+rest)
}

// guardModules are the modules a guard imports whole; ok is false when one
// of its bindings is not an import.
func (b *jsBranch) guardModules(g *jspat.Guard) ([]string, bool) {
	var mods []string
	for _, bd := range g.Bindings {
		if bd.Imported != "" {
			continue
		}
		if m, isMod := bd.Module(); isMod {
			mods = append(mods, m)
			continue
		}
		if bd.ModuleVar == "" || b.scope[bd.ModuleVar] != nil {
			return nil, false
		}
		r, err := b.moduleVar(bd.ModuleVar)
		if err != nil {
			return nil, false
		}
		mods = append(mods, r.modules...)
	}
	return mods, true
}

// filterNotImports is the sink's not_imports: the excluded modules, less its
// own (a file calling the sink always imports it).
func filterNotImports(mods, own []string) []string {
	var out []string
	for _, m := range mods {
		if !inList(m, own) {
			out = append(out, m)
		}
	}
	return uniqueSorted(out)
}

func uniqueSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// ---------- the rule ----------

// compileJSRule is compileRule for a node rule.
func compileJSRule(r *OMap) ([]*OMap, error) {
	if asOr[string](r.GetOr("mode")) == strTaint {
		return compileJSTaint(r)
	}
	node := &OMap{}
	for _, k := range []string{jsLeaf, jsEither, jsPatterns} {
		if v, has := r.Get(k); has {
			node.Set(k, v)
		}
	}
	if node.Len() != 1 {
		if r.Has("pattern-regex") {
			return nil, skip(jsPatternRegex)
		}
		return nil, skip("unsupported top-level formula")
	}
	return compileJSFormula(node)
}

// compileJSTaint compiles a taint rule as the other languages do: the sinks
// compile as a search formula and each carries the regexes of the sources'
// values (compileSource). Sanitizers and propagators are not modeled, so such
// a rule is skipped.
func compileJSTaint(r *OMap) ([]*OMap, error) {
	if pyTruthy(r.GetOr("pattern-sanitizers")) || pyTruthy(r.GetOr("pattern-propagators")) {
		return nil, skip("taint sanitizers/propagators")
	}
	srcs, err := asSeq(r.GetOr("pattern-sources"), "pattern-sources")
	if err != nil {
		return nil, err
	}
	sources := []any{}
	for _, src := range srcs {
		rxs, err := compileSource(src)
		if err != nil {
			return nil, err
		}
		sources = append(sources, rxs...)
	}
	snks, err := asSeq(r.GetOr("pattern-sinks"), "pattern-sinks")
	if err != nil {
		return nil, err
	}
	node := &OMap{}
	node.Set(jsEither, snks)
	sinks, err := compileJSFormula(node)
	if err != nil {
		return nil, err
	}
	for _, s := range sinks {
		s.Set("taint_sources", sources)
	}
	return sinks, nil
}

// compileJSFormula compiles a positive formula (one of pattern, pattern-either
// or patterns) into the rule's merged sink entries.
func compileJSFormula(node *OMap) ([]*OMap, error) {
	branches, err := jsDNF(node)
	if err != nil {
		return nil, err
	}
	cache := &jsCache{guards: map[string]jsGuardParse{}, exprs: map[string]jsExprParse{}}
	var sinks []*jsSink
	var reasons []string
	for _, br := range branches {
		out, err := lowerBranch(br, cache)
		if err != nil {
			s, ok := asSkip(err)
			if !ok {
				return nil, err
			}
			reasons = append(reasons, s.reason)
			continue
		}
		sinks = append(sinks, out...)
	}
	if len(sinks) == 0 {
		return nil, skip(jsMostFrequent(reasons))
	}
	var ruleDropped []string
	for _, reason := range reasons {
		ruleDropped = append(ruleDropped, "pattern-either alternative: "+reason)
	}
	ruleDropped = uniqueSorted(ruleDropped)
	merged := mergeJSSinks(sinks)
	out := make([]*OMap, len(merged))
	for i, s := range merged {
		e := s.entry(true)
		dropped := make([]any, 0, len(s.dropped)+len(ruleDropped))
		for _, d := range uniqueSorted(append(append([]string{}, s.dropped...), ruleDropped...)) {
			dropped = append(dropped, d)
		}
		e.Set("dropped_clauses", dropped)
		out[i] = e
	}
	return out, nil
}

// jsMostFrequent is the reason most alternatives were dropped for, the first
// seen on a tie.
func jsMostFrequent(reasons []string) string {
	if len(reasons) == 0 {
		return "no alternative"
	}
	count := map[string]int{}
	best := reasons[0]
	for _, r := range reasons {
		count[r]++
		if count[r] > count[best] {
			best = r
		}
	}
	return best
}

// mergeJSSinks unions the module lists (and an object callee's ways from its
// producer) of sinks equal in everything else, their producers' module lists
// included, and removes repeats, keeping the first-seen order.
func mergeJSSinks(sinks []*jsSink) []*jsSink {
	var out []*jsSink
	at := map[string]int{}
	for _, s := range sinks {
		k := jsonValue(s.entry(false))
		i, seen := at[k]
		if !seen {
			at[k] = len(out)
			cp := *s
			cp.callee.from = append([]*jsSink{}, s.callee.from...)
			cp.producers = append([]jsProducer{}, s.producers...)
			for j := range cp.producers {
				cp.producers[j].from = append([]*jsSink{}, s.producers[j].from...)
			}
			out = append(out, &cp)
			continue
		}
		m := out[i]
		m.callee.modules = uniqueSorted(append(append([]string{}, m.callee.modules...), s.callee.modules...))
		m.callee.via = uniqueSorted(append(append([]string{}, m.callee.via...), s.callee.via...))
		for j, f := range s.callee.from {
			fm := *m.callee.from[j]
			fm.callee.modules = uniqueSorted(append(append([]string{}, fm.callee.modules...), f.callee.modules...))
			m.callee.from[j] = &fm
		}
		for j, p := range s.producers {
			for k, f := range p.from {
				fm := *m.producers[j].from[k]
				fm.callee.modules = uniqueSorted(append(append([]string{}, fm.callee.modules...), f.callee.modules...))
				m.producers[j].from[k] = &fm
			}
		}
	}
	return out
}

// entry is the only place that knows the JSON of a node entry. modules=false
// leaves the module lists and an object callee's via out (the merge key).
func (s *jsSink) entry(modules bool) *OMap {
	e := omap("callee", s.callee.omap(modules))
	s.setMethod(e)
	s.setArgs(e)
	e.Set("constraints", jsConstraints(s.constraints))
	s.setNegations(e)
	s.setRelated(e, modules)
	if s.focus != "" {
		e.Set("focus_metavar", s.focus)
	}
	if !modules {
		e.Set("dropped_clauses", jsAnyList(s.dropped))
	}
	return e
}

// setNegations sets the entry's not_calls, not_imports, not_regexes,
// not_enclosed and read keys.
func (s *jsSink) setNegations(e *OMap) {
	nots := make([]any, len(s.notCalls))
	for i, n := range s.notCalls {
		nots[i] = n.notEntry()
	}
	e.Set("not_calls", nots)
	if len(s.notImports) > 0 {
		e.Set("not_imports", jsAnyList(s.notImports))
	}
	if len(s.notRegexes) > 0 {
		e.Set("not_regexes", jsAnyList(s.notRegexes))
	}
	if len(s.notEnclosed) > 0 {
		e.Set("not_enclosed", jsAnyList(s.notEnclosed))
	}
	if s.read {
		e.Set("read", true)
	}
}

// setRelated sets the entry's not_producers, within, not_entries, consumers
// and producers keys.
func (s *jsSink) setRelated(e *OMap, modules bool) {
	if len(s.notProducers) > 0 {
		ps := make([]any, len(s.notProducers))
		for i, p := range s.notProducers {
			ps[i] = p.omap(modules)
		}
		e.Set("not_producers", ps)
	}
	if len(s.within) > 0 {
		ws := make([]any, len(s.within))
		for i, w := range s.within {
			ws[i] = w.fromEntry(modules)
		}
		e.Set("within", ws)
	}
	if len(s.notEntries) > 0 {
		ns := make([]any, len(s.notEntries))
		for i, n := range s.notEntries {
			ns[i] = n.entry(modules)
		}
		e.Set("not_entries", ns)
	}
	if len(s.consumers) > 0 {
		cs := make([]any, len(s.consumers))
		for i, c := range s.consumers {
			cs[i] = c.omap()
		}
		e.Set("consumers", cs)
	}
	if len(s.producers) > 0 {
		ps := make([]any, len(s.producers))
		for i, p := range s.producers {
			ps[i] = p.omap(modules)
		}
		e.Set("producers", ps)
	}
}

// constrain adds a nested pattern-not's metavariable-regex clauses to its
// not_calls entry. A clause on a metavariable the negated call's arguments do
// not bind cannot be read there: false.
func (s *jsSink) constrain(regexes []jsConstraint) bool {
	for _, c := range regexes {
		if !s.bound[c.metavar] {
			return false
		}
	}
	s.constraints = append(s.constraints, regexes...)
	return true
}

// notEntry is the JSON of a not_calls entry: its argument pattern, its
// constraints and its exceptions when it has any.
func (s *jsSink) notEntry() *OMap {
	e := &OMap{}
	s.setArgs(e)
	if len(s.constraints) > 0 {
		e.Set("constraints", jsConstraints(s.constraints))
	}
	if len(s.notCalls) > 0 {
		except := make([]any, len(s.notCalls))
		for i, x := range s.notCalls {
			except[i] = x.notEntry()
		}
		e.Set("not_calls", except)
	}
	return e
}

func (s *jsSink) setArgs(e *OMap) {
	e.Set("min_arity", int64(s.minArity))
	if s.maxArity != nil {
		e.Set("max_arity", int64(*s.maxArity))
	} else {
		e.Set("max_arity", nil)
	}
	if s.args != nil {
		e.Set("arg_pattern", *s.args)
	}
}

func (c *jsCallee) omap(modules bool) *OMap {
	m := omap("bind", string(c.bind))
	if modules && len(c.modules) > 0 {
		m.Set("modules", jsAnyList(c.modules))
	}
	if c.path != "" {
		m.Set("path", c.path)
	} else if c.pathRegex != "" {
		m.Set("path_regex", c.pathRegex)
	}
	c.setShape(m)
	if len(c.from) == 0 {
		return m
	}
	from := make([]any, len(c.from))
	for i, f := range c.from {
		from[i] = f.fromEntry(modules)
	}
	m.Set("from", from)
	if modules {
		m.Set("via", jsAnyList(c.via))
	}
	return m
}

// setShape sets the callee's flag keys, new through props, in order.
func (c *jsCallee) setShape(m *OMap) {
	if c.isNew {
		m.Set("new", true)
	}
	if c.localRegex != "" {
		m.Set("local_regex", c.localRegex)
	}
	if c.written != "" {
		m.Set("written", c.written)
	}
	if c.localFirst {
		m.Set("local_first", true)
	}
	if c.member {
		m.Set("member", true)
	}
	if c.wrapped {
		m.Set("wrapped", true)
	}
	if c.inline {
		m.Set("inline", true)
	}
	if c.assigned {
		m.Set("assigned", true)
	}
	if c.props != "" {
		m.Set("props", c.props)
	}
}

// fromEntry is a producer as an object callee's from entry: its call
// pattern alone.
func (s *jsSink) fromEntry(modules bool) *OMap {
	e := omap("callee", s.callee.omap(modules))
	s.setMethod(e)
	s.setArgs(e)
	if s.read {
		e.Set("read", true)
	}
	if len(s.constraints) > 0 {
		e.Set("constraints", jsConstraints(s.constraints))
	}
	return e
}

func (s *jsSink) setMethod(e *OMap) {
	if s.callee.method != "" {
		e.Set("method", s.callee.method)
	} else {
		e.Set("method", nil)
	}
}

func jsConstraints(cs []jsConstraint) []any {
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = omap("metavar", c.metavar, "regex", c.regex)
	}
	return out
}

func jsAnyList(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
