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

// The Rust rule compiler. A Rust rule compiles to one entry per positive
// alternative, each carrying a RustPattern in Entry.Rust. It is strict: a
// clause outside the closed shape set, in any branch, skips the whole rule
// with one rustSkip reason, so a Rust entry never has dropped clauses and
// "compiled" means equal to OpenGrep by construction.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/dlclark/regexp2"
)

// The rule clause keys the Rust compiler reads.
const (
	keyPattern          = "pattern"
	keyPatterns         = "patterns"
	keyPatternInside    = "pattern-inside"
	keyPatternNotInside = "pattern-not-inside"
	keyMetavarRegex     = "metavariable-regex"
	keyPatternEither    = "pattern-either"
	keyPatternNot       = "pattern-not"
)

// rustSkip is the closed set of reasons a Rust rule is skipped.
type rustSkip string

const (
	skipRustSanitizers   rustSkip = "rust: taint sanitizers/propagators"
	skipRustSource       rustSkip = "rust: taint source shape"
	skipRustPatternRegex rustSkip = "rust: pattern-regex"
	skipRustFormula      rustSkip = "rust: formula"
	skipRustClause       rustSkip = "rust: clause"
	skipRustSyntax       rustSkip = "rust: unreadable pattern"
	skipRustMacro        rustSkip = "rust: macro"
	skipRustExpr         rustSkip = "rust: expression"
	skipRustType         rustSkip = "rust: type"
	skipRustPositive     rustSkip = "rust: positive shape"
	skipRustPositives    rustSkip = "rust: several positives"
	skipRustNoPositive   rustSkip = "rust: no positive"
	skipRustContext      rustSkip = "rust: context shape"
	skipRustSequence     rustSkip = "rust: sequence context"
	skipRustItem         rustSkip = "rust: item context"
	skipRustNot          rustSkip = "rust: pattern-not shape"
	skipRustUnbound      rustSkip = "rust: metavariable-regex on an unbound metavariable"
	skipRustRegex        rustSkip = "rust: metavariable-regex that does not compile"
	skipRustFocus        rustSkip = "rust: focus-metavariable"
)

// rustSkipReasons is the closed set, for the histogram and its test.
var rustSkipReasons = []rustSkip{
	skipRustSanitizers, skipRustSource, skipRustPatternRegex, skipRustFormula, skipRustClause, skipRustSyntax,
	skipRustMacro, skipRustExpr, skipRustType, skipRustPositive, skipRustPositives,
	skipRustNoPositive, skipRustContext, skipRustSequence, skipRustItem, skipRustNot,
	skipRustUnbound, skipRustRegex, skipRustFocus,
}

func (r rustSkip) err() error { return skip(string(r)) }

// RustPattern is one alternative of a Rust rule: one positive (a call, a
// bare path, an item, a binary expression or a let statement) and the
// filters of every conjunction above it.
type RustPattern struct {
	Call *RustCall `json:"call,omitempty"`
	Ref  *RustPath `json:"ref,omitempty"`
	Item *RustItem `json:"item,omitempty"` // an item written as the pattern (`type $N = A<$C>;`)
	// Let is a let statement written as the pattern (`let $N = $V;`), matched
	// at the let declarations of function bodies.
	Let *RustLet `json:"let,omitempty"`
	// Binary is a binary expression written as the pattern (`$S * $BASE`),
	// a RustExprBinary.
	Binary *RustExpr `json:"binary,omitempty"`
	// Inside: every context holds (a pattern-either of pattern-insides makes
	// one alternative per branch).
	Inside []RustContext `json:"inside,omitempty"`
	// NotInside: the site is dropped when any context holds.
	NotInside []RustContext `json:"not_inside,omitempty"`
	// Not: pattern-not alternatives, each a pattern of its own (a call, or a
	// call with its own contexts), under the same metavariable bindings: the
	// site is dropped when one of them matches it.
	Not []RustPattern `json:"not,omitempty"`
	// Within: the second positive of a conjunction, read as OpenGrep 1.33.1
	// intersects two positives: a site is kept when it lies in a range one of
	// these patterns matches (the site itself or a call around it), under the
	// same metavariable bindings. Each pattern keeps its own contexts and
	// filters, which hold at its range, not at the site. The compiler writes
	// one only when every such pattern specializes a positive of the site's
	// side (rustWithinSide), so the ranges OpenGrep keeps on the other side
	// are sites too.
	Within []RustPattern `json:"within,omitempty"`
	// Where: metavariable-regex filters on what the positive and the insides bind.
	Where []RustWhere `json:"where,omitempty"`
	// Focus: focus-metavariable; the finding is reported at its binding.
	Focus string `json:"focus,omitempty"`
	// Taint: the sources of a taint rule's sink (rust_taint.go).
	Taint *RustTaint `json:"taint,omitempty"`
	// Needs are the fragment fact tables the pattern reads (needsOf).
	Needs RustNeeds `json:"needs"`
}

// RustTaint is what a taint rule's sink must hold, read at intra-file level
// as OpenGrep's --taint-intrafile reads it: a value a regex matches (Values),
// or what a call matching an object source returns (Objects).
type RustTaint struct {
	Values  []RustTaintValue `json:"values,omitempty"`
	Objects []RustPattern    `json:"objects,omitempty"`
}

// RustTaintValue is a source written as a bare metavariable, with the
// metavariable-regex its value matches (nil: any value).
type RustTaintValue struct {
	Metavar string  `json:"metavar"`
	Regex   *string `json:"regex,omitempty"`
}

// RustPlace is where a context sits relative to the site.
type RustPlace string

// The places a context sits.
const (
	RustAround   RustPlace = "around"   // `mod m { ... }`, `$B.sign(...)`: the site is inside it
	RustBefore   RustPlace = "before"   // `use a::B; ...`: it precedes the site in an enclosing block
	RustAfter    RustPlace = "after"    // `... mod m {...}`: it follows the site in an enclosing block
	RustAnywhere RustPlace = "anywhere" // `... mod m {...} ...`: before or after, in an enclosing block
)

// RustContext is one pattern-inside or pattern-not-inside: exactly one of
// Use, ExternCrate, Let, Item and Call is set.
type RustContext struct {
	Place       RustPlace        `json:"place"`
	Use         *RustUse         `json:"use,omitempty"`
	ExternCrate *RustExternCrate `json:"extern_crate,omitempty"`
	Let         *RustLet         `json:"let,omitempty"`
	Item        *RustItem        `json:"item,omitempty"`
	Call        *RustCall        `json:"call,omitempty"`
	// Until is the expression statement that ends a sequence context (`let
	// $N = $V; ... f(&$N)`): the site lies in it, after the statement.
	Until *RustExpr `json:"until,omitempty"`
	// Where filters the metavariables this context binds, from a
	// metavariable-regex written beside it (`pattern-not-inside: {patterns:
	// [pattern: use $X::m; ..., metavariable-regex: $X]}`).
	Where []RustWhere `json:"where,omitempty"`
}

// RustUse is `use Path;`, `use Path::*;` or `use Path as Alias;`. A lone
// metavariable path (`use $IMPORT;`) binds the whole written tree; OpenGrep
// 1.22.0 binds it, for a grouped `use a::{B, c::D};`, to several partial
// token ranges (`a::B`, `a::{B`, `a::{B, c::D`), one result each.
type RustUse struct {
	Path  RustPath `json:"path"`
	Glob  bool     `json:"glob,omitempty"`
	Alias string   `json:"alias,omitempty"`
}

// RustExternCrate is `extern crate Name;` or `extern crate Name as Alias;`
// (each a name or a metavariable).
type RustExternCrate struct {
	Name  string `json:"name"`
	Alias string `json:"alias,omitempty"`
}

// RustLet is `let [mut] Name = Init;` or `let (A, B) = Init;` (each name a
// metavariable, a name or `_`).
type RustLet struct {
	Name  string    `json:"name,omitempty"`
	Tuple []string  `json:"tuple,omitempty"`
	Mut   bool      `json:"mut,omitempty"`
	Type  *RustType `json:"type,omitempty"`
	Init  RustExpr  `json:"init"`
	// src is where a let read from source text is written; nil for a
	// pattern's.
	src *rustLetSrc
}

// rustLetSrc is where the parts of a let read from source text are written:
// byte offsets in that text, end exclusive.
type rustLetSrc struct {
	text string
	pat  int    // the pattern after `let`, `mut` included
	name [2]int // the name, or the tuple pattern
	init [2]int // the initializer, without the `;`
}

// patText is the pattern after `let` as written, without `mut`.
func (l *RustLet) patText() string {
	return l.src.text[l.src.name[0]:l.src.name[1]]
}

// initText is the initializer as written, what a metavariable binds it to.
func (l *RustLet) initText() string {
	if l.src == nil {
		return l.Init.String()
	}
	return l.src.text[l.src.init[0]:l.src.init[1]]
}

// RustItem is an item: `mod m {...}`, `struct S ...`, `impl S {...}`,
// `fn f(..., $P: T, ...) -> R {...}`, `type T = U;` or `const/static Name:
// Type = Value;`, optionally `pub`. A body is never constrained (`{...}`).
type RustItem struct {
	Kind   string      `json:"kind"` // mod, struct, impl, fn, type, const, static
	Pub    bool        `json:"pub,omitempty"`
	Name   string      `json:"name"`
	Params []RustParam `json:"params,omitempty"` // fn
	Type   *RustType   `json:"type,omitempty"`   // const/static type, type alias target, fn return type
	Value  *RustExpr   `json:"value,omitempty"`  // const/static value
	// Use is the use a fn body declares, written `{ ... use P; ... }`.
	Use *RustUse `json:"use,omitempty"`
}

// RustParam is a fn parameter pattern: `...` or `name: Type` (the name a
// metavariable or a name).
type RustParam struct {
	Ellipsis bool      `json:"ellipsis,omitempty"`
	Name     string    `json:"name,omitempty"`
	Type     *RustType `json:"type,omitempty"`
}

// RustWhere is one metavariable-regex (Python spelling, read with re.match).
type RustWhere struct {
	Metavar string `json:"metavar"`
	Regex   string `json:"regex"`
}

// RustNeeds are the fragment fact tables a pattern reads beyond the call
// sites and source lines every Rust fragment carries.
type RustNeeds struct {
	Imports      bool `json:"imports,omitempty"`      // use and extern crate contexts
	Items        bool `json:"items,omitempty"`        // item contexts and item positives
	Declarations bool `json:"declarations,omitempty"` // let contexts
	Refs         bool `json:"refs,omitempty"`         // bare path positives
	// Binaries: binary expression positives, and a sequence context's end
	// (graph-fragment-1.30). Params: fn item contexts whose parameter list
	// is not `...` only (graph-fragment-1.30).
	Binaries bool `json:"binaries,omitempty"`
	Params   bool `json:"params,omitempty"`
}

// check rejects a metavariable-regex or focus-metavariable on a metavariable
// nothing binds (outer: what the enclosing pattern binds) and sets the needs.
func (p *RustPattern) check(outer map[string]bool) error {
	bound := maps.Clone(outer)
	p.binds(bound)
	for _, w := range p.Where {
		if !bound[w.Metavar] {
			return skipRustUnbound.err()
		}
	}
	for _, c := range p.NotInside {
		local := maps.Clone(bound)
		c.vars(local)
		for _, w := range c.Where {
			if !local[w.Metavar] {
				return skipRustUnbound.err()
			}
		}
	}
	if p.Focus != "" && !bound[p.Focus] {
		return skipRustFocus.err()
	}
	for i := range p.Not {
		if err := p.Not[i].check(bound); err != nil {
			return err
		}
	}
	for i := range p.Within {
		// A within pattern is matched on its own range: its filters read
		// only what it binds.
		if err := p.Within[i].check(map[string]bool{}); err != nil {
			return err
		}
	}
	p.Needs = needsOf(p)
	return nil
}

// binds adds the metavariables a match of p binds: its positive's, its
// insides' and its within patterns'.
func (p *RustPattern) binds(out map[string]bool) {
	switch {
	case p.Call != nil:
		p.Call.vars(out)
	case p.Ref != nil:
		p.Ref.vars(out)
	case p.Item != nil:
		p.Item.vars(out)
	case p.Binary != nil:
		p.Binary.vars(out)
	case p.Let != nil:
		(&RustContext{Let: p.Let}).vars(out)
	}
	for i := range p.Inside {
		p.Inside[i].vars(out)
	}
	for i := range p.Within {
		p.Within[i].binds(out)
	}
}

// whereBound: every metavariable-regex of p, and of its within patterns,
// names a metavariable the pattern binds. OpenGrep 1.33.1 reads one that
// names an unbound metavariable as matching nothing: the alternative is
// dropped, not the rule.
func (p *RustPattern) whereBound() bool {
	bound := map[string]bool{}
	p.binds(bound)
	for _, w := range p.Where {
		if !bound[w.Metavar] {
			return false
		}
	}
	for i := range p.Within {
		if !p.Within[i].whereBound() {
			return false
		}
	}
	return true
}

// needsOf derives a pattern's needs from its clauses; nothing else sets them.
func needsOf(p *RustPattern) RustNeeds {
	n := RustNeeds{Refs: p.Ref != nil, Items: p.Item != nil, Binaries: p.Binary != nil, Declarations: p.Let != nil}
	subs := slices.Concat(p.Not, p.Within)
	if p.Taint != nil {
		subs = append(subs, p.Taint.Objects...)
	}
	for i := range subs {
		m := needsOf(&subs[i])
		n = RustNeeds{
			Imports: n.Imports || m.Imports, Items: n.Items || m.Items, Declarations: n.Declarations || m.Declarations, Refs: n.Refs || m.Refs,
			Binaries: n.Binaries || m.Binaries, Params: n.Params || m.Params,
		}
	}
	for _, c := range append(append([]RustContext{}, p.Inside...), p.NotInside...) {
		n.addContext(&c)
	}
	return n
}

// addContext adds the fact tables the context c reads.
func (n *RustNeeds) addContext(c *RustContext) {
	n.Imports = n.Imports || c.Use != nil || c.ExternCrate != nil
	n.Items = n.Items || c.Item != nil
	n.Imports = n.Imports || (c.Item != nil && c.Item.Use != nil)
	n.Declarations = n.Declarations || c.Let != nil
	n.Binaries = n.Binaries || (c.Until != nil && rustHasBinary(c.Until))
	n.Params = n.Params || (c.Item != nil && rustFnReadsParams(c.Item))
}

// rustHasBinary: e is or holds a binary expression.
func rustHasBinary(e *RustExpr) bool {
	return rustWalk(*e, func(x RustExpr) bool { return x.Kind == RustExprBinary })
}

// rustFnReadsParams: the fn item it is decided from its parameters
// (graph-fragment-1.30), not only its name and span: its parameter list is
// not `...` only.
func rustFnReadsParams(it *RustItem) bool {
	if it.Kind != "fn" || it.Use != nil {
		return false
	}
	return !rustParamsAnyList(it.Params)
}

// rustParamsAnyList: a non-empty parameter list of `...` only, which every
// parameter list matches.
func rustParamsAnyList(params []RustParam) bool {
	for _, prm := range params {
		if !prm.Ellipsis {
			return false
		}
	}
	return len(params) > 0
}

// positive: the pattern has its positive (it is not a filter-only conjunction).
func (p *RustPattern) positive() bool {
	return p.Call != nil || p.Ref != nil || p.Item != nil || p.Binary != nil || p.Let != nil
}

// compileRustRule compiles a Rust rule into its entries, one per positive
// alternative, or skips the whole rule with one rustSkip reason.
func compileRustRule(r *OMap) ([]*OMap, error) {
	if asOr[string](r.GetOr("mode")) == strTaint {
		return compileRustTaint(r)
	}
	node := &OMap{}
	for _, k := range []string{keyPattern, keyPatternEither, keyPatterns} {
		if v, has := r.Get(k); has {
			node.Set(k, v)
		}
	}
	if node.Len() != 1 {
		if r.Has("pattern-regex") || r.Has("pattern-not-regex") {
			return nil, skipRustPatternRegex.err()
		}
		return nil, skipRustFormula.err()
	}
	alts, err := rustAlternatives(node)
	if err != nil {
		return nil, err
	}
	out := make([]*OMap, 0, len(alts))
	for _, a := range alts {
		if !a.positive() {
			return nil, skipRustNoPositive.err()
		}
		if !a.whereBound() {
			if len(a.Within) > 0 {
				// The positive that a within pattern specializes may be
				// what is dropped; OpenGrep then still keeps the ranges it
				// matches inside the other side's.
				return nil, skipRustPositives.err()
			}
			continue
		}
		e, err := rustEntry(a)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, skipRustUnbound.err()
	}
	return out, nil
}

// rustEntry checks an alternative's bindings and gives its index entry: the
// method bucket and arity the shared Entry fields carry, and the pattern.
func rustEntry(p *RustPattern) (*OMap, error) {
	if err := p.check(map[string]bool{}); err != nil {
		return nil, err
	}
	var method any
	minArity, maxArity := 0, -1
	switch {
	case p.Call != nil && p.Call.Callee != nil:
		if last := p.Call.Callee.Last(); last.Var == "" {
			method = last.Name
		}
		minArity, maxArity = p.Call.Arity()
	case p.Call != nil:
		if !isMetavar(p.Call.Method) {
			method = p.Call.Method
		}
		minArity, maxArity = p.Call.Arity()
	}
	var maxA any
	if maxArity >= 0 {
		maxA = int64(maxArity)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("rust pattern: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	rust, err := decodeOrdered(dec)
	if err != nil {
		return nil, fmt.Errorf("rust pattern: %w", err)
	}
	return omap("method", method, "min_arity", int64(minArity), "max_arity", maxA, "rust", rust, "dropped_clauses", []any{}), nil
}

// rustList is a clause's list value; anything else reads as an empty list,
// which no rule shape accepts.
func rustList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func isMetavar(s string) bool { return len(s) > 1 && s[0] == '$' }

// rustAlternatives expands a formula node (one key: pattern, pattern-either,
// patterns or pattern-inside) into its alternatives. pattern-either is a
// union, so every alternative is an entry of its own; an alternative without
// a positive (a pattern-either branch of pattern-insides) is a filter that a
// conjunction joins with its positive.
func rustAlternatives(node *OMap) ([]*RustPattern, error) {
	if node.Len() != 1 {
		return nil, skipRustFormula.err()
	}
	val := node.Vals[0]
	switch asOr[string](node.Keys[0]) {
	case keyPattern:
		p, err := rustPositive(val)
		if err != nil {
			return nil, err
		}
		return []*RustPattern{p}, nil
	case keyPatternEither:
		branches := rustList(val)
		if len(branches) == 0 {
			// An empty or non-list either has no branch OpenGrep could
			// match; compiling it to no entry would count a rule that
			// matches nothing as compiled.
			return nil, skipRustFormula.err()
		}
		var out []*RustPattern
		for _, b := range branches {
			bm, ok := b.(*OMap)
			if !ok {
				return nil, skipRustFormula.err()
			}
			alts, err := rustAlternatives(bm)
			if err != nil {
				return nil, err
			}
			out = append(out, alts...)
		}
		return out, nil
	case keyPatterns:
		return rustConjunction(rustList(val))
	case keyPatternInside:
		c, err := rustContextOf(val)
		if err != nil {
			return nil, err
		}
		return []*RustPattern{{Inside: []RustContext{c}}}, nil
	case "pattern-regex", "pattern-not-regex":
		return nil, skipRustPatternRegex.err()
	case keyPatternNotInside, keyPatternNot:
		return nil, skipRustNoPositive.err()
	}
	return nil, skipRustClause.err()
}

// rustConjunction compiles the items of a `patterns`: the product of its
// alternatives-bearing items (a second positive becomes a within pattern,
// rustProduct), each joined with the conjunction's other clauses.
func rustConjunction(items []any) ([]*RustPattern, error) { //nolint:gocognit,gocyclo // one case per clause kind of the closed set
	if len(items) == 0 {
		return nil, skipRustFormula.err()
	}
	alts := []*RustPattern{{}}
	var f RustPattern
	for _, it := range items {
		m, ok := it.(*OMap)
		if !ok || m.Len() != 1 {
			return nil, skipRustFormula.err()
		}
		key := asOr[string](m.Keys[0])
		val := m.Vals[0]
		switch key {
		case keyPattern, keyPatterns, keyPatternEither, keyPatternInside:
			branch, err := rustAlternatives(m)
			if err != nil {
				return nil, err
			}
			if alts, err = rustProduct(alts, branch); err != nil {
				return nil, err
			}
		case keyPatternNotInside, keyPatternNot:
			if err := f.addNegative(key, val); err != nil {
				return nil, err
			}
		case keyMetavarRegex:
			w, err := rustWhereOf(val)
			if err != nil {
				return nil, err
			}
			f.Where = append(f.Where, w)
		case "focus-metavariable":
			v := val
			if l, isList := val.([]any); isList && len(l) == 1 {
				v = l[0]
			}
			s, isStr := v.(string)
			if !isStr || !isMetavar(s) || f.Focus != "" {
				return nil, skipRustFocus.err()
			}
			f.Focus = s
		case "pattern-regex", "pattern-not-regex":
			return nil, skipRustPatternRegex.err()
		default:
			return nil, skipRustClause.err()
		}
	}
	out, err := rustProduct(alts, []*RustPattern{&f})
	if err != nil {
		return nil, err
	}
	for _, a := range out {
		if !a.positive() && len(a.NotInside)+len(a.Not) > 0 {
			// A conjunction of contexts (a pattern-either branch) keeps the
			// context ranges no negative holds over, not the sites: OpenGrep
			// 1.33.1 keeps a site inside a not-inside context when the
			// branch's own context range is not inside it.
			return nil, skipRustContext.err()
		}
	}
	return out, nil
}

// rustProduct joins every alternative of a with every one of b: their
// positives and their filters. When both have a positive, OpenGrep 1.33.1
// keeps a range of one side that lies in a range of the other (the same
// range or one around it), from either side: the positive of the side
// rustWithinSide names the base stays the site's, the other becomes a
// within pattern of it.
func rustProduct(a, b []*RustPattern) ([]*RustPattern, error) {
	baseB, err := rustWithinSide(a, b)
	if err != nil {
		return nil, err
	}
	out := make([]*RustPattern, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			j, err := rustJoinAlts(x, y, baseB)
			if err != nil {
				return nil, err
			}
			out = append(out, j)
		}
	}
	return out, nil
}

// rustJoinAlts joins two alternatives. When both have a positive, the one of
// the base side (y's when baseB) stays the site's and the other, whole,
// becomes its within pattern.
func rustJoinAlts(x, y *RustPattern, baseB bool) (*RustPattern, error) {
	if x.positive() && y.positive() {
		base, in := x, y
		if baseB {
			base, in = y, x
		}
		if in.Focus != "" {
			return nil, skipRustFocus.err()
		}
		j := *base
		j.Within = append(slices.Clone(base.Within), *in)
		return &j, nil
	}
	if x.Focus != "" && y.Focus != "" {
		return nil, skipRustFocus.err()
	}
	j := &RustPattern{
		Call: x.Call, Ref: x.Ref, Item: x.Item, Binary: x.Binary, Let: x.Let, Focus: x.Focus + y.Focus,
		Inside:    slices.Concat(x.Inside, y.Inside),
		NotInside: slices.Concat(x.NotInside, y.NotInside),
		Not:       slices.Concat(x.Not, y.Not),
		Where:     slices.Concat(x.Where, y.Where),
		Within:    slices.Concat(x.Within, y.Within),
	}
	if y.positive() {
		j.Call, j.Ref, j.Item, j.Binary, j.Let = y.Call, y.Ref, y.Item, y.Binary, y.Let
	}
	return j, nil
}

// rustWithinSide picks, when both a and b have positives, the side whose
// positives stay the sites' (baseB: b's). OpenGrep also reports a range of
// the other side that lies in a site of the base side, so that range must be
// a site of the base side too: every positive of the other side specializes
// one of the base side, whose positives carry no filter but the same
// contexts (which a range inside a site inherits). Otherwise the rule is
// skipped.
func rustWithinSide(a, b []*RustPattern) (baseB bool, err error) {
	pa := slices.DeleteFunc(slices.Clone(a), func(p *RustPattern) bool { return !p.positive() })
	pb := slices.DeleteFunc(slices.Clone(b), func(p *RustPattern) bool { return !p.positive() })
	switch {
	case len(pa) == 0 || len(pb) == 0:
		return false, nil
	case rustBase(pa) && rustAllSpecialize(pb, pa):
		return false, nil
	case rustBase(pb) && rustAllSpecialize(pa, pb):
		return true, nil
	}
	return false, skipRustPositives.err()
}

// rustBase: the positives carry no negative, regex or within pattern, and
// the same contexts.
func rustBase(ps []*RustPattern) bool {
	for _, p := range ps {
		if len(p.NotInside)+len(p.Not)+len(p.Where)+len(p.Within) > 0 || p.Focus != "" ||
			!reflect.DeepEqual(p.Inside, ps[0].Inside) {
			return false
		}
	}
	return true
}

// rustAllSpecialize: every pattern of in specializes a pattern of base.
func rustAllSpecialize(in, base []*RustPattern) bool {
	for _, y := range in {
		if !slices.ContainsFunc(base, func(x *RustPattern) bool { return rustSpecializes(y, x) }) {
			return false
		}
	}
	return true
}

// rustNegativeContext reads `patterns: [K: text, metavariable-regex...]`, K
// one of ctxKeys, as one context with its own filters; isCtx is false when
// the items are not of that shape.
func rustNegativeContext(val any, ctxKeys ...string) (c RustContext, isCtx bool, err error) {
	m, ok := val.(*OMap)
	if !ok || m.Len() != 1 || asOr[string](m.Keys[0]) != keyPatterns {
		return c, false, nil
	}
	var text any
	var where []RustWhere
	for _, it := range rustList(m.Vals[0]) {
		im, ok := it.(*OMap)
		if !ok || im.Len() != 1 {
			return c, false, nil
		}
		switch k := asOr[string](im.Keys[0]); {
		case slices.Contains(ctxKeys, k):
			if text != nil {
				return c, false, nil
			}
			text = im.Vals[0]
		case k == keyMetavarRegex:
			w, err := rustWhereOf(im.Vals[0])
			if err != nil {
				return c, true, err
			}
			where = append(where, w)
		default:
			return c, false, nil
		}
	}
	if text == nil {
		return c, false, nil
	}
	c, err = rustContextOf(text)
	c.Where = where
	return c, true, err
}

// addNegative compiles a pattern-not-inside or a pattern-not. A pattern-not
// of a conjunction whose only positive is a pattern-inside reads as a
// pattern-not-inside: OpenGrep's pattern-inside ranges keep their inside
// kind, and a negative of that kind removes the positives it includes.
func (p *RustPattern) addNegative(key string, val any) error {
	_, isText := val.(string)
	if key == keyPatternNotInside && isText {
		c, err := rustContextOf(val)
		p.NotInside = append(p.NotInside, c)
		return err
	}
	ctxKeys := []string{keyPatternInside}
	if key == keyPatternNotInside {
		ctxKeys = append(ctxKeys, keyPattern)
	}
	c, isCtx, err := rustNegativeContext(val, ctxKeys...)
	switch {
	case err != nil:
		return err
	case isCtx:
		p.NotInside = append(p.NotInside, c)
		return nil
	case key == keyPatternNotInside:
		return skipRustNot.err()
	}
	node, isMap := val.(*OMap)
	if !isMap {
		node = omap(keyPattern, val)
	}
	alts, err := rustAlternatives(node)
	if err != nil {
		return err
	}
	for _, a := range alts {
		if !a.positive() || a.Focus != "" || len(a.Within) > 0 {
			return skipRustNot.err()
		}
		p.Not = append(p.Not, *a)
	}
	return nil
}

// rustWhereOf reads a metavariable-regex.
func rustWhereOf(val any) (RustWhere, error) {
	m, ok := val.(*OMap)
	if !ok || m.Len() != 2 {
		return RustWhere{}, skipRustClause.err()
	}
	mv, okMv := m.GetOr("metavariable").(string)
	rx, okRx := m.GetOr("regex").(string)
	if !okMv || !okRx || !isMetavar(mv) {
		return RustWhere{}, skipRustClause.err()
	}
	rx = pcreToPyText(rx)
	if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
		return RustWhere{}, skipRustRegex.err()
	}
	return RustWhere{Metavar: mv, Regex: rx}, nil
}

// rustPositive reads a pattern's text: a call, a bare path, an item, a
// binary expression or a let statement.
func rustPositive(val any) (*RustPattern, error) {
	text, ok := val.(string)
	if !ok {
		return nil, skipRustFormula.err()
	}
	toks, err := lexRust(text)
	if err != nil {
		return nil, skipRustSyntax.err()
	}
	p := &rustParser{toks: toks, pattern: true}
	if p.accept("let") {
		l, err := p.parseLet()
		if err != nil {
			return nil, err
		}
		if !p.eof() {
			return nil, skipRustPositive.err()
		}
		return &RustPattern{Let: l}, nil
	}
	if p.startsItem() {
		it, err := p.parseItem()
		if err != nil {
			return nil, err
		}
		if !p.eof() {
			return nil, skipRustPositive.err()
		}
		return &RustPattern{Item: it}, nil
	}
	e, err := parseRustPatternExpr(text)
	if err != nil {
		return nil, err
	}
	if e.Kind == RustExprCall {
		return &RustPattern{Call: e.Call}, nil
	}
	if e.Kind == RustExprPath {
		return &RustPattern{Ref: e.Path}, nil
	}
	if e.Kind == RustExprBinary {
		return &RustPattern{Binary: e}, nil
	}
	return nil, skipRustPositive.err()
}

// rustContextOf reads a pattern-inside or pattern-not-inside text: one
// statement, item or call, with `...` before it, after it, both or neither,
// or a statement, `...` and the expression statement that ends the range.
func rustContextOf(val any) (RustContext, error) {
	text, ok := val.(string)
	if !ok {
		return RustContext{}, skipRustContext.err()
	}
	toks, err := lexRust(text)
	if err != nil {
		return RustContext{}, skipRustSyntax.err()
	}
	p := &rustParser{toks: toks, pattern: true}
	lead := p.accept(rustEllipsis)
	c, err := p.parseStatement()
	if err != nil {
		return RustContext{}, err
	}
	trail := p.accept(rustEllipsis)
	trail = trail || p.structRange(&c)
	if trail && !lead && !p.eof() {
		until, err := p.parseExpr()
		if err != nil {
			return RustContext{}, err
		}
		p.accept(";")
		c.Until = until
		trail = false
	}
	if !p.eof() {
		return RustContext{}, skipRustSequence.err()
	}
	switch {
	case lead && trail:
		c.Place = RustAnywhere
	case lead:
		c.Place = RustAfter
	case trail || c.Until != nil:
		c.Place = RustBefore
	default:
		c.Place = RustAround
	}
	return c, nil
}

// structRange: a struct context written `struct S ...` ends in the range's
// `...`: OpenGrep 1.22.0 reads `... struct S ...` as a struct anywhere in
// the block, `struct S ... ...` as one before the site.
func (p *rustParser) structRange(c *RustContext) bool {
	return c.Item != nil && c.Item.Kind == rustItemStruct && p.eof() && p.toks[p.i-1].text == rustEllipsis
}

// parseStatement reads one context statement.
func (p *rustParser) parseStatement() (RustContext, error) {
	switch {
	case p.accept("use"):
		u, err := p.parseUse()
		return RustContext{Use: u}, err
	case p.accept("extern"):
		x, err := p.parseExternCrate()
		return RustContext{ExternCrate: x}, err
	case p.accept("let"):
		l, err := p.parseLet()
		if err != nil {
			return RustContext{}, err
		}
		return RustContext{Let: l}, nil
	case p.startsItem():
		it, err := p.parseItem()
		if err != nil {
			return RustContext{}, err
		}
		return RustContext{Item: it}, nil
	case p.segStart() || p.is("::") || p.is("<"):
		e, err := p.parseExpr()
		if err != nil {
			return RustContext{}, err
		}
		if e.Kind != RustExprCall {
			return RustContext{}, skipRustContext.err()
		}
		p.accept(";")
		return RustContext{Call: e.Call}, nil
	}
	return RustContext{}, skipRustContext.err()
}

// parseUse reads a use declaration after the `use`.
func (p *rustParser) parseUse() (*RustUse, error) {
	path, err := p.parsePath(true)
	if err != nil {
		return nil, skipRustContext.err()
	}
	u := &RustUse{Path: *path}
	switch {
	case p.is("::") && p.peekAt(1).text == "*":
		p.i += 2
		u.Glob = true
	case p.accept("as"):
		if u.Alias, err = p.name(); err != nil {
			return nil, err
		}
	}
	return u, p.expect(";", skipRustContext)
}

// parseExternCrate reads `crate name [as alias];` after the `extern`.
func (p *rustParser) parseExternCrate() (*RustExternCrate, error) {
	if err := p.expect("crate", skipRustContext); err != nil {
		return nil, err
	}
	x := &RustExternCrate{}
	var err error
	if x.Name, err = p.name(); err != nil {
		return nil, err
	}
	if p.accept("as") {
		if x.Alias, err = p.name(); err != nil {
			return nil, err
		}
	}
	return x, p.expect(";", skipRustContext)
}

// parseLet reads a let statement after the `let`.
func (p *rustParser) parseLet() (*RustLet, error) {
	l := &RustLet{Mut: p.accept("mut")}
	if p.accept("(") {
		l.Tuple = []string{}
		for !p.accept(")") {
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			l.Tuple = append(l.Tuple, n)
			if !p.accept(",") && !p.is(")") {
				return nil, skipRustContext.err()
			}
		}
	} else {
		var err error
		if l.Name, err = p.name(); err != nil {
			return nil, err
		}
	}
	if p.accept(":") {
		t, err := p.parseType()
		if err != nil {
			return nil, err
		}
		l.Type = &t
	}
	if err := p.expect("=", skipRustContext); err != nil {
		return nil, err
	}
	init, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	l.Init = *init
	if err := p.expect(";", skipRustContext); err != nil {
		return nil, err
	}
	return l, nil
}

// rustItemKinds are the items a pattern can write.
var rustItemKinds = setOf("mod", "struct", "impl", "fn", "type", "const", "static")

// startsItem: the current token starts an item (or `pub` and an item).
func (p *rustParser) startsItem() bool {
	t := p.peekAt(0)
	if t.text == "pub" {
		t = p.peekAt(1)
	}
	return t.kind == rtIdent && rustItemKinds[t.text]
}

// parseItem reads `[pub] mod|struct|impl|fn|type|const|static Name ...`.
func (p *rustParser) parseItem() (*RustItem, error) {
	it := &RustItem{Pub: p.accept("pub")}
	it.Kind = p.toks[p.i].text
	p.i++
	var err error
	if it.Name, err = p.name(); err != nil {
		return nil, skipRustItem.err()
	}
	switch it.Kind {
	case "mod", "impl":
		return it, p.itemBody(false)
	case rustItemStruct:
		return it, p.itemBody(true)
	case "fn":
		return it, p.parseFn(it)
	case "type":
		if err := p.expect("=", skipRustItem); err != nil {
			return nil, err
		}
		t, err := p.parseType()
		if err != nil {
			return nil, err
		}
		it.Type = &t
		return it, p.expect(";", skipRustItem)
	}
	if err := p.expect(":", skipRustItem); err != nil {
		return nil, err
	}
	t, err := p.parseType()
	if err != nil {
		return nil, err
	}
	it.Type = &t
	if err := p.expect("=", skipRustItem); err != nil {
		return nil, err
	}
	if it.Value, err = p.parseExpr(); err != nil {
		return nil, err
	}
	return it, p.expect(";", skipRustItem)
}

// itemBody reads an item's body: `;`, `{}` or `{...}`, and for a struct a
// bare `...`.
func (p *rustParser) itemBody(bareEllipsis bool) error {
	switch {
	case p.accept(";"):
		return nil
	case bareEllipsis && p.accept(rustEllipsis):
		return nil
	case p.accept("{"):
		p.accept(rustEllipsis)
		return p.expect("}", skipRustItem)
	}
	return skipRustItem.err()
}

// parseFn reads a fn's parameters, return type and body.
func (p *rustParser) parseFn(it *RustItem) error {
	var err error
	if it.Params, err = p.parseParams(); err != nil {
		return err
	}
	if p.accept("->") {
		t, err := p.parseType()
		if err != nil {
			return err
		}
		it.Type = &t
	}
	if p.is("{") && p.peekAt(1).text == rustEllipsis && p.peekAt(2).text == "use" {
		it.Use, err = p.bodyUse()
		return err
	}
	return p.itemBody(false)
}

// bodyUse reads a fn body that declares a use: `{ ... use P; ... }`.
func (p *rustParser) bodyUse() (*RustUse, error) {
	p.i += 3 // `{`, `...`, `use`
	u, err := p.parseUse()
	if err != nil {
		return nil, err
	}
	if err := p.expect(rustEllipsis, skipRustItem); err != nil {
		return nil, err
	}
	return u, p.expect("}", skipRustItem)
}

// parseParams reads a fn's parameters: `...` or `name: Type` each.
func (p *rustParser) parseParams() ([]RustParam, error) {
	if err := p.expect("(", skipRustItem); err != nil {
		return nil, err
	}
	params := []RustParam{}
	for !p.accept(")") {
		if p.accept(rustEllipsis) {
			params = append(params, RustParam{Ellipsis: true})
		} else {
			n, err := p.name()
			if err != nil {
				return nil, skipRustItem.err()
			}
			if err := p.expect(":", skipRustItem); err != nil {
				return nil, err
			}
			t, err := p.parseType()
			if err != nil {
				return nil, err
			}
			params = append(params, RustParam{Name: n, Type: &t})
		}
		if !p.accept(",") && !p.is(")") {
			return nil, skipRustItem.err()
		}
	}
	return params, nil
}

// name reads a binding or item name: an identifier or a metavariable.
func (p *rustParser) name() (string, error) {
	if !p.segStart() {
		return "", skipRustContext.err()
	}
	p.i++
	return p.toks[p.i-1].text, nil
}

// vars adds the metavariables a pattern part binds.
func (c *RustCall) vars(out map[string]bool) {
	if c.Callee != nil {
		c.Callee.vars(out)
	}
	if c.Receiver != nil {
		c.Receiver.vars(out)
	}
	if isMetavar(c.Method) {
		out[c.Method] = true
	}
	typeVars(c.Turbofish, out)
	for i := range c.Args {
		c.Args[i].vars(out)
	}
}

func (p *RustPath) vars(out map[string]bool) {
	if p.QSelf != nil {
		p.QSelf.Self.vars(out)
		if p.QSelf.Trait != nil {
			p.QSelf.Trait.vars(out)
		}
	}
	for _, s := range p.Segs {
		if s.Var != "" {
			out[s.Var] = true
		}
		typeVars(s.Generics, out)
	}
}

func (t RustType) vars(out map[string]bool) {
	if t.Var != "" {
		out[t.Var] = true
	}
	typeVars(t.Tuple, out)
	if t.Path != nil {
		t.Path.vars(out)
	}
	if t.Ref != nil {
		t.Ref.vars(out)
	}
}

func typeVars(ts []RustType, out map[string]bool) {
	for _, t := range ts {
		t.vars(out)
	}
}

func (e *RustExpr) vars(out map[string]bool) {
	if e.Var != "" {
		out[e.Var] = true
	}
	if e.Path != nil {
		e.Path.vars(out)
	}
	if e.Sub != nil {
		e.Sub.vars(out)
	}
	if e.Index != nil {
		e.Index.vars(out)
	}
	if e.Right != nil {
		e.Right.vars(out)
	}
	if e.Call != nil {
		e.Call.vars(out)
	}
}

func (c *RustContext) vars(out map[string]bool) {
	addName := func(s string) {
		if isMetavar(s) {
			out[s] = true
		}
	}
	switch {
	case c.Use != nil:
		c.Use.Path.vars(out)
		addName(c.Use.Alias)
	case c.ExternCrate != nil:
		addName(c.ExternCrate.Name)
		addName(c.ExternCrate.Alias)
	case c.Let != nil:
		addName(c.Let.Name)
		for _, n := range c.Let.Tuple {
			addName(n)
		}
		if c.Let.Type != nil {
			c.Let.Type.vars(out)
		}
		c.Let.Init.vars(out)
	case c.Item != nil:
		c.Item.vars(out)
	case c.Call != nil:
		c.Call.vars(out)
	}
	if c.Until != nil {
		c.Until.vars(out)
	}
}

func (it *RustItem) vars(out map[string]bool) {
	if isMetavar(it.Name) {
		out[it.Name] = true
	}
	for _, prm := range it.Params {
		if isMetavar(prm.Name) {
			out[prm.Name] = true
		}
		if prm.Type != nil {
			prm.Type.vars(out)
		}
	}
	if it.Type != nil {
		it.Type.vars(out)
	}
	if it.Value != nil {
		it.Value.vars(out)
	}
	if it.Use != nil {
		(&RustContext{Use: it.Use}).vars(out)
	}
}
