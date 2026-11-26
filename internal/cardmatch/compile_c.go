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

// The C rule compiler. A C rule compiles to one entry per positive
// alternative, each carrying a CPattern in Entry.C. It is strict, as the Rust
// compiler is: a clause outside the closed shape set, in any branch, skips the
// whole rule with one cSkip reason, so a C entry never has dropped clauses
// and "compiled" means equal to OpenGrep by construction.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/dlclark/regexp2"
)

// The rule clause keys the C compiler reads besides the Rust compiler's.
const (
	keyPatternRegex    = "pattern-regex"
	keyPatternNotRegex = "pattern-not-regex"
	keyFocusMetavar    = "focus-metavariable"
)

// cSkip is the closed set of reasons a C rule is skipped.
type cSkip string

const (
	skipCTaintSanitizers cSkip = "c: taint sanitizers/propagators"
	skipCTaintSource     cSkip = "c: taint source shape"
	skipCTaintSink       cSkip = "c: taint sink shape"
	skipCPatternRegex    cSkip = "c: pattern-regex"
	skipCFormula         cSkip = "c: formula"
	skipCClause          cSkip = "c: clause"
	skipCSyntax          cSkip = "c: unreadable pattern"
	skipCStatement       cSkip = "c: statement"
	skipCString          cSkip = "c: string literal"
	skipCExpr            cSkip = "c: expression"
	skipCBareExpr        cSkip = "c: bare expression"
	skipCPositives       cSkip = "c: several positives"
	skipCNoPositive      cSkip = "c: no positive"
	skipCContext         cSkip = "c: context shape"
	skipCSequence        cSkip = "c: sequence context"
	skipCFunction        cSkip = "c: function context"
	skipCDeclaration     cSkip = "c: declaration context"
	skipCNot             cSkip = "c: pattern-not shape"
	skipCUnbound         cSkip = "c: metavariable-regex on an unbound metavariable"
	skipCOrOperand       cSkip = "c: metavariable read from a | operand"
	skipCRegex           cSkip = "c: metavariable-regex that does not compile"
	skipCFocus           cSkip = "c: focus-metavariable"
)

// cSkipReasons is the closed set, for the histogram and its test.
var cSkipReasons = []cSkip{
	skipCTaintSanitizers, skipCTaintSource, skipCTaintSink, skipCPatternRegex, skipCFormula, skipCClause, skipCSyntax, skipCStatement, skipCString,
	skipCExpr, skipCBareExpr, skipCPositives, skipCNoPositive, skipCContext, skipCSequence, skipCFunction,
	skipCDeclaration, skipCNot, skipCUnbound, skipCOrOperand, skipCRegex, skipCFocus, skipCPPConstruct, skipCPPTyped, skipCPPRegex,
}

func (r cSkip) err() error { return skip(string(r)) }

// CPattern is one alternative of a C rule: one positive (a call, a bare
// metavariable read inside a call context, or a regex over #include
// directives) and the filters of every conjunction above it.
type CPattern struct {
	Call *CExpr `json:"call,omitempty"`
	// Stmt: the call is written as a statement pattern, `f(...);`: it
	// matches a call of an expression statement, a declaration or a return,
	// not one in a condition (an if, while, for or switch header).
	Stmt bool `json:"stmt,omitempty"`
	// Store is an assignment to a field positive, `$J->mode = $V`: it
	// matches the fragment's field stores.
	Store *CExpr `json:"store,omitempty"`
	// Expr is a bare metavariable positive: every expression written inside
	// the call an around context matches (the callee and the call included).
	Expr *CExpr `json:"expr,omitempty"`
	// Str is a string literal positive, `"$X"` (or a literal content): it
	// matches the fragment's string literals, each piece of a concatenation
	// on its own; StrRegex are the pattern-regex filters beside it, each read
	// as OpenGrep intersects ranges: a match within the literal, reported at
	// the match.
	Str      *CExpr   `json:"str,omitempty"`
	StrRegex []string `json:"str_regex,omitempty"`
	// Regex is a pattern-regex that only an #include directive can match (it
	// starts with `#include`): it is searched in the directives' text.
	Regex string `json:"regex,omitempty"`
	// Inside: every context holds (a pattern-either of pattern-insides makes
	// one alternative per branch).
	Inside []CContext `json:"inside,omitempty"`
	// NotInside: the site is dropped when any context holds.
	NotInside []CContext `json:"not_inside,omitempty"`
	// Not: pattern-not alternatives, each a call under the same metavariable
	// bindings: the site is dropped when one of them matches it.
	Not []CPattern `json:"not,omitempty"`
	// Where: metavariable-regex filters on what the positive and the insides bind.
	Where []CWhere `json:"where,omitempty"`
	// LineRegex (C++) is a pattern-regex positive that an around context
	// confines: it is searched in the lines of the construct the context
	// matches, each match inside the construct reported. SiteRegex (C++) is
	// a pattern-regex positive with no such context: it is searched in the
	// lines of every call, construction and string literal, each match that
	// lies wholly in one reported. NotRegex (C++) are pattern-not-regex
	// filters: a match is dropped when a match of one of them, searched in
	// its lines, holds it or lies in it. Each is a site regex (cppSiteRegex).
	LineRegex string   `json:"line_regex,omitempty"`
	SiteRegex string   `json:"site_regex,omitempty"`
	NotRegex  []string `json:"not_regex,omitempty"`
	// Focus: focus-metavariable; the finding is reported where it binds.
	Focus string `json:"focus,omitempty"`
	// Taint: the sources of a taint rule's sink (c_taint.go).
	Taint *CTaint `json:"taint,omitempty"`
}

// The places a context sits relative to the site.
const (
	// CBefore: `#include H` and `...`, the directive precedes the site in its
	// file; `f(...);` and `...` or `T x = v;` and `...`, the statement
	// precedes the site in its function (a function body reads as one block).
	CBefore = "before"
	// CAround: `f(...)`, the site is written inside the call; `T f(...) {
	// ... }`, the site is in the function.
	CAround = "around"
)

// CContext is one pattern-inside or pattern-not-inside: exactly one of
// Include, Call, Decl and Func is set. A Call placed before is a call
// written as a statement of its own.
type CContext struct {
	Place   string        `json:"place"`
	Include *CIncludeLine `json:"include,omitempty"`
	Call    *CExpr        `json:"call,omitempty"`
	Decl    *CDeclLine    `json:"decl,omitempty"`
	Func    *CFuncLine    `json:"func,omitempty"`
	Where   []CWhere      `json:"where,omitempty"`
}

// CDeclLine is a local declaration pattern, `T name;`, `T *name = v;` or
// `T name[] = {..., v, ...};`: the type's words (a lone metavariable binds
// the whole type), the name, the pointers, the array (with its size or
// none) and the initializer (none: the declaration has none).
type CDeclLine struct {
	Type  []string `json:"type"`
	Name  string   `json:"name"`
	Ptr   int      `json:"ptr,omitempty"`
	Array bool     `json:"array,omitempty"`
	Size  *CExpr   `json:"size,omitempty"`
	Init  *CExpr   `json:"init,omitempty"`
}

// CFuncLine is a function definition pattern `T name(...) { ... }`: the
// return type and the name, each a word or a metavariable. A storage class
// is not compared, as OpenGrep does not compare it.
type CFuncLine struct {
	Type string `json:"type"`
	Name string `json:"name"`
	// Params (C++) are the parameter patterns, `...` and typed parameters
	// `T &$X`; none for a C function context.
	Params []CExpr `json:"params,omitempty"`
}

// CIncludeLine is an #include directive pattern: `#include <h>` (Form
// "system"), `#include "h"` ("quote") or `#include "$H"` ("any"), which
// matches both forms and binds $H to `<h>` or to `h`.
type CIncludeLine struct {
	Form   string `json:"form"`
	Header string `json:"header,omitempty"`
	Var    string `json:"var,omitempty"`
}

// The include forms.
const (
	CIncludeSystem = "system"
	CIncludeQuote  = "quote"
	CIncludeAny    = "any"
)

// CWhere is one metavariable-regex (Python spelling, read with re.match).
type CWhere struct {
	Metavar string `json:"metavar"`
	Regex   string `json:"regex"`
}

// positive: the pattern has its positive (it is not a filter-only conjunction).
func (p *CPattern) positive() bool {
	return p.Call != nil || p.Store != nil || p.Expr != nil || p.Str != nil || p.Regex != "" || p.LineRegex != "" || p.SiteRegex != ""
}

// compileCRule compiles a C or C++ rule into its entries, one per positive
// alternative, or skips the whole rule with one cSkip reason.
func compileCRule(r *OMap) ([]*OMap, error) {
	if asOr[string](r.GetOr("mode")) == strTaint {
		return compileCTaint(r)
	}
	d := cDialect{cpp: cppOnlyRule(r)}
	node := &OMap{}
	for _, k := range []string{keyPattern, keyPatternEither, keyPatterns, keyPatternRegex} {
		if v, has := r.Get(k); has {
			node.Set(k, v)
		}
	}
	if node.Len() != 1 {
		return nil, skipCFormula.err()
	}
	alts, err := d.cAlternatives(node)
	if err != nil {
		return nil, err
	}
	out := make([]*OMap, 0, len(alts))
	for _, a := range cFocused(alts) {
		if !a.positive() {
			return nil, skipCNoPositive.err()
		}
		e, err := cEntry(a)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, skipCFocus.err()
	}
	return out, nil
}

// cFocused drops the alternatives whose focus-metavariable their positive
// and contexts do not bind: OpenGrep reports nothing for such a match.
func cFocused(alts []*CPattern) []*CPattern {
	out := alts[:0:0]
	for _, a := range alts {
		bound := map[string]bool{}
		for _, e := range []*CExpr{a.Call, a.Store, a.Expr} {
			if e != nil {
				cVars(e, bound, map[string]bool{}, false)
			}
		}
		for i := range a.Inside {
			a.Inside[i].vars(bound, map[string]bool{})
		}
		if a.Focus == "" || bound[a.Focus] {
			out = append(out, a)
		}
	}
	return out
}

// cEntry checks an alternative and gives its index entry: the method bucket
// and arity the shared Entry fields carry, and the pattern.
func cEntry(p *CPattern) (*OMap, error) {
	if err := p.check(map[string]bool{}); err != nil {
		return nil, err
	}
	var method any
	minArity, maxArity := 0, -1
	if p.Call != nil {
		if p.Call.Kind == CExprCall && p.Call.Callee.Kind == CExprIdent {
			method = p.Call.Callee.Name
		}
		minArity, maxArity = cArity(p.Call.Args)
	}
	var maxA any
	if maxArity >= 0 {
		maxA = int64(maxArity)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("c pattern: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	c, err := decodeOrdered(dec)
	if err != nil {
		return nil, fmt.Errorf("c pattern: %w", err)
	}
	return omap("method", method, "min_arity", int64(minArity), "max_arity", maxA, "c", c, "dropped_clauses", []any{}), nil
}

// cArity is the least and most arguments a pattern's argument list takes
// (-1: any number).
func cArity(args []CExpr) (int, int) {
	n, open := 0, false
	for _, a := range args {
		if a.Kind == CExprEllipsis {
			open = true
		} else {
			n++
		}
	}
	if open {
		return n, -1
	}
	return n, n
}

// check rejects a metavariable-regex or focus-metavariable on a metavariable
// nothing binds (outer: what the enclosing pattern binds), and one on a
// metavariable an `|` operand binds (OpenGrep binds it to several operand
// subsets, one result each).
func (p *CPattern) check(outer map[string]bool) error { //nolint:gocognit,gocyclo // one check per clause kind
	bound := maps.Clone(outer)
	orBound := map[string]bool{}
	if p.Call != nil {
		cVars(p.Call, bound, orBound, false)
	}
	if p.Expr != nil {
		cVars(p.Expr, bound, orBound, false)
	}
	if p.Store != nil {
		cVars(p.Store, bound, orBound, false)
	}
	if p.Str != nil {
		cVars(p.Str, bound, orBound, false)
	}
	for i := range p.Inside {
		p.Inside[i].vars(bound, orBound)
	}
	for _, w := range p.Where {
		if orBound[w.Metavar] {
			return skipCOrOperand.err()
		}
		if !bound[w.Metavar] {
			return skipCUnbound.err()
		}
	}
	for _, c := range p.NotInside {
		local := maps.Clone(bound)
		c.vars(local, orBound)
		for _, w := range c.Where {
			if !local[w.Metavar] {
				return skipCUnbound.err()
			}
		}
	}
	if p.Focus != "" && (!bound[p.Focus] || orBound[p.Focus]) {
		return skipCFocus.err()
	}
	if p.Expr != nil && !slices.ContainsFunc(p.Inside, func(c CContext) bool { return c.Call != nil }) {
		return skipCBareExpr.err()
	}
	for i := range p.Not {
		if err := p.Not[i].check(bound); err != nil {
			return err
		}
	}
	return nil
}

// cVars adds the metavariables a pattern expression binds; those under a `|`
// operand also go to orBound.
func cVars(e *CExpr, out, orBound map[string]bool, underOr bool) {
	if e.Var != "" {
		out[e.Var] = true
		if underOr {
			orBound[e.Var] = true
		}
	}
	if e.Kind == CExprMember && isMetavar(e.Name) { // C++: `$X.$M`
		out[e.Name] = true
	}
	or := underOr || (e.Kind == CExprBinary && e.Op == "|")
	if e.Callee != nil {
		cVars(e.Callee, out, orBound, or)
	}
	if e.Sub != nil {
		cVars(e.Sub, out, orBound, or)
	}
	for i := range e.Args {
		cVars(&e.Args[i], out, orBound, or)
	}
}

func (c *CContext) vars(out, orBound map[string]bool) {
	addName := func(s string) {
		if isMetavar(s) {
			out[s] = true
		}
	}
	switch {
	case c.Include != nil && c.Include.Var != "":
		out[c.Include.Var] = true
	case c.Call != nil:
		cVars(c.Call, out, orBound, false)
	case c.Decl != nil:
		for _, w := range c.Decl.Type {
			addName(w)
		}
		addName(c.Decl.Name)
		for _, e := range []*CExpr{c.Decl.Size, c.Decl.Init} {
			if e != nil {
				cVars(e, out, orBound, false)
			}
		}
	case c.Func != nil:
		addName(c.Func.Type)
		addName(c.Func.Name)
		for _, p := range c.Func.Params {
			addName(p.Var)
		}
	}
}

// cList is a clause's list value; anything else reads as an empty list,
// which no rule shape accepts.
func cList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

// cAlternatives expands a formula node (one key) into its alternatives.
// pattern-either is a union, so every alternative is an entry of its own; an
// alternative without a positive (a pattern-either branch of pattern-insides)
// is a filter that a conjunction joins with its positive.
func (d cDialect) cAlternatives(node *OMap) ([]*CPattern, error) { //nolint:gocyclo,gocognit // one case per formula key
	if node.Len() != 1 {
		return nil, skipCFormula.err()
	}
	val := node.Vals[0]
	switch asOr[string](node.Keys[0]) {
	case keyPattern:
		p, err := d.cPositive(val)
		if err != nil {
			return nil, err
		}
		return []*CPattern{p}, nil
	case keyPatternRegex:
		rx, ok := val.(string)
		if ok && d.cpp && !strings.HasPrefix(rx, "#include") {
			return d.cppSiteRegexAlt(rx)
		}
		if !ok || !strings.HasPrefix(rx, "#include") {
			return nil, skipCPatternRegex.err()
		}
		if _, err := regexp2.Compile(pyToNet(pcreToPyText(rx)), regexp2.None); err != nil {
			return nil, skipCPatternRegex.err()
		}
		return []*CPattern{{Regex: pcreToPyText(rx)}}, nil
	case keyPatternEither:
		var out []*CPattern
		for _, b := range cList(val) {
			bm, ok := b.(*OMap)
			if !ok {
				return nil, skipCFormula.err()
			}
			alts, err := d.cAlternatives(bm)
			if err != nil {
				return nil, err
			}
			out = append(out, alts...)
		}
		return out, nil
	case keyPatterns:
		return d.cConjunction(cList(val))
	case keyPatternInside:
		c, err := d.cContextOf(val)
		if err != nil {
			return nil, err
		}
		return []*CPattern{{Inside: []CContext{c}}}, nil
	case keyPatternNotInside, keyPatternNot:
		return nil, skipCNoPositive.err()
	case keyPatternNotRegex:
		return nil, skipCPatternRegex.err()
	}
	return nil, skipCClause.err()
}

// cConjunction compiles the items of a `patterns`: the product of its
// alternatives-bearing items (at most one with a positive), each joined with
// the conjunction's other clauses.
func (d cDialect) cConjunction(items []any) ([]*CPattern, error) { //nolint:gocognit,gocyclo,funlen // one case per clause kind of the closed set
	if len(items) == 0 {
		return nil, skipCFormula.err()
	}
	alts := []*CPattern{{}}
	var f CPattern
	for _, it := range items {
		m, ok := it.(*OMap)
		if !ok || m.Len() != 1 {
			return nil, skipCFormula.err()
		}
		key := asOr[string](m.Keys[0])
		val := m.Vals[0]
		switch key {
		case keyPattern, keyPatterns, keyPatternEither, keyPatternInside:
			branch, err := d.cAlternatives(m)
			if err != nil {
				return nil, err
			}
			if alts, err = cProduct(alts, branch); err != nil {
				return nil, err
			}
		case keyPatternRegex:
			rx, ok := val.(string)
			switch {
			case !ok || (!d.cpp && !cBoundedRegex(rx)):
				return nil, skipCPatternRegex.err()
			case d.cpp && !cBoundedRegex(rx) && !cppSiteRegex(rx):
				return nil, skipCPPRegex.err()
			}
			rx = pcreToPyText(rx)
			if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
				return nil, skipCPatternRegex.err()
			}
			f.StrRegex = append(f.StrRegex, rx)
		case keyPatternNotRegex:
			rx, ok := val.(string)
			switch {
			case !ok || !d.cpp:
				return nil, skipCPatternRegex.err()
			case !cppSiteRegex(rx):
				return nil, skipCPPRegex.err()
			}
			rx = pcreToPyText(rx)
			if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
				return nil, skipCPatternRegex.err()
			}
			f.NotRegex = append(f.NotRegex, rx)
		case keyPatternNotInside, keyPatternNot:
			if err := f.addNegative(d, key, val); err != nil {
				return nil, err
			}
		case keyMetavarRegex:
			w, err := cWhereOf(val)
			if err != nil {
				return nil, err
			}
			f.Where = append(f.Where, w)
		case keyFocusMetavar:
			v := val
			if l, isList := val.([]any); isList && len(l) == 1 {
				v = l[0]
			}
			s, isStr := v.(string)
			if !isStr || !isMetavar(s) || f.Focus != "" {
				return nil, skipCFocus.err()
			}
			f.Focus = s
		default:
			return nil, skipCClause.err()
		}
	}
	out, err := cProduct(alts, []*CPattern{&f})
	if err != nil {
		return nil, err
	}
	for _, p := range out {
		if d.cpp {
			if err := p.cppRegexes(); err != nil {
				return nil, err
			}
		}
		switch {
		case p.Regex != "" && (len(p.Inside)+len(p.NotInside)+len(p.Not)+len(p.Where)+len(p.StrRegex) > 0 || p.Focus != ""):
			return nil, skipCPatternRegex.err()
		case p.Str == nil && len(p.StrRegex) > 0:
			return nil, skipCPatternRegex.err()
		case p.Str != nil && (len(p.Inside)+len(p.NotInside)+len(p.Not) > 0 || p.Focus != ""):
			return nil, skipCString.err() // a literal's function and enclosing call are not facts
		}
	}
	return out, nil
}

// cProduct joins every alternative of a with every one of b: their positives
// (at most one of the two has one) and their filters.
func cProduct(a, b []*CPattern) ([]*CPattern, error) {
	out := make([]*CPattern, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			if x.positive() && y.positive() {
				return nil, skipCPositives.err()
			}
			if x.Focus != "" && y.Focus != "" {
				return nil, skipCFocus.err()
			}
			j := &CPattern{
				Call: x.Call, Stmt: x.Stmt, Store: x.Store, Expr: x.Expr, Str: x.Str, Regex: x.Regex, LineRegex: x.LineRegex, SiteRegex: x.SiteRegex, Focus: x.Focus + y.Focus,
				StrRegex:  slices.Concat(x.StrRegex, y.StrRegex),
				Inside:    slices.Concat(x.Inside, y.Inside),
				NotInside: slices.Concat(x.NotInside, y.NotInside),
				Not:       slices.Concat(x.Not, y.Not),
				Where:     slices.Concat(x.Where, y.Where),
				NotRegex:  slices.Concat(x.NotRegex, y.NotRegex),
			}
			if y.positive() {
				j.Call, j.Stmt, j.Store, j.Expr, j.Str, j.Regex, j.LineRegex, j.SiteRegex = y.Call, y.Stmt, y.Store, y.Expr, y.Str, y.Regex, y.LineRegex, y.SiteRegex
			}
			out = append(out, j)
		}
	}
	return out, nil
}

// addNegative compiles a pattern-not-inside or a pattern-not. A pattern-not
// is a call read under the positive's bindings; a pattern-not-inside a context.
func (p *CPattern) addNegative(d cDialect, key string, val any) error {
	if key == keyPatternNotInside {
		c, err := d.cContextOf(val)
		if err != nil {
			return err
		}
		p.NotInside = append(p.NotInside, c)
		return nil
	}
	node, isMap := val.(*OMap)
	if !isMap {
		node = omap(keyPattern, val)
	}
	alts, err := d.cAlternatives(node)
	if err != nil {
		return err
	}
	for _, a := range alts {
		if a.Call == nil || a.Focus != "" || len(a.Inside)+len(a.NotInside)+len(a.Not) > 0 {
			return skipCNot.err()
		}
		p.Not = append(p.Not, *a)
	}
	return nil
}

// cWhereOf reads a metavariable-regex.
func cWhereOf(val any) (CWhere, error) {
	m, ok := val.(*OMap)
	if !ok || m.Len() != 2 {
		return CWhere{}, skipCClause.err()
	}
	mv, okMv := m.GetOr("metavariable").(string)
	rx, okRx := m.GetOr("regex").(string)
	if !okMv || !okRx || !isMetavar(mv) {
		return CWhere{}, skipCClause.err()
	}
	rx = pcreToPyText(rx)
	if _, err := regexp2.Compile(pyToNet(rx), regexp2.None); err != nil {
		return CWhere{}, skipCRegex.err()
	}
	return CWhere{Metavar: mv, Regex: rx}, nil
}

// cPositive reads a pattern's text: a call or a bare metavariable.
func (d cDialect) cPositive(val any) (*CPattern, error) { //nolint:gocognit,gocyclo // one case per positive shape
	text, ok := val.(string)
	if !ok {
		return nil, skipCFormula.err()
	}
	text = strings.TrimSpace(text)
	if stmt, ok := strings.CutSuffix(text, ";"); ok {
		e, ok := d.read(stmt)
		if d.cpp && (!ok || e.Kind != CExprCall) {
			return d.cppDeclPositive(text)
		}
		if !ok || e.Kind != CExprCall {
			return nil, d.unreadable(text, skipCStatement).err()
		}
		if err := d.cPatternCall(e); err != nil {
			return nil, err
		}
		return &CPattern{Call: e, Stmt: true}, nil
	}
	if (strings.HasSuffix(text, "}") && !d.cpp) || strings.HasPrefix(text, "#") {
		return nil, skipCStatement.err()
	}
	e, ok := d.read(text)
	if !ok {
		return nil, d.unreadable(text, skipCSyntax).err()
	}
	switch e.Kind {
	case CExprNew:
		if err := d.cppConstruct(e); err != nil {
			return nil, err
		}
		return &CPattern{Call: e}, nil
	case CExprCall:
		if err := d.cPatternCall(e); err != nil {
			return nil, err
		}
		return &CPattern{Call: e}, nil
	case CExprMetavar:
		return &CPattern{Expr: e}, nil
	case CExprStrVar, CExprString:
		return &CPattern{Str: e}, nil
	case CExprAssign:
		if err := d.cPatternStore(e); err != nil {
			return nil, err
		}
		return &CPattern{Store: e}, nil
	}
	return nil, skipCExpr.err()
}

// cBoundedRegex: a pattern-regex has no repetition, anchor or lookaround,
// so a match it makes in a literal's text is the match it makes at that
// place of the file's text: it cannot run past the literal, and nothing
// around the literal changes it.
func cBoundedRegex(rx string) bool { //nolint:gocyclo // one case per regex construct the check rejects
	inClass := false
	for i := 0; i < len(rx); i++ {
		c := rx[i]
		switch {
		case c == '\\':
			if i+1 < len(rx) && !inClass && strings.IndexByte("bBAZzG", rx[i+1]) >= 0 { // an anchor
				return false
			}
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '*' || c == '+' || c == '{' || c == '^' || c == '$':
			return false
		case c == '(' && strings.HasPrefix(rx[i:], "(?") && (strings.HasPrefix(rx[i+2:], "=") || strings.HasPrefix(rx[i+2:], "!") ||
			strings.HasPrefix(rx[i+2:], "<=") || strings.HasPrefix(rx[i+2:], "<!")):
			return false
		}
	}
	return true
}

// cPatternStore checks an assignment pattern is a store to a field, `$J->f
// = v` or `$J.f = v`, of a name or metavariable receiver.
func (d cDialect) cPatternStore(e *CExpr) error {
	lhs, rhs := &e.Args[0], &e.Args[1]
	if e.Op != "=" || lhs.Kind != CExprMember || (lhs.Sub.Kind != CExprMetavar && lhs.Sub.Kind != CExprIdent) {
		return skipCStatement.err()
	}
	return d.cPatternArg(rhs)
}

// cPatternCall checks a call pattern is in the closed shape set: a name or a
// metavariable called with arguments that are each `...`, a metavariable, a
// name, an integer or string literal, `<... e ...>`, a prefix operator on
// one, an `|` of them or a call of the same shape.
func (d cDialect) cPatternCall(e *CExpr) error {
	if d.cpp {
		return d.cppPatternCall(e)
	}
	if e.Callee.Kind != CExprIdent && e.Callee.Kind != CExprMetavar {
		return skipCExpr.err()
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

func (d cDialect) cPatternArg(e *CExpr) error {
	if d.cpp {
		if handled, err := d.cppPatternArg(e); handled {
			return err
		}
	}
	switch e.Kind {
	case CExprMetavar, CExprIdent, CExprInt, CExprString:
		return nil
	case CExprCall:
		return d.cPatternCall(e)
	case CExprUnary:
		return d.cPatternArg(e.Sub)
	case CExprDeep:
		return d.cPatternArg(e.Sub)
	case CExprBinary:
		if e.Op != "|" {
			return skipCExpr.err()
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
	case CExprStrVar:
		return skipCString.err()
	}
	return skipCExpr.err()
}

// cContextOf reads a pattern-inside or pattern-not-inside text: an
// #include directive followed by `...`, or a call.
func (d cDialect) cContextOf(val any) (CContext, error) {
	text, ok := val.(string)
	if !ok {
		return CContext{}, skipCContext.err()
	}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "#include") {
		return cIncludeContext(text)
	}
	if body, ok := strings.CutSuffix(text, rustEllipsis); ok {
		return d.cStatementContext(strings.TrimSpace(body))
	}
	if strings.HasSuffix(text, "}") {
		if d.cpp {
			return d.cppFuncContextOf(text)
		}
		return cFuncContext(text)
	}
	e, ok := d.read(text)
	if d.cpp && (!ok || e.Kind == CExprNew) {
		return d.cppAroundContext(text, e)
	}
	switch {
	case !ok:
		return CContext{}, d.unreadable(text, skipCContext).err()
	case e.Kind != CExprCall:
		return CContext{}, skipCContext.err()
	}
	if err := d.cPatternCall(e); err != nil {
		return CContext{}, err
	}
	return CContext{Place: CAround, Call: e}, nil
}

// cStatementContext reads a statement followed by `...`: a call written as
// a statement, or a local declaration.
func (d cDialect) cStatementContext(body string) (CContext, error) {
	stmt, ok := strings.CutSuffix(body, ";")
	if !ok {
		return CContext{}, skipCContext.err()
	}
	if e, ok := d.read(stmt); ok {
		if e.Kind != CExprCall {
			return CContext{}, skipCSequence.err() // an assignment: no fact lists them
		}
		if err := d.cPatternCall(e); err != nil {
			return CContext{}, err
		}
		return CContext{Place: CBefore, Call: e}, nil
	}
	if d.cpp { // a declaration of C++ constructs its variable
		decl, err := d.cppDeclPattern(body)
		if err != nil {
			return CContext{}, err
		}
		return CContext{Place: CBefore, Call: decl}, nil
	}
	decl, ok := readCDecl(body, true)
	if !ok || len(decl.Decls) != 1 {
		return CContext{}, skipCDeclaration.err()
	}
	dc := decl.Decls[0]
	if len(decl.Type) > 1 && slices.ContainsFunc(decl.Type, isMetavar) {
		return CContext{}, skipCDeclaration.err()
	}
	for _, e := range []*CExpr{dc.Size, dc.Init} {
		if e != nil && !d.cDeclPart(e) {
			return CContext{}, skipCDeclaration.err()
		}
	}
	return CContext{Place: CBefore, Decl: &CDeclLine{Type: decl.Type, Name: dc.Name, Ptr: dc.Ptr, Array: dc.Array, Size: dc.Size, Init: dc.Init}}, nil
}

// cDeclPart: a declaration pattern's size or initializer is in the closed
// argument shapes, an initializer list of them included.
func (d cDialect) cDeclPart(e *CExpr) bool {
	if e.Kind != CExprInit {
		return d.cPatternArg(e) == nil
	}
	for i := range e.Args {
		if e.Args[i].Kind != CExprEllipsis && d.cPatternArg(&e.Args[i]) != nil {
			return false
		}
	}
	return true
}

// cFuncContext reads `[static] T name(...) { ... }`.
func cFuncContext(text string) (CContext, error) {
	toks, err := lexC(text, true)
	if err != nil {
		return CContext{}, skipCFunction.err()
	}
	var words []string
	i := 0
	for ; i < len(toks) && (toks[i].kind == ctIdent || toks[i].kind == ctVar); i++ {
		if !cTypeQualifiers[toks[i].text] {
			words = append(words, toks[i].text)
		}
	}
	rest := make([]string, 0, len(toks)-i)
	for _, t := range toks[i:] {
		rest = append(rest, t.text)
	}
	if len(words) != 2 || !slices.Equal(rest, []string{"(", rustEllipsis, ")", "{", rustEllipsis, "}"}) {
		return CContext{}, skipCFunction.err()
	}
	return CContext{Place: CAround, Func: &CFuncLine{Type: words[0], Name: words[1]}}, nil
}

// cIncludeContext reads `#include <h>`, `#include "h"` or `#include "$H"`,
// then `...` on a line of its own.
func cIncludeContext(text string) (CContext, error) {
	line, rest, _ := strings.Cut(text, "\n")
	if strings.TrimSpace(rest) != rustEllipsis {
		return CContext{}, skipCContext.err()
	}
	path := strings.TrimSpace(strings.TrimPrefix(line, "#include"))
	if len(path) < 3 {
		return CContext{}, skipCContext.err()
	}
	inner := path[1 : len(path)-1]
	if strings.ContainsAny(inner, "<>\" \t") {
		return CContext{}, skipCContext.err()
	}
	inc := &CIncludeLine{Header: inner}
	switch {
	case path[0] == '<' && path[len(path)-1] == '>':
		inc.Form = CIncludeSystem
	case path[0] == '"' && path[len(path)-1] == '"' && isCMetavarName(inner):
		inc.Form, inc.Header, inc.Var = CIncludeAny, "", inner
	case path[0] == '"' && path[len(path)-1] == '"':
		inc.Form = CIncludeQuote
	default:
		return CContext{}, skipCContext.err()
	}
	if strings.Contains(inner, "$") && inc.Var == "" {
		return CContext{}, skipCContext.err()
	}
	return CContext{Place: CBefore, Include: inc}, nil
}
