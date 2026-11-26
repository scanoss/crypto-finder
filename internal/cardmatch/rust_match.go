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

// The Rust matcher. It reads the callee of each call site as written, from
// the fragment's source lines and the call's span, with the same reader that
// reads a rule's pattern, and unifies the pattern with it into an
// environment of metavariable bindings. It never reads reach's resolved
// target_key: OpenGrep matches syntax, and a resolved key loses what the
// pattern can name (turbofish generics, `<A as B>::f`, the way a path is
// written).
//
// Contexts read the scope facts of a graph-fragment-1.26 (rust_scope.go):
// use and extern crate declarations, items, let declarations, and constant
// references for bare path patterns. A hand card's type alias pattern
// (`type $A = Mode<$C>;`) reads the type alias items of a
// graph-fragment-1.27, each with its aliased type as written (matchAliases).
// A binary expression positive (`$S * $BASE`) reads the binary expressions of
// a graph-fragment-1.30, and so does a sequence context that ends in one; a
// fn context with typed parameters reads the parameters its fn items carry
// there. An entry that reads a fact the fragment
// does not carry, or a context shape no fact can decide, is held: it finds
// nothing and is counted, never approximated. A match that a fact cannot
// decide at one site (a use tree, a naming no pin covers) is counted as
// undecided, and a negative context that cannot be decided drops the site.

import (
	"maps"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/scanoss/reach/graphfrag"
)

// The reasons an entry is held.
const (
	// Facts a fragment older than graph-fragment-1.26 does not carry.
	holdImports      = "imports"
	holdItems        = "items"
	holdDeclarations = "declarations"
	holdRefs         = "constant_refs"
	holdItemTypes    = "item types"   // a type alias's aliased type (graph-fragment-1.27)
	holdBinaries     = "binary_exprs" // binary expressions of function bodies (graph-fragment-1.30)
	holdParams       = "params"       // a fn item's parameters (graph-fragment-1.30)
	holdNames        = "names"        // one-segment names read as values (graph-fragment-1.33)
	holdTypes        = "types"        // paths written as types (graph-fragment-1.35)
	// Shapes no fact decides.
	holdSequence  = "sequence"      // a call before or after the site, a statement ending a range but a let's (rustUntilServable)
	holdUseShape  = "use shape"     // a use path the leaf rules do not cover (`use $A::b::$C;`), a use around the site
	holdItemShape = "item shape"    // `pub`, a fn's return type, a const's type or value read elsewhere, a type alias whose type is not a plain path (rustAliasContextServable)
	holdLetShape  = "let shape"     // a let after the site, a let positive written `mut`
	holdRefShape  = "ref shape"     // a bare path with generics, a qualified self, or one segment no fragment lists
	holdItemPos   = "item positive" // an item written as the pattern, but a hand card's type alias (rustAliasServable)
)

// The reasons a site is undecided.
const (
	undecidedUseTree  = "use tree"   // a use tree the reader does not know, a leaf form no pin covers
	undecidedNaming   = "naming"     // a path qualified through a binding no pin covers
	undecidedLet      = "let text"   // a let declaration whose text cannot be read
	undecidedBareName = "bare name"  // per entry and file: a one-segment path a use may qualify to the pattern
	undecidedAliasTyp = "alias type" // a type alias item whose aliased type cannot be read
	undecidedGenerics = "generics"   // a type the fragment's source lines cannot place in or out of generic arguments
)

// RustMatchStats counts what the Rust matcher did with one fragment.
type RustMatchStats struct {
	Entries int // Rust entries in the index
	Held    int // entries that wait for a fact the fragment lacks or a shape no fact decides
	// HeldBy counts the held entries by reason; an entry held for several
	// counts under each.
	HeldBy map[string]int
	// UnreadableSites are the call sites whose written call could not be
	// read (no source line or column, a call the reader has no shape for).
	UnreadableSites int
	// Undecided counts, by reason, the entry and site pairs no finding was
	// made for because a fact could not decide the match.
	Undecided map[string]int
	// UnfocusedSites counts the matches of a focus-metavariable rule whose
	// metavariable is bound neither to a call argument nor to what `$X` of
	// `$X.m(...)` binds: reported nowhere.
	UnfocusedSites int
}

// rustHolds are the reasons a pattern is held on a fragment that carries the
// scope facts (facts) or not. card: the pattern is a hand card's, whose type
// alias positives are served.
func rustHolds(p *RustPattern, facts, card bool) []string {
	var out []string
	add := func(h string, on bool) {
		if on && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	if !facts {
		n := needsOf(p)
		add(holdImports, n.Imports)
		add(holdItems, n.Items)
		add(holdDeclarations, n.Declarations)
		add(holdRefs, n.Refs)
	}
	rustShapeHolds(p, p, card, add)
	if p.Taint != nil && len(p.Taint.Values) == 0 {
		// A sink waits for its sources only when none of them can be read.
		var held []string
		for i := range p.Taint.Objects {
			h := rustSourceHolds(&p.Taint.Objects[i], facts)
			if len(h) == 0 {
				return out
			}
			held = append(held, h...)
		}
		for _, h := range held {
			add(h, true)
		}
	}
	return out
}

// rustUseHeld: no fact decides the use context c, or the use its fn item
// context declares in the body.
func rustUseHeld(c *RustContext) bool {
	if c.Item != nil && c.Item.Use != nil && !rustUseServable(c.Item.Use) {
		return true
	}
	return (c.Use != nil || c.ExternCrate != nil) && (c.Place == RustAround || (c.Use != nil && !rustUseServable(c.Use)))
}

// rustShapeHolds adds the shapes of p (or a pattern-not of root) no fact
// decides; card: a hand card's type alias positives are decided.
func rustShapeHolds(root, p *RustPattern, card bool, add func(string, bool)) {
	add(holdItemPos, p.Item != nil && (!card || !rustAliasServable(root, p)))
	add(holdRefShape, p.Ref != nil && !rustRefServable(p.Ref))
	add(holdLetShape, rustLetPositiveHeld(p))
	for _, c := range slices.Concat(p.Inside, p.NotInside) {
		add(holdSequence, (c.Until != nil && !rustUntilServable(&c)) || (c.Call != nil && c.Place != RustAround))
		add(holdUseShape, rustUseHeld(&c))
		add(holdLetShape, c.Let != nil && c.Place != RustBefore && c.Place != RustAround)
		add(holdItemShape, c.Item != nil && !rustItemServable(root, p, &c))
	}
	for i := range p.Not {
		rustShapeHolds(root, &p.Not[i], card, add)
	}
	for i := range p.Within {
		rustShapeHolds(&p.Within[i], &p.Within[i], card, add)
	}
}

// rustLetPositiveHeld: p's positive is a let no pin covers: written `mut`.
func rustLetPositiveHeld(p *RustPattern) bool {
	return p.Let != nil && p.Let.Mut
}

// rustUntilServable: the sequence context c, `let $S = V; ... E`, ends in an
// expression the facts find after the let in its function: a binary
// expression or a call, bare or anywhere in a statement (`<... E ...>;`), or
// a reference anywhere in a statement (`<... &mut $S ...>;`), which the
// facts find in a call's arguments and receiver and in a let's initializer.
// OpenGrep 1.33.1 reads a bare binary or call end the same way as a deep
// one: it matches one nested in a call, in another binary expression, in a
// method chain, in a let's initializer, in a closure, in an inner block or
// as the block's tail (pinned by invented rules).
func rustUntilServable(c *RustContext) bool {
	if c.Let == nil || c.Place != RustBefore {
		return false
	}
	e := c.Until
	if e.Kind == RustExprDeep {
		e = e.Sub
		return e.Kind == RustExprBinary || e.Kind == RustExprCall || e.Kind == RustExprRef
	}
	return e.Kind == RustExprBinary || e.Kind == RustExprCall
}

// rustAliasServable: the item positive of p (or of a pattern-not of root)
// is a type alias, `type $A = T;`, which the type alias items decide. Only a
// hand card's is served: OpenGrep 1.33.1 reads the same pattern in a rule
// YAML as a type item too, but compares its paths by their last segment and
// reports from the alias name, so a rule's is held. `pub type` and a focus
// are held.
func rustAliasServable(root, p *RustPattern) bool {
	return p.Item.Kind == rustItemType && !p.Item.Pub && root.Focus == "" && p.Focus == ""
}

// rustReadsAliases: p, a pattern-not or a within pattern of it, has a type
// alias positive.
func rustReadsAliases(p *RustPattern) bool {
	if p.Item != nil && p.Item.Kind == rustItemType {
		return true
	}
	return slices.ContainsFunc(slices.Concat(p.Not, p.Within), func(q RustPattern) bool { return rustReadsAliases(&q) })
}

// rustRefServable: a bare path pattern constant references can decide: no
// generics, and two segments or more, the last a name or a metavariable
// (`acme::sig::$ALG`), or one name a graph-fragment-1.33 lists where it is
// read (rustOneName). It is served where a value is read and, on a
// graph-fragment-1.35, where a type is written (unifyTypePath).
func rustRefServable(p *RustPath) bool {
	if p.Global || p.QSelf != nil || len(p.Segs) == 0 || rustHasGenerics(p) {
		return false
	}
	if len(p.Segs) == 1 {
		return rustOneName(p)
	}
	return p.Last().Name != "" || p.Last().Var != ""
}

// rustOneName: the pattern is one name a graph-fragment-1.33 lists where it
// is read (rustListedName); a fragment before it holds the pattern.
func rustOneName(p *RustPath) bool {
	return len(p.Segs) == 1 && p.Segs[0].Var == "" && rustListedName(p.Segs[0].Name)
}

// rustUseServable: the use pattern is one of the forms the leaf rules
// cover (useLeaf).
func rustUseServable(u *RustUse) bool {
	segs := u.Path.Segs
	if u.Path.Global || u.Path.QSelf != nil || len(segs) == 0 || rustHasGenerics(&u.Path) {
		return false
	}
	for i := 1; i < len(segs)-1; i++ {
		if segs[i].Var != "" {
			return false
		}
	}
	switch {
	case u.Glob:
		return u.Alias == "" && (len(segs) == 1 || segs[0].Var == "")
	case len(segs) > 1 && segs[0].Var != "":
		return len(segs) == 2 && u.Alias == ""
	}
	return true
}

// rustItemServable: the items table decides the item context c of p.
func rustItemServable(root, p *RustPattern, c *RustContext) bool {
	it := c.Item
	if it.Kind == rustItemType {
		return rustAliasContextServable(root, p, c)
	}
	if it.Pub {
		return false
	}
	switch it.Kind {
	case rustItemMod, rustItemImpl, rustItemStruct:
		return true
	case "fn":
		return rustFnServable(it)
	case "const", "static":
		if it.Type == nil || it.Type.Var == "" || it.Value == nil || it.Value.Kind != RustExprVar {
			return false
		}
		used := rustVarsBesides(root, p, c)
		free := func(v string) bool { return v == "$_" || !used[v] }
		return free(it.Type.Var) && free(it.Value.Var) && (it.Type.Var != it.Value.Var || it.Type.Var == "$_")
	}
	return false
}

// rustAliasContextServable: the type alias context c, `type $T = $M::Hash;
// ...`, is decided by the items table: it precedes the site, and its aliased
// type is a plain path (no generics, no leading `::`, no qualified self)
// ending in a name. OpenGrep 1.33.1 reads `pub` as nothing (`pub type` and
// `type` each match both) and binds no metavariable in front of the last
// segment (aliasTail), so one the rule uses elsewhere is held.
func rustAliasContextServable(root, p *RustPattern, c *RustContext) bool {
	t := c.Item.Type
	if c.Place != RustBefore || t == nil || t.Path == nil {
		return false
	}
	path := t.Path
	if path.Global || path.QSelf != nil || rustHasGenerics(path) || path.Last().Name == "" {
		return false
	}
	used := map[string]bool{}
	for _, q := range []*RustPattern{root, p} {
		rest := *q
		rest.Inside = slices.DeleteFunc(slices.Clone(q.Inside), func(o RustContext) bool { return o.Item == c.Item })
		rest.binds(used)
		for _, w := range q.Where {
			used[w.Metavar] = true
		}
		used[q.Focus] = true
	}
	for _, w := range c.Where {
		used[w.Metavar] = true
	}
	for _, s := range path.Segs[:len(path.Segs)-1] {
		if s.Var != "" && s.Var != "$_" && used[s.Var] {
			return false
		}
	}
	return true
}

// rustFnServable: the items table decides the fn item context it: its name,
// and its parameters, which a fn item carries as written
// (graph-fragment-1.30; a list of `...` only needs none of them). OpenGrep
// 1.33.1 reads `fn $F()` as no parameters at all, a self receiver included.
// A return type is held: the table records none. A fn whose body declares a
// use is decided by its name only, so its parameters must be `...`.
func rustFnServable(it *RustItem) bool {
	if it.Type != nil {
		return false
	}
	if it.Use != nil {
		return rustParamsAnyList(it.Params)
	}
	return true
}

// rustVarsBesides are the metavariables a negative item context c of p (or
// of root, the pattern p negates under) shares with what binds them: the
// positives, the insides, the filters. Another negative's metavariables are
// its own.
func rustVarsBesides(root, p *RustPattern, c *RustContext) map[string]bool {
	out := map[string]bool{}
	for _, q := range []*RustPattern{root, p} {
		q.binds(out)
		for _, w := range q.Where {
			out[w.Metavar] = true
		}
		out[q.Focus] = true
	}
	for _, w := range c.Where {
		out[w.Metavar] = true
	}
	return out
}

func rustHasGenerics(p *RustPath) bool {
	for _, s := range p.Segs {
		if s.Generics != nil {
			return true
		}
	}
	return false
}

// RustEntryHolds counts the index's Rust entries by why they are held on a
// fragment that carries the scope facts ("" counts the entries that can
// match).
func (a *Assets) RustEntryHolds() map[string]int {
	out := map[string]int{}
	for _, e := range a.index.Entries {
		if e.Rust == nil {
			continue
		}
		h := rustHolds(e.Rust, true, false)
		if len(h) == 0 {
			out[""]++
		}
		for _, r := range h {
			out[r]++
		}
	}
	return out
}

// rustMatcher is the state of one match over a fragment.
type rustMatcher struct {
	fr    *Frag
	reads map[*Site]*rustRead
	srcs  map[*Entry][]RustPattern // the object sources of a taint entry that can be read
	lets  map[*Site]*RustLet
	stats RustMatchStats
	found []*Finding
	seen  map[string]bool // findingKey of the findings
	// file and at are where the paths being unified are written, for the
	// naming of their first segment; undecided is the reason a fact could
	// not decide the current entry at the current site.
	file      string
	at        rustPos
	undecided string
	// byFile holds the fragment's sites by file, built on first use: a
	// context only encloses a site of its own file. bins holds the binary
	// expressions by file (binaries).
	byFile map[string][]*Site
	bins   map[string][]rustBinarySite
	// calls holds the call sites of each function of a file, in fileSites
	// order, and callerBins its binary expressions, in binaries order, both
	// built per file on first use: the end of a sequence context is looked
	// for in the site's own function, and one generated file can hold
	// thousands of functions.
	calls      map[string]map[string][]*Site
	callerBins map[string]map[string][]rustBinarySite
	// shadows holds each function's lets by the name they declare
	// (letsByName).
	shadows map[string]map[string]rustNameLets
	letsOf  map[string][]rustCallerLet
	// letNames holds each function's lets by the text they bind
	// (letsNamed).
	letNames map[string]rustNamedLets
	// negating counts the negatives being evaluated (negated).
	negating int
}

// callerCalls: the call sites of caller's body in file, in fileSites order.
func (m *rustMatcher) callerCalls(file, caller string) []*Site {
	byCaller, ok := m.calls[file]
	if !ok {
		byCaller = map[string][]*Site{}
		for _, o := range m.fileSites(file) {
			if rustCallSite(o) {
				byCaller[o.Caller] = append(byCaller[o.Caller], o)
			}
		}
		if m.calls == nil {
			m.calls = map[string]map[string][]*Site{}
		}
		m.calls[file] = byCaller
	}
	return byCaller[caller]
}

// callerBinaries: the binary expressions of caller's body in file, in
// binaries order.
func (m *rustMatcher) callerBinaries(file, caller string) []rustBinarySite {
	byCaller, ok := m.callerBins[file]
	if !ok {
		byCaller = map[string][]rustBinarySite{}
		for _, b := range m.binaries(file) {
			byCaller[b.site.Caller] = append(byCaller[b.site.Caller], b)
		}
		if m.callerBins == nil {
			m.callerBins = map[string]map[string][]rustBinarySite{}
		}
		m.callerBins[file] = byCaller
	}
	return byCaller[caller]
}

// fileSites: the fragment's sites in file.
func (m *rustMatcher) fileSites(file string) []*Site {
	if m.byFile == nil {
		m.byFile = map[string][]*Site{}
		for _, o := range m.fr.Sites {
			m.byFile[o.File] = append(m.byFile[o.File], o)
		}
	}
	return m.byFile[file]
}

// rustRead is a site's written call, a constant reference's path, a type
// alias item, a binary expression, or a let declaration.
type rustRead struct {
	call  *RustCall
	ref   *RustPath
	alias *rustAlias
	bin   *rustBinary
	let   *RustLet
	span  [4]int // start line, start col, end line, end col
	// typ: ref is a path written as a type (rustTypeRef), matched as
	// OpenGrep matches a path pattern there (unifyTypePath).
	typ bool
}

// rustBinary is a binary expression of a function body: its operands read
// from their text (expr, a RustExprBinary), and that text as written.
type rustBinary struct {
	expr        *RustExpr
	left, right string
}

// rustAlias is a type alias as written: `type name = typ;`.
type rustAlias struct {
	name string
	typ  RustType
}

func (rd *rustRead) pos() rustPos { return rustPos{rd.span[0], rd.span[1]} }

// matchRust matches a Rust fragment.
func matchRust(a *Assets, fr *Frag) []*Finding {
	found, _ := matchRustStats(a, fr)
	return found
}

func matchRustStats(a *Assets, fr *Frag) ([]*Finding, RustMatchStats) {
	m := &rustMatcher{
		fr: fr, reads: map[*Site]*rustRead{}, srcs: map[*Entry][]RustPattern{}, lets: map[*Site]*RustLet{}, seen: map[string]bool{},
		stats: RustMatchStats{HeldBy: map[string]int{}, Undecided: map[string]int{}},
	}
	b := m.bucket(a)
	for _, s := range fr.Sites {
		if !rustCallSite(s) {
			continue
		}
		cands := slices.Concat(b.byMethod[s.Method], b.anyMethod)
		if len(cands) == 0 && len(b.refs) == 0 {
			continue
		}
		if rd := m.read(s); rd != nil {
			m.emitAll(cands, s, rd)
			if rd.call.Callee != nil {
				m.emitAll(b.refs, s, &rustRead{ref: rd.call.Callee, span: rd.span})
			}
		}
	}
	if len(b.refs) > 0 {
		m.matchRefs(b.refs)
	}
	if len(b.aliases) > 0 {
		m.matchAliases(b.aliases)
	}
	m.matchBinaries(b.binaries)
	m.matchLets(b.lets)
	return m.found, m.stats
}

// matchRefs matches the bare path positives at every constant reference of
// the fragment, a type at its last segment (rustLastSegSite).
func (m *rustMatcher) matchRefs(entries []*Entry) {
	for _, r := range m.fr.Refs {
		if rd := m.readRef(r); rd != nil {
			if rd.typ {
				r = rustLastSegSite(r, rd)
			}
			m.emitAll(entries, r, rd)
		}
	}
	m.countBareNames(entries)
}

// matchLets matches the let positives at every let declaration of the
// fragment, once per let: reach lists a let that binds several names once
// per name, each with the whole let's span.
func (m *rustMatcher) matchLets(entries []*Entry) {
	if len(entries) == 0 {
		return
	}
	seen := map[rustFileSpan]bool{}
	for _, d := range m.fr.Decls {
		at := rustFileSpan{d.File, d.Line, d.Col, d.EndLine, d.EndCol}
		if seen[at] {
			continue
		}
		seen[at] = true
		l := m.readLet(d)
		if l == nil {
			m.stats.UnreadableSites++
			continue
		}
		m.emitAll(entries, d, &rustRead{let: l, span: [4]int{d.Line, d.Col, max(d.EndLine, d.Line), d.EndCol}})
	}
}

// rustFileSpan is a span of a file.
type rustFileSpan struct {
	file                       string
	line, col, endLine, endCol int
}

// rustCallSite: the site is a call, not a constant reference, a declaration
// or a cast.
func rustCallSite(s *Site) bool {
	return s.Kind != "constant_ref" && s.Kind != "declaration" && s.Kind != "cast"
}

// matchBinaries matches the binary expression positives at every binary
// expression of the fragment, file by file in source order.
func (m *rustMatcher) matchBinaries(entries []*Entry) {
	if len(entries) == 0 {
		return
	}
	for _, file := range slices.Sorted(maps.Keys(m.fr.RustBinaries)) {
		for _, b := range m.binaries(file) {
			m.emitAll(entries, b.site, b.read)
		}
	}
}

// rustBinarySite is a binary expression of a function body as a site, with
// its read.
type rustBinarySite struct {
	site *Site
	read *rustRead
}

// binaries are the binary expressions of file's function bodies, in source
// order, each a site whose caller is the function that holds it; an
// expression whose operands do not lex is counted unreadable and left out.
// Built on first use.
func (m *rustMatcher) binaries(file string) []rustBinarySite {
	if out, ok := m.bins[file]; ok {
		return out
	}
	var out []rustBinarySite
	for _, b := range m.fr.RustBinaries[file] {
		left, okL := readRustExpr(b.Left)
		right, okR := readRustExpr(b.Right)
		if !okL || !okR {
			m.stats.UnreadableSites++
			continue
		}
		s := &Site{
			File: file, Line: b.Line, LineOK: true, Col: b.StartCol, ColOK: true, EndCol: b.EndCol, EndLine: b.EndLine,
			Kind: "binary_expr", Method: b.Op, Caller: b.Function,
		}
		e := &RustExpr{Kind: RustExprBinary, Op: b.Op, Sub: &left, Right: &right}
		bin := &rustBinary{expr: e, left: strings.TrimSpace(b.Left), right: strings.TrimSpace(b.Right)}
		out = append(out, rustBinarySite{site: s, read: &rustRead{bin: bin, span: [4]int{b.Line, b.StartCol, max(b.EndLine, b.Line), b.EndCol}}})
	}
	if m.bins == nil {
		m.bins = map[string][]rustBinarySite{}
	}
	m.bins[file] = out
	return out
}

// matchAliases matches the type alias positives at every type alias item of
// the fragment, file by file in source order.
func (m *rustMatcher) matchAliases(entries []*Entry) {
	for _, file := range slices.Sorted(maps.Keys(m.fr.RustScopes)) {
		for _, it := range m.fr.RustScopes[file].items {
			if it.kind != rustItemType {
				continue
			}
			s, rd := rustAliasSite(file, it)
			if rd == nil {
				m.stats.UnreadableSites++
				continue
			}
			m.emitAll(entries, s, rd)
		}
	}
}

// rustAliasSite is a type alias item as a site, from its `type` keyword to
// the end of the item, as OpenGrep 1.33.1 reports a pattern-regex that
// matches it, and its read: the name and the aliased type. nil when the
// keyword is not on the item's first line or the type cannot be read.
func rustAliasSite(file string, it rustItemFact) (*Site, *rustRead) {
	if it.keywordCol < 1 || it.typ == "" {
		return nil, nil
	}
	toks, err := lexRust(it.typ)
	if err != nil {
		return nil, nil
	}
	p := &rustParser{toks: toks}
	t, err := p.parseType()
	if err != nil || !p.eof() {
		return nil, nil
	}
	s := &Site{
		File: file, Line: it.span.from.line, LineOK: true, Col: it.keywordCol, ColOK: true,
		EndCol: it.span.to.col, Kind: "type_alias", Method: it.name,
	}
	if it.span.to.line != it.span.from.line {
		s.EndLine = it.span.to.line
	}
	return s, &rustRead{alias: &rustAlias{name: it.name, typ: t}, span: [4]int{s.Line, s.Col, it.span.to.line, s.EndCol}}
}

// emitAll matches each entry at the site and keeps the findings, one per
// rule and site; a match no fact decides is counted.
func (m *rustMatcher) emitAll(entries []*Entry, s *Site, rd *rustRead) {
	for _, e := range entries {
		m.file, m.undecided = s.File, ""
		env, ok := m.matchEntry(e, s, rd)
		var hit *rustTaintHit
		if ok && e.Rust.Taint != nil {
			h, tainted := m.tainted(e, s, rd, env)
			ok, hit = tainted, &h
		}
		switch key := findingKey(e.RuleID, s, nil); {
		case !ok && m.undecided != "":
			m.stats.Undecided[m.undecided]++
		case ok && !m.seen[key]:
			m.seen[key] = true
			m.found = append(m.found, m.finding(e, s, rd, env, hit))
		}
	}
}

// rustBuckets are the Rust entries that can match, by positive: byMethod
// those that call a method name, anyMethod those that call a metavariable,
// refs those whose positive is a bare path, aliases a hand card's type
// alias, binaries a binary expression, lets a let statement.
type rustBuckets struct {
	byMethod                                 map[string][]*Entry
	anyMethod, refs, aliases, binaries, lets []*Entry
}

// bucket counts the Rust entries and sorts the ones that can match (not
// held) by their positive. The entries are the compiled ones of the rules
// without a hand card, and the Rust hand cards'.
func (m *rustMatcher) bucket(a *Assets) rustBuckets {
	b := rustBuckets{byMethod: map[string][]*Entry{}}
	compiled := slices.DeleteFunc(slices.Clone(a.index.Entries), func(e *Entry) bool {
		return e.Rust == nil || a.cards.RuleIDs[e.RuleID]
	})
	for i, e := range slices.Concat(compiled, a.cards.Rust) {
		m.stats.Entries++
		card := i >= len(compiled)
		h := m.holds(e, card)
		if len(h) > 0 {
			m.stats.Held++
			for _, r := range h {
				m.stats.HeldBy[r]++
			}
			continue
		}
		switch {
		case e.Rust.Ref != nil:
			b.refs = append(b.refs, e)
		case e.Rust.Item != nil:
			b.aliases = append(b.aliases, e)
		case e.Rust.Binary != nil:
			b.binaries = append(b.binaries, e)
		case e.Rust.Let != nil:
			b.lets = append(b.lets, e)
		case e.Rust.Call == nil:
		case e.Method != nil:
			b.byMethod[*e.Method] = append(b.byMethod[*e.Method], e)
		default:
			b.anyMethod = append(b.anyMethod, e)
		}
	}
	return b
}

// holds are the reasons the entry e (a hand card's: card) is held on the
// fragment.
func (m *rustMatcher) holds(e *Entry, card bool) []string {
	h := rustHolds(e.Rust, m.fr.RustFacts, card)
	if card && m.fr.RustFacts && !m.fr.RustAliases && rustReadsAliases(e.Rust) {
		h = append(h, holdItemTypes)
	}
	if n := needsOf(e.Rust); !m.fr.RustOps {
		if n.Binaries {
			h = append(h, holdBinaries)
		}
		if n.Params {
			h = append(h, holdParams)
		}
	}
	if e.Rust.Ref != nil && rustOneName(e.Rust.Ref) && !m.fr.RustNames {
		h = append(h, holdNames)
	}
	if e.Rust.Ref != nil && m.fr.RustFacts && !m.fr.RustTypes {
		h = append(h, holdTypes)
	}
	return h
}

// readRef reads a constant reference as a path; nil for one that is the
// head of a longer path (`a::B` of `a::B::<T>::f`), which OpenGrep does not
// match as a path of its own.
func (m *rustMatcher) readRef(r *Site) *rustRead {
	line := m.fr.Lines[r.File][r.Line]
	if r.EndLine == 0 && r.EndCol >= 1 && r.EndCol-1 <= len(line) && strings.HasPrefix(strings.TrimLeft(line[r.EndCol-1:], " \t"), "::") {
		return nil
	}
	toks, err := lexRust(r.Raw)
	if err != nil {
		return nil
	}
	p := &rustParser{toks: toks}
	path, err := p.parsePath(false)
	if err != nil || !p.eof() {
		return nil
	}
	return &rustRead{ref: path, span: [4]int{r.Line, r.Col, max(r.EndLine, r.Line), r.EndCol}, typ: r.RefContext == rustTypeRef}
}

// rustTypeRef is the position kind of a path written as a type
// (graph-fragment-1.35).
const rustTypeRef = "type"

// rustLastSegSite is the type reference r placed at its path's last
// segment, where OpenGrep 1.33.1 reports a path pattern matched on a type
// (`Key` of `acme::Key`); rd, its read, moves with it.
func rustLastSegSite(r *Site, rd *rustRead) *Site {
	last := rd.ref.Last().Name
	out := *r
	out.Line, out.Col, out.EndLine = max(r.EndLine, r.Line), r.EndCol-len(last), 0
	rd.span = [4]int{out.Line, out.Col, out.Line, out.EndCol}
	return &out
}

// countBareNames counts, per ref entry and file, the files where a path
// written as one segment may read as the pattern's path through a use or a
// glob: the fragment lists no such reference. A graph-fragment-1.33 lists
// those whose name starts with an upper-case letter.
func (m *rustMatcher) countBareNames(refs []*Entry) {
	for _, fs := range m.fr.RustScopes {
		for _, e := range refs {
			if m.fr.RustNames && rustListedName(e.Rust.Ref.Last().Name) {
				continue
			}
			if fs.mayName(e.Rust.Ref) {
				m.stats.Undecided[undecidedBareName]++
			}
		}
	}
}

// rustListedName: a graph-fragment-1.33 lists a one-segment path of this
// name where a value is read: it starts with an upper-case letter and is not
// a prelude value.
func rustListedName(name string) bool {
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r) && !rustPreludeValues[name]
}

// rustPreludeValues are the prelude values reach leaves out of constant_refs.
var rustPreludeValues = map[string]bool{"None": true, "Some": true, "Ok": true, "Err": true, "Self": true}

// mayName: a use leaf or glob of the file can name pattern from one segment.
func (fs *rustFileScope) mayName(pattern *RustPath) bool {
	fits := func(segs []string) bool {
		if len(segs) != len(pattern.Segs) {
			return false
		}
		for i, s := range pattern.Segs {
			if s.Var == "" && s.Name != segs[i] {
				return false
			}
		}
		return true
	}
	for _, d := range fs.uses {
		if d.odd {
			return true
		}
		for _, l := range d.leaves {
			if !l.glob && fits(l.segs) {
				return true
			}
		}
	}
	for _, g := range fs.globs {
		if fits(append(append([]string{}, g...), pattern.Last().Name)) {
			return true
		}
	}
	return false
}

// undecide records why the current match could not be decided.
func (m *rustMatcher) undecide(reason string) {
	if m.undecided == "" {
		m.undecided = reason
	}
}

// withAt runs f with the written paths placed at p.
func (m *rustMatcher) withAt(p rustPos, f func() bool) bool {
	old := m.at
	m.at = p
	ok := f()
	m.at = old
	return ok
}

// matchEntry reports whether the entry's pattern matches the site, with the
// bindings of the first environment that passes every filter.
func (m *rustMatcher) matchEntry(e *Entry, s *Site, rd *rustRead) (rustEnv, bool) {
	var out rustEnv
	focusMiss := false
	ok := m.matchPattern(e.Rust, s, rd, rustEnv{}, func(env rustEnv) bool {
		if f := e.Rust.Focus; f != "" {
			if _, isArg := env.arg[f]; !isArg && !rustFocusRecv(e.Rust, rd, f) && !rustFocusLet(e.Rust, f) {
				focusMiss = true
				return false
			}
		}
		out = env
		return true
	})
	if !ok && focusMiss {
		m.stats.UnfocusedSites++
	}
	return out, ok
}

// rustFocusRecv: the focus metavariable f is `$X` of the pattern's
// `$X.m(...)`, and the site says where what it binds is written.
func rustFocusRecv(p *RustPattern, rd *rustRead, f string) bool {
	r := p.Call
	return r != nil && r.Receiver != nil && r.Receiver.Kind == RustExprVar && r.Receiver.Var == f &&
		rd.call != nil && rd.call.RecvSpan[1] > 0
}

// rustFocusLet: the focus metavariable f is the name or the initializer of
// the pattern's `let $N = $V;`, reported where what it binds is written.
func rustFocusLet(p *RustPattern, f string) bool {
	l := p.Let
	return l != nil && (l.Name == f || (l.Init.Kind == RustExprVar && l.Init.Var == f))
}

// matchPattern unifies the pattern's positive with the site, then applies
// its contexts, its within patterns, its not-inside contexts, its
// pattern-not alternatives and its metavariable-regex filters; k takes each
// environment that passes, and the first one it accepts ends the search.
func (m *rustMatcher) matchPattern(p *RustPattern, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	return m.matchPatternArgs(p, s, rd, env, siteArgs, k)
}

// matchPatternArgs is matchPattern with the index the site's arguments
// bind (otherArgs: the site is not the finding's, it binds none).
func (m *rustMatcher) matchPatternArgs(p *RustPattern, s *Site, rd *rustRead, env rustEnv, args int, k func(rustEnv) bool) bool {
	rest := func(env rustEnv) bool {
		return m.matchInside(p.Inside, s, rd, env, func(env rustEnv) bool {
			return m.matchWithin(p.Within, s, rd, env, func(env rustEnv) bool { return m.filtered(p, s, rd, env, k) })
		})
	}
	return m.withAt(rd.pos(), func() bool {
		switch {
		case p.Call != nil && rd.call != nil:
			return m.unifyCall(p.Call, rd.call, env, args, rest)
		case p.Ref != nil && rd.ref != nil:
			return m.unifyRef(p.Ref, rd, env, rest)
		case p.Item != nil && rd.alias != nil:
			return unifyAlias(p.Item, rd.alias, env, rest)
		case p.Binary != nil && rd.bin != nil:
			return m.unifyBinary(p.Binary, rd.bin, env, rest)
		case p.Let != nil && rd.let != nil:
			return m.unifyLet(p.Let, rd.let, env, rest)
		}
		return false
	})
}

// unifyLet unifies a pattern let with a let declaration: the name (a
// metavariable binds it, also to a tuple pattern as written), a tuple's
// names one by one (`mut` and `ref` left out), `mut` when the pattern writes
// it, the type when the pattern writes one, and the initializer, which a
// metavariable binds as written. A let without an initializer matches
// nothing.
func (m *rustMatcher) unifyLet(pl, l *RustLet, env rustEnv, k func(rustEnv) bool) bool {
	if (pl.Mut && !l.Mut) || l.Init.Kind == "" {
		return false
	}
	ok := true
	switch {
	case pl.Tuple != nil:
		if len(pl.Tuple) != len(l.Tuple) {
			return false
		}
		for i := 0; ok && i < len(pl.Tuple); i++ {
			env, ok = rustBindName(env, pl.Tuple[i], l.Tuple[i])
		}
	case l.Tuple != nil:
		ok = isMetavar(pl.Name)
		if ok {
			env, ok = env.bind(pl.Name, l.patText())
		}
	default:
		env, ok = rustBindName(env, pl.Name, l.Name)
	}
	if !ok {
		return false
	}
	init := func(env rustEnv) bool {
		if pl.Init.Kind == RustExprVar {
			env, ok := env.bind(pl.Init.Var, l.initText())
			return ok && k(env)
		}
		return m.unifyExpr(pl.Init, l.Init, env, k)
	}
	if pl.Type == nil {
		return init(env)
	}
	return l.Type != nil && m.unifyType(*pl.Type, *l.Type, env, init)
}

// unifyBinary unifies a pattern binary expression with one of a function
// body: the operator, and each operand, which a metavariable binds as
// written (`s * base`), as OpenGrep binds it.
func (m *rustMatcher) unifyBinary(pe *RustExpr, sb *rustBinary, env rustEnv, k func(rustEnv) bool) bool {
	if pe.Op != sb.expr.Op {
		return false
	}
	operand := func(p, s *RustExpr, written string, env rustEnv, k func(rustEnv) bool) bool {
		if p.Kind == RustExprVar {
			env, ok := env.bind(p.Var, written)
			return ok && k(env)
		}
		return m.unifyExpr(*p, *s, env, k)
	}
	return operand(pe.Sub, sb.expr.Sub, sb.left, env, func(env rustEnv) bool {
		return operand(pe.Right, sb.expr.Right, sb.right, env, k)
	})
}

// unifyAlias unifies a type alias pattern, `type $A = T;`, with a type alias
// item: the name (a metavariable binds it), and the aliased type as written
// (unifyWrittenType).
func unifyAlias(pi *RustItem, sa *rustAlias, env rustEnv, k func(rustEnv) bool) bool {
	if pi.Kind != rustItemType || pi.Type == nil {
		return false
	}
	env, ok := rustBindName(env, pi.Name, sa.name)
	return ok && unifyWrittenType(*pi.Type, sa.typ, env, k)
}

// unifyWrittenType unifies a pattern type with a written one as written:
// a path segment by segment, a leading `::` and a qualified self included,
// with the generics on each segment (none matches none only); a tuple
// element by element; any other type by its canonical text. A metavariable
// binds the whole written type in its canonical spelling
// (`aes::Aes128`, `Wrap<u8>`), what a metavariable-regex then reads. Unlike
// a call's generics (unifyType), a path is not told apart by its last
// segment only, and no use names it: `cbc::Mode<$C>` does not match
// `Mode<Blk>` nor `other::Mode<Blk>`.
func unifyWrittenType(pt, st RustType, env rustEnv, k func(rustEnv) bool) bool {
	switch {
	case pt.Var != "":
		env, ok := env.bind(pt.Var, st.String())
		return ok && k(env)
	case pt.Path != nil && st.Path != nil:
		return unifyWrittenPath(pt.Path, st.Path, env, k)
	case pt.Tuple != nil && st.Tuple != nil && len(pt.Tuple) == len(st.Tuple):
		return unifyWrittenTypes(pt.Tuple, st.Tuple, env, k)
	case pt.Ref != nil && st.Ref != nil && pt.Mut == st.Mut:
		return unifyWrittenType(*pt.Ref, *st.Ref, env, k)
	}
	return rustTextType(pt) && rustTextType(st) && pt.Text == st.Text && k(env)
}

// rustTextType: t is a type read as canonical text, no shape of its own.
func rustTextType(t RustType) bool {
	return t.Path == nil && t.Tuple == nil && t.Ref == nil && t.Var == ""
}

func unifyWrittenTypes(pts, sts []RustType, env rustEnv, k func(rustEnv) bool) bool {
	if len(pts) == 0 {
		return k(env)
	}
	return unifyWrittenType(pts[0], sts[0], env, func(env rustEnv) bool {
		return unifyWrittenTypes(pts[1:], sts[1:], env, k)
	})
}

// unifyWrittenPath unifies two paths in type position as written.
func unifyWrittenPath(pp, sp *RustPath, env rustEnv, k func(rustEnv) bool) bool {
	if pp.Global != sp.Global || (pp.QSelf == nil) != (sp.QSelf == nil) || len(pp.Segs) != len(sp.Segs) {
		return false
	}
	segs := func(env rustEnv) bool { return unifyWrittenSegs(pp.Segs, sp.Segs, env, k) }
	if pp.QSelf == nil {
		return segs(env)
	}
	pq, sq := pp.QSelf, sp.QSelf
	if (pq.Trait == nil) != (sq.Trait == nil) {
		return false
	}
	return unifyWrittenType(pq.Self, sq.Self, env, func(env rustEnv) bool {
		if pq.Trait == nil {
			return segs(env)
		}
		return unifyWrittenPath(pq.Trait, sq.Trait, env, segs)
	})
}

func unifyWrittenSegs(ps, ss []RustSeg, env rustEnv, k func(rustEnv) bool) bool {
	if len(ps) == 0 {
		return k(env)
	}
	p, s := ps[0], ss[0]
	env, ok := rustBindSeg(env, p, s.Name)
	if !ok || (p.Generics == nil) != (s.Generics == nil) || len(p.Generics) != len(s.Generics) {
		return false
	}
	return unifyWrittenTypes(p.Generics, s.Generics, env, func(env rustEnv) bool {
		return unifyWrittenSegs(ps[1:], ss[1:], env, k)
	})
}

// filtered calls k with env past p's negatives and where clauses (the
// latter extending it), when env passes them. Outside a negative the where
// clauses go first, each test still given env: both only filter, and a
// where clause on what a use context binds turns down most uses of the
// file, which a negative's own use context would each walk again. Inside
// one, what the negatives leave undecided decides it (negated), so they
// keep their turn.
func (m *rustMatcher) filtered(p *RustPattern, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	if m.negating == 0 {
		wenv, ok := rustWhere(p.Where, env)
		return ok && !m.rejected(p, s, rd, env) && k(wenv)
	}
	if m.rejected(p, s, rd, env) {
		return false
	}
	env, ok := rustWhere(p.Where, env)
	return ok && k(env)
}

// rejected: a not-inside context or a pattern-not of p holds at the site
// under env.
func (m *rustMatcher) rejected(p *RustPattern, s *Site, rd *rustRead, env rustEnv) bool {
	for i := range p.NotInside {
		if m.negated(func() bool { return m.enclosed(&p.NotInside[i], s, rd, env) }) {
			return true
		}
	}
	for i := range p.Not {
		if m.negated(func() bool { return m.matchPattern(&p.Not[i], s, rd, env, func(rustEnv) bool { return true }) }) {
			return true
		}
	}
	return false
}

// negated evaluates a negative: true when it holds, and also when a fact
// could not decide it (the site is then dropped and counted undecided).
func (m *rustMatcher) negated(holds func() bool) bool {
	saved := m.undecided
	m.undecided = ""
	m.negating++
	ok := holds()
	m.negating--
	if !ok && m.undecided != "" {
		return true
	}
	if m.undecided == "" {
		m.undecided = saved
	}
	return ok
}

// matchInside requires every context to hold at the site, binding what it
// binds.
func (m *rustMatcher) matchInside(ctxs []RustContext, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	f := &rustFeasible{env: env}
	if m.negating == 0 {
		// Outside a negative what is left undecided only feeds the counts,
		// so a context that cannot hold ends the search before the contexts
		// in front of it are walked.
		for i := 1; i < len(ctxs); i++ {
			if !m.feasible(ctxs, i, f, s, rd) {
				return false
			}
		}
	}
	return m.matchContexts(ctxs, 0, f, s, rd, env, k)
}

// rustFeasible records, for one matchInside, which contexts were found to
// hold under its starting environment: by index, 0 unknown, 1 they may, -1
// they cannot.
type rustFeasible struct {
	env   rustEnv
	known []int8
}

// matchContexts calls k with each environment under which the contexts from
// ctxs[i] on hold at the site, until k accepts one.
//
// The contexts are a conjunction searched by backtracking: without a check,
// a let or call context that cannot hold is searched again for every way
// the contexts before it hold (each use leaf a use context matches, say), a
// product the size of a generated file. So such a context is first searched
// once under the starting environment, f.env, and skipped from then on when
// that search failed. Skipping it is exact: the environment it would be
// searched under extends f.env, and a context reads its environment only
// through bind, which an extension can only refuse, and through the names
// it binds, which only hide more lets (letContext); its paths are a subset
// of the failed search's, which all failed. Inside a negative the check
// counts only when it recorded nothing undecided (a negative that cannot be
// decided holds, negated). It reaches only up to the first where clause, as
// its named groups overwrite metavariables (rustWhere). Let and call
// contexts place their paths themselves; a use context names paths at the
// position the contexts before it leave, so it is not checked.
func (m *rustMatcher) matchContexts(ctxs []RustContext, i int, f *rustFeasible, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	if i == len(ctxs) {
		return k(env)
	}
	c := &ctxs[i]
	if i > 0 && !m.feasible(ctxs, i, f, s, rd) {
		return false
	}
	return m.context(c, s, rd, env, func(env rustEnv) bool {
		env, ok := rustWhere(c.Where, env)
		return ok && m.matchContexts(ctxs, i+1, f, s, rd, env, k)
	})
}

// feasible: the check of matchContexts for ctxs[i], i > 0, run once.
func (m *rustMatcher) feasible(ctxs []RustContext, i int, f *rustFeasible, s *Site, rd *rustRead) bool {
	c := &ctxs[i]
	if c.Let == nil && c.Call == nil {
		return true
	}
	for _, before := range ctxs[:i] {
		if len(before.Where) > 0 {
			return true
		}
	}
	if f.known == nil {
		f.known = make([]int8, len(ctxs))
	}
	if f.known[i] == 0 {
		undecided := m.undecided
		m.undecided = ""
		holds := m.context(c, s, rd, f.env, func(rustEnv) bool { return true })
		f.known[i] = 1
		if !holds && (m.undecided == "" || m.negating == 0) {
			f.known[i] = -1
		}
		if undecided != "" || f.known[i] > 0 {
			m.undecided = undecided
		}
	}
	return f.known[i] > 0
}

// matchWithin requires every within pattern to match the site or a call
// around it, binding what it binds.
func (m *rustMatcher) matchWithin(ws []RustPattern, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	if len(ws) == 0 {
		return k(env)
	}
	w := &ws[0]
	next := func(env rustEnv) bool { return m.matchWithin(ws[1:], s, rd, env, k) }
	if m.matchPattern(w, s, rd, env, next) {
		return true
	}
	for _, o := range m.fileSites(s.File) {
		if !m.contains(o, s, rd) {
			continue
		}
		if ord := m.read(o); ord != nil && m.matchPatternArgs(w, o, ord, env, otherArgs, next) {
			return true
		}
	}
	return false
}

// enclosed: the context holds at the site under env.
func (m *rustMatcher) enclosed(c *RustContext, s *Site, rd *rustRead, env rustEnv) bool {
	return m.matchInside([]RustContext{*c}, s, rd, env, func(rustEnv) bool { return true })
}

// context calls k with each environment a fact satisfying c at the site
// binds, until k accepts one.
func (m *rustMatcher) context(c *RustContext, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	fs := m.fr.RustScopes[s.File]
	switch {
	case c.Call != nil:
		return m.callContext(c, s, rd, env, k)
	case c.Let != nil:
		return m.letContext(c, s, rd.pos(), env, k)
	case fs == nil:
		return false
	case c.Item != nil && c.Item.Use != nil:
		return m.fnUseContext(fs, c, rd.pos(), env, k)
	case c.Item != nil:
		return m.itemContext(fs, c, rd.pos(), env, k)
	}
	return m.useContext(fs, c, rd.pos(), env, k)
}

// fnUseContext: `fn $F(...) { ... use P; ... }` holds at a site inside a
// fn that declares a use P anywhere in its span, before or after the site,
// in a nested block or in a nested fn, as OpenGrep 1.22.0 and 1.33.1 read
// it; a use of the enclosing mod does not count.
func (m *rustMatcher) fnUseContext(fs *rustFileScope, c *RustContext, p rustPos, env rustEnv, k func(rustEnv) bool) bool {
	use := &RustContext{Use: c.Item.Use}
	for _, it := range fs.items {
		if it.kind != "fn" || !it.span.contains(p) {
			continue
		}
		if env, ok := rustBindName(env, c.Item.Name, it.name); ok && m.usesIn(fs, it.span, use, env, k) {
			return true
		}
	}
	return false
}

// usesIn: a use declared inside span matches the use context c.
func (m *rustMatcher) usesIn(fs *rustFileScope, span rustSpan, c *RustContext, env rustEnv, k func(rustEnv) bool) bool {
	for _, d := range fs.uses {
		if !span.contains(d.span.from) {
			continue
		}
		if d.odd {
			m.undecide(undecidedUseTree)
			continue
		}
		for _, l := range d.leaves {
			if m.useLeaf(c, &l, env, k) {
				return true
			}
		}
	}
	return false
}

// itemContext: an item of the file placed as c says matches c's item; a fn
// also its parameters, unless they are `...` only.
func (m *rustMatcher) itemContext(fs *rustFileScope, c *RustContext, p rustPos, env rustEnv, k func(rustEnv) bool) bool {
	params := c.Item.Kind == "fn" && rustFnReadsParams(c.Item)
	for _, it := range fs.items {
		if it.kind != c.Item.Kind || !fs.placed(c.Place, it.span, p) {
			continue
		}
		env, ok := rustBindName(env, c.Item.Name, it.name)
		if !ok {
			continue
		}
		if c.Item.Kind == rustItemType && !m.aliasTail(c.Item.Type, it.typ) {
			continue
		}
		if params && m.unifyParams(c.Item.Params, it.params, env, k) || !params && k(env) {
			return true
		}
	}
	return false
}

// aliasTail: the aliased type as written, text, is what the type alias
// context's pattern type pt reads. OpenGrep 1.33.1 tells path types apart
// by their last segment only, and by its generics (pinned by invented
// rules): `type $T = $M::Hash;` matches `sha256::Hash`, `a::b::Hash`,
// `Hash` and `<X as Tr>::Hash`, not `Other`, `Hash<u8>`, `&Hash` or a
// tuple. A type no reader knows is counted undecided.
func (m *rustMatcher) aliasTail(pt *RustType, text string) bool {
	st, ok := readRustType(text)
	if !ok {
		m.undecide(undecidedAliasTyp)
		return false
	}
	if st.Path == nil {
		return false
	}
	last := st.Path.Last()
	return last.Name == pt.Path.Last().Name && last.Generics == nil
}

// unifyParams unifies a fn pattern's parameters with a fn item's, as OpenGrep
// 1.33.1 reads them (pinned by invented rules): `...` matches any run of
// parameters, a self receiver included; `name: T` matches a parameter that
// is not a self receiver, typed or not, whose pattern is the name (a
// metavariable binds it, `mut` left out) and whose type matches T as
// unifyParamType reads it.
func (m *rustMatcher) unifyParams(pps []RustParam, sps []graphfrag.GraphFragmentParam, env rustEnv, k func(rustEnv) bool) bool {
	if len(pps) == 0 {
		return len(sps) == 0 && k(env)
	}
	if pps[0].Ellipsis {
		for n := 0; n <= len(sps); n++ {
			if m.unifyParams(pps[1:], sps[n:], env, k) {
				return true
			}
		}
		return false
	}
	if len(sps) == 0 || sps[0].Self {
		return false
	}
	name := strings.TrimSpace(strings.TrimPrefix(sps[0].Pattern, "mut "))
	env, ok := rustBindName(env, pps[0].Name, name)
	if !ok {
		return false
	}
	return m.unifyParamType(*pps[0].Type, sps[0].Type, env, func(env rustEnv) bool {
		return m.unifyParams(pps[1:], sps[1:], env, k)
	})
}

// unifyParamType unifies a pattern type with a parameter's type as written.
// OpenGrep 1.33.1 tells path types apart by their last segment and its
// generics (`acme::Key` matches `other::Key` and `Key`; a metavariable
// segment in front of the last binds nothing); `&T` matches `&T` and `&mut
// T` and `&mut T` only `&mut T`, a lifetime ignored; any other type compares
// as written. A metavariable binds the type as written, but a path type
// (`acme::Wrap<X>`, `dyn acme::Tr`) only from its last segment (`Wrap<X>`).
func (m *rustMatcher) unifyParamType(pt RustType, written string, env rustEnv, k func(rustEnv) bool) bool {
	written = strings.TrimSpace(written)
	st, ok := readRustType(written)
	if !ok {
		return false
	}
	switch {
	case pt.Var != "":
		env, ok := env.bind(pt.Var, rustWrittenTypeBound(written, st))
		return ok && k(env)
	case pt.Ref != nil:
		if st.Ref == nil || (pt.Mut && !st.Mut) {
			return false
		}
		return m.unifyParamType(*pt.Ref, rustRefElemText(written), env, k)
	case pt.Trait != nil:
		return m.unifyTraitParam(pt.Trait, st, env, k)
	}
	return m.unifyType(pt, st, env, k)
}

// unifyTraitParam unifies a pattern `dyn P` or `impl P` with a parameter's
// type. OpenGrep 1.33.1 reads neither keyword and compares the paths by
// their last segment only (pinned by invented rules): `&dyn acme::Tr`
// matches `&dyn Tr`, `&impl Tr`, `&acme::Tr` and also `&dyn other::Tr`,
// whatever trait Tr names there. The matcher keeps the last segment rule
// but, for a qualified P, also requires the written path to be P as
// written or as the file's uses before the site name it (a glob included):
// `&dyn Tr` after `use crate::crypto::Tr;`, `&dyn other::Tr` and `&dyn Tr`
// with no use are OpenGrep false positives on another library's trait,
// not copied. A use no pin covers leaves the site undecided.
func (m *rustMatcher) unifyTraitParam(pp *RustPath, st RustType, env rustEnv, k func(rustEnv) bool) bool {
	sp := st.Trait
	if sp == nil {
		sp = st.Path
	}
	if sp == nil || sp.QSelf != nil || sp.Last().Generics != nil || sp.Last().Name != pp.Last().Name {
		return false
	}
	if !pp.Qualified() {
		return k(env)
	}
	return m.unifyPath(pp, sp, env, true, k)
}

// readRustType reads source text as a type.
func readRustType(text string) (RustType, bool) {
	toks, err := lexRust(text)
	if err != nil {
		return RustType{}, false
	}
	p := &rustParser{toks: toks}
	t, err := p.parseType()
	return t, err == nil && p.eof()
}

// rustRefElemText is the written text of a reference type's referenced type:
// `acme::Key` of `&'a mut acme::Key`.
func rustRefElemText(written string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(written, "&"))
	if strings.HasPrefix(rest, "'") {
		i := 1
		for i < len(rest) && isRustIdentByte(rest[i]) {
			i++
		}
		rest = strings.TrimSpace(rest[i:])
	}
	if after, ok := strings.CutPrefix(rest, "mut"); ok && (after == "" || !isRustIdentByte(after[0])) {
		rest = strings.TrimSpace(after)
	}
	return rest
}

// rustWrittenTypeBound is what a metavariable binds on a type written as
// text and read as t, as OpenGrep 1.33.1 binds it in a fn parameter: a path
// type from its last segment, generics included and as written
// (`Wrap<other::Blk>` of `acme::Wrap<other::Blk>`, `Sealer` of `dyn
// acme::Sealer`), any other type whole.
func rustWrittenTypeBound(written string, t RustType) string {
	if t.Text != "" {
		if rest, ok := strings.CutPrefix(written, "dyn "); ok {
			if inner, ok := readRustType(strings.TrimSpace(rest)); ok && inner.Path != nil {
				return rustWrittenTypeBound(strings.TrimSpace(rest), inner)
			}
		}
		return written
	}
	if t.Path == nil || t.Path.QSelf != nil {
		return written
	}
	return strings.TrimSpace(written[rustLastPathSegment(written):])
}

// rustLastPathSegment: the offset in written after its last top-level
// `::`, outside generics, or 0.
func rustLastPathSegment(written string) int {
	depth, last := 0, 0
	for i := 0; i+1 < len(written); i++ {
		switch written[i] {
		case '<':
			depth++
		case '>':
			if i == 0 || written[i-1] != '-' { // the > of -> closes nothing
				depth--
			}
		case ':':
			if depth == 0 && written[i+1] == ':' {
				last = i + 2
			}
		}
	}
	return last
}

// useContext: a leaf of a use declaration (or extern crate) placed as c
// says matches c's use.
func (m *rustMatcher) useContext(fs *rustFileScope, c *RustContext, p rustPos, env rustEnv, k func(rustEnv) bool) bool {
	for _, d := range fs.uses {
		if !fs.placed(c.Place, d.span, p) {
			continue
		}
		if d.odd {
			m.undecide(undecidedUseTree)
			continue
		}
		for _, l := range d.leaves {
			if m.useLeaf(c, &l, env, k) {
				return true
			}
		}
	}
	return false
}

// callContext: a call enclosing the site matches the context's call.
func (m *rustMatcher) callContext(c *RustContext, s *Site, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	for _, o := range m.fileSites(s.File) {
		if !m.contains(o, s, rd) {
			continue
		}
		ord := m.read(o)
		if ord == nil {
			continue
		}
		if m.withAt(ord.pos(), func() bool { return m.unifyCall(c.Call, ord.call, env, otherArgs, k) }) {
			return true
		}
	}
	return false
}

// letContext: a let declaration of the site's function, before the site (or
// around it), matches the context's let. A function body is one block.
// OpenGrep 1.33.1 tells a name the let binds from the same name a later let
// binds (pinned by invented rules): a metavariable of the let that the site
// or another context already binds must not be bound again by a let
// between the two.
func (m *rustMatcher) letContext(c *RustContext, s *Site, p rustPos, env rustEnv, k func(rustEnv) bool) bool {
	var read map[string]bool
	if c.Until != nil {
		read = map[string]bool{}
		c.Until.vars(read)
	}
	for _, cl := range m.letCandidates(c, s, env) {
		d, span := cl.decl, cl.span
		if !rustLetPlaced(c.Place, span, p) {
			continue
		}
		l := m.readLet(d)
		if l == nil {
			m.undecide(undecidedLet)
			continue
		}
		if l.Tuple == nil && l.Name != d.AssignedVar {
			continue
		}
		if m.shadowed(s.Caller, rustLetNames(c.Let, l, func(v string) bool { _, ok := env.vars.get(v); return ok }), span, p) {
			continue
		}
		next := k
		if c.Until != nil {
			names := rustLetNames(c.Let, l, func(v string) bool { return read[v] })
			next = func(env rustEnv) bool { return m.untilAfter(c.Until, names, s, span, p, env, k) }
		}
		if m.withAt(span.from, func() bool { return m.unifyLet(c.Let, l, env, next) }) {
			return true
		}
	}
	return false
}

// letCandidates are the lets of s's function that the context's let can
// match under env, in callerLets order. A pattern let that names what it
// binds, as written or by a metavariable env already binds, unifies only
// with a let that binds that text (unifyLet): those come from an index, the
// unreadable lets kept among them for what they leave undecided. Without
// it each let of a generated function with hundreds of them would try every
// other one.
func (m *rustMatcher) letCandidates(c *RustContext, s *Site, env rustEnv) []rustCallerLet {
	lets := m.callerLets(s.Caller)
	name := c.Let.Name
	if c.Let.Tuple != nil || name == "$_" {
		return lets
	}
	if isMetavar(name) {
		text, ok := env.vars.get(name)
		if !ok {
			return lets
		}
		name = text
	}
	named := m.letsNamed(s.Caller)
	if out, ok := named.byText[name]; ok {
		return out
	}
	return named.odd
}

// rustNamedLets are a function's lets by the text they bind, and its
// unreadable lets.
type rustNamedLets struct {
	byText map[string][]rustCallerLet
	odd    []rustCallerLet
}

// letsNamed indexes callerLets by the text a let binds, its name or its
// tuple pattern as written, each list in callerLets order with the
// unreadable lets in their places. A let listed under a name it does not
// declare (letContext skips it) is left out.
func (m *rustMatcher) letsNamed(caller string) rustNamedLets {
	if named, ok := m.letNames[caller]; ok {
		return named
	}
	out := map[string][]rustCallerLet{}
	var odd []rustCallerLet
	for _, cl := range m.callerLets(caller) {
		l := m.readLet(cl.decl)
		switch {
		case l == nil:
			odd = append(odd, cl)
			for k := range out {
				out[k] = append(out[k], cl)
			}
			continue
		case l.Tuple == nil && l.Name != cl.decl.AssignedVar:
			continue
		}
		key := l.Name
		if l.Tuple != nil {
			key = l.patText()
		}
		if _, ok := out[key]; !ok {
			out[key] = slices.Clone(odd)
		}
		out[key] = append(out[key], cl)
	}
	if m.letNames == nil {
		m.letNames = map[string]rustNamedLets{}
	}
	named := rustNamedLets{byText: out, odd: odd}
	m.letNames[caller] = named
	return named
}

// rustCallerLet is a let of a function and its span.
type rustCallerLet struct {
	decl *Site
	span rustSpan
}

// callerLets are caller's lets in DeclsByCaller order, each span once (the
// first listing): reach lists a let that binds several names once per name.
// Built on first use, as each let of a function asks for the others.
func (m *rustMatcher) callerLets(caller string) []rustCallerLet {
	if out, ok := m.letsOf[caller]; ok {
		return out
	}
	seen := map[rustSpan]bool{}
	out := []rustCallerLet{}
	for _, d := range m.fr.DeclsByCaller[caller] {
		span := rustSpanOf(d.Line, d.Col, d.EndCol, d.EndLine)
		if !seen[span] {
			seen[span] = true
			out = append(out, rustCallerLet{d, span})
		}
	}
	if m.letsOf == nil {
		m.letsOf = map[string][]rustCallerLet{}
	}
	m.letsOf[caller] = out
	return out
}

// rustLetNames are the names the let l binds to a metavariable of the
// pattern let pl that read accepts: a later let of one of them hides l from
// what reads it.
func rustLetNames(pl, l *RustLet, read func(string) bool) []string {
	var out []string
	switch {
	case pl.Tuple != nil && len(pl.Tuple) == len(l.Tuple):
		for i, n := range pl.Tuple {
			if isMetavar(n) && read(n) {
				out = append(out, l.Tuple[i])
			}
		}
	case pl.Tuple == nil && l.Tuple == nil && isMetavar(pl.Name) && read(pl.Name):
		out = append(out, l.Name)
	}
	return out
}

// untilAfter: the end of a sequence context, until, matches an expression of
// the site's function that starts after the let at span and ends after the
// site at p (rustUntilServable), with no let of names in between: OpenGrep
// 1.33.1 tells a name the let binds from the same name a later let binds
// (pinned by invented rules). A let in a block that has ended still counts,
// as no fact gives the blocks.
func (m *rustMatcher) untilAfter(until *RustExpr, names []string, s *Site, span rustSpan, p rustPos, env rustEnv, k func(rustEnv) bool) bool {
	e := until
	if e.Kind == RustExprDeep {
		e = e.Sub
	}
	after := func(rd *rustRead) bool {
		from := rustPos{rd.span[0], rd.span[1]}
		return !from.before(span.to) && p.before(rustPos{rd.span[2], rd.span[3]}) && !m.shadowed(s.Caller, names, span, from)
	}
	if e.Kind == RustExprRef {
		return m.untilDeep(e, s, after, env, k)
	}
	if e.Kind == RustExprBinary {
		for _, b := range m.callerBinaries(s.File, s.Caller) {
			if after(b.read) && m.withAt(b.read.pos(), func() bool { return m.unifyBinary(e, b.read.bin, env, k) }) {
				return true
			}
		}
		return false
	}
	return m.untilCall(e.Call, s, after, env, k)
}

// shadowed: a let of the function declares one of names after the let at
// span and ends before at.
func (m *rustMatcher) shadowed(caller string, names []string, span rustSpan, at rustPos) bool {
	if len(names) == 0 {
		return false
	}
	byName := m.letsByName(caller)
	for _, n := range names {
		ls := byName[n]
		i := sort.Search(len(ls.from), func(i int) bool { return !ls.from[i].before(span.to) })
		if i < len(ls.from) && !at.before(ls.minTo[i]) {
			return true
		}
	}
	return false
}

// rustNameLets are the lets of a function that declare one name, by start:
// minTo[i] is the earliest end of the lets from the i-th on, so a let that
// starts after a position and ends before another is one search away.
type rustNameLets struct {
	from, minTo []rustPos
}

// letsByName indexes caller's lets by the name they declare, built on first
// use: shadowed is asked for each pair of a let and a later call, and a
// function can declare hundreds of lets.
func (m *rustMatcher) letsByName(caller string) map[string]rustNameLets {
	if out, ok := m.shadows[caller]; ok {
		return out
	}
	spans := map[string][]rustSpan{}
	for _, d := range m.fr.DeclsByCaller[caller] {
		spans[d.AssignedVar] = append(spans[d.AssignedVar], rustSpanOf(d.Line, d.Col, d.EndCol, d.EndLine))
	}
	out := make(map[string]rustNameLets, len(spans))
	for name, ss := range spans {
		slices.SortStableFunc(ss, func(a, b rustSpan) int {
			switch {
			case a.from.before(b.from):
				return -1
			case b.from.before(a.from):
				return 1
			}
			return 0
		})
		ls := rustNameLets{from: make([]rustPos, len(ss)), minTo: make([]rustPos, len(ss))}
		for i := len(ss) - 1; i >= 0; i-- {
			ls.from[i], ls.minTo[i] = ss[i].from, ss[i].to
			if i+1 < len(ss) && ls.minTo[i+1].before(ls.minTo[i]) {
				ls.minTo[i] = ls.minTo[i+1]
			}
		}
		out[name] = ls
	}
	if m.shadows == nil {
		m.shadows = map[string]map[string]rustNameLets{}
	}
	m.shadows[caller] = out
	return out
}

// untilDeep: the expression e is written in a call of the site's function
// (its receiver or arguments, at any depth) or in a let's initializer that
// after accepts: the end of a sequence context, `<... E ...>;`.
func (m *rustMatcher) untilDeep(e *RustExpr, s *Site, after func(*rustRead) bool, env rustEnv, k func(rustEnv) bool) bool {
	in := func(rd *rustRead, x RustExpr) bool {
		return after(rd) && m.withAt(rd.pos(), func() bool {
			return rustWalk(x, func(sub RustExpr) bool { return m.unifyExpr(*e, sub, env, k) })
		})
	}
	for _, o := range m.callerCalls(s.File, s.Caller) {
		if rd := m.read(o); rd != nil && in(rd, RustExpr{Kind: RustExprCall, Call: rd.call}) {
			return true
		}
	}
	for _, d := range m.fr.DeclsByCaller[s.Caller] {
		if l := m.readLet(d); l != nil && l.Init.Kind != "" && in(&rustRead{span: [4]int{d.Line, d.Col, max(d.EndLine, d.Line), d.EndCol}}, l.Init) {
			return true
		}
	}
	return false
}

// untilCall: a call of the site's function that after accepts matches the
// end of a sequence context, `<... C ...>;` or a bare `C`.
func (m *rustMatcher) untilCall(c *RustCall, s *Site, after func(*rustRead) bool, env rustEnv, k func(rustEnv) bool) bool {
	for _, o := range m.callerCalls(s.File, s.Caller) {
		if rd := m.read(o); rd != nil && after(rd) && m.withAt(rd.pos(), func() bool { return m.unifyCall(c, rd.call, env, otherArgs, k) }) {
			return true
		}
	}
	return false
}

// rustLetPlaced: a let at span holds at p, around it or before it in the
// function.
func rustLetPlaced(place RustPlace, span rustSpan, p rustPos) bool {
	if place == RustAround {
		return span.contains(p)
	}
	return !p.before(span.from)
}

// readLet reads a let declaration from its source text; nil when it cannot.
func (m *rustMatcher) readLet(d *Site) *RustLet {
	if l, ok := m.lets[d]; ok {
		return l
	}
	var l *RustLet
	if text, ok := m.spanText(d.File, d.Line, d.Col, d.EndLine, d.EndCol); ok {
		l = readRustLet(text)
	}
	m.lets[d] = l
	return l
}

// readRustLet reads `let [mut] pat[: T] [= init];`, pat a name or a tuple
// pattern (its elements in Tuple, see tuplePattern); a let without an
// initializer reads with a nil Init. It returns nil for any other pattern or
// an initializer it cannot read.
func readRustLet(text string) *RustLet {
	toks, err := lexRust(text)
	if err != nil {
		return nil
	}
	p := &rustParser{toks: toks}
	if !p.accept("let") {
		return nil
	}
	src := &rustLetSrc{text: text}
	if !p.eof() {
		src.pat = p.toks[p.i].off
	}
	l := &RustLet{Mut: p.accept("mut"), src: src}
	switch {
	case p.is("("):
		from := p.toks[p.i].off
		if l.Tuple = p.tuplePattern(); l.Tuple == nil {
			return nil
		}
		src.name = [2]int{from, p.toks[p.i-1].end()}
	case p.segStart():
		l.Name = p.toks[p.i].text
		src.name = [2]int{p.toks[p.i].off, p.toks[p.i].end()}
		p.i++
	default:
		return nil
	}
	if p.accept(":") {
		t, err := p.parseType()
		if err != nil {
			return nil
		}
		l.Type = &t
	}
	if !p.accept("=") {
		return l
	}
	rest := p.toks[p.i:]
	if n := len(rest); n > 0 && rest[n-1].text == ";" {
		rest = rest[:n-1]
	}
	init, ok := readRustExpr(rustJoin(rest))
	if !ok || len(rest) == 0 {
		return nil
	}
	l.Init = init
	src.init = [2]int{rest[0].off, rest[len(rest)-1].end()}
	return l
}

// tuplePattern reads a tuple pattern of source text, `(a, mut b, _)`: each
// element a name (`ref` and `mut` left out), `_`, or a nested tuple as its
// canonical text; nil for any other element.
func (p *rustParser) tuplePattern() []string {
	if !p.accept("(") {
		return nil
	}
	out := []string{}
	for !p.accept(")") {
		switch {
		case p.is("("):
			from := p.i
			if p.tuplePattern() == nil {
				return nil
			}
			out = append(out, rustJoin(p.toks[from:p.i]))
		default:
			p.accept("ref")
			p.accept("mut")
			if p.eof() || p.toks[p.i].kind != rtIdent {
				return nil
			}
			out = append(out, p.toks[p.i].text)
			p.i++
		}
		if !p.accept(",") && !p.is(")") {
			return nil
		}
	}
	return out
}

// useLeaf calls k with what the use (or extern crate) context c binds on
// leaf l, as OpenGrep 1.22.0 reads each form (pinned by invented rules).
func (m *rustMatcher) useLeaf(c *RustContext, l *rustLeaf, env rustEnv, k func(rustEnv) bool) bool { //nolint:funlen,gocognit,gocyclo // one case per pinned use form
	if c.ExternCrate != nil {
		return m.externLeaf(c.ExternCrate, l, env, k)
	}
	u := c.Use
	segs := u.Path.Segs
	aliasOK := func(env rustEnv) (rustEnv, bool) {
		if u.Alias == "" {
			return env, true
		}
		if l.extern || l.alias == "" {
			return env, false
		}
		return rustBindName(env, u.Alias, l.alias)
	}
	switch {
	case u.Glob: // `use a::*;`, `use $X::*;`
		if !l.glob {
			return false
		}
		if segs[0].Var != "" {
			if l.grouped {
				m.undecide(undecidedUseTree)
				return false
			}
			env, ok := env.bind(segs[0].Var, l.text)
			return ok && k(env)
		}
		return !l.grouped && rustSegsPrefix(segs, l.segs) && k(env)
	case l.glob && len(segs) > 1 && (!l.grouped || l.own == 0): // `use a::b;` on `use a::b::c::*;`, `use a::b::c::{*};`
		return m.globLeaf(u, l, env, k)
	case l.glob && len(segs) > 1 && segs[0].Var != "": // `use $M::N;` on `use a::{b::*};`
		return u.Alias == "" && m.globModLeaf(segs, rustNestedGlobPath(l), env, k)
	case len(segs) == 1 && segs[0].Var != "": // `use $X;`, `use $X as A;`
		env, ok := env.bind(segs[0].Var, l.text)
		if !ok {
			return false
		}
		env, ok = aliasOK(env)
		return ok && k(env)
	case segs[0].Var != "": // `use $M::N;`
		if l.self {
			return m.selfModLeaf(u, l, env, k)
		}
		if l.glob && isMetavar(segs[1].Var+segs[1].Name) {
			m.undecide(undecidedUseTree)
			return false
		}
		if l.extern || l.glob || l.module == "" {
			return false
		}
		env, ok := env.bind(segs[0].Var, l.module)
		if !ok {
			return false
		}
		env, ok = rustBindSeg(env, segs[1], l.segs[len(l.segs)-1])
		return ok && k(env)
	case len(segs) == 1: // `use a;`, `use a as A;`
		if l.nested || l.segs[0] != segs[0].Name {
			return false
		}
		if u.Alias == "" {
			return k(env)
		}
		if l.extern || l.alias == "" || l.self {
			return false
		}
		if len(l.segs) > 1 {
			m.undecide(undecidedUseTree)
			return false
		}
		env, ok := aliasOK(env)
		return ok && k(env)
	}
	// `use a::b::N;`, `use a::$N;`, with or without an alias
	if l.self && !rustSelfLeafMayMatch(segs, l) {
		return false
	}
	if l.self || (l.glob && l.grouped) {
		m.undecide(undecidedUseTree)
		return false
	}
	if rustUsePrefix(u, l) {
		return k(env)
	}
	env, ok := rustBindLeafPath(segs, l, env)
	if !ok {
		return false
	}
	env, ok = aliasOK(env)
	return ok && k(env)
}

// selfModLeaf: `use $M::N;` on a self leaf. OpenGrep 1.33.1 reads
// `use a::N::{self, X};` as a use of the module path a::N, binding $M to `a`,
// only when that path has two segments and the self sits in the outermost
// group (pinned by invented rules): `use a::b::N::{self};`,
// `use a::{N::{self}};` and `use N::{self};` do not match, and neither does
// a self leaf whose path ends in another name than N. `use $M::$N;` binds $M
// to the whole path in front of the self, of any length, and $N to `self`
// (`use a::b::{self, C};`, also nested or aliased). Other forms are
// undecided.
func (m *rustMatcher) selfModLeaf(u *RustUse, l *rustLeaf, env rustEnv, k func(rustEnv) bool) bool {
	segs := u.Path.Segs
	if len(segs) == 2 && segs[1].Var != "" && u.Alias == "" {
		env, ok := env.bind(segs[0].Var, strings.Join(l.segs, "::"))
		if !ok {
			return false
		}
		env, ok = env.bind(segs[1].Var, "self")
		return ok && k(env)
	}
	if len(segs) != 2 || segs[1].Var != "" || u.Alias != "" {
		m.undecide(undecidedUseTree)
		return false
	}
	if len(l.segs) != 2 || l.nested || l.segs[1] != segs[1].Name {
		return false
	}
	env, ok := env.bind(segs[0].Var, l.segs[0])
	return ok && k(env)
}

// rustSelfLeafMayMatch: a use path whose head is written (`use a::$N;`,
// `use a::b::N;`) may match the self leaf `use x::y::{self, ..};` only when
// the written head segments start its path: OpenGrep 1.33.1 reports no
// `use thrussh::$N;` on `use russh::server::{self, Auth};` (pinned by
// invented rules). What it binds on a head that does start the path is not
// pinned.
func rustSelfLeafMayMatch(segs []RustSeg, l *rustLeaf) bool {
	for i, s := range segs[:len(segs)-1] {
		if s.Var != "" {
			return true
		}
		if i >= len(l.segs) || l.segs[i] != s.Name {
			return false
		}
	}
	return true
}

// globLeaf calls k with what a use context of two segments or more, with
// no glob, binds on an ungrouped glob leaf. OpenGrep 1.33.1 reads the glob
// `use a::b::c::*;` as a use of its module path and the pattern's path as a
// prefix of it (pinned by invented rules): `use a::b;` and `use a::b::c;`
// match it, `use a::$N;` binds $N to `b::c`, `use $M::b;` binds $M to `a`.
// Forms no rule pins are undecided.
func (m *rustMatcher) globLeaf(u *RustUse, l *rustLeaf, env rustEnv, k func(rustEnv) bool) bool {
	segs, mod := u.Path.Segs, l.segs
	if u.Alias != "" {
		return false
	}
	if segs[0].Var != "" {
		return m.globModLeaf(segs, mod, env, k)
	}
	head, last := segs[:len(segs)-1], segs[len(segs)-1]
	for _, s := range head {
		if s.Var != "" {
			m.undecide(undecidedUseTree)
			return false
		}
	}
	if len(mod) <= len(head) || !rustSegsPrefix(head, mod) {
		return false
	}
	if last.Var != "" {
		env, ok := env.bind(last.Var, strings.Join(mod[len(head):], "::"))
		return ok && k(env)
	}
	return mod[len(head)] == last.Name && k(env)
}

// globModLeaf: `use $M::N;` on a glob of module path mod binds $M to mod's
// first segment when N is its second; `use $M::$N;` binds $N to the rest of
// mod, of one segment or more, and does not match a glob of one segment
// (`use acme::*;`, `use super::*;`), as OpenGrep 1.33.1 does (pinned by
// invented rules).
func (m *rustMatcher) globModLeaf(segs []RustSeg, mod []string, env rustEnv, k func(rustEnv) bool) bool {
	if len(segs) != 2 {
		m.undecide(undecidedUseTree)
		return false
	}
	if segs[1].Var != "" {
		if len(mod) < 2 {
			return false
		}
		env, ok := env.bind(segs[0].Var, mod[0])
		if !ok {
			return false
		}
		env, ok = env.bind(segs[1].Var, strings.Join(mod[1:], "::"))
		return ok && k(env)
	}
	switch {
	case len(mod) >= 2 && mod[1] == segs[1].Name:
		env, ok := env.bind(segs[0].Var, mod[0])
		return ok && k(env)
	case len(mod) > 2 && slices.Contains(mod[2:], segs[1].Name):
		m.undecide(undecidedUseTree)
	}
	return false
}

// rustNestedGlobPath is the module path OpenGrep 1.33.1 reads a glob written
// inside a group under: the first segment of the group's own path, then the
// path in front of the group, then the rest of the group's own path
// (`use a::b::{c::*};` reads as c::a::b, `use a::{b::d::*};` as b::a::d;
// pinned by invented rules).
func rustNestedGlobPath(l *rustLeaf) []string {
	outer := len(l.segs) - l.own
	out := append([]string{l.segs[outer]}, l.segs[:outer]...)
	return append(out, l.segs[outer+1:]...)
}

// rustBindLeafPath unifies a use path of two or more segments with a leaf
// of the same length: its module, and its last segment (a metavariable
// binds it).
func rustBindLeafPath(segs []RustSeg, l *rustLeaf, env rustEnv) (rustEnv, bool) {
	if l.extern || l.nested || l.modSegs < len(segs)-1 || !rustSegsPrefix(segs[:len(segs)-1], l.segs[:l.modSegs]) {
		return env, false
	}
	return rustBindSeg(env, segs[len(segs)-1], l.segs[l.modSegs])
}

// externLeaf: `extern crate a;` reads as `use a;`, `extern crate a as $A;`
// matches extern crates with an alias only.
func (m *rustMatcher) externLeaf(x *RustExternCrate, l *rustLeaf, env rustEnv, k func(rustEnv) bool) bool {
	if x.Alias == "" {
		seg := RustSeg{Name: x.Name}
		if isMetavar(x.Name) {
			seg = RustSeg{Var: x.Name}
		}
		return m.useLeaf(&RustContext{Use: &RustUse{Path: RustPath{Segs: []RustSeg{seg}}}}, l, env, k)
	}
	if !l.extern || l.alias == "" {
		return false
	}
	env, ok := rustBindName(env, x.Name, l.segs[0])
	if !ok {
		return false
	}
	env, ok = rustBindName(env, x.Alias, l.alias)
	return ok && k(env)
}

// rustUsePrefix: OpenGrep reads a use path of names, without an alias, as a
// prefix of a longer leaf path: `use a::m;` holds at `use a::m::Kdf;` and at
// `use a::m::{Kdf, X};`, not at a leaf under a nested group.
func rustUsePrefix(u *RustUse, l *rustLeaf) bool {
	segs := u.Path.Segs
	return !l.glob && !l.extern && !l.nested && u.Alias == "" && segs[len(segs)-1].Var == "" &&
		len(l.segs) > len(segs) && rustSegsPrefix(segs, l.segs)
}

// rustSegsPrefix: the literal pattern segments are a prefix of names.
func rustSegsPrefix(ps []RustSeg, names []string) bool {
	if len(ps) > len(names) {
		return false
	}
	for i, s := range ps {
		if s.Name != names[i] {
			return false
		}
	}
	return true
}

// rustBindName binds a metavariable to text, or compares a name with it.
func rustBindName(env rustEnv, name, text string) (rustEnv, bool) {
	if isMetavar(name) {
		return env.bind(name, text)
	}
	return env, name == text
}

func rustBindSeg(env rustEnv, s RustSeg, text string) (rustEnv, bool) {
	if s.Var != "" {
		return env.bind(s.Var, text)
	}
	return env, s.Name == text
}

// contains: the call o encloses the call s (a strictly larger span of the
// same file).
func (m *rustMatcher) contains(o, s *Site, rd *rustRead) bool {
	if o == s || o.File != s.File {
		return false
	}
	ord := m.read(o)
	if ord == nil {
		return false
	}
	a, b := ord.span, rd.span
	return rustPosLE(a[0], a[1], b[0], b[1]) && rustPosLE(b[2], b[3], a[2], a[3]) && a != b
}

func rustPosLE(l1, c1, l2, c2 int) bool { return l1 < l2 || (l1 == l2 && c1 <= c2) }

// rustWhere: every metavariable-regex matches the text its metavariable
// binds; the regex's named groups bind as metavariables (`(?P<bits>...)`
// binds `$bits`), as OpenGrep binds them.
func rustWhere(ws []RustWhere, env rustEnv) (rustEnv, bool) {
	for _, w := range ws {
		text, ok := env.vars.get(w.Metavar)
		if !ok {
			return env, false
		}
		groups := reMatch(w.Regex, text)
		if groups == nil {
			return env, false
		}
		for _, k := range slices.Sorted(maps.Keys(groups)) {
			env = env.set("$"+k, groups[k])
		}
	}
	return env, true
}

// read is the site's written call, nil when it cannot be read.
func (m *rustMatcher) read(s *Site) *rustRead {
	if rd, ok := m.reads[s]; ok {
		return rd
	}
	rd := m.readSite(s)
	if rd == nil {
		m.stats.UnreadableSites++
	}
	m.reads[s] = rd
	return rd
}

func (m *rustMatcher) readSite(s *Site) *rustRead {
	if !s.LineOK || !s.ColOK {
		return nil
	}
	text, ok := m.spanText(s.File, s.Line, s.Col, s.EndLine, s.EndCol)
	if !ok {
		return nil
	}
	e, ok := readRustExpr(text)
	if !ok || e.Kind != RustExprCall {
		return nil
	}
	return &rustRead{call: e.Call, span: [4]int{s.Line, s.Col, max(s.EndLine, s.Line), s.EndCol}}
}

// spanText is the source text of a span from the fragment's source lines.
func (m *rustMatcher) spanText(file string, line, col, endLine, endCol int) (string, bool) {
	if col < 1 || endCol < 1 {
		return "", false
	}
	endLine = max(endLine, line)
	lines := m.fr.Lines[file]
	var b strings.Builder
	for l := line; l <= endLine; l++ {
		text, ok := lines[l]
		if !ok {
			return "", false
		}
		from, to := 0, len(text)
		if l == line {
			from = col - 1
		}
		if l == endLine {
			to = endCol - 1
		}
		if from > to || to > len(text) {
			return "", false
		}
		if l > line {
			b.WriteByte('\n')
		}
		b.WriteString(text[from:to])
	}
	return b.String(), true
}

// finding is the finding of entry e at site s under env. A bare path matched
// as a call's callee is reported at the callee.
// A taint finding also fills what its source binds that the sink does not.
func (m *rustMatcher) finding(e *Entry, s *Site, rd *rustRead, env rustEnv, hit *rustTaintHit) *Finding {
	fg := fillGroups{}
	if hit != nil {
		hit.env.vars.each(func(k, v string) { fg[strings.TrimPrefix(k, "$")] = &v })
	}
	env.vars.each(func(k, v string) { fg[strings.TrimPrefix(k, "$")] = &v })
	f := &Finding{
		RuleID: e.RuleID, File: s.File, Line: s.Line, LineOK: s.LineOK, Col: s.Col, ColOK: s.ColOK,
		How: "symbol", Resolution: s.Resolution, SiteKind: s.Kind, Callee: calleeOf(s),
		Metadata: fillCF(e.Metadata.M, fg, s, e), Caller: s.Caller, EndCol: s.EndCol, EndLine: s.EndLine,
	}
	if e.Rust.Ref != nil && s.Kind != "constant_ref" {
		if callee := rd.ref.String(); strings.HasPrefix(s.Src, callee) {
			f.EndCol, f.EndLine = s.Col+len(callee), 0
		}
	}
	if hit != nil {
		v := hit.value
		f.Taint, f.How, f.Value = true, hit.how, &v
	}
	if foc := e.Rust.Focus; foc != "" {
		f.FocusText, _ = env.vars.get(foc)
		switch i, ok := env.arg[foc]; {
		case ok:
			f.FocusArg = &i
		case rd.let == nil:
			m.focusRecv(f, rd)
		}
	}
	if rd.let != nil {
		rustLetPlace(f, e.Rust, rd)
	}
	return f
}

// rustLetPlace reports f where OpenGrep 1.33.1 reports a let positive: at
// its focus, the name or the initializer as written, or else from the
// pattern after `let` to the end of the let.
func rustLetPlace(f *Finding, p *RustPattern, rd *rustRead) {
	src := rd.let.src
	from, to := src.pat, len(src.text)
	switch p.Focus {
	case "":
	case p.Let.Name:
		from, to = src.name[0], src.name[1]
	default:
		from, to = src.init[0], src.init[1]
	}
	f.Line, f.Col = rustTextPos(rd, src.text, from)
	f.EndLine, f.EndCol = rustTextPos(rd, src.text, to)
	if f.EndLine == f.Line {
		f.EndLine = 0
	}
}

// rustTextPos is the line and column of the byte offset off in text, the
// source text of rd's span.
func rustTextPos(rd *rustRead, text string, off int) (line, col int) {
	line, col = rd.span[0], rd.span[1]+off
	if nl := strings.LastIndexByte(text[:off], '\n'); nl >= 0 {
		line, col = line+strings.Count(text[:off], "\n"), off-nl
	}
	return line, col
}

// focusRecv reports f where its focus, `$X` of `$X.m(...)`, is written, as
// OpenGrep does: the receiver, or the path before a path call's method.
func (m *rustMatcher) focusRecv(f *Finding, rd *rustRead) {
	text, ok := m.spanText(f.File, rd.span[0], rd.span[1], rd.span[2], rd.span[3])
	if !ok {
		return
	}
	f.Line, f.Col = rustTextPos(rd, text, rd.call.RecvSpan[0])
	f.EndLine, f.EndCol = rustTextPos(rd, text, rd.call.RecvSpan[1])
	if f.EndLine == f.Line {
		f.EndLine = 0
	}
}

// rustEnv binds metavariables to the text they match, and records which
// call argument a metavariable matched whole (for focus-metavariable).
type rustEnv struct {
	vars *rustVars
	arg  map[string]int
}

// rustVars are the bindings of an environment, the latest first. An
// environment is extended at every step of a search and kept by each branch
// of it, so a binding is one node its extensions share, not a copy of the
// ones before it.
type rustVars struct {
	name, text string
	next       *rustVars
}

// get is the text the latest binding of name binds.
func (v *rustVars) get(name string) (string, bool) {
	for ; v != nil; v = v.next {
		if v.name == name {
			return v.text, true
		}
	}
	return "", false
}

// each calls f with every name bound and the text its latest binding binds.
func (v *rustVars) each(f func(name, text string)) {
	seen := map[string]bool{}
	for ; v != nil; v = v.next {
		if !seen[v.name] {
			seen[v.name] = true
			f(v.name, v.text)
		}
	}
}

// bind extends the environment; false when the metavariable is bound to
// other text. `$_` matches anything and binds nothing.
func (e rustEnv) bind(name, text string) (rustEnv, bool) {
	if name == "$_" {
		return e, true
	}
	if old, ok := e.vars.get(name); ok {
		return e, old == text
	}
	return rustEnv{vars: &rustVars{name, text, e.vars}, arg: e.arg}, true
}

// set binds name to text, over what it bound.
func (e rustEnv) set(name, text string) rustEnv {
	return rustEnv{vars: &rustVars{name, text, e.vars}, arg: e.arg}
}

func (e rustEnv) bindArg(name string, i int) rustEnv {
	if name == "$_" {
		return e
	}
	out := rustEnv{vars: e.vars, arg: make(map[string]int, len(e.arg)+1)}
	for k, v := range e.arg {
		out.arg[k] = v
	}
	out.arg[name] = i
	return out
}

// siteArgs and otherArgs are the index unifyArgs gives a call's first
// argument: only the site's own call binds its arguments' indexes, which a
// focus-metavariable reports; an argument of a nested call or of an
// enclosing pattern-inside call is no argument of the site.
const (
	siteArgs  = 0
	otherArgs = -1
)

// unifyCall unifies a pattern call with a written call. args is siteArgs
// for the site's own call, else otherArgs.
func (m *rustMatcher) unifyCall(pc, sc *RustCall, env rustEnv, args int, k func(rustEnv) bool) bool {
	switch {
	case pc.Callee != nil && rustBareVar(pc.Callee):
		// OpenGrep binds `$F(...)` to the whole callee: a path with its
		// generics, a qualified self, or a method call's receiver and method.
		env, ok := env.bind(pc.Callee.Segs[0].Var, sc.CalleeString())
		return ok && m.unifyArgs(pc.Args, sc.Args, args, env, k)
	case pc.Callee != nil && sc.Callee != nil:
		return m.unifyPath(pc.Callee, sc.Callee, env, true, func(env rustEnv) bool {
			return m.unifyArgs(pc.Args, sc.Args, args, env, k)
		})
	case pc.Receiver != nil && sc.Receiver != nil:
		if !m.unifyMethod(pc, sc, &env) || !rustTypesEqual(pc.Turbofish, sc.Turbofish, &env) {
			return false
		}
		return m.unifyExpr(*pc.Receiver, *sc.Receiver, env, func(env rustEnv) bool {
			return m.unifyArgs(pc.Args, sc.Args, args, env, k)
		})
	case pc.Receiver != nil && sc.Callee != nil && pc.Receiver.Kind == RustExprVar:
		return m.unifyMethodOnPath(pc, sc, env, args, k)
	}
	return false
}

// rustBareVar: the path is one metavariable, with no generics.
func rustBareVar(p *RustPath) bool {
	return !p.Global && p.QSelf == nil && len(p.Segs) == 1 && p.Segs[0].Var != "" && p.Segs[0].Generics == nil
}

// unifyMethodOnPath: OpenGrep reads `$X.m(...)` on `A::m(...)` too, with $X
// bound to the path in front of the method.
func (m *rustMatcher) unifyMethodOnPath(pc, sc *RustCall, env rustEnv, args int, k func(rustEnv) bool) bool {
	prefix, last := rustPathSplit(sc.Callee)
	if prefix == "" || last.Generics != nil || pc.Turbofish != nil {
		return false
	}
	if isMetavar(pc.Method) {
		var ok bool
		if env, ok = env.bind(pc.Method, last.Name); !ok {
			return false
		}
	} else if pc.Method != last.Name {
		return false
	}
	env, ok := env.bind(pc.Receiver.Var, prefix)
	return ok && m.unifyArgs(pc.Args, sc.Args, args, env, k)
}

// rustPathSplit is a plain path's text before its last segment (""
// when it has none, or carries generics, a qualified self or a leading `::`)
// and its last segment.
func rustPathSplit(p *RustPath) (string, RustSeg) {
	if p.Global || p.QSelf != nil || len(p.Segs) < 2 {
		return "", RustSeg{}
	}
	last := p.Segs[len(p.Segs)-1]
	names := make([]string, 0, len(p.Segs)-1)
	for _, s := range p.Segs[:len(p.Segs)-1] {
		if s.Generics != nil || s.Name == "" {
			return "", RustSeg{}
		}
		names = append(names, s.Name)
	}
	if last.Name == "" {
		return "", RustSeg{}
	}
	return strings.Join(names, "::"), last
}

// unifyMethod unifies the method name (a metavariable binds it).
func (m *rustMatcher) unifyMethod(pc, sc *RustCall, env *rustEnv) bool {
	if isMetavar(pc.Method) {
		e, ok := env.bind(pc.Method, sc.Method)
		*env = e
		return ok
	}
	return pc.Method == sc.Method
}

// rustTypesEqual unifies generic argument lists that bind nothing the caller
// reads again: here, a method call's turbofish (identity, never dropped).
func rustTypesEqual(pt, st []RustType, env *rustEnv) bool {
	if (pt == nil) != (st == nil) || len(pt) != len(st) {
		return false
	}
	for i := range pt {
		if !unifyTypeFlat(pt[i], st[i], env) {
			return false
		}
	}
	return true
}

// unifyTypeFlat unifies a type with no continuation: the first way to bind it.
func unifyTypeFlat(pt, st RustType, env *rustEnv) bool {
	ok := false
	(&rustMatcher{}).unifyType(pt, st, *env, func(e rustEnv) bool {
		*env, ok = e, true
		return true
	})
	return ok
}

// unifyPath unifies a pattern path with a written one: as written, and for a
// qualified pattern path also as the written path reads through the file's
// uses (rustFileScope.naming). A metavariable matched through that naming
// binds the written path's last segment, as OpenGrep 1.22.0 does. qual is
// false in type position, where no pin says whether OpenGrep reads the
// naming: a match only through it is undecided there.
func (m *rustMatcher) unifyPath(pp, sp *RustPath, env rustEnv, qual bool, k func(rustEnv) bool) bool {
	if pp.QSelf != nil || sp.QSelf != nil {
		return pp.QSelf != nil && sp.QSelf != nil && m.unifyQSelf(pp, sp, env, k)
	}
	if sp.Global && !pp.Global {
		// OpenGrep reads `::acme::f` as `acme::f`, a crate path no use renames.
		local := *sp
		local.Global = false
		return m.unifyWritten(pp, &local, env, k)
	}
	return m.unifyWritten(pp, sp, env, k) || m.unifyNamed(pp, sp, env, qual, k)
}

// unifyWritten unifies a pattern path with a written one as written.
func (m *rustMatcher) unifyWritten(pp, sp *RustPath, env rustEnv, k func(rustEnv) bool) bool {
	if len(pp.Segs) == 2 && pp.Segs[0].Var != "" && !pp.Global && !sp.Global {
		return m.unifyHead(pp, sp, env, k)
	}
	return pp.Global == sp.Global && len(pp.Segs) == len(sp.Segs) && m.unifySegs(pp.Segs, sp.Segs, env, k)
}

// unifyNamed unifies a qualified pattern path with a written one read
// through the file's uses.
func (m *rustMatcher) unifyNamed(pp, sp *RustPath, env rustEnv, qual bool, k func(rustEnv) bool) bool {
	written, ok := rustPlainPath(sp)
	if !ok || pp.Global || !pp.Qualified() || rustHasGenerics(pp) || m.fr == nil || !m.fr.RustFacts {
		return false
	}
	n := m.fr.RustScopes[m.file].naming(written, m.at)
	if n.undecided {
		m.undecide(undecidedNaming)
	}
	for _, c := range n.cands {
		if len(c) != len(pp.Segs) {
			continue
		}
		env, ok := rustUnifyNamed(pp.Segs, c, written[len(written)-1], env)
		switch {
		case !ok:
		case !qual:
			m.undecide(undecidedNaming)
		case k(env):
			return true
		}
	}
	return false
}

// unifyHead unifies `$X::f`, a metavariable followed by one segment, as
// OpenGrep 1.33.1 does: $X binds every written segment in front of the last,
// as written but without the generics on the last of them
// (`acme_mode::Encryptor` on `acme_mode::Encryptor::<Blk>::new`,
// `a::Wrap::<X>::Encryptor` on `a::Wrap::<X>::Encryptor::new`). Generics
// written on $X are ignored and bind nothing: `$X::<$C>::new` and
// `$X::<Blk>::new` match what `$X::new` matches. A metavariable followed by
// two segments or more binds one segment (unifySegs).
func (m *rustMatcher) unifyHead(pp, sp *RustPath, env rustEnv, k func(rustEnv) bool) bool {
	n := len(sp.Segs) - 1
	if n < 1 {
		return false
	}
	head := slices.Clone(sp.Segs[:n])
	for _, s := range head {
		if s.Name == "" {
			return false
		}
	}
	head[n-1].Generics = nil
	env, ok := env.bind(pp.Segs[0].Var, (&RustPath{Segs: head}).String())
	return ok && m.unifySeg(pp.Segs[1], sp.Segs[n], env, k)
}

// unifyTypePath unifies a pattern path with a path written as a type, as
// OpenGrep 1.33.1 does (pinned by testdata/rust_typerefs): only the written
// path's last segment counts. A one-segment pattern matches the type whose
// last segment is its name (`AcmeRng`, `vendor::AcmeRng`,
// `Vec<vendor::AcmeRng>`), generic arguments included; an alias a use binds
// does not read as the name it renames. A longer pattern matches only
// through the file's uses: the last segment is a name a use before the type
// binds to the pattern's path (`use acme::Key as K;` then `K`, `x::K`) or a
// glob's module joins to it, and not inside generic arguments (inGenerics).
// Written out without a use, `acme::Key` does not match. A metavariable
// binds the name as written (`K`), only as the pattern's last segment, and
// no glob reads as it.
func (m *rustMatcher) unifyTypePath(pp, sp *RustPath, env rustEnv, k func(rustEnv) bool) bool {
	written, ok := rustPlainPath(sp)
	if !ok || pp.Global || pp.QSelf != nil || rustHasGenerics(pp) {
		return false
	}
	last := written[len(written)-1]
	if len(pp.Segs) == 1 {
		return pp.Segs[0].Var == "" && pp.Segs[0].Name == last && k(env)
	}
	env, ok = m.namedType(pp, last, env)
	return ok && m.outsideGenerics(last) && k(env)
}

// unifyRef unifies a bare path pattern with the path a site reads: as a type
// (unifyTypePath) or as a value.
func (m *rustMatcher) unifyRef(pp *RustPath, rd *rustRead, env rustEnv, k func(rustEnv) bool) bool {
	if rd.typ {
		return m.unifyTypePath(pp, rd.ref, env, k)
	}
	return m.unifyPath(pp, rd.ref, env, true, k)
}

// namedType unifies a longer pattern path with the name last a type is
// written with, read through the file's uses (unifyTypePath).
func (m *rustMatcher) namedType(pp *RustPath, last string, env rustEnv) (rustEnv, bool) {
	if slices.ContainsFunc(pp.Segs[:len(pp.Segs)-1], func(s RustSeg) bool { return s.Var != "" }) {
		return env, false
	}
	fs := m.fr.RustScopes[m.file]
	if fs == nil {
		return env, false // no use binds the name: the file lists none
	}
	bound, undecided := fs.binding(last, m.at)
	if undecided {
		m.undecide(undecidedNaming)
	}
	if bound != nil && len(bound.segs) == len(pp.Segs) {
		if out, ok := rustUnifyNamed(pp.Segs, bound.segs, last, env); ok {
			return out, true
		}
	}
	names := rustSegNames(pp.Segs)
	return env, pp.Last().Var == "" && slices.ContainsFunc(fs.globs, func(g []string) bool {
		return slices.Equal(append(slices.Clone(g), last), names)
	})
}

// outsideGenerics: the type written at the current position as last is not
// inside generic arguments (inGenerics); undecided when the source lines
// cannot tell.
func (m *rustMatcher) outsideGenerics(last string) bool {
	in, ok := m.inGenerics(m.at, rustPos{m.at.line, m.at.col + len(last)})
	if !ok {
		m.undecide(undecidedGenerics)
	}
	return ok && !in
}

// rustSegNames are the names of plain segments.
func rustSegNames(segs []RustSeg) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.Name
	}
	return out
}

// inGenerics reports whether the type written from p to end of the current
// file is inside generic arguments (`Option<Key>`, `Vec<(u8, Key)>`,
// `make::<Key>()`): reading the source backwards from p, an unclosed `<`
// comes before a `:` (`k: Key`), `as`, `;`, `{` or `}`. A tuple, an array or
// a fn type around the type is looked through (`(u8, Key)`, `fn(Key)`). The
// type is not inside when it is an argument of a turbofish on a path
// segment the path goes on from (`Vec::<Key>::new()`, `HashMap::<u8,
// Key>::new()`), where OpenGrep 1.33.1 matches it. ok is false when a line
// it needs is not among the fragment's source lines, but for a type after a
// `->` outside any brackets, a return type.
func (m *rustMatcher) inGenerics(p, end rustPos) (in, ok bool) {
	lines := m.fr.Lines[m.file]
	sc := &rustGenericsScan{}
	for l := p.line; l >= 1 && l > p.line-rustGenericsLines; l-- {
		text, has := lines[l]
		if !has {
			// A return type (`) -> Key {`) of a fn whose parameters are
			// written on the lines before.
			return false, sc.ret
		}
		to := len(text)
		if l == p.line {
			to = min(p.col-1, to)
		}
		for i := to - 1; i >= 0; i-- {
			var v rustGenericsVerdict
			if i, v = sc.step(text, i); v == rustOutside {
				return false, true
			} else if v == rustOpened {
				return m.openedGenerics(sc, text[:i], end)
			}
		}
	}
	return false, false
}

// openedGenerics is inGenerics once an unclosed `<` is found, before; a
// turbofish whose path goes on (`Vec::<Key>::new()`) does not count when
// the type is its argument itself.
func (m *rustMatcher) openedGenerics(sc *rustGenericsScan, before string, end rustPos) (in, ok bool) {
	if sc.wrapped || !strings.HasSuffix(before, "::") {
		return true, true
	}
	next, ok := m.afterGenerics(end)
	return !strings.HasPrefix(next, "::"), ok
}

// rustGenericsVerdict is what one step of a rustGenericsScan decides.
type rustGenericsVerdict int

const (
	rustUndecided rustGenericsVerdict = iota // read on
	rustOutside                              // the type is outside generic arguments
	rustOpened                               // an unclosed `<` opens the generic arguments the type is in
)

// rustGenericsScan reads source backwards from a type (inGenerics): the
// `>`, `)` and `]` it has seen unclosed, whether it passed an unclosed `(` or
// `[` (wrapped) and a `->` outside brackets (ret).
type rustGenericsScan struct {
	angles, others int
	wrapped, ret   bool
}

// step reads the byte i of text; it returns the index to go on from, one
// below the next byte to read, and what the byte decides.
func (sc *rustGenericsScan) step(text string, i int) (int, rustGenericsVerdict) {
	c := text[i]
	if i > 0 && rustTwoByte[text[i-1:i+1]] {
		sc.ret = sc.ret || (text[i-1:i+1] == "->" && sc.others == 0 && sc.angles == 0)
		return i - 1, rustUndecided
	}
	switch c {
	case '>':
		sc.angles++
	case '<':
		if sc.angles == 0 {
			return i, rustOpened
		}
		sc.angles--
	case ')', ']':
		sc.others++
	case '(', '[':
		if sc.others == 0 {
			sc.wrapped = true
		} else {
			sc.others--
		}
	default:
		if sc.ends(text, i) {
			return i, rustOutside
		}
	}
	return i, rustUndecided
}

// rustTwoByte are the tokens a rustGenericsScan reads as one: neither `->`
// nor `=>` closes generics, and `::` is no `:`.
var rustTwoByte = map[string]bool{"->": true, "=>": true, "::": true}

// ends: the byte i of text ends what the type can be inside: `{`, `}`, or
// outside brackets `:` (`k: Key`), `;` or `as`.
func (sc *rustGenericsScan) ends(text string, i int) bool {
	c := text[i]
	if c == '{' || c == '}' {
		return true
	}
	return sc.others == 0 && sc.angles == 0 && (c == ':' || c == ';' || rustWordAt(text, i, "as"))
}

// afterGenerics is the source text of the current file's line that closes
// the generic arguments a type ending at end is in, from just after the
// closing `>`; ok is false when a line it needs is not among the fragment's
// source lines.
func (m *rustMatcher) afterGenerics(end rustPos) (string, bool) {
	lines := m.fr.Lines[m.file]
	angles := 0
	for l := end.line; l < end.line+rustGenericsLines; l++ {
		text, has := lines[l]
		if !has {
			return "", false
		}
		from := 0
		if l == end.line {
			from = min(end.col-1, len(text))
		}
		for i := from; i < len(text); i++ {
			switch c := text[i]; {
			case c == '-' && i+1 < len(text) && text[i+1] == '>':
				i++
			case c == '<':
				angles++
			case c == '>' && angles == 0:
				return strings.TrimLeft(text[i+1:], " \t"), true
			case c == '>':
				angles--
			}
		}
	}
	return "", false
}

// rustGenericsLines bounds how many lines inGenerics reads back.
const rustGenericsLines = 16

// rustWordAt: the word w ends at byte i of text, a whole word.
func rustWordAt(text string, i int, w string) bool {
	from := i + 1 - len(w)
	if from < 0 || text[from:i+1] != w {
		return false
	}
	word := func(j int) bool {
		return j >= 0 && j < len(text) && (text[j] == '_' || unicode.IsLetter(rune(text[j])) || unicode.IsDigit(rune(text[j])))
	}
	return !word(from-1) && !word(i+1)
}

// rustPlainPath is a path's segment names when it is written with names
// only: no leading `::`, no qualified self, no generics.
func rustPlainPath(p *RustPath) ([]string, bool) {
	if p.Global || p.QSelf != nil {
		return nil, false
	}
	out := make([]string, len(p.Segs))
	for i, s := range p.Segs {
		if s.Name == "" || s.Generics != nil {
			return nil, false
		}
		out[i] = s.Name
	}
	return out, true
}

// rustUnifyNamed unifies pattern segments with a qualified path; a
// metavariable binds last, the written path's last segment.
func rustUnifyNamed(ps []RustSeg, names []string, last string, env rustEnv) (rustEnv, bool) {
	for i, s := range ps {
		var ok bool
		if s.Var != "" {
			env, ok = env.bind(s.Var, last)
		} else {
			ok = s.Name == names[i]
		}
		if !ok {
			return env, false
		}
	}
	return env, true
}

func (m *rustMatcher) unifySegs(ps, ss []RustSeg, env rustEnv, k func(rustEnv) bool) bool {
	if len(ps) == 0 {
		return k(env)
	}
	return m.unifySeg(ps[0], ss[0], env, func(env rustEnv) bool {
		return m.unifySegs(ps[1:], ss[1:], env, k)
	})
}

// unifySeg unifies one segment: its name (a metavariable binds it) and its
// generics, which are identity: a segment without generics does not match
// one with them.
func (m *rustMatcher) unifySeg(ps, ss RustSeg, env rustEnv, k func(rustEnv) bool) bool {
	if ss.Var != "" {
		return false
	}
	if ps.Var != "" {
		var ok bool
		if env, ok = env.bind(ps.Var, ss.Name); !ok {
			return false
		}
	} else if ps.Name != ss.Name {
		return false
	}
	if (ps.Generics == nil) != (ss.Generics == nil) || len(ps.Generics) != len(ss.Generics) {
		return false
	}
	return m.unifyTypes(ps.Generics, ss.Generics, env, k)
}

func (m *rustMatcher) unifyTypes(pts, sts []RustType, env rustEnv, k func(rustEnv) bool) bool {
	if len(pts) == 0 {
		return k(env)
	}
	return m.unifyType(pts[0], sts[0], env, func(env rustEnv) bool {
		return m.unifyTypes(pts[1:], sts[1:], env, k)
	})
}

func (m *rustMatcher) unifyType(pt, st RustType, env rustEnv, k func(rustEnv) bool) bool {
	switch {
	case pt.Var != "":
		env, ok := env.bind(pt.Var, rustTypeBound(st))
		return ok && k(env)
	case pt.Path != nil && st.Path != nil && pt.Path.QSelf == nil:
		// OpenGrep 1.22.0 and 1.33.1 tell path types apart by their last
		// segment and its generics: `Kdf::<acme::Sha9>` matches
		// `Kdf::<Sha9>` and `Kdf::<b::Sha9>`.
		return m.unifySeg(pt.Path.Last(), st.Path.Last(), env, k)
	case pt.Path != nil && st.Path != nil:
		return m.unifyPath(pt.Path, st.Path, env, false, k)
	case pt.Tuple != nil && st.Tuple != nil && len(pt.Tuple) == len(st.Tuple):
		return m.unifyTypes(pt.Tuple, st.Tuple, env, k)
	case pt.Ref != nil:
		return m.unifyRefType(pt, st, env, k)
	}
	return rustTextType(pt) && pt.String() == st.String() && k(env)
}

// unifyRefType unifies a pattern reference type: `&T` matches `&T` and
// `&mut T`, `&mut T` only `&mut T` (pinned on fn parameters and let types).
func (m *rustMatcher) unifyRefType(pt, st RustType, env rustEnv, k func(rustEnv) bool) bool {
	if st.Ref == nil || (pt.Mut && !st.Mut) {
		return false
	}
	return m.unifyType(*pt.Ref, *st.Ref, env, k)
}

// rustTypeBound is what a metavariable in type position binds: OpenGrep
// 1.22.0 and 1.33.1 bind a path type to its last segment with its generics
// (`Sha256` for `sha2::Sha256`, `Wrap<Sha9>` for `acme::Wrap<Sha9>`, `C` for
// `<A as B>::C`), any other type to its text.
func rustTypeBound(t RustType) string {
	if t.Path == nil || len(t.Path.Segs) == 0 {
		return t.String()
	}
	last := t.Path.Segs[len(t.Path.Segs)-1]
	return (&RustPath{Segs: []RustSeg{last}}).typeString()
}

// unifyQSelf unifies `<T as Tr>::f` paths. OpenGrep 1.22.0 compares the self
// type and the trait by their last segment, whatever the qualifier written
// (`<Sha256 as Digest>::f` and `<x::Sha256 as a::Digest>::f` match each
// other); a path without a trait matches nothing.
func (m *rustMatcher) unifyQSelf(pp, sp *RustPath, env rustEnv, k func(rustEnv) bool) bool {
	if pp.QSelf.Trait == nil || sp.QSelf.Trait == nil || len(pp.Segs) != len(sp.Segs) {
		return false
	}
	return m.unifyQType(pp.QSelf.Self, sp.QSelf.Self, env, func(env rustEnv) bool {
		return m.unifyQType(RustType{Path: pp.QSelf.Trait}, RustType{Path: sp.QSelf.Trait}, env, func(env rustEnv) bool {
			return m.unifySegs(pp.Segs, sp.Segs, env, k)
		})
	})
}

// unifyQType unifies two types of a qualified self by their last segment.
func (m *rustMatcher) unifyQType(pt, st RustType, env rustEnv, k func(rustEnv) bool) bool {
	if pt.Path != nil && rustBareVar(pt.Path) && st.Path != nil {
		// `<A as $TR>` binds the trait's last segment with its generics.
		env, ok := env.bind(pt.Path.Segs[0].Var, rustTypeBound(st))
		return ok && k(env)
	}
	if pt.Path != nil && st.Path != nil {
		return m.unifySeg(pt.Path.Last(), st.Path.Last(), env, k)
	}
	return m.unifyType(pt, st, env, k)
}

// unifyArgs unifies argument lists; `...` matches any run of arguments.
// idx is the position of sas[0] in the site's call, negative (otherArgs)
// when the call is not the site's: its arguments bind no index.
func (m *rustMatcher) unifyArgs(pas, sas []RustExpr, idx int, env rustEnv, k func(rustEnv) bool) bool {
	if len(pas) == 0 {
		return len(sas) == 0 && k(env)
	}
	if pas[0].Kind == RustExprEllipsis {
		for n := 0; n <= len(sas); n++ {
			if m.unifyArgs(pas[1:], sas[n:], rustArgIdx(idx, n), env, k) {
				return true
			}
		}
		return false
	}
	if len(sas) == 0 {
		return false
	}
	return m.unifyExpr(pas[0], sas[0], env, func(env rustEnv) bool {
		if pas[0].Kind == RustExprVar && idx >= 0 {
			env = env.bindArg(pas[0].Var, idx)
		}
		return m.unifyArgs(pas[1:], sas[1:], rustArgIdx(idx, 1), env, k)
	})
}

// rustArgIdx is the index n arguments after idx, or idx when it is not the
// site's call.
func rustArgIdx(idx, n int) int {
	if idx < 0 {
		return idx
	}
	return idx + n
}

// unifyExpr unifies a pattern expression with a written one.
func (m *rustMatcher) unifyExpr(pe, se RustExpr, env rustEnv, k func(rustEnv) bool) bool { //nolint:gocyclo // one case per expression shape of the closed set
	switch pe.Kind { //nolint:exhaustive // the other kinds read below
	case RustExprVar:
		env, ok := env.bind(pe.Var, se.bound())
		return ok && k(env)
	case RustExprDeep:
		return rustWalk(se, func(sub RustExpr) bool { return m.unifyExpr(*pe.Sub, sub, env, k) })
	}
	if se.Kind == RustExprParen {
		return m.unifyExpr(pe, *se.Sub, env, k)
	}
	if pe.Kind != se.Kind {
		return false
	}
	switch pe.Kind { //nolint:exhaustive // a pattern has no text, and var, ellipsis and deep are handled above
	case RustExprLit:
		return pe.Lit == se.Lit && k(env)
	case RustExprRange:
		return k(env)
	case RustExprPath:
		return m.unifyPath(pe.Path, se.Path, env, true, k)
	case RustExprRef:
		// OpenGrep 1.33.1 reads `&mut x` as `&x` both ways: `&$X` matches
		// `&mut x`, and `&mut $X` matches `&x`.
		return m.unifyExpr(*pe.Sub, *se.Sub, env, k)
	case RustExprBinary:
		if pe.Op != se.Op {
			return false
		}
		return m.unifyExpr(*pe.Sub, *se.Sub, env, func(env rustEnv) bool {
			return m.unifyExpr(*pe.Right, *se.Right, env, k)
		})
	case RustExprTry:
		return m.unifyExpr(*pe.Sub, *se.Sub, env, k)
	case RustExprCall:
		return m.unifyCall(pe.Call, se.Call, env, otherArgs, k)
	case RustExprField:
		if isMetavar(pe.Field) {
			var ok bool
			if env, ok = env.bind(pe.Field, se.Field); !ok {
				return false
			}
		} else if pe.Field != se.Field {
			return false
		}
		return m.unifyExpr(*pe.Sub, *se.Sub, env, k)
	case RustExprIndex:
		return m.unifyExpr(*pe.Sub, *se.Sub, env, func(env rustEnv) bool {
			return m.unifyExpr(*pe.Index, *se.Index, env, k)
		})
	}
	return false
}

// rustWalk calls f on the expression and each expression inside it until f
// returns true.
func rustWalk(e RustExpr, f func(RustExpr) bool) bool {
	if f(e) {
		return true
	}
	for _, sub := range []*RustExpr{e.Sub, e.Index, e.Right} {
		if sub != nil && rustWalk(*sub, f) {
			return true
		}
	}
	if e.Call != nil {
		if e.Call.Receiver != nil && rustWalk(*e.Call.Receiver, f) {
			return true
		}
		for _, a := range e.Call.Args {
			if rustWalk(a, f) {
				return true
			}
		}
	}
	return false
}
