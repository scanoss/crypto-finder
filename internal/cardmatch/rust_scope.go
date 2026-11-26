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

// The scope facts of a Rust fragment (graph-fragment-1.26): each file's use
// declarations, read back into the leaves OpenGrep binds from the written
// use tree, and its items, whose spans place a fact in the block that
// encloses it. reach writes them; nothing here reads a source file.
//
// OpenGrep 1.22.0 facts this reproduces (pinned by invented rules):
//   - A context `use ...; ...` holds from the declaration to the end of the
//     block that encloses it (a file, an inline mod, a function); a fn body
//     is one block here, its inner blocks are not told apart.
//   - Naming is per file and by position: a path written after `use a::B;`
//     (or `use a::C as B;`, or a first-level leaf of `use a::{B, ..}`)
//     anywhere later in the file also reads as `a::B::...`; the latest such
//     use wins. A leaf under a nested group or a multi-segment leaf of a
//     group (`use a::{m::B}`) and a `self` leaf name nothing. A glob `use
//     a::*;` at the top level of the file qualifies every path of the file,
//     wherever it is written; a glob inside a fn or a mod qualifies nothing,
//     and so does a glob under a group with its own module path (`use
//     a::{self, m::*};`, `use a::{x, m::{n::*}};`, OpenGrep 1.33.1).
//   - A context `use a::m; ...` holds at a leaf whose path `a::m` begins:
//     `use a::m::Kdf;`, `use a::{m, z};`, not a leaf under a nested group.
//   - `use $X;` binds, for each leaf, the tree text from its start to the end
//     of the leaf's path: `a::{B` and `a::{B, c::D` for `use a::{B, c::D};`.

import (
	"slices"
	"strings"
	"unicode"

	"github.com/scanoss/reach/graphfrag"
)

// Item kinds the matcher names more than once.
const (
	rustItemMod    = "mod"
	rustItemImpl   = "impl"
	rustItemStruct = "struct"
	rustItemType   = "type"
	// rustItemBlock is a block of a fn body that declares a use of its own
	// (graph-algo-rs-12): the use is in scope in that block only.
	rustItemBlock = "block"
)

// rustPos is a position in a file: line, 1-based column.
type rustPos struct{ line, col int }

func (a rustPos) before(b rustPos) bool {
	return a.line < b.line || (a.line == b.line && a.col < b.col)
}

// rustSpan is a range, end exclusive.
type rustSpan struct{ from, to rustPos }

func rustSpanOf(line, startCol, endCol, endLine int) rustSpan {
	if endLine == 0 {
		endLine = line
	}
	return rustSpan{rustPos{line, startCol}, rustPos{endLine, endCol}}
}

func (s rustSpan) contains(p rustPos) bool { return !p.before(s.from) && p.before(s.to) }

// rustLeaf is one binding of a use declaration or an extern crate.
type rustLeaf struct {
	segs  []string // the leaf's full path; a glob's module path
	alias string
	// glob: `a::*`; self: `a::{self}`; grouped: inside braces; nested: its
	// module runs inside braces (`a::{m::B}`, `a::{x, m::{B}}`).
	glob, self, grouped, nested bool
	extern                      bool // `extern crate`
	text                        string
	module                      string // the tree text up to the end of the module ("" for none)
	modSegs                     int    // segments of the module
	own                         int    // segments written in the leaf's own group (a glob's before the `*`)
}

// rustUseDecl is one use declaration (or extern crate) of a file.
type rustUseDecl struct {
	span   rustSpan
	local  bool
	leaves []rustLeaf
	odd    bool   // a use tree the reader has no shape for
	text   string // the use tree's text
}

// rustItemFact is an item a file declares. A type alias also has its
// aliased type as written and the column of its `type` keyword on the span's
// first line (graph-fragment-1.27; 0 when the keyword is on another line); a
// fn its parameters as written (graph-fragment-1.30).
type rustItemFact struct {
	kind, name string
	span       rustSpan
	typ        string
	keywordCol int
	params     []graphfrag.GraphFragmentParam
}

// rustFileScope is one file's scope facts.
type rustFileScope struct {
	uses   []*rustUseDecl // in source order
	items  []rustItemFact
	blocks []rustSpan // mod, fn, impl and trait items, and blocks with a use
	// globs are the module paths of the file's ungrouped glob uses at the
	// top level of the file.
	globs [][]string
	// parents caches parent: the block enclosing a fact never changes.
	parents map[rustSpan]*rustSpan
	// globAt are the spans of the declarations of globs, until the file's
	// blocks are known (topLevelGlobs).
	globAt []rustSpan
	// byName holds the leaves that bind each name, not globs, in the order
	// of uses then leaves, and odd the unreadable use trees, in uses order:
	// binding is asked once per path written, and a file can declare many
	// uses.
	byName map[string][]rustNamed
	odd    []*rustUseDecl
}

// rustNamed is a leaf that binds a name and where its declaration starts.
type rustNamed struct {
	from rustPos
	leaf *rustLeaf
}

// indexNames builds byName and odd from uses.
func (fs *rustFileScope) indexNames() {
	fs.byName = map[string][]rustNamed{}
	for _, d := range fs.uses {
		if d.odd {
			fs.odd = append(fs.odd, d)
		}
		for i := range d.leaves {
			if l := &d.leaves[i]; !l.glob {
				fs.byName[l.bound()] = append(fs.byName[l.bound()], rustNamed{d.span.from, l})
			}
		}
	}
}

// rustScopes reads every file's scope facts of a fragment.
func rustScopes(imports map[string][]graphfrag.GraphFragmentImport, items map[string][]graphfrag.GraphFragmentItem) map[string]*rustFileScope {
	out := map[string]*rustFileScope{}
	get := func(file string) *rustFileScope {
		if out[file] == nil {
			out[file] = &rustFileScope{}
		}
		return out[file]
	}
	for file, imps := range imports {
		get(file).addImports(imps)
	}
	for file, its := range items {
		fs := get(file)
		for _, it := range its {
			f := rustItemFact{
				kind: it.Kind, name: it.Name, span: rustSpanOf(it.Line, it.StartCol, it.EndCol, it.EndLine),
				typ: it.Type, keywordCol: it.KeywordCol, params: it.Params,
			}
			fs.items = append(fs.items, f)
			switch it.Kind {
			case rustItemMod, "fn", rustItemImpl, "trait", rustItemBlock:
				fs.blocks = append(fs.blocks, f.span)
			}
		}
	}
	for _, fs := range out {
		fs.topLevelGlobs()
		fs.indexNames()
	}
	return out
}

// addImports reads a file's import entries, one declaration per span.
func (fs *rustFileScope) addImports(imps []graphfrag.GraphFragmentImport) {
	var last *rustUseDecl
	for _, imp := range imps {
		span := rustSpanOf(imp.Line, imp.StartCol, imp.EndCol, imp.EndLine)
		if last != nil && last.span == span {
			continue // another leaf of the same declaration
		}
		last = rustReadDecl(imp, span)
		fs.uses = append(fs.uses, last)
		for _, l := range last.leaves {
			if l.glob && !l.grouped {
				fs.globs = append(fs.globs, l.segs)
				fs.globAt = append(fs.globAt, span)
			}
		}
	}
}

// topLevelGlobs keeps the globs declared at the top level of the file:
// OpenGrep 1.22.0 and 1.33.1 qualify the file's paths through a glob there
// (before it and inside nested modules too), and through a glob inside a
// fn or a mod not at all.
func (fs *rustFileScope) topLevelGlobs() {
	kept := fs.globs[:0]
	for i, g := range fs.globs {
		if fs.parent(fs.globAt[i]) == nil {
			kept = append(kept, g)
		}
	}
	fs.globs, fs.globAt = kept, nil
}

// rustReadDecl reads one declaration from its first import entry: an extern
// crate (no name) or a use tree.
func rustReadDecl(imp graphfrag.GraphFragmentImport, span rustSpan) *rustUseDecl {
	d := &rustUseDecl{span: span, local: imp.Local, text: imp.Text}
	if imp.Name == "" && imp.Module != "" {
		d.leaves = []rustLeaf{{segs: []string{imp.Module}, alias: imp.Alias, extern: true, text: imp.Module}}
		return d
	}
	leaves, ok := rustUseLeaves(imp.Text)
	d.leaves, d.odd = leaves, !ok
	return d
}

// parent is the innermost block enclosing the span, nil for the file.
func (fs *rustFileScope) parent(s rustSpan) *rustSpan {
	if b, ok := fs.parents[s]; ok {
		return b
	}
	if fs.parents == nil {
		fs.parents = map[rustSpan]*rustSpan{}
	}
	b := fs.enclosing(s)
	fs.parents[s] = b
	return b
}

// enclosing walks the blocks for parent.
func (fs *rustFileScope) enclosing(s rustSpan) *rustSpan {
	var best *rustSpan
	for i := range fs.blocks {
		b := &fs.blocks[i]
		if *b == s || !b.contains(s.from) || s.to.before(b.from) || b.to.before(s.to) {
			continue
		}
		if best == nil || best.from.before(b.from) {
			best = b
		}
	}
	return best
}

// placed reports whether a fact at span reaches the site at p from where the
// context puts it: around it, before it, after it or anywhere in the block
// that encloses the fact.
func (fs *rustFileScope) placed(place RustPlace, fact rustSpan, p rustPos) bool {
	if place == RustAround {
		return fact.contains(p)
	}
	if b := fs.parent(fact); b != nil && !b.contains(p) {
		return false
	}
	switch place {
	case RustBefore:
		return !p.before(fact.from)
	case RustAfter:
		return p.before(fact.to)
	case RustAnywhere, RustAround:
	}
	return true
}

// rustNaming is what a written path's first segment names at a position:
// the full paths it reads as, besides itself.
type rustNaming struct {
	cands     [][]string
	undecided bool // a binding no pin says how OpenGrep reads
}

// naming qualifies a written path (plain names, no generics) at p.
func (fs *rustFileScope) naming(written []string, p rustPos) rustNaming {
	var out rustNaming
	if fs == nil || len(written) == 0 {
		return out
	}
	bound, undecided := fs.binding(written[0], p)
	out.undecided = undecided
	if bound != nil {
		out.cands = append(out.cands, append(append([]string{}, bound.segs...), written[1:]...))
	}
	for _, g := range fs.globs {
		out.cands = append(out.cands, append(append([]string{}, g...), written...))
	}
	return out
}

// binding is the latest leaf before p that binds name, and whether a
// binding no pin covers may name it too (a nested leaf beside a plain one,
// an unreadable tree that may bind it).
func (fs *rustFileScope) binding(name string, p rustPos) (bound *rustLeaf, undecided bool) {
	for _, d := range fs.odd {
		if d.span.from.before(p) && d.mayBind(name) {
			undecided = true
			break
		}
	}
	nested := false
	for _, n := range fs.byName[name] {
		if !n.from.before(p) {
			continue
		}
		switch l := n.leaf; {
		case l.self:
			// `use a::{self}` names nothing, as OpenGrep 1.22.0 and 1.33.1 read it.
		case l.nested:
			nested = true
		default:
			bound = l
		}
	}
	return bound, undecided || (nested && bound != nil)
}

// mayBind: the text of an unreadable use tree could bind name, as a word of
// it or through a glob.
func (d *rustUseDecl) mayBind(name string) bool {
	text := rustStripComments(d.text)
	if strings.Contains(text, "*") {
		return true
	}
	words := strings.FieldsFunc(text, func(r rune) bool { return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	return slices.Contains(words, name)
}

// bound is the name a leaf binds: its alias, else its last segment; an
// extern crate without an alias binds nothing new.
func (l *rustLeaf) bound() string {
	if l.alias != "" || l.extern {
		return l.alias
	}
	return l.segs[len(l.segs)-1]
}

// rustUseLeaves reads a use tree's text into its leaves, ok false for a shape
// the reader does not know.
func rustUseLeaves(text string) ([]rustLeaf, bool) {
	sc := &rustUseScan{s: text}
	sc.ws()
	if strings.HasPrefix(sc.s[sc.i:], "::") {
		sc.i += 2
		sc.ws()
	}
	if !sc.top() {
		return nil, false
	}
	sc.ws()
	return sc.out, sc.i == len(sc.s) && len(sc.out) > 0
}

type rustUseScan struct {
	s       string
	i, base int
	out     []rustLeaf
}

// top reads the tree at the top of a declaration. A bare group
// (`use {a::X, b::{Y, Z}};`) is transparent: OpenGrep 1.33.1 reads each of
// its trees as a declaration of its own, `use $X;` binding the text from
// the tree's start (pinned by invented rules).
func (sc *rustUseScan) top() bool {
	sc.ws()
	if !sc.take("{") {
		sc.base = sc.i
		return sc.tree(nil, -1, 0)
	}
	for {
		sc.ws()
		if sc.take("}") {
			return true
		}
		if !sc.top() {
			return false
		}
		sc.ws()
		if !sc.take(",") {
			return sc.take("}")
		}
	}
}

// ws skips whitespace and comments.
func (sc *rustUseScan) ws() {
	for sc.i < len(sc.s) {
		switch rest := sc.s[sc.i:]; {
		case strings.ContainsRune(" \t\r\n", rune(rest[0])):
			sc.i++
		case strings.HasPrefix(rest, "//"):
			n := strings.IndexByte(rest, '\n')
			if n < 0 {
				n = len(rest) - 1
			}
			sc.i += n + 1
		case strings.HasPrefix(rest, "/*"):
			n := strings.Index(rest[2:], "*/")
			if n < 0 {
				sc.i = len(sc.s)
				return
			}
			sc.i += n + 4
		default:
			return
		}
	}
}

// rustStripComments drops the `//` and `/* */` comments of a use tree's text.
func rustStripComments(text string) string {
	sc := &rustUseScan{s: text}
	var b strings.Builder
	for sc.i < len(sc.s) {
		start := sc.i
		sc.ws()
		if sc.i > start {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(sc.s[sc.i])
		sc.i++
	}
	return b.String()
}

func (sc *rustUseScan) ident() string {
	start := sc.i
	for sc.i < len(sc.s) && isRustIdentByte(sc.s[sc.i]) {
		sc.i++
	}
	return sc.s[start:sc.i]
}

func (sc *rustUseScan) take(tok string) bool {
	if strings.HasPrefix(sc.s[sc.i:], tok) {
		sc.i += len(tok)
		return true
	}
	return false
}

// tree reads one use tree under prefix, whose text ends at prefixEnd (-1 for
// none), at group depth depth.
func (sc *rustUseScan) tree(prefix []string, prefixEnd, depth int) bool { //nolint:gocognit // one case per use-tree shape
	var segs []string
	end := prefixEnd
	for {
		sc.ws()
		switch {
		case sc.take("{"):
			if len(prefix)+len(segs) == 0 {
				return false
			}
			return sc.group(append(append([]string{}, prefix...), segs...), end, depth+1)
		case sc.take("*"):
			if len(prefix)+len(segs) == 0 {
				return false
			}
			sc.add(rustLeaf{segs: append(append([]string{}, prefix...), segs...), glob: true, grouped: depth > 0}, end, -1, depth, len(segs))
			return true
		}
		id := sc.ident()
		if id == "" {
			return false
		}
		segs = append(segs, id)
		modEnd := end
		end = sc.i
		sc.ws()
		if sc.take("::") {
			continue
		}
		l := rustLeaf{grouped: depth > 0}
		if id == "self" && len(segs) == 1 && depth > 0 {
			l.segs, l.self = append([]string{}, prefix...), true
		} else {
			l.segs = append(append([]string{}, prefix...), segs...)
		}
		if sc.take("as") {
			sc.ws()
			if l.alias = sc.ident(); l.alias == "" {
				return false
			}
		}
		sc.add(l, end, modEnd, depth, len(segs))
		return true
	}
}

func (sc *rustUseScan) group(prefix []string, prefixEnd, depth int) bool {
	for {
		sc.ws()
		if sc.take("}") {
			return true
		}
		if !sc.tree(prefix, prefixEnd, depth) {
			return false
		}
		sc.ws()
		if !sc.take(",") {
			return sc.take("}")
		}
	}
}

// add records a leaf whose path ends at end and module at modEnd; own is
// the number of segments written in the leaf's own group.
func (sc *rustUseScan) add(l rustLeaf, end, modEnd, depth, own int) {
	l.text = sc.s[sc.base:end]
	if modEnd >= 0 {
		l.module = sc.s[sc.base:modEnd]
	}
	l.modSegs = len(l.segs) - 1
	l.own = own
	l.nested = depth > 1 || (depth == 1 && own > 1)
	sc.out = append(sc.out, l)
}
