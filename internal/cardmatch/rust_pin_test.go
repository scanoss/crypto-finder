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

import (
	"cmp"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// opengrepHit is one OpenGrep result: the file, the match range (1-based
// columns, end exclusive) and what its metavariables bound.
type opengrepHit struct {
	File    string            `json:"file"`
	Line    int               `json:"line"`
	Col     int               `json:"col"`
	EndCol  int               `json:"end_col"`
	Metavar map[string]string `json:"metavars"`
}

// rustFixture loads the invented rules, the fragment reach v0.14.0 exports for
// the .rs files of testdata/rust (graph-fragment-1.35, regenerated with the
// scan's --export-graph-fragment and trimmed
// to the tables the matcher reads), and what OpenGrep 1.33.1 reports for the
// rules on those files.
func rustFixture(t *testing.T) (*Assets, *FragmentJSON, map[string][]opengrepHit) {
	t.Helper()
	return rustFixtureAt(t, filepath.Join("testdata", "rust"))
}

// rustFixtureAt loads the rules, fragment.json and expected.json of dir.
func rustFixtureAt(t *testing.T, dir string) (*Assets, *FragmentJSON, map[string][]opengrepHit) {
	t.Helper()
	assets, err := Load("", "", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var frag FragmentJSON
	var want map[string][]opengrepHit
	for name, v := range map[string]any{"fragment.json": &frag, "expected.json": &want} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, v); err != nil {
			t.Fatal(err)
		}
	}
	return assets, &frag, want
}

// rustFocus: rules whose finding is the argument a focus-metavariable names;
// OpenGrep's range is that argument's, ours is the call with the argument's index.
var rustFocus = map[string]bool{"focus": true}

// rustPinKey is a result's place; OpenGrep reports one result per binding
// at a place, the matcher one finding.
type rustPinKey struct {
	File              string
	Line, Col, EndCol int
}

// TestRustMatchesAsOpenGrep pins the Rust matcher to what OpenGrep 1.33.1
// reports for invented rules on invented files: same places (columns start
// at the callee or the receiver, end exclusive), and an algorithmName filled
// from one of the bindings OpenGrep reports there. It covers use and extern
// crate contexts (glob imports read as their module path), naming through
// uses (a glob under a group names nothing; a bare group is transparent),
// item, const and let contexts, and
// bare paths.
func TestRustMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixture(t)
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	got := map[string]map[rustPinKey]string{}
	for _, f := range found {
		k := rustPinKey{f.File, f.Line, f.Col, f.EndCol}
		if rustFocus[f.RuleID] {
			k.Col, k.EndCol = 0, 0
		}
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]string{}
		}
		got[f.RuleID][k] = rustTokens(f.MetadataFields()["algorithmName"].(string))
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		exp := map[rustPinKey][]string{}
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			if rustFocus[id] {
				k.Col, k.EndCol = 0, 0
			}
			exp[k] = append(exp[k], rustTokens(rustName(assets, id, h)))
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
			continue
		}
		for k, name := range got[id] {
			if !slices.Contains(exp[k], name) {
				t.Errorf("%s at %v: algorithmName %q, OpenGrep binds %q", id, k, name, exp[k])
			}
		}
	}
}

func rustPinKeys[V any](m map[rustPinKey]V) []rustPinKey {
	out := slices.Collect(maps.Keys(m))
	slices.SortFunc(out, func(a, b rustPinKey) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Col, b.Col), cmp.Compare(a.EndCol, b.EndCol))
	})
	return out
}

// rulesOf is the rule ids of the index.
func rulesOf(a *Assets) map[string]bool {
	out := map[string]bool{}
	for _, e := range a.index.Entries {
		out[e.RuleID] = true
	}
	return out
}

// rustName is the algorithmName the fixture's rule fills from OpenGrep's
// bindings: the rule's template with each metavariable replaced.
func rustName(a *Assets, id string, h opengrepHit) string {
	var tmpl string
	for _, e := range a.index.Entries {
		if e.RuleID == id {
			tmpl, _ = e.Metadata.M.GetOr("algorithmName").(string)
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(h.Metavar), func(a, b string) int { return len(b) - len(a) }) {
		tmpl = strings.ReplaceAll(tmpl, k, h.Metavar[k])
	}
	return tmpl
}

// rustTokens is text as its word tokens: OpenGrep prints a binding as its
// tokens (`acme_kdf Kdf` for `acme_kdf::Kdf`).
func rustTokens(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return !isRustIdentByte(byte(r)) && r != '"' }), " ")
}

// Turbofish is identity in OpenGrep 1.22.0, and a path is compared as
// written.
func TestRustTurbofishIsIdentity(t *testing.T) {
	assets, frag, _ := rustFixture(t)
	found, _ := matchRustStats(assets, newFrag(frag))
	found = slices.DeleteFunc(found, func(f *Finding) bool { return f.File != "src/main.rs" })
	lines := map[string][]int{}
	for _, f := range found {
		lines[f.RuleID] = append(lines[f.RuleID], f.Line)
	}
	for id, want := range map[string][]int{
		"new":          {4, 12, 13},    // Kdf::new does not match Kdf::<Sha256>::new (5), nor acme_kdf::Kdf::new (9)
		"turbofish":    {5},            // Kdf::<$H>::new binds $H=Sha256; the qualified site (6) is a longer path
		"qualturbo":    {6},            // binds $H=Sha512; a generic site (5) is not read through the use
		"qual":         {4, 9, 12, 13}, // through `use acme_kdf::Kdf;`, not the generic site (6)
		"recv":         {7, 8, 10, 11}, // $X.derive(...) also reads Other::derive(1), binding $X=Other
		"focus":        {4, 12, 13},    // the focus argument is reported, not the call
		"turbofish512": nil,            // no written Sha512 behind a bare Kdf::<..>
	} {
		slices.Sort(lines[id])
		if !slices.Equal(lines[id], want) {
			t.Errorf("%s lines = %v, want %v", id, lines[id], want)
		}
	}
	for _, f := range found {
		if f.RuleID == "focus" && (f.FocusArg == nil || *f.FocusArg != 1 || f.FocusText != map[int]string{4: "2", 12: "2", 13: "6"}[f.Line]) {
			t.Errorf("focus at %d: arg %v text %q", f.Line, f.FocusArg, f.FocusText)
		}
	}
}

var rustFocusDir = filepath.Join("testdata", "rust_focus")

// rustFocusGaps are the OpenGrep results of testdata/rust_focus the matcher
// does not reproduce, each counted: OpenGrep also binds `$SIG` of
// `$SIG.verify(...)` to the method of a path call (`Verifier::verify(...)`,
// a second result at `verify`), and a focus on the receiver of a call
// inside the pattern's receiver, or on an argument of a call nested in the
// site's arguments, is not read (UnfocusedSites).
var rustFocusGaps = map[string][]rustPinKey{
	"recv":      {{"src/main.rs", 10, 15, 21}},
	"nested":    {{"src/main.rs", 11, 5, 6}},
	"nestedarg": {{"src/main.rs", 38, 43, 45}},
}

// rustFocusOutside counts the sites of testdata/rust_focus whose focus is an
// argument of an enclosing pattern-inside call: outside the match, OpenGrep
// reports nothing there, and the matcher counts them (UnfocusedSites).
const rustFocusOutside = 1

// TestRustFocusAndGroupsAsOpenGrep pins focus-metavariable on a receiver to
// what OpenGrep 1.33.1 reports for invented rules on an invented file: the
// place of what `$X` of `$X.m(...)` binds (a receiver written as a name, a
// call, a chain over two lines, a field, a `?`, the path in front of a path
// call's method), for match and taint sinks; a tainted argument does not
// reach a sink focused on its receiver; a path call with a turbofish on its
// method (`Verifier::verify::<u8>(...)`) is no `$X.verify(...)`. And the named groups of a
// metavariable-regex bind metavariables the metadata reads, on a match rule
// and a taint sink. And a metavariable followed by one segment (`$X::new`,
// `$X::<$C>::new`) binds the written path in front of that segment, of one,
// two or three segments, generics in front included; generics written on the
// metavariable bind nothing; a metavariable followed by two segments binds one.
func TestRustFocusAndGroupsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, rustFocusDir)
	fr := newFrag(frag)
	fr.ResolveParams = true
	found, stats := matchRustStats(assets, fr)
	unfocused := len(rustFocusGaps["nested"]) + len(rustFocusGaps["nestedarg"]) + rustFocusOutside
	if stats.Held != 0 || len(stats.Undecided) != 0 || stats.UnfocusedSites != unfocused {
		t.Fatalf("stats = %+v, want none held or undecided, %d unfocused", stats, unfocused)
	}
	got := map[string]map[rustPinKey]string{}
	for _, f := range found {
		if f.EndLine != 0 {
			t.Errorf("%s at %d: ends on line %d, OpenGrep's results here end on their line", f.RuleID, f.Line, f.EndLine)
		}
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]string{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = rustTokens(f.MetadataFields()["algorithmName"].(string))
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		exp := map[rustPinKey][]string{}
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			if !slices.Contains(rustFocusGaps[id], k) {
				exp[k] = append(exp[k], strings.ReplaceAll(rustTokens(rustName(assets, id, h)), `"`, ""))
			}
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
			continue
		}
		for k, name := range got[id] {
			if !slices.Contains(exp[k], name) {
				t.Errorf("%s at %v: algorithmName %q, OpenGrep binds %q", id, k, name, exp[k])
			}
		}
	}
}

// TestRustGapsAsOpenGrep pins two positives in one `patterns` and a
// metavariable-regex on a metavariable only some branches bind to what
// OpenGrep 1.33.1 reports for invented rules on invented files: same places
// and the same metadata, filled from the bindings OpenGrep reports there. A
// second positive pattern-either that mixes a specialized pattern with a
// context keeps a site the pattern matches, or one inside a range it
// matches, and a site inside the context; a branch conjunction's context
// holds at its own range; the either may come first. A branch that does not
// bind the metavariable a metavariable-regex names is dropped, the rule is
// not. Rule cross reads no metavariable: at Mac::new(1) inside
// Kdf::new(...), OpenGrep binds $X from the enclosing Kdf site, the matcher
// from the site's own match.
func TestRustGapsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_gaps"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	ids := rulesOf(assets)
	for _, id := range []string{"mixed", "mixedrev", "equal", "outer", "subpatterns", "cross", "unbound", "viainside", "nestedeither", "negonly", "within"} {
		if !ids[id] {
			t.Errorf("%s does not compile", id)
		}
	}
	got := map[string]map[rustPinKey]map[string]any{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]map[string]any{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = f.MetadataFields()
	}
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		exp := map[rustPinKey][]map[string]any{}
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			exp[k] = append(exp[k], rustMetadata(assets, id, h))
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
			continue
		}
		for k, md := range got[id] {
			name := rustTokens(md["algorithmName"].(string))
			md["algorithmName"] = name
			if !slices.ContainsFunc(exp[k], func(e map[string]any) bool { return maps.Equal(e, md) }) {
				t.Errorf("%s at %v: metadata %v, OpenGrep binds %v", id, k, md, exp[k])
			}
		}
	}
}

// rustMetadata is the metadata the fixture's rule fills from OpenGrep's
// bindings h, its algorithmName as word tokens.
func rustMetadata(a *Assets, id string, h opengrepHit) map[string]any {
	var out map[string]any
	for _, e := range a.index.Entries {
		if e.RuleID == id {
			out = map[string]any{}
			for i, k := range e.Metadata.M.Keys {
				out[pyStr(k)] = e.Metadata.M.Vals[i]
			}
		}
	}
	out["algorithmName"] = rustTokens(rustName(a, id, h))
	return out
}

// TestRustRefsAsOpenGrep pins bare paths whose last segment names a type or a
// variant (`acme_kms::types::Spec::Es256`) to OpenGrep 1.33.1 on a
// graph-fragment-1.35: they are found where a value is read, also as a match
// arm pattern, a struct literal's path and through a use, and so are
// one-segment names a use brings in (`Es256`, `&LEVEL`), in every place they
// are read (an argument, a match scrutinee, an if or while condition, a
// closure body, a tail), never as a one-segment match arm (`Es256 =>`, a
// binding to OpenGrep too). OpenGrep reports none of the types written
// out without a use (`let x: acme_kms::Key`, parameter and return types),
// which the fragment lists.
// A lower-case one-segment name (`default_level`) is not listed: that place
// is the one known difference, counted as an undecided bare name.
func TestRustRefsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_refs"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || !maps.Equal(stats.Undecided, map[string]int{"bare name": 1}) {
		t.Fatalf("stats = %+v, want none held, 1 undecided bare name", stats)
	}
	unlisted := map[string][]rustPinKey{"lower": {{"src/names.rs", 8, 17, 30}}}
	got := map[string][]rustPinKey{}
	for _, f := range found {
		got[f.RuleID] = append(got[f.RuleID], rustPinKey{f.File, f.Line, f.Col, f.EndCol})
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		var exp []rustPinKey
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			if !slices.Contains(unlisted[id], k) {
				exp = append(exp, k)
			}
		}
		g := slices.Clone(got[id])
		sortPinKeys(g)
		sortPinKeys(exp)
		if !slices.Equal(g, exp) {
			t.Errorf("%s\n got %v\nwant %v", id, g, exp)
		}
	}
}

func sortPinKeys(ks []rustPinKey) {
	slices.SortFunc(ks, func(a, b rustPinKey) int {
		if a.File != b.File {
			return strings.Compare(a.File, b.File)
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return a.Col - b.Col
	})
}

// TestRustRefVarsAsOpenGrep pins bare path patterns whose last segment is a
// metavariable (`acme_sig::signature::$ALG`, its binding read by a
// metavariable-regex and a named group) and one-segment path patterns under
// a use context (`BASE_TABLE`) to OpenGrep 1.33.1 on a graph-fragment-1.35:
// a one-segment pattern matches only a name written as one segment, never
// the last segment of a longer path (`crate::constants::BASE_TABLE`).
func TestRustRefVarsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_refvars"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// A one-segment path pattern is held on a fragment before
// graph-fragment-1.33, which does not list one-segment names.
func TestRustOneNameHeldBeforeNames(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, filepath.Join("testdata", "rust_refvars"))
	frag.SchemaVersion = "graph-fragment-1.30"
	_, stats := matchRustStats(assets, newFrag(frag))
	if stats.HeldBy[holdNames] != 1 {
		t.Fatalf("stats = %+v, want one entry held by %s", stats, holdNames)
	}
}

// A bare path pattern is held on a fragment before graph-fragment-1.35,
// which does not list the paths written as types.
func TestRustRefHeldBeforeTypes(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, filepath.Join("testdata", "rust_refvars"))
	frag.SchemaVersion = "graph-fragment-1.34"
	found, stats := matchRustStats(assets, newFrag(frag))
	if len(found) != 0 || stats.Held != stats.Entries || stats.HeldBy[holdTypes] != stats.Entries {
		t.Fatalf("found %d, stats = %+v, want every entry held by %s", len(found), stats, holdTypes)
	}
}

// TestRustAliasContextAsOpenGrep pins type alias items as enclosing contexts
// (`type $T = $M::Digest; ...`) to OpenGrep 1.33.1 on a graph-fragment-1.34:
// `pub` in the pattern or the item is read as nothing, the aliased type is
// compared by its last segment (`acme::Digest`, `a::b::Digest`, `Digest` and
// `<X as Tr>::Digest` match; `acme::Other`, `acme::Digest<u8>`, `&Digest` and
// a tuple do not), and the alias holds from where it is declared to the end
// of the block that declares it.
func TestRustAliasContextAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_aliasctx"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	got := map[string]map[rustPinKey]bool{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]bool{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = true
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		exp := map[rustPinKey]bool{}
		for _, h := range want[id] {
			exp[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = true
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
		}
	}
}

// TestRustGroupReceiverAsOpenGrep pins method calls on a parenthesized
// expression or a tuple to OpenGrep 1.33.1: a pattern reads `(a).decrypt(k)`
// as `a.decrypt(k)`, and a metavariable binds the group with its
// parentheses, except around a plain name (`(a)` binds `a`); a focus on it
// lands where it binds (`(key).m()` at `key`).
func TestRustGroupReceiverAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_groupreceiver"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 || stats.UnreadableSites != 0 {
		t.Fatalf("stats = %+v, want none held, undecided or unreadable", stats)
	}
	got := map[string]map[rustPinKey]bool{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]bool{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = true
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		exp := map[rustPinKey]bool{}
		for _, h := range want[id] {
			exp[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = true
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
		}
	}
}

// TestRustLetsAsOpenGrep pins a let statement as the positive (`let $N =
// $V;`) to OpenGrep 1.33.1: it matches every let with an initializer, `mut`
// or typed, reported from its name to its `;`, or at its focus, the name or
// the initializer as written (what a metavariable-regex reads: `hex !(..)`
// is not `hex!(`). A sequence context's end, bare, deep or a statement,
// is found in a statement, a let's initializer, an argument, a method chain,
// an inner block, a closure or the tail. A not-inside sequence that ends in
// `<... &mut $N ...>;` drops a let followed by `&mut n` or `&n` anywhere
// later in the function, not `&mut n[..]`; a later let of the same name
// hides the first from both ends.
func TestRustLetsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_lets"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustTupleLetsAsOpenGrep pins tuple let statements to OpenGrep 1.33.1:
// `let ($S, $H) = ...` binds the names one by one (`mut` and `ref` left out,
// `_` as written), only a tuple of as many elements, nested tuples as a
// whole; a written type `(_, $HT)` matches only a let that writes it, `_`
// included; `let $N = ...` binds $N to the whole tuple pattern. A later let
// of a name the site reads hides the first let, in a tuple or not, in a
// pattern-inside and a pattern-not-inside.
func TestRustTupleLetsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_tuples"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustTypeRefsAsOpenGrep pins bare path patterns matched where a path is
// written as a type (graph-fragment-1.35) to OpenGrep 1.33.1: fields,
// parameters, return types, let annotations, casts, aliases, impl self
// types, const and static types, references, tuples, arrays, fn types, `dyn`
// and `impl` traits and macro arguments, reported at the path's last
// segment. A one-segment name matches a type whose last segment is that name,
// generic arguments included, but not an alias a use binds to it. A longer
// path matches only where a use before the type (or a glob) binds the type's
// last segment to it, not written out without one, and not inside generic
// arguments but a turbofish on a segment the path goes on from
// (`Vec::<Key>::new()`). Generic heads, trait bounds, an impl's trait and
// qualified paths match nothing.
func TestRustTypeRefsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_typerefs"))
	found, stats := matchRustStats(assets, newFrag(frag))
	// Undecided: the files where a use may name scopedvar's path from one
	// segment (bare names), and Key in the generic arguments written across
	// lines no other reference lists (`type Q = Vec<` and `k: HashMap<`), which
	// OpenGrep does not match either.
	if want := map[string]int{undecidedBareName: 7, undecidedGenerics: 4}; stats.Held != 0 || !maps.Equal(stats.Undecided, want) {
		t.Fatalf("stats = %+v, want none held, undecided %v", stats, want)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// A file the fragment lists neither uses nor items for has no file scope; a
// scoped pattern finds no use there to bind a type's last segment, so it
// matches nothing (and the matcher does not read the missing scope).
func TestRustTypeRefsWithoutFileScope(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, filepath.Join("testdata", "rust_typerefs"))
	frag.Imports, frag.Items = nil, nil
	found, _ := matchRustStats(assets, newFrag(frag))
	for _, f := range found {
		if f.RuleID == "scoped" || f.RuleID == "scopedvar" || f.RuleID == "deep" {
			t.Errorf("%s matched at %s:%d with no file scope", f.RuleID, f.File, f.Line)
		}
	}
}

// rustAssertAsOpenGrep checks that the findings are OpenGrep's results, per
// rule, at the same places with the same metadata.
func rustAssertAsOpenGrep(t *testing.T, assets *Assets, found []*Finding, want map[string][]opengrepHit) {
	t.Helper()
	got := map[string]map[rustPinKey]map[string]any{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]map[string]any{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = f.MetadataFields()
	}
	for _, id := range slices.Sorted(maps.Keys(rulesOf(assets))) {
		exp := map[rustPinKey][]map[string]any{}
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			exp[k] = append(exp[k], rustMetadata(assets, id, h))
		}
		if !slices.Equal(rustPinKeys(got[id]), rustPinKeys(exp)) {
			t.Errorf("%s\n got %v\nwant %v", id, rustPinKeys(got[id]), rustPinKeys(exp))
			continue
		}
		for k, md := range got[id] {
			md["algorithmName"] = rustTokens(md["algorithmName"].(string))
			if !slices.ContainsFunc(exp[k], func(e map[string]any) bool { return maps.Equal(e, md) }) {
				t.Errorf("%s at %v: metadata %v, OpenGrep binds %v", id, k, md, exp[k])
			}
		}
	}
}

// TestRustSelfUseAsOpenGrep pins `use $V::N;` on use trees with a self leaf
// to OpenGrep 1.33.1: `use a::N::{self, X};` (also aliased, or rooted with
// `::`) binds $V to `a`; a self leaf whose path ends in another name
// (`use std::io::{self, IoSlice};`), a longer path, a nested group, or a
// one-segment path is no use of N, so the negative context keeps the site.
func TestRustSelfUseAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_selfuse"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustBareGroupAsOpenGrep pins a bare group at the top of a use
// declaration (`use {x::Y, acme_hash::{AcmeHash, Other}};`, also across
// lines, rooted with `::` or doubled) to OpenGrep 1.33.1: each tree in it
// reads as a use declaration of its own, `use $I;` binding the text from
// that tree's start.
func TestRustBareGroupAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_baregroup"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustTraitParamsAsOpenGrep pins fn parameter types `&dyn P` and
// `impl P` (P a qualified trait path) to OpenGrep 1.33.1, which reads
// neither keyword and compares paths by their last segment: the written
// trait as P (`&dyn acme::rand::SecureRng`, `&mut`, a lifetime, `::` in
// front), through a use or a glob, or written without `dyn` or as `&impl`.
// OpenGrep also matches a trait of the same last segment from another
// library, which the matcher does not copy (rustTraitParamsNotCopied).
func TestRustTraitParamsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_traitparams"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	for id, hits := range want {
		want[id] = slices.DeleteFunc(hits, func(h opengrepHit) bool {
			return rustTraitParamsNotCopied[strings.TrimSuffix(filepath.Base(h.File), ".rs")]
		})
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// rustTraitParamsNotCopied are the rust_traitparams files where OpenGrep
// matches a trait parameter the matcher deliberately does not: OpenGrep
// false positives on a trait of another library with the same last segment
// (a crate's own trait through `use crate::crypto::SecureRng;`, a path
// written to another crate, a use aliasing another item to the name), and
// a name no use before the site resolves (no use at all, or a use after
// the fn, which Rust reads but the matcher's naming does not), and a name a
// nested use leaf binds (`use acme::{rand::{SecureRng}};`), which the
// naming reads as naming nothing, as it does for calls.
var rustTraitParamsNotCopied = map[string]bool{
	"foreign": true, "foreignpath": true, "implforeign": true, "aliasedsame": true,
	"nouse": true, "later": true, "grouped": true,
}

// TestRustGlobUseAsOpenGrep pins `use $CRATE::$TYPE;` against glob uses to
// OpenGrep 1.33.1: `use other::*;` (also in a group, of a longer path, or
// reached through `use super::*;`) is no use of $TYPE, so a negative context
// written with it keeps the site, and a positive one does not match.
func TestRustGlobUseAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_globuse"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustSelfGroupAsOpenGrep pins use contexts on a use group with a self
// leaf (`use a::b::{self, C};`, also aliased, nested, beside a glob, alone)
// to OpenGrep 1.33.1: `use $IMPORT;` binds the leaf's path with its self
// (`a::b::self`), `use $M::$N;` binds $M to the path in front of the self and
// $N to `self`, and the file's other uses still match.
func TestRustSelfGroupAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_selfgroup"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustCfgVariantsAsOpenGrep pins functions of one name declared more
// than once in one file under mutually exclusive #[cfg] attributes (free
// functions, also three times, and methods of one impl) to OpenGrep 1.33.1,
// which reads every body: reach keeps the calls of each variant under the
// one key (graph-algo-rs-11), and a use inside one variant scopes to it.
func TestRustCfgVariantsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_cfgdup"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}

// TestRustBlockUseAsOpenGrep pins a use declared in a block inside a
// function body (a match arm, an if branch, a nested block, a closure's,
// an async or an unsafe block) to OpenGrep 1.33.1, which scopes it to that
// block: a later sibling block, an else branch and the rest of the body do
// not see it, an inner block does. reach lists such a block among the
// file's items (kind block, graph-fragment-1.36).
func TestRustBlockUseAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_blockuse"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	rustAssertAsOpenGrep(t, assets, found, want)
}
