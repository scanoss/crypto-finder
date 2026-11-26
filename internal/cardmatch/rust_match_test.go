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
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// rustSrcFrag is a Rust fragment over one file, one source line per element
// (line 1 first); each call names the text of a call on a line and its method,
// and gets the span reach gives it.
type rustSrcCall struct {
	line         int
	text, method string
	endLine      int
}

func rustSrcFrag(src []string, calls ...rustSrcCall) *FragmentJSON {
	frag := &FragmentJSON{
		SchemaVersion: "graph-fragment-1.25",
		Functions:     []FunctionJSON{{Key: "probe.main", Package: "probe", FilePath: "src/main.rs"}},
		SourceLines:   map[string]map[int]string{"src/main.rs": {}},
	}
	frag.ScanMetadata.Ecosystem = "rust"
	for i, l := range src {
		frag.SourceLines["src/main.rs"][i+1] = l
	}
	for _, c := range calls {
		line, endLine := c.line, c.endLine
		first := strings.Split(c.text, "\n")
		col := strings.Index(src[line-1], first[0]) + 1
		end := col + len(c.text)
		if endLine > 0 {
			end = len(first[len(first)-1]) + strings.Index(src[endLine-1], first[len(first)-1]) + 1
		}
		call := ExternalJSON{CallerKey: "probe.main", MethodName: c.method, Line: &line, EndLine: endLine, StartCol: &col, EndCol: &end, Resolution: "exact"}
		frag.ExternalCalls = append(frag.ExternalCalls, call)
	}
	return frag
}

func rustMatchRules(t *testing.T, rules map[string]string, frag *FragmentJSON) ([]*Finding, RustMatchStats) {
	t.Helper()
	assets, err := Load("", "", writeRules(t, rustRuleYAML(rules)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return matchRustStats(assets, newFrag(frag))
}

func rustFoundLines(found []*Finding) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.RuleID+"@"+itoa(f.Line))
	}
	slices.Sort(out)
	return out
}

// An entry that reads a fact reach v0.1.1 does not carry is held: no finding,
// counted under what it waits for; a plain entry on the same fragment matches.
func TestRustHeldEntriesFindNothing(t *testing.T) {
	src := []string{"use acme_kdf::Kdf;", "let k = Kdf::new(1, 2);"}
	frag := rustSrcFrag(src, rustSrcCall{line: 2, text: "Kdf::new(1, 2)", method: "new"})
	found, stats := rustMatchRules(t, map[string]string{
		"plain":  "pattern: Kdf::new(...)",
		"use":    "patterns:\n- pattern-inside: |\n    use acme_kdf::Kdf;\n    ...\n- pattern: Kdf::new(...)",
		"let":    "patterns:\n- pattern-inside: |\n    let $X = acme_kdf::PARAM;\n    ...\n- pattern: Kdf::new(...)",
		"mod":    "patterns:\n- pattern: Kdf::new(...)\n- pattern-not-inside: |\n    mod acme_kdf { ... }",
		"before": "patterns:\n- pattern: Kdf::new(...)\n- pattern-inside: |\n    init(...);\n    ...",
	}, frag)
	if got, want := rustFoundLines(found), []string{"plain@2"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.Entries != 5 || stats.Held != 4 {
		t.Errorf("stats = %+v, want 5 entries, 4 held", stats)
	}
	for hold, n := range map[string]int{holdImports: 1, holdDeclarations: 1, holdItems: 1, holdSequence: 1} {
		if stats.HeldBy[hold] != n {
			t.Errorf("held by %s = %d, want %d (%v)", hold, stats.HeldBy[hold], n, stats.HeldBy)
		}
	}
}

// The holds of the index are countable without a fragment: on one that
// carries the scope facts, only shapes no fact decides are held.
func TestRustEntryHolds(t *testing.T) {
	assets, err := Load("", "", writeRules(t, rustRuleYAML(map[string]string{
		"plain":   "pattern: Kdf::new(...)",
		"ref":     "pattern: acme_kdf::PARAM_A",
		"use":     "patterns:\n- pattern-inside: |\n    use acme_kdf::Kdf;\n    ...\n- pattern: Kdf::new(...)",
		"type":    "pattern: acme_kdf::Kdf",
		"generic": "pattern: acme_kdf::Kdf::<u8>::MAX",
		"params":  "patterns:\n- pattern-inside: |\n    fn $F(..., $K: Key, ...) { ... }\n- pattern: Kdf::new(...)",
		"tuple":   "patterns:\n- pattern-inside: |\n    let ($A, $B) = acme_kdf::pair();\n    ...\n- pattern: Kdf::new(...)",
		"usevar":  "patterns:\n- pattern-inside: |\n    use $A::kdf::$B;\n    ...\n- pattern: Kdf::new(...)",
		"cvalue":  "patterns:\n- pattern: Kdf::new($A)\n- pattern-not-inside: |\n    const $A: u8 = 1;\n    ...",
		"noargs":  "patterns:\n- pattern-inside: |\n    fn $F() { ... }\n- pattern: Kdf::new(...)",
		"bodyuse": "patterns:\n- pattern-inside: |\n    fn $F(...) { ... use $M::x::$N; ... }\n- pattern: Kdf::new(...)",
		"alias":   "pattern: type $A = acme_kdf::Mode<$C>;",
		"letmut":  "pattern: let mut $N = $V;",
	})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := assets.RustEntryHolds()
	// A path that names a type is served where a value is read; one with
	// generics is held. A type alias pattern is served from a hand card only
	// (rustAliasServable).
	// A fn context is decided from its parameters (graph-fragment-1.30), but
	// for one whose body declares a use with a parameter list that is not
	// `...`. A tuple let context is served, a let positive written `mut` is
	// held.
	want := map[string]int{"": 7, holdRefShape: 1, holdItemShape: 1, holdLetShape: 1, holdUseShape: 2, holdItemPos: 1}
	if !maps.Equal(got, want) {
		t.Errorf("holds = %v, want %v", got, want)
	}
}

// rustFactsFrag is a graph-fragment-1.26 over one file: its source lines,
// imports and items, and the calls on it.
func rustFactsFrag(src []string, imports []graphfrag.GraphFragmentImport, items []graphfrag.GraphFragmentItem, calls ...rustSrcCall) *FragmentJSON {
	frag := rustSrcFrag(src, calls...)
	frag.SchemaVersion = "graph-fragment-1.26"
	frag.Imports = map[string][]graphfrag.GraphFragmentImport{"src/main.rs": imports}
	frag.Items = map[string][]graphfrag.GraphFragmentItem{"src/main.rs": items}
	return frag
}

// A use tree the reader has no shape for decides nothing: a context that
// needs it finds nothing, a negative one drops the site, and both count as
// undecided; a site the facts decide still matches.
func TestRustUndecidedUseTree(t *testing.T) {
	src := []string{"use acme_kdf::{Kdf, r#type};", "fn main() {", "    Kdf::new(1);", "}"}
	frag := rustFactsFrag(src,
		[]graphfrag.GraphFragmentImport{{Line: 1, Module: "acme_kdf", Name: "Kdf", StartCol: 1, EndCol: 29, Text: "acme_kdf::{Kdf, r#type}"}},
		[]graphfrag.GraphFragmentItem{{Line: 2, StartCol: 1, EndCol: 2, EndLine: 4, Kind: "fn", Name: "main"}},
		rustSrcCall{line: 3, text: "Kdf::new(1)", method: "new"})
	found, stats := rustMatchRules(t, map[string]string{
		"inside": "patterns:\n- pattern-inside: |\n    use $I;\n    ...\n- pattern: Kdf::new(...)",
		"not":    "patterns:\n- pattern: Kdf::new(...)\n- pattern-not-inside: |\n    use acme_kdf::Kdf;\n    ...",
		"qual":   "pattern: acme_kdf::Kdf::new(...)",
		"plain":  "pattern: Kdf::new(...)",
	}, frag)
	if got, want := rustFoundLines(found), []string{"plain@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.Undecided[undecidedUseTree] != 2 || stats.Undecided[undecidedNaming] != 1 {
		t.Errorf("undecided = %v, want 2 use tree, 1 naming", stats.Undecided)
	}
}

// The leaves of a use tree: what `use $X;` binds (the text up to the end of
// each leaf's path), what `use $M::N;` binds, and the leaf's form.
func TestRustUseLeaves(t *testing.T) {
	type leaf struct {
		text, module string
		segs         []string
		alias        string
		glob, self   bool
		grouped      bool
		nested       bool
	}
	for text, want := range map[string][]leaf{
		"acme::Kdf":        {{text: "acme::Kdf", module: "acme", segs: []string{"acme", "Kdf"}}},
		"::acme::Kdf as K": {{text: "acme::Kdf", module: "acme", segs: []string{"acme", "Kdf"}, alias: "K"}},
		"acme::m::*":       {{text: "acme::m", segs: []string{"acme", "m"}, glob: true}},
		// A glob alone in a group reads as the group's module path.
		"acme::{*}": {{text: "acme", segs: []string{"acme"}, glob: true, grouped: true}},
		// A bare group is transparent: each tree reads as a declaration.
		"{x::Y, acme::{Kdf}}": {
			{text: "x::Y", module: "x", segs: []string{"x", "Y"}},
			{text: "acme::{Kdf", module: "acme", segs: []string{"acme", "Kdf"}, grouped: true},
		},
		"acme::{Kdf, m::{P, Q as R}, self}": {
			{text: "acme::{Kdf", module: "acme", segs: []string{"acme", "Kdf"}, grouped: true},
			{text: "acme::{Kdf, m::{P", module: "acme::{Kdf, m", segs: []string{"acme", "m", "P"}, grouped: true, nested: true},
			{text: "acme::{Kdf, m::{P, Q", module: "acme::{Kdf, m", segs: []string{"acme", "m", "Q"}, alias: "R", grouped: true, nested: true},
			{text: "acme::{Kdf, m::{P, Q as R}, self", module: "acme", segs: []string{"acme"}, self: true, grouped: true},
		},
	} {
		leaves, ok := rustUseLeaves(text)
		if !ok || len(leaves) != len(want) {
			t.Errorf("%s: %+v, %v", text, leaves, ok)
			continue
		}
		for i, l := range leaves {
			got := leaf{l.text, l.module, l.segs, l.alias, l.glob, l.self, l.grouped, l.nested}
			if !reflect.DeepEqual(got, want[i]) {
				t.Errorf("%s leaf %d\n got %+v\nwant %+v", text, i, got, want[i])
			}
		}
	}
	// Comments inside a use tree are skipped like whitespace.
	commented := "acme::{\n    Kdf, // keyed\n    /* a * b */ Mac,\n}"
	if leaves, ok := rustUseLeaves(commented); !ok || len(leaves) != 2 || !slices.Equal(leaves[0].segs, []string{"acme", "Kdf"}) || !slices.Equal(leaves[1].segs, []string{"acme", "Mac"}) {
		t.Errorf("%q: %+v, %v", commented, leaves, ok)
	}
	if d := (&rustUseDecl{text: "acme::{Kdf /* a * b */}"}); d.mayBind("Mac") {
		t.Errorf("a `*` inside a comment makes %q bind any name", d.text)
	}
	for _, odd := range []string{"{acme::Kdf", "{acme::Kdf,, b}", "{*}", "acme::", "acme::Kdf as"} {
		if _, ok := rustUseLeaves(odd); ok {
			t.Errorf("%s read", odd)
		}
	}
}

// A bare path a use may name from one segment, which no fact lists (a
// lower-case name), is counted per entry and file; the references the fragment lists still match.
func TestRustBareNameCounted(t *testing.T) {
	src := []string{"use acme_kdf::param_a;", "fn main() {", "    let a = acme_kdf::param_a;", "}"}
	frag := rustFactsFrag(src,
		[]graphfrag.GraphFragmentImport{{Line: 1, Module: "acme_kdf", Name: "param_a", StartCol: 1, EndCol: 23, Text: "acme_kdf::param_a"}},
		[]graphfrag.GraphFragmentItem{{Line: 2, StartCol: 1, EndCol: 2, EndLine: 4, Kind: "fn", Name: "main"}})
	frag.SchemaVersion = "graph-fragment-1.35"
	frag.ConstantRefs = []graphfrag.GraphFragmentConstantRef{{Function: 0, Line: 3, StartCol: 13, EndCol: 30, Text: "acme_kdf::param_a", Context: "init"}}
	found, stats := rustMatchRules(t, map[string]string{"ref": "pattern: acme_kdf::param_a"}, frag)
	if got, want := rustFoundLines(found), []string{"ref@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.Undecided[undecidedBareName] != 1 {
		t.Errorf("undecided = %v, want 1 bare name", stats.Undecided)
	}
}

// A call the reader cannot place is counted, never guessed: no source line,
// and a span that falls outside the line.
func TestRustUnreadableSites(t *testing.T) {
	frag := rustSrcFrag([]string{"let k = Kdf::new(1, 2);"}, rustSrcCall{line: 1, text: "Kdf::new(1, 2)", method: "new"})
	delete(frag.SourceLines["src/main.rs"], 1)
	found, stats := rustMatchRules(t, map[string]string{"plain": "pattern: Kdf::new(...)"}, frag)
	if len(found) != 0 || stats.UnreadableSites != 1 {
		t.Errorf("found %v, stats %+v", rustFoundLines(found), stats)
	}
}

// Arguments the reader has no shape for (a macro, a closure, a sum) are their
// text, matched by a metavariable; a call over several lines is read whole.
func TestRustCallShapes(t *testing.T) {
	src := []string{
		"let a = Kdf::new(vec![1, 2], |x| x + 1);",
		"let b = Kdf::new(",
		"    Kdf::new(3, 4),",
		"    n + 1,",
		");",
	}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 1, text: "Kdf::new(vec![1, 2], |x| x + 1)", method: "new"},
		rustSrcCall{line: 2, text: "Kdf::new(\n    Kdf::new(3, 4),\n    n + 1,\n)", method: "new", endLine: 5},
		rustSrcCall{line: 3, text: "Kdf::new(3, 4)", method: "new"},
	)
	found, stats := rustMatchRules(t, map[string]string{
		"two":    "patterns:\n- pattern: Kdf::new($A, $B)\n- metavariable-regex: {metavariable: $A, regex: '^(vec|Kdf)'}",
		"nested": "pattern: Kdf::new(Kdf::new(3, 4), ...)",
	}, frag)
	want := []string{"nested@2", "two@1", "two@2"}
	if got := rustFoundLines(found); !slices.Equal(got, want) {
		t.Errorf("found %v, want %v (%+v)", got, want, stats)
	}
}

// A receiver that is a call binds as written, and chained calls are sites of
// their own.
func TestRustMethodChain(t *testing.T) {
	src := []string{"let d = Kdf::new(1, 2).derive(&out);"}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 1, text: "Kdf::new(1, 2).derive(&out)", method: "derive"},
		rustSrcCall{line: 1, text: "Kdf::new(1, 2)", method: "new"},
	)
	found, _ := rustMatchRules(t, map[string]string{
		"recv": "pattern: $X.derive(...)\nmetadata: {crypto: {algorithmName: $X}}",
		"new":  "pattern: Kdf::new(...)",
	}, frag)
	if got, want := rustFoundLines(found), []string{"new@1", "recv@1"}; !slices.Equal(got, want) {
		t.Fatalf("found %v, want %v", got, want)
	}
	for _, f := range found {
		if f.RuleID == "recv" && f.MetadataFields()["algorithmName"] != "Kdf::new(1, 2)" {
			t.Errorf("$X = %v", f.MetadataFields()["algorithmName"])
		}
	}
}

// pattern-not drops the site under the bindings of the positive; a
// not-inside call drops a site written inside it.
func TestRustNegatives(t *testing.T) {
	src := []string{"let a = Kdf::new(1, 2);", "let b = Kdf::new(3, 4);", "let c = sign(Kdf::new(5, 6));"}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 1, text: "Kdf::new(1, 2)", method: "new"},
		rustSrcCall{line: 2, text: "Kdf::new(3, 4)", method: "new"},
		rustSrcCall{line: 3, text: "Kdf::new(5, 6)", method: "new"},
		rustSrcCall{line: 3, text: "sign(Kdf::new(5, 6))", method: "sign"},
	)
	found, _ := rustMatchRules(t, map[string]string{
		"not":       "patterns:\n- pattern: Kdf::new($A, $B)\n- pattern-not: Kdf::new(1, ...)",
		"notsame":   "patterns:\n- pattern: Kdf::new($A, $B)\n- pattern-not: Kdf::new($A, 4)",
		"notinside": "patterns:\n- pattern: Kdf::new(...)\n- pattern-not-inside: sign(...)",
		"inside":    "patterns:\n- pattern: Kdf::new($A, ...)\n- pattern-inside: sign($S)",
	}, frag)
	want := []string{"inside@3", "not@2", "not@3", "notinside@1", "notinside@2", "notsame@1", "notsame@3"}
	if got := rustFoundLines(found); !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A focus-metavariable on the receiver reports the finding where the
// receiver is written (TestRustFocusAndGroupsAsOpenGrep pins the places);
// one on an argument names the argument, for the scanner to place.
func TestRustFocusOnReceiver(t *testing.T) {
	frag := rustSrcFrag([]string{"let d = kdf.derive(&out);"}, rustSrcCall{line: 1, text: "kdf.derive(&out)", method: "derive"})
	found, stats := rustMatchRules(t, map[string]string{
		"recv": "patterns:\n- pattern: $X.derive($O)\n- focus-metavariable: $X",
		"arg":  "patterns:\n- pattern: $X.derive($O)\n- focus-metavariable: $O",
	}, frag)
	if got, want := rustFoundLines(found), []string{"arg@1", "recv@1"}; !slices.Equal(got, want) || stats.UnfocusedSites != 0 {
		t.Fatalf("found %v, %d unfocused; want %v, none", got, stats.UnfocusedSites, want)
	}
	for _, f := range found {
		switch f.RuleID {
		case "recv":
			if f.FocusArg != nil || f.FocusText != "kdf" || f.Col != 9 || f.EndCol != 12 || f.EndLine != 0 {
				t.Errorf("recv: arg %v text %q at %d-%d (line %d), want the receiver at 9-12", f.FocusArg, f.FocusText, f.Col, f.EndCol, f.EndLine)
			}
		case "arg":
			if f.FocusArg == nil || *f.FocusArg != 0 || f.FocusText != "&out" || f.Col != 9 {
				t.Errorf("arg: arg %v text %q at %d", f.FocusArg, f.FocusText, f.Col)
			}
		}
	}
}

// A focus-metavariable bound in a nested call's arguments, or in an
// enclosing pattern-inside call's, is no argument of the site: no finding
// reports it as the site's argument at that index. It is counted instead.
// OpenGrep 1.33.1 reports no result for the pattern-inside one (the focus
// is outside the match), and the nested ones (`acme_wrap($K)`, `$W($K)`)
// where `iv` is written.
func TestRustFocusOutsideTheSiteArgsIsCounted(t *testing.T) {
	frag := rustSrcFrag([]string{
		"acme_encrypt(key, acme_wrap(iv), m);",
		"acme_outer(iv, || {",
		"    acme_encrypt(key, m);",
		"});",
	},
		rustSrcCall{line: 1, text: "acme_encrypt(key, acme_wrap(iv), m)", method: "acme_encrypt"},
		rustSrcCall{line: 2, text: "acme_outer(iv, || {\n    acme_encrypt(key, m);\n})", method: "acme_outer", endLine: 4},
		rustSrcCall{line: 3, text: "acme_encrypt(key, m)", method: "acme_encrypt"},
	)
	found, stats := rustMatchRules(t, map[string]string{
		"nested":    "patterns:\n- pattern: acme_encrypt(..., acme_wrap($K), ...)\n- focus-metavariable: $K",
		"nestedvar": "patterns:\n- pattern: acme_encrypt(..., $W($K), ...)\n- focus-metavariable: $K",
		"inside":    "patterns:\n- pattern-inside: acme_outer($K, ...)\n- pattern: acme_encrypt(...)\n- focus-metavariable: $K",
		"top":       "patterns:\n- pattern: acme_encrypt($A, $K, ...)\n- focus-metavariable: $K",
	}, frag)
	if got, want := rustFoundLines(found), []string{"top@1", "top@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if stats.UnfocusedSites != 3 {
		t.Errorf("UnfocusedSites = %d, want 3", stats.UnfocusedSites)
	}
	for _, f := range found {
		if f.FocusArg == nil || *f.FocusArg != 1 {
			t.Errorf("%s@%d: focus arg %v, want 1", f.RuleID, f.Line, f.FocusArg)
		}
	}
}

// A callee written as one metavariable binds the whole callee, as OpenGrep
// 1.22.0 and 1.33.1 do: a path with its turbofish, a path qualified through
// a crate, a method call's receiver and method.
func TestRustCalleeMetavarBindsWholeCallee(t *testing.T) {
	src := []string{
		"fn main() {",
		"    let m = Mac::<Sha9>::new(&k);",
		"    let n = acme_mac::Mac::<acme_hash::Sha9>::new_from_slice(&k);",
		"    let p = x.update(&k);",
		"    let q = Mac::<Sha1>::new(&k);",
		"}",
	}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 2, text: "Mac::<Sha9>::new(&k)", method: "new"},
		rustSrcCall{line: 3, text: "acme_mac::Mac::<acme_hash::Sha9>::new_from_slice(&k)", method: "new_from_slice"},
		rustSrcCall{line: 4, text: "x.update(&k)", method: "update"},
		rustSrcCall{line: 5, text: "Mac::<Sha1>::new(&k)", method: "new"},
	)
	found, _ := rustMatchRules(t, map[string]string{
		"path":   "patterns:\n- pattern: $F(...)\n- metavariable-regex:\n    metavariable: $F\n    regex: ^(?:acme_mac::)?Mac::<(?:\\w+::)*Sha9>::new(?:_from_slice)?$",
		"method": "patterns:\n- pattern: $F(...)\n- metavariable-regex:\n    metavariable: $F\n    regex: ^x\\.update$",
	}, frag)
	if got, want := rustFoundLines(found), []string{"method@4", "path@2", "path@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A glob use qualifies the file's paths only from the top level of the file,
// as OpenGrep 1.22.0 and 1.33.1 read it: there it reaches paths before it and
// inside nested modules; inside a fn or a mod it qualifies nothing.
func TestRustGlobQualifiesFromTopLevelOnly(t *testing.T) {
	rules := map[string]string{"qual": "pattern: acme_hash::compute(...)"}
	nested := rustFactsFrag(
		[]string{"fn f(d: &[u8]) {", "    use acme_hash::*;", "    compute(d);", "}", "mod m {", "    use acme_hash::*;", "    fn g(d: &[u8]) { compute(d); }", "}"},
		[]graphfrag.GraphFragmentImport{
			{Line: 2, Module: "acme_hash", Name: "*", StartCol: 5, EndCol: 22, Text: "acme_hash::*"},
			{Line: 6, Module: "acme_hash", Name: "*", StartCol: 5, EndCol: 22, Text: "acme_hash::*"},
		},
		[]graphfrag.GraphFragmentItem{
			{Line: 1, StartCol: 1, EndCol: 2, EndLine: 4, Kind: "fn", Name: "f"},
			{Line: 5, StartCol: 1, EndCol: 2, EndLine: 8, Kind: "mod", Name: "m"},
			{Line: 7, StartCol: 5, EndCol: 35, Kind: "fn", Name: "g"},
		},
		rustSrcCall{line: 3, text: "compute(d)", method: "compute"},
		rustSrcCall{line: 7, text: "compute(d)", method: "compute"})
	if found, _ := rustMatchRules(t, rules, nested); len(found) != 0 {
		t.Errorf("nested globs found %v, want nothing", rustFoundLines(found))
	}
	top := rustFactsFrag(
		[]string{"fn before(d: &[u8]) { compute(d); }", "use acme_hash::*;", "mod n {", "    fn g(d: &[u8]) { compute(d); }", "}"},
		[]graphfrag.GraphFragmentImport{{Line: 2, Module: "acme_hash", Name: "*", StartCol: 1, EndCol: 18, Text: "acme_hash::*"}},
		[]graphfrag.GraphFragmentItem{
			{Line: 1, StartCol: 1, EndCol: 37, Kind: "fn", Name: "before"},
			{Line: 3, StartCol: 1, EndCol: 2, EndLine: 5, Kind: "mod", Name: "n"},
			{Line: 4, StartCol: 5, EndCol: 35, Kind: "fn", Name: "g"},
		},
		rustSrcCall{line: 1, text: "compute(d)", method: "compute"},
		rustSrcCall{line: 4, text: "compute(d)", method: "compute"})
	found, _ := rustMatchRules(t, rules, top)
	if got, want := rustFoundLines(found), []string{"qual@1", "qual@4"}; !slices.Equal(got, want) {
		t.Errorf("top-level glob found %v, want %v", got, want)
	}
}

// A use context whose path is names reads as a prefix of the declared path,
// as OpenGrep 1.22.0 and 1.33.1 read it: `use acme::m;` holds at a deeper
// leaf, a first-level leaf of a group and an aliased leaf, not at a leaf
// under a nested group or at a sibling module whose name only starts alike.
func TestRustUseContextIsAPathPrefix(t *testing.T) {
	src := []string{
		"fn a() { use acme::m::Kdf::Inner; Kdf::new(1); }",
		"fn b() { use acme::{m, z}; Kdf::new(1); }",
		"fn c() { use acme::m::Kdf as K; Kdf::new(1); }",
		"fn d() { use acme::m::{x::Kdf}; Kdf::new(1); }",
		"fn e() { use acme::mm::Kdf; Kdf::new(1); }",
	}
	imp := func(line int, text, module, name, alias string) graphfrag.GraphFragmentImport {
		col := strings.Index(src[line-1], "use ") + 5
		return graphfrag.GraphFragmentImport{Line: line, Module: module, Name: name, Alias: alias, StartCol: col, EndCol: col + len(text), Text: text, Local: true}
	}
	items := make([]graphfrag.GraphFragmentItem, 0, len(src))
	calls := make([]rustSrcCall, 0, len(src))
	for i, l := range src {
		items = append(items, graphfrag.GraphFragmentItem{Line: i + 1, StartCol: 1, EndCol: len(l) + 1, Kind: "fn", Name: l[3:4]})
		calls = append(calls, rustSrcCall{line: i + 1, text: "Kdf::new(1)", method: "new"})
	}
	frag := rustFactsFrag(src, []graphfrag.GraphFragmentImport{
		imp(1, "acme::m::Kdf::Inner", "acme::m::Kdf", "Inner", ""),
		imp(2, "acme::{m, z}", "acme", "m", ""),
		imp(2, "acme::{m, z}", "acme", "z", ""),
		imp(3, "acme::m::Kdf as K", "acme::m", "Kdf", "K"),
		imp(4, "acme::m::{x::Kdf}", "acme::m::x", "Kdf", ""),
		imp(5, "acme::mm::Kdf", "acme::mm", "Kdf", ""),
	}, items, calls...)
	found, _ := rustMatchRules(t, map[string]string{
		"in":  "patterns:\n- pattern-inside: |\n    use acme::m;\n    ...\n- pattern: Kdf::new(...)",
		"out": "patterns:\n- pattern: Kdf::new(...)\n- pattern-not-inside: |\n    use acme::m;\n    ...",
	}, frag)
	want := []string{"in@1", "in@2", "in@3", "out@4", "out@5"}
	if got := rustFoundLines(found); !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A metavariable in type position binds a path type's last segment with its
// generics, as OpenGrep 1.22.0 and 1.33.1 do: `Sha9` for `acme_hash::Sha9`,
// `Wrap<Sha9>` for `acme::Wrap<Sha9>`, also as a qualified self type.
func TestRustTypeMetavarBindsLastSegment(t *testing.T) {
	src := []string{
		"fn main() {",
		"    let a = Kdf::<acme_hash::Sha9>::new(1);",
		"    let b = Kdf::<acme::Wrap<Sha9>>::new(1);",
		"    let c = <acme_hash::Sha9 as Tr>::new(1);",
		"}",
	}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 2, text: "Kdf::<acme_hash::Sha9>::new(1)", method: "new"},
		rustSrcCall{line: 3, text: "Kdf::<acme::Wrap<Sha9>>::new(1)", method: "new"},
		rustSrcCall{line: 4, text: "<acme_hash::Sha9 as Tr>::new(1)", method: "new"})
	regex := func(pattern, re string) string {
		return "patterns:\n- pattern: " + pattern + "\n- metavariable-regex:\n    metavariable: $D\n    regex: " + re
	}
	found, _ := rustMatchRules(t, map[string]string{
		"last":  regex("Kdf::<$D>::new(...)", "^Sha9$"),
		"full":  regex("Kdf::<$D>::new(...)", "^acme_hash::Sha9$"),
		"wrap":  regex("Kdf::<$D>::new(...)", "^Wrap<Sha9>$"),
		"qself": regex("<$D as $T>::new(...)", "^Sha9$"),
	}, frag)
	if got, want := rustFoundLines(found), []string{"last@2", "qself@4", "wrap@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// Path types in a turbofish compare by their last segment and its generics,
// as OpenGrep 1.22.0 and 1.33.1 compare them; a written path with a leading
// `::` reads as the crate path a pattern names.
func TestRustTypeLastSegmentAndGlobalPaths(t *testing.T) {
	src := []string{
		"fn main() {",
		"    let a = Kdf::<acme_hash::Sha9>::new(1);",
		"    let b = Kdf::<Sha9>::new(1);",
		"    let c = Kdf::<acme::Wrap<other::Sha9>>::new(1);",
		"    let d = Kdf::<Sha8>::new(1);",
		"    let e = ::acme::f(1);",
		"    let g = ::other::acme::f(1);",
		"}",
	}
	frag := rustSrcFrag(src,
		rustSrcCall{line: 2, text: "Kdf::<acme_hash::Sha9>::new(1)", method: "new"},
		rustSrcCall{line: 3, text: "Kdf::<Sha9>::new(1)", method: "new"},
		rustSrcCall{line: 4, text: "Kdf::<acme::Wrap<other::Sha9>>::new(1)", method: "new"},
		rustSrcCall{line: 5, text: "Kdf::<Sha8>::new(1)", method: "new"},
		rustSrcCall{line: 6, text: "::acme::f(1)", method: "f"},
		rustSrcCall{line: 7, text: "::other::acme::f(1)", method: "f"})
	found, _ := rustMatchRules(t, map[string]string{
		"short": "pattern: Kdf::<Sha9>::new(...)",
		"qual":  "pattern: Kdf::<b::Sha9>::new(...)",
		"wrap":  "pattern: Kdf::<Wrap<acme_hash::Sha9>>::new(...)",
		"crate": "pattern: acme::f(...)",
	}, frag)
	want := []string{"crate@6", "qual@2", "qual@3", "short@2", "short@3", "wrap@4"}
	if got := rustFoundLines(found); !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// `fn $F(...) { ... use $I; ... }` holds at a site inside a fn whose span
// holds a matching use anywhere, as OpenGrep 1.22.0 and 1.33.1 read it: a
// use after the site or in a nested block counts, one of the enclosing mod
// does not.
func TestRustFnBodyUseContext(t *testing.T) {
	src := []string{
		"fn a() -> u8 { use acme::Kdf; Kdf::random(1) }",
		"fn b() { Kdf::random(1); use acme::Kdf; }",
		"fn c() { if x { use acme::Kdf; } Kdf::random(1); }",
		"mod d { use acme::Kdf;",
		"    fn e() { Kdf::random(1); } }",
		"fn f() { use other::Kdf; Kdf::random(1); }",
	}
	imp := func(line int, text, module string) graphfrag.GraphFragmentImport {
		col := strings.Index(src[line-1], "use ") + 5
		return graphfrag.GraphFragmentImport{Line: line, Module: module, Name: "Kdf", StartCol: col, EndCol: col + len(text), Text: text, Local: true}
	}
	fnItem := func(line int, name string) graphfrag.GraphFragmentItem {
		start := strings.Index(src[line-1], "fn ") + 1
		return graphfrag.GraphFragmentItem{Line: line, StartCol: start, EndCol: len(src[line-1]) + 1, Kind: "fn", Name: name}
	}
	items := []graphfrag.GraphFragmentItem{
		fnItem(1, "a"), fnItem(2, "b"), fnItem(3, "c"),
		{Line: 4, StartCol: 1, EndCol: len(src[4]) + 1, EndLine: 5, Kind: "mod", Name: "d"},
		{Line: 5, StartCol: 5, EndCol: len(src[4]) - 1, Kind: "fn", Name: "e"},
		fnItem(6, "f"),
	}
	calls := make([]rustSrcCall, 0, 5)
	for _, line := range []int{1, 2, 3, 5, 6} {
		calls = append(calls, rustSrcCall{line: line, text: "Kdf::random(1)", method: "random"})
	}
	frag := rustFactsFrag(src, []graphfrag.GraphFragmentImport{
		imp(1, "acme::Kdf", "acme"), imp(2, "acme::Kdf", "acme"), imp(3, "acme::Kdf", "acme"),
		imp(4, "acme::Kdf", "acme"), imp(6, "other::Kdf", "other"),
	}, items, calls...)
	found, _ := rustMatchRules(t, map[string]string{
		"fnuse": "patterns:\n- pattern: Kdf::random(...)\n- pattern-inside: |\n    fn $F(...) {\n      ...\n      use $I;\n      ...\n    }\n- metavariable-regex:\n    metavariable: $I\n    regex: ^acme",
	}, frag)
	if got, want := rustFoundLines(found), []string{"fnuse@1", "fnuse@2", "fnuse@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A metavariable for the trait of a qualified self binds the trait's last
// segment with its generics, as OpenGrep 1.22.0 and 1.33.1 do.
func TestRustQSelfTraitMetavarBindsGenerics(t *testing.T) {
	src := []string{"fn main() {", "    let p = <G2 as acme::HashTo<u8>>::hash(1);", "}"}
	frag := rustSrcFrag(src, rustSrcCall{line: 2, text: "<G2 as acme::HashTo<u8>>::hash(1)", method: "hash"})
	found, _ := rustMatchRules(t, map[string]string{
		"tr": "patterns:\n- pattern: <G2 as $TR>::hash(...)\n- metavariable-regex:\n    metavariable: $TR\n    regex: ^HashTo<u8>$",
	}, frag)
	if got, want := rustFoundLines(found), []string{"tr@2"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A `self` leaf names nothing, as OpenGrep 1.22.0 and 1.33.1 read it, so a
// path whose first segment it binds is decided: a negative call context the
// path cannot be does not drop the site.
func TestRustSelfLeafNamesNothing(t *testing.T) {
	src := []string{"use acme::{self, Other};", "fn main() {", "    acme::run(Kdf::new(1));", "}"}
	frag := rustFactsFrag(src,
		[]graphfrag.GraphFragmentImport{
			{Line: 1, Module: "acme", Name: "self", StartCol: 1, EndCol: 24, Text: "acme::{self, Other}"},
			{Line: 1, Module: "acme", Name: "Other", StartCol: 1, EndCol: 24, Text: "acme::{self, Other}"},
		},
		[]graphfrag.GraphFragmentItem{{Line: 2, StartCol: 1, EndCol: 2, EndLine: 4, Kind: "fn", Name: "main"}},
		rustSrcCall{line: 3, text: "acme::run(Kdf::new(1))", method: "run"},
		rustSrcCall{line: 3, text: "Kdf::new(1)", method: "new"})
	found, stats := rustMatchRules(t, map[string]string{
		"kdf": "patterns:\n- pattern: Kdf::new(...)\n- pattern-not-inside: zeta::Other::wrap(...)",
	}, frag)
	if got, want := rustFoundLines(found), []string{"kdf@3"}; !slices.Equal(got, want) {
		t.Errorf("found %v, want %v (undecided %v)", got, want, stats.Undecided)
	}
}

// A type alias pattern unifies with the aliased type as written: every
// segment of a path, a leading `::`, a qualified self, the generics on each
// segment, a tuple; a metavariable binds the written type.
func TestUnifyWrittenType(t *testing.T) {
	read := func(text string, pattern bool) RustType {
		t.Helper()
		toks, err := lexRust(text)
		if err != nil {
			t.Fatal(err)
		}
		p := &rustParser{toks: toks, pattern: pattern}
		ty, err := p.parseType()
		if err != nil || !p.eof() {
			t.Fatalf("%s: %v", text, err)
		}
		return ty
	}
	for _, tc := range []struct {
		pattern, written, binds string // binds: $C's text, "-" for no match
	}{
		{"acme::Mode<$C>", "acme::Mode<a::b::Blk128>", "a::b::Blk128"},
		{"acme::Mode<$C>", "acme :: Mode < Blk128 >", "Blk128"},
		{"acme::Mode<$C>", "Mode<Blk128>", "-"},
		{"Mode<$C>", "acme::Mode<Blk128>", "-"},
		{"acme::Mode<$C>", "other::Mode<Blk128>", "-"},
		{"acme::Mode<$C>", "::acme::Mode<Blk128>", "-"},
		{"::acme::Mode<$C>", "::acme::Mode<Blk128>", "Blk128"},
		{"acme::Mode", "acme::Mode<Blk128>", "-"},
		{"acme::Mode<$C>", "acme::Mode<Blk128, N12>", "-"},
		{"$M::Mode<$C>", "acme::Mode<Wrap<u8>>", "Wrap<u8>"},
		{"acme::Mode<($C, u8)>", "acme::Mode<(Blk128, u8)>", "Blk128"},
		{"acme::Mode<[u8; 16], $C>", "acme::Mode<[u8; 16], Blk128>", "Blk128"},
		{"acme::Mode<[u8; 32], $C>", "acme::Mode<[u8; 16], Blk128>", "-"},
		{"<$C as acme::Tr>::Out", "<Blk128 as acme::Tr>::Out", "Blk128"},
		{"<$C as acme::Tr>::Out", "<Blk128 as Tr>::Out", "-"},
	} {
		got := "-"
		unifyWrittenType(read(tc.pattern, true), read(tc.written, false), rustEnv{}, func(env rustEnv) bool {
			got, _ = env.vars.get("$C")
			return true
		})
		if got != tc.binds {
			t.Errorf("%s on %s: $C = %q, want %q", tc.pattern, tc.written, got, tc.binds)
		}
	}
}
