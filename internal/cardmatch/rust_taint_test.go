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
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var rustTaintDir = filepath.Join("testdata", "rust_taint")

// TestRustTaintMatchesAsOpenGrep pins Rust taint rules to what OpenGrep
// 1.33.1 --taint-intrafile reports for invented rules on invented files:
// value sources reached through a literal, a const, a let chain, a
// reassigned let and a parameter a caller of the same file fills, and object
// sources reached through a local, a chained call, an argument and a
// parameter; not through a caller in another file, nor through a local a
// later let binds from a parameter, a field or a call of no source
// (rebind.rs).
func TestRustTaintMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, rustTaintDir)
	fr := newFrag(frag)
	fr.ResolveParams = true
	found, stats := matchRustStats(assets, fr)
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	got := map[string]map[rustPinKey]string{}
	for _, f := range found {
		if !f.Taint || f.Value == nil {
			t.Errorf("%s at %d: not reported as a taint finding", f.RuleID, f.Line)
		}
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]string{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = rustTokens(f.MetadataFields()["algorithmName"].(string))
	}
	for _, id := range []string{"value", "object"} {
		exp := map[rustPinKey][]string{}
		for _, h := range want[id] {
			k := rustPinKey{h.File, h.Line, h.Col, h.EndCol}
			// crypto-finder fills a string literal's binding without its quotes.
			exp[k] = append(exp[k], strings.ReplaceAll(rustTokens(rustName(assets, id, h)), `"`, ""))
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
	if ids := slices.Sorted(maps.Keys(got)); !slices.Equal(ids, []string{"object", "value"}) {
		t.Errorf("rules found %v, want object and value", ids)
	}
}

// How each value reaches its sink: a parameter's value is the caller's, and
// a function only another file calls is not followed into.
func TestRustTaintValueHow(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, rustTaintDir)
	fr := newFrag(frag)
	fr.ResolveParams = true
	found, _ := matchRustStats(assets, fr)
	how := map[int]string{}
	for _, f := range found {
		if f.RuleID == "value" && f.File == "src/main.rs" {
			how[f.Line] = f.How + " " + *f.Value
		}
	}
	for line, want := range map[int]string{
		5:  `direct "AES-128-GCM"`,
		6:  `resolved "AES-256-GCM"`, // the const ALG
		10: `resolved "AES-192-GCM"`, // let b = a; let a = "..."
		13: `resolved "AES-128-CBC"`, // a let assigned again
		18: `param "AES-256-CBC"`,    // wrap's caller in the same file
	} {
		if how[line] != want {
			t.Errorf("line %d: %q, want %q", line, how[line], want)
		}
	}
	if _, ok := how[21]; ok {
		t.Errorf("line 21: exported is called from other.rs only, OpenGrep does not follow it")
	}
}

// A taint rule with a sanitizer is skipped with its reason; the others compile.
func TestRustTaintCompiles(t *testing.T) {
	rules, err := ExportRules(rustTaintDir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		want := "compiled"
		if r.ID == "sanitized" {
			want = "skipped"
		}
		if r.Status != want || !r.Taint {
			t.Errorf("%s: %s %q taint=%v, want %s", r.ID, r.Status, r.Reason, r.Taint, want)
		}
		if r.ID == "sanitized" && r.Reason != string(skipRustSanitizers) {
			t.Errorf("sanitized: reason %q, want %q", r.Reason, skipRustSanitizers)
		}
	}
}
