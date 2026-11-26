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
	"testing"
)

// rustOpsOnlyOpenGrep and rustOpsOnlyCards are the known differences of the
// rust_ops fixture, by rule and place. OpenGrep reports a parenthesized
// binary expression with its parentheses (ops.rs:9), where reach's span is
// the expression inside them: same line, other columns. reach lists a binary
// expression in a macro's arguments (ops.rs:15), which OpenGrep does not
// read. Two binary expressions starting at one column (`s * base * p`,
// ops.rs:8) are one finding, as two calls there would be: the outer one.
var (
	rustOpsOnlyOpenGrep = map[string][]rustPinKey{
		"mul": {{"src/ops.rs", 8, 13, 21}, {"src/ops.rs", 9, 13, 23}},
	}
	rustOpsOnlyCards = map[string][]rustPinKey{
		"mul": {{"src/ops.rs", 9, 14, 22}, {"src/ops.rs", 15, 16, 24}},
	}
	// rustOpsWritten are the bindings OpenGrep prints as their abstract
	// content but binds, and its regexes read, as written (rule mulwritten
	// pins it): `&mut s` printed `&s`.
	rustOpsWritten = map[string]map[rustPinKey]string{
		"mul": {{"src/ops.rs", 17, 13, 24}: "MUL mut s BY p"},
	}
)

// TestRustOpsAsOpenGrep pins binary expression positives, sequence contexts
// that end in one, typed fn parameter contexts and reference types to what
// OpenGrep 1.33.1 reports for invented rules on invented files
// (testdata/rust_ops): same places and the metadata filled from the
// bindings, but for the differences above.
func TestRustOpsAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, filepath.Join("testdata", "rust_ops"))
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 0 || len(stats.Undecided) != 0 || stats.UnreadableSites != 0 {
		t.Fatalf("stats = %+v, want none held, undecided or unreadable", stats)
	}
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
			if slices.Contains(rustOpsOnlyOpenGrep[id], k) {
				continue
			}
			md := rustMetadata(assets, id, h)
			if name, ok := rustOpsWritten[id][k]; ok {
				md["algorithmName"] = name
			}
			exp[k] = append(exp[k], md)
		}
		for _, k := range rustOpsOnlyCards[id] {
			if _, ok := got[id][k]; !ok {
				t.Errorf("%s: no finding at %v, a known cards-only place", id, k)
			}
			delete(got[id], k)
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

// On a fragment older than graph-fragment-1.30, which lists no binary
// expression and no fn parameter, the entries that read them are held, never
// approximated.
func TestRustOpsHeldOnOlderFragment(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, filepath.Join("testdata", "rust_ops"))
	frag.SchemaVersion = "graph-fragment-1.29"
	frag.BinaryExprs = nil
	found, stats := matchRustStats(assets, newFrag(frag))
	// mul, refmul, sub, add, mulpath, mulwritten and mulafter read binary
	// expressions as their positive, seq and notseq and one branch of
	// seqdeep as the end of a sequence; ptype, ptyperef, ptypepath, pref,
	// pmut, powned, prefvar, pgen, phead, pheadre, pone, pany, pnot and
	// pnotref read parameters.
	if stats.HeldBy[holdBinaries] != 10 || stats.HeldBy[holdParams] != 14 {
		t.Errorf("held by %v, want 10 for binary_exprs and 14 for params", stats.HeldBy)
	}
	for _, f := range found {
		switch f.RuleID {
		case "deep", "argref", "letref", "letplain", "seqdeep":
		default:
			t.Errorf("%s found at %s:%d on a 1.29 fragment", f.RuleID, f.File, f.Line)
		}
	}
}

func TestRustWrittenTypeBoundSkipsArrow(t *testing.T) {
	for written, want := range map[string]string{
		"acme::Key":                     "Key",
		"Box<dyn Fn() -> acme::Out>":    "Box<dyn Fn() -> acme::Out>",
		"acme::Wrap<fn() -> acme::Out>": "Wrap<fn() -> acme::Out>",
	} {
		typ, ok := readRustType(written)
		if !ok {
			t.Fatalf("readRustType(%q) failed", written)
		}
		if got := rustWrittenTypeBound(written, typ); got != want {
			t.Errorf("rustWrittenTypeBound(%q) = %q, want %q", written, got, want)
		}
	}
}
