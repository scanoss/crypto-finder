// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"path/filepath"
	"slices"
	"testing"
)

var goTaintDir = filepath.Join("testdata", "go_taint")

// TestGoTaintMatchesAsOpenGrep pins Go taint rules to what OpenGrep 1.33.1
// --taint-intrafile reports for an invented rule on invented files (go-port
// audit T3): a value source reached directly, through a local, through a
// parameter a caller of the same file fills (up to four calls deep), and
// through a call's result; not through a parameter no caller fills, nor
// through an object a source call returns (k.Use(), object flow is T4).
func TestGoTaintMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, goTaintDir)
	found, _ := assets.mustMatch(t, frag)
	got := map[rustPinKey]string{}
	vals := map[rustPinKey]string{}
	for _, f := range found {
		if f.RuleID != "value" || !f.Taint || f.Value == nil {
			t.Errorf("%s at %s:%d: not a value taint finding", f.RuleID, f.File, f.Line)
			continue
		}
		k := rustPinKey{f.File, f.Line, f.Col, f.EndCol}
		got[k] = f.How + " " + *f.Value
		vals[k] = *f.Value
	}
	exp := map[rustPinKey]string{}
	for _, h := range want["value"] {
		exp[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = h.Metavar["$K"]
	}
	if !slices.Equal(rustPinKeys(got), rustPinKeys(exp)) {
		t.Fatalf("\n got %v\nwant %v", rustPinKeys(got), rustPinKeys(exp))
	}
	for k, v := range exp {
		if vals[k] != v {
			t.Errorf("%v: value %s, OpenGrep binds $K to %s", k, vals[k], v)
		}
	}
	for k, how := range map[rustPinKey]string{
		{"src/main.go", 6, 2, 27}:   `direct "hardcoded-key"`,
		{"src/main.go", 11, 2, 13}:  `resolved "hardcoded-key"`, // m := "..."
		{"src/main.go", 15, 2, 13}:  `param "hardcoded-key"`,    // caller() fills k
		{"src/main.go", 23, 2, 34}:  `resolved "hardcoded-key"`, // wrapS("...")
		{"src/deep.go", 6, 21, 32}:  `param "hardcoded-key"`,    // two calls deep
		{"src/deep.go", 12, 21, 32}: `param "hardcoded-key"`,    // four calls deep
	} {
		if got[k] != how {
			t.Errorf("%v: %q, want %q", k, got[k], how)
		}
	}
}
