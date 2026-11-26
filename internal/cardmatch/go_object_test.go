// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"path/filepath"
	"slices"
	"testing"
)

var goObjectDir = filepath.Join("testdata", "go_object")

// TestGoObjectFlowMatchesAsOpenGrep pins Go taint rules whose sources are
// objects to what OpenGrep 1.33.1 --taint-intrafile reports for invented
// rules on invented files (go-port audit T4/T7). A factory call's object
// reaches the sink's receiver through a local, a chained call, a parameter
// a caller of the same file fills, a call it flows through, a local copied
// from another (`u := t`) and a field a composite literal fills (`h.Thing`,
// also through a nested literal); also when a reassignment (of the local,
// or of a field's local) or a field store sits in a branch the sink may not
// have come through (reach.go), or in an if header, which OpenGrep's taint
// does not scope to the if; not through a `:=` in a nested block, which
// declares another variable; not after
// the local is assigned again in the sink's own block, a field store in it
// overwrites the field, nor from a call no source matches. A
// rule with propagators compiles without them and reports the same places.
// A factory written after an import clause names that import's package
// (`example.com/acme/v2`). A typed metavariable source holds any value of
// its type; a composite literal source a local it makes and what a function
// of the same file returns as one, not a parameter of the type no caller
// passes one for. A caller's literal names the rule's
// import through the package's own name (`acme` at example.com/go-acme/v4),
// not through an alias (alias.go).
func TestGoObjectFlowMatchesAsOpenGrep(t *testing.T) {
	assets, frag, want := rustFixtureAt(t, goObjectDir)
	found, _ := assets.mustMatch(t, frag)
	got := map[string]map[rustPinKey]bool{}
	for _, f := range found {
		if !f.Taint {
			t.Errorf("%s at %s:%d: not a taint finding", f.RuleID, f.File, f.Line)
		}
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[rustPinKey]bool{}
		}
		got[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = true
	}
	for _, id := range []string{"object", "object-prop", "imported", "typed", "composite", "composite-imported", "arg"} {
		exp := map[rustPinKey]bool{}
		for _, h := range want[id] {
			exp[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = true
		}
		if g, w := rustPinKeys(got[id]), rustPinKeys(exp); !slices.Equal(g, w) {
			t.Errorf("%s\n got %v\nwant %v", id, g, w)
		}
	}
}

// The propagators are recorded as a dropped clause; a sanitizer still skips.
func TestGoObjectFlowCompiles(t *testing.T) {
	rules, err := ExportRules(goObjectDir)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range rules {
		status[r.ID] = r.Status + " " + r.Reason
		if r.ID == "object-prop" && !slices.Contains(r.DroppedClauses, "taint propagators") {
			t.Errorf("object-prop: dropped %v, want taint propagators", r.DroppedClauses)
		}
	}
	for id, want := range map[string]string{
		"object":             "compiled ",
		"object-prop":        "compiled ",
		"imported":           "compiled ",
		"typed":              "compiled ",
		"composite":          "compiled ",
		"composite-imported": "compiled ",
		"arg":                "compiled ",
	} {
		if status[id] != want {
			t.Errorf("%s: %q, want %q", id, status[id], want)
		}
	}
}
