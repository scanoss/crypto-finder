// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestGoCallSourceMatchesAsOpenGrep pins a Go taint rule whose source is a
// call of no arguments its callee's metavariable-regex names (`$FUNC()`,
// `^(?<package>shapes)\.P(?<curve>224|256|384)$`) to what OpenGrep 1.33.1
// --taint-intrafile reports for an invented rule on invented files: the
// call written in any argument of the sink, through a local, a parameter a
// caller of the same file fills, and a call it is passed to; not a call the
// regex does not name. The regex's named groups fill the metadata.
func TestGoCallSourceMatchesAsOpenGrep(t *testing.T) {
	dir := filepath.Join("testdata", "go_call_source")
	assets, frag, want := rustFixtureAt(t, dir)
	found, _ := assets.mustMatch(t, frag)
	got := map[rustPinKey]string{}
	others := map[string]map[rustPinKey]bool{}
	for _, f := range found {
		if f.RuleID != "curve" {
			if others[f.RuleID] == nil {
				others[f.RuleID] = map[rustPinKey]bool{}
			}
			others[f.RuleID][rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = true
			continue
		}
		md := f.MetadataMap()
		got[rustPinKey{f.File, f.Line, f.Col, f.EndCol}] = md["algorithmName"].(string) + " " + md["curve"].(string)
	}
	exp := map[rustPinKey]string{}
	for _, h := range want["curve"] {
		exp[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = "ACME-P" + h.Metavar["$curve"] + " P" + h.Metavar["$curve"]
	}
	if g, w := rustPinKeys(got), rustPinKeys(exp); !slices.Equal(g, w) {
		t.Fatalf("\n got %v\nwant %v", g, w)
	}
	for k, v := range exp {
		if got[k] != v {
			t.Errorf("%v: metadata %q, want %q", k, got[k], v)
		}
	}
	// A prefix regex and an alternation with a `$` per branch match as
	// OpenGrep reads them on the callee.
	for _, id := range []string{"prefix", "branches"} {
		w := map[rustPinKey]bool{}
		for _, h := range want[id] {
			w[rustPinKey{h.File, h.Line, h.Col, h.EndCol}] = true
		}
		if g, wk := rustPinKeys(others[id]), rustPinKeys(w); !slices.Equal(g, wk) {
			t.Errorf("%s\n got %v\nwant %v", id, g, wk)
		}
	}
}

// goCallRegex reads a callee regex as OpenGrep's metavariable-regex does,
// matched from the callee's start: a prefix regex, an alternation with a `$`
// per branch, and a `$` inside a character class (go-port audit, review of
// #48). The text is a call of no arguments, never the bare callee.
func TestGoCallRegex(t *testing.T) {
	for _, c := range []struct {
		re, text string
		want     bool
	}{
		{`^(?<package>shapes)\.P`, "shapes.P256()", true},
		{`^(?<package>shapes)\.P`, "shapes.Q256()", false},
		{`^(?<package>shapes)\.P`, "shapes.P256", false},
		{`^shapes\.P256$|^shapes\.P384$`, "shapes.P256()", true},
		{`^shapes\.P256$|^shapes\.P384$`, "shapes.P384()", true},
		{`^shapes\.P256$|^shapes\.P384$`, "shapes.P2560()", false},
		{`^(?<package>elliptic)\.P(?<curve>224|256|384|521)$`, "elliptic.P256()", true},
		{`^(?<package>elliptic)\.P(?<curve>224|256|384|521)$`, "elliptic.P2560()", false},
		{`^x[$]y$`, "x$y()", true},
	} {
		if _, ok := reMatchFull(goCallRegex(c.re), c.text); ok != c.want {
			t.Errorf("%s on %s: %v", c.re, c.text, ok)
		}
	}
}
