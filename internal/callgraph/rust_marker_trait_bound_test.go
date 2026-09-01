// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A zero-method marker trait (`Sized`, `Send`, `Sync`, `Copy`, `Eq`) can never
// own a called method. Taking whichever bound came first in the source text
// fabricated `std.Sized.update` for a real `Digest::update` call whenever the
// marker happened to be written first -- an identity that names a real
// standard-library trait and a plausible-looking method neither one declares,
// order-dependently: `T: Digest + Sized` resolved correctly by accident,
// `T: Sized + Digest` did not.
func TestRustParser_MarkerTraitBoundNeverProvidesAnIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		bounds string
	}{
		{"marker written first", "Sized + Digest"},
		{"marker written last", "Digest + Sized"},
		{"two markers around the real trait", "Send + Digest + Sync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := "use digest::Digest;\nfn f<T: " + tc.bounds + ">(x: &mut T, data: &[u8]) {\n    x.update(data);\n}\n"
			got := parseRustCalleeFQNs(t, src)
			asserted := 0
			for raw, key := range got {
				if !strings.HasSuffix(raw, "update") {
					continue
				}
				asserted++
				if key != "digest.Digest.update" {
					t.Errorf("%s resolved to %q, want %q", raw, key, "digest.Digest.update")
				}
			}
			if asserted == 0 {
				t.Fatalf("no update call parsed; got %v", got)
			}
		})
	}
}

// A generic parameter bound ONLY to zero-method marker traits has no method
// any of them could own. Falling back to the first one anyway fabricated
// `std.Sized.foo` -- `Sized` declares no `foo`, or any method at all -- so the
// call must carry no type, the same degradation an unbound parameter already
// gets, rather than invent one.
func TestRustParser_AllMarkerBoundsCarryNoType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		bounds string
	}{
		{"single marker", "Sized"},
		{"multiple markers", "Send + Sync + Copy + Eq"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := "fn f<T: " + tc.bounds + ">(x: &mut T) {\n    x.foo();\n}\n"
			got := parseRustCalleeFQNs(t, src)
			asserted := 0
			for raw, key := range got {
				if !strings.HasSuffix(raw, "foo") {
					continue
				}
				asserted++
				if key != "app.foo" {
					t.Errorf("%s resolved to %q, want the untyped fallback %q", raw, key, "app.foo")
				}
			}
			if asserted == 0 {
				t.Fatalf("no foo call parsed; got %v", got)
			}
		})
	}
}
