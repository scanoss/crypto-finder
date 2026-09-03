// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"os"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// balloon publishes two crate-root free functions and, from 0.0.13, a generic
// `Balloon<D>` struct. The two shapes emit DIFFERENT key forms and getting them
// the wrong way round produces a contract nothing joins to — which looks
// exactly like having no contract.
//
// Read off an exported call graph, not written from the API: the free functions
// emit one dot (`balloon.balloon`) and are authored with a dot; the struct's
// methods emit two (`balloon.Balloon.new`) and are authored `balloon::Balloon.new`.
func TestLoadEmbeddedRustIncludesBalloonContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		role   string
	}{
		// Arities exclude the receiver and are read from the declarations:
		// balloon(pass, salt, space, time, delta) is 5 and
		// verify(val, pass, salt, space, time, delta) is 6 (src/lib.rs:205,:238).
		{"balloon.balloon", 5, "operation"},
		{"balloon.verify", 6, "operation"},
		{"balloon.compare_ct", 2, "output"},
		{"balloon::Balloon.new", 3, "factory"},
		{"balloon::Balloon.reconfigure", 3, "config"},
		{"balloon::Balloon.process", 2, "operation"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): %d contracts, want exactly 1", tc.method, tc.arity, len(got))
		}
		if got[0].SourceLibrary != "balloon" {
			t.Errorf("%s: library = %q, want balloon", tc.method, got[0].SourceLibrary)
		}
		if got[0].Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, got[0].Role, tc.role)
		}
		if len(got[0].ParameterTypes) != tc.arity {
			t.Errorf("%s: %d parameter_types, want %d", tc.method, len(got[0].ParameterTypes), tc.arity)
		}
	}
}

// The dot-joined call-site spelling the graph actually emits, and an unknown
// arity, must both resolve.
func TestBalloonEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"balloon.balloon",
		"balloon.verify",
		"balloon.compare_ct",
		"balloon.Balloon.new",
		"balloon.Balloon.process",
		"balloon.Balloon.reconfigure",
	} {
		if got := kb.ContractsFor(m, -1); len(got) == 0 {
			t.Errorf("ContractsFor(%q, -1): no contract for the emitted key", m)
		}
	}
}

// `return.type` is the resolution type a caller chains from; the full declared
// type belongs in `canonical_return_type`. Putting the wrapper in `return.type`
// hands `Result` back as the next receiver and produces `core::result.(Result).*`
// edges downstream.
func TestBalloonReturnTypesFollowTheKBConvention(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	checked := 0
	for _, ctrs := range kb.Contracts {
		for i := range ctrs {
			c := &ctrs[i]
			if c.SourceLibrary != "balloon" {
				continue
			}
			checked++
			if strings.HasPrefix(c.Return.Type, "core::result::Result") ||
				strings.HasPrefix(c.Return.Type, "core::option::Option") {
				t.Errorf("%s: return.type is the wrapper %q; it must be the type a "+
					"caller chains from, with the wrapper in canonical_return_type",
					c.Method, c.Return.Type)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no balloon contracts were checked")
	}
}

// `compare_ct` is typed so a DIRECT consumer call resolves, but it is NOT a
// Balloon operation and the rules deliberately stay silent on it. A contract
// entry carries a signature, not a cryptographic claim; this pins the exact
// role so a later author neither promotes it to an operation nor "fixes" the
// rules to match it.
func TestBalloonCompareCtIsTypedButNotAnOperation(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := kb.ContractsFor("balloon.compare_ct", 2)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(balloon.compare_ct, 2): %d contracts, want 1", len(got))
	}
	if got[0].Role != "output" {
		t.Errorf("compare_ct: role = %q, want output; it is a constant-time slice "+
			"comparison the crate borrowed from orion, not a Balloon operation",
			got[0].Role)
	}
}

// THE DECLARED SIGNATURES AND THE DECLARED ERA MOVE TOGETHER, and this test
// exists because they once did not. `verify` returns `Result<bool, Error>` at
// 0.0.13 (src/lib.rs:243) and only becomes `Result<(), Error>` at 0.0.14
// (:245), so declaring `()` while claiming `>=0.0.13` served a return type the
// range said was covered and the source said was wrong. `version_range` is
// never consulted at lookup, so nothing downstream catches that — a wrong
// bound is silent. Pinning the range next to the return types it licenses is
// the only place the pair can be checked.
//
// Changing any return type below means re-reading the crate source and moving
// the range with it. Widening the range means splitting `verify` into its own
// era file first; the other five entries are already correct at 0.0.13.
func TestBalloonSignaturesArePinnedToTheDeclaredEra(t *testing.T) {
	t.Parallel()

	const wantRange = ">=0.0.14,<0.1.0"

	data, err := os.ReadFile("rust/balloon.yaml")
	if err != nil {
		t.Fatalf("read balloon.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(balloon.yaml): %v", err)
	}
	if single.Library == nil {
		t.Fatal("balloon.yaml declares no library: block")
	}
	if single.Library.VersionRange != wantRange {
		t.Errorf("version_range = %q, want %q — the range must cover only versions "+
			"for which every declared signature below is true",
			single.Library.VersionRange, wantRange)
	}

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method    string
		arity     int
		ret       string
		canonical string
		params    []string
	}{
		{
			"balloon.balloon", 5,
			"blake3::Hash",
			"core::result::Result<blake3::Hash, balloon::Error>",
			[]string{"&[u8]", "&[u8]", "usize", "usize", "usize"},
		},
		{
			// The one that sets the era bound.
			"balloon.verify", 6,
			"()",
			"core::result::Result<(), balloon::Error>",
			[]string{"&blake3::Hash", "&[u8]", "&[u8]", "usize", "usize", "usize"},
		},
		{
			"balloon.compare_ct", 2,
			"balloon::Error",
			"core::option::Option<balloon::Error>",
			[]string{"&[u8]", "&[u8]"},
		},
		{
			"balloon::Balloon.new", 3,
			"balloon::Balloon", "",
			[]string{"usize", "usize", "usize"},
		},
		{
			"balloon::Balloon.reconfigure", 3,
			"()", "",
			[]string{"usize", "usize", "usize"},
		},
		{
			"balloon::Balloon.process", 2,
			"digest::generic_array::GenericArray", "",
			[]string{"&[u8]", "&[u8]"},
		},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): %d contracts, want 1", tc.method, tc.arity, len(got))
			continue
		}
		c := got[0]
		if c.Return.Type != tc.ret {
			t.Errorf("%s: return.type = %q, want %q", tc.method, c.Return.Type, tc.ret)
		}
		if c.CanonicalReturnType != tc.canonical {
			t.Errorf("%s: canonical_return_type = %q, want %q",
				tc.method, c.CanonicalReturnType, tc.canonical)
		}
		if strings.Join(c.ParameterTypes, ", ") != strings.Join(tc.params, ", ") {
			t.Errorf("%s: parameter_types = %v, want %v", tc.method, c.ParameterTypes, tc.params)
		}
	}
}
