// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bellman and the groth16 crate are the same proving system by the same
// authors: bellman exposes it under `bellman::groth16`, groth16 exposes the
// identical function names at its own crate root. A contract keyed on the wrong
// one resolves silently and mislabels the crate rather than failing, so assert
// the exact key, arity, owning library, role and return type for both.
func TestLoadEmbeddedRustIncludesBellmanContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
		ret    string
	}{
		{"bellman::groth16.generate_random_parameters", 2, "bellman", "factory", "core::result::Result"},
		{"bellman::groth16.generate_parameters", 8, "bellman", "factory", "core::result::Result"},
		{"bellman::groth16.create_random_proof", 3, "bellman", "operation", "core::result::Result"},
		{"bellman::groth16.create_proof", 4, "bellman", "operation", "core::result::Result"},
		{"bellman::groth16.prepare_verifying_key", 1, "bellman", "factory", "bellman::groth16::PreparedVerifyingKey"},
		{"bellman::groth16.verify_proof", 3, "bellman", "operation", "core::result::Result"},

		{"groth16.generate_random_parameters", 2, "groth16", "factory", "core::result::Result"},
		{"groth16.create_random_proof", 3, "groth16", "operation", "core::result::Result"},
		{"groth16.prepare_verifying_key", 1, "groth16", "factory", "groth16::PreparedVerifyingKey"},
		{"groth16.verify_proof", 3, "groth16", "operation", "core::result::Result"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		c := got[0]
		if c.SourceLibrary != tc.lib {
			t.Errorf("%s: library = %q, want %q", tc.method, c.SourceLibrary, tc.lib)
		}
		if c.Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, c.Role, tc.role)
		}
		if c.Return.Type != tc.ret {
			t.Errorf("%s: return = %q, want %q", tc.method, c.Return.Type, tc.ret)
		}
	}
}

// THE KEY SHAPE IS THE WHOLE POINT OF THIS TEST.
//
// These are FREE FUNCTIONS, not methods. The call-site FQN the parser emits is
// `bellman::groth16.generate_random_parameters` -- module path joined with
// "::", then a DOT before the function name. The Rust key normalisation only
// rewrites the separator in front of a receiver TYPE, and returns keys with
// fewer than two dots unchanged, so a contract authored as
// `bellman::groth16::generate_random_parameters` never resolves against the key
// the parser actually produces. That mistake was made first here, and the
// exported call graph showed `verify_proof(?, ?, ?)` with no parameter types --
// indistinguishable from having no contract at all.
func TestBellmanContractsResolveFromEmittedCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// Exactly the keys observed in an exported call graph.
	tests := []struct {
		callSiteKey string
		arity       int
		wantLib     string
	}{
		{"bellman::groth16.generate_random_parameters", 2, "bellman"},
		{"bellman::groth16.generate_random_parameters", -1, "bellman"},
		{"bellman::groth16.verify_proof", 3, "bellman"},
		{"groth16.verify_proof", 3, "groth16"},
		{"groth16.verify_proof", -1, "groth16"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.callSiteKey, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for an emitted call-site key", tc.callSiteKey, tc.arity)
			continue
		}
		if got[0].SourceLibrary != tc.wantLib {
			t.Errorf("%s: library = %q, want %q", tc.callSiteKey, got[0].SourceLibrary, tc.wantLib)
		}
	}
}

// `bellman::groth16` contains the substring `groth16`. Assert the two crates
// stay distinct at the contract layer, not only in the detection rules: one
// consumer call site must never be attributable to both.
func TestBellmanAndGroth16ContractsDoNotCollide(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	bellman := kb.ContractsFor("bellman::groth16.verify_proof", 3)
	groth := kb.ContractsFor("groth16.verify_proof", 3)
	if len(bellman) == 0 || len(groth) == 0 {
		t.Fatalf("expected both keys to resolve; bellman=%d groth16=%d", len(bellman), len(groth))
	}
	if bellman[0].SourceLibrary == groth[0].SourceLibrary {
		t.Errorf("both keys resolved to %q: the crates collapsed", bellman[0].SourceLibrary)
	}
}

// A contract that resolves but declares no parameter types still exports
// "verify_proof(?, ?, ?)", which reads exactly like a missing contract.
func TestBellmanContractsDeclareParameterTypes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   []string
	}{
		{"bellman::groth16.generate_random_parameters", 2, []string{"bellman::Circuit", "&mut rand_core::RngCore"}},
		{"bellman::groth16.verify_proof", 3, []string{"&bellman::groth16::PreparedVerifyingKey", "&bellman::groth16::Proof", "&[E::Fr]"}},
		{"groth16.verify_proof", 3, []string{"&groth16::PreparedVerifyingKey", "&groth16::Proof", "&[E::Fr]"}},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		pt := got[0].ParameterTypes
		if len(pt) != len(tc.want) {
			t.Errorf("%s: parameter_types = %v, want %v", tc.method, pt, tc.want)
			continue
		}
		for i := range pt {
			if pt[i] != tc.want[i] {
				t.Errorf("%s: parameter_types[%d] = %q, want %q", tc.method, i, pt[i], tc.want[i])
			}
		}
	}
}
