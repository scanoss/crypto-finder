// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The three arkworks crates ship together and reach each other's APIs, so a
// contract keyed on the wrong crate resolves silently and mislabels the
// receiver rather than failing. Assert the exact key, the owning library, the
// arity, the role and the return type for each.
//
// The pairing methods are reached through a concrete curve type in
// ark-bls12-381 and through the trait in ark-ec. Both keys must exist and must
// report DIFFERENT libraries: that is what keeps one consumer call site from
// being counted against two crates.
func TestLoadEmbeddedRustIncludesArkworksContracts(t *testing.T) {
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
		// ark-bls12-381: the concrete curve. `product_of_pairings` is the
		// 0.2/0.3-era spelling that `multi_pairing` replaced in 0.4.0.
		{"ark_bls12_381::Bls12_381.pairing", 2, "ark-bls12-381", "operation", "ark_ec::pairing::PairingOutput"},
		{"ark_bls12_381::Bls12_381.multi_pairing", 2, "ark-bls12-381", "operation", "ark_ec::pairing::PairingOutput"},
		{"ark_bls12_381::Bls12_381.product_of_pairings", 1, "ark-bls12-381", "operation", "ark_bls12_381::Fq12"},
		{"ark_bls12_381::Bls12_381.final_exponentiation", 1, "ark-bls12-381", "operation", "core::option::Option"},
		{"ark_bls12_381::Fr.rand", 1, "ark-bls12-381", "factory", "ark_bls12_381::Fr"},
		{"ark_bls12_381::G1Affine.generator", 0, "ark-bls12-381", "factory", "ark_bls12_381::G1Affine"},
		{"ark_bls12_381::G2Projective.rand", 1, "ark-bls12-381", "factory", "ark_bls12_381::G2Projective"},

		// ark-ec: the generic traits, both eras. `PairingEngine` sits at the
		// crate root in 0.2/0.3; `pairing::Pairing` gains a module segment in
		// 0.4.0, so these are different keys and not spellings of one.
		{"ark_ec::pairing::Pairing.pairing", 2, "ark-ec", "operation", "ark_ec::pairing::PairingOutput"},
		{"ark_ec::pairing::Pairing.multi_pairing", 2, "ark-ec", "operation", "ark_ec::pairing::PairingOutput"},
		{"ark_ec::PairingEngine.pairing", 2, "ark-ec", "operation", "ark_ec::PairingEngine::Fqk"},
		{"ark_ec::PairingEngine.product_of_pairings", 1, "ark-ec", "operation", "ark_ec::PairingEngine::Fqk"},
		{"ark_ec::hashing::HashToCurve.hash_to_curve", 1, "ark-ec", "operation", "core::result::Result"},

		// ark-ff: hash-to-field (0.4.0+) and uniform sampling (whole range).
		{"ark_ff::field_hashers::DefaultFieldHasher.new", 1, "ark-ff", "factory", "ark_ff::field_hashers::DefaultFieldHasher"},
		{"ark_ff::field_hashers::HashToField.hash_to_field", 1, "ark-ff", "operation", "ark_ff::Field"},
		{"ark_ff::Field.from_random_bytes", 1, "ark-ff", "factory", "core::option::Option"},
		{"ark_ff::PrimeField.from_random_bytes", 1, "ark-ff", "factory", "core::option::Option"},
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

// A call-site FQN joins every segment with "." while the KB is authored with
// Rust's "::" module separator, and Rust callees carry no encoded arity so
// callers pass -1. Both shapes, and the unknown arity, must resolve — otherwise
// the contract is present in the file and absent in practice, which is the
// failure this family's exported call graph showed as "pairing(?, ?)".
func TestArkworksContractsResolveFromCallSiteKeyShapes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		callSiteKey string
		arity       int
		wantLib     string
	}{
		{"ark_bls12_381.Bls12_381.pairing", 2, "ark-bls12-381"},
		{"ark_bls12_381.Bls12_381.pairing", -1, "ark-bls12-381"},
		{"ark_ec::pairing.Pairing.pairing", 2, "ark-ec"},
		{"ark_ec::pairing.Pairing.pairing", -1, "ark-ec"},
		{"ark_ff::field_hashers.DefaultFieldHasher.new", 1, "ark-ff"},
		{"ark_ff::field_hashers.DefaultFieldHasher.new", -1, "ark-ff"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.callSiteKey, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.callSiteKey, tc.arity)
			continue
		}
		if got[0].SourceLibrary != tc.wantLib {
			t.Errorf("%s: library = %q, want %q", tc.callSiteKey, got[0].SourceLibrary, tc.wantLib)
		}
	}
}

// The exported canonical_signature is only as good as parameter_types: a
// contract that resolves but declares none still exports "pairing(?, ?)", which
// reads exactly like a missing contract. Pin the parameter types for the call
// shapes a consumer writes.
func TestArkworksContractsDeclareParameterTypes(t *testing.T) {
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
		{"ark_bls12_381::Bls12_381.pairing", 2, []string{"ark_bls12_381::G1Affine", "ark_bls12_381::G2Affine"}},
		{"ark_bls12_381::Fr.rand", 1, []string{"&mut rand::Rng"}},
		{"ark_ec::pairing::Pairing.pairing", 2, []string{"ark_ec::pairing::Pairing::G1Prepared", "ark_ec::pairing::Pairing::G2Prepared"}},
		{"ark_ff::field_hashers::DefaultFieldHasher.new", 1, []string{"&[u8]"}},
		{"ark_ff::Field.from_random_bytes", 1, []string{"&[u8]"}},
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
