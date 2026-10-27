// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The ML-KEM and ML-DSA surface of aws-lc-rs is keyed on three module paths
// that are alive in different releases: `aws_lc_rs::kem` (1.6.0+),
// `aws_lc_rs::unstable::signature` (1.13.0 - 1.17.x, deprecated aliases in
// 1.18.x) and `aws_lc_rs::signature` (1.18.0+). A contract authored on the
// wrong path or arity loads cleanly and joins nothing, so assert the exact
// key, arity, role, return type and the algorithm contribution for each era.
func TestLoadEmbeddedRustIncludesAwsLcPqcContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method   string
		arity    int
		role     string
		ret      string
		property string
	}{
		// ML-KEM, stable module.
		{"aws_lc_rs::kem::DecapsulationKey.generate", 1, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::kem::DecapsulationKey.new", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::kem::DecapsulationKey.encapsulation_key", 0, "output", "core::result::Result", ""},
		{"aws_lc_rs::kem::DecapsulationKey.decapsulate", 1, "operation", "core::result::Result", "ciphertext"},
		{"aws_lc_rs::kem::DecapsulationKey.algorithm", 0, "output", "&'static aws_lc_rs::kem::Algorithm", ""},
		{"aws_lc_rs::kem::EncapsulationKey.new", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::kem::EncapsulationKey.encapsulate", 0, "operation", "core::result::Result", ""},
		{"aws_lc_rs::kem::EncapsulationKey.key_bytes", 0, "output", "core::result::Result", ""},

		// Kyber R3 era selector, 1.6.0 - 1.12.x.
		{"aws_lc_rs::unstable::kem.get_algorithm", 1, "factory", "core::option::Option", "algorithm"},

		// ML-DSA era 1, unstable spelling.
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.generate", 1, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.from_pkcs8", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.sign", 2, "operation", "core::result::Result", ""},
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.to_pkcs8", 0, "output", "core::result::Result", ""},
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.public_key", 0, "output", "&aws_lc_rs::unstable::signature::PqdsaPublicKey", ""},

		// ML-DSA era 2, stable spelling.
		{"aws_lc_rs::signature::PqdsaKeyPair.generate", 1, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::signature::PqdsaKeyPair.from_raw_private_key", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::signature::PqdsaKeyPair.from_seed", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::signature::PqdsaKeyPair.sign", 2, "operation", "core::result::Result", ""},
		{"aws_lc_rs::signature::PqdsaKeyPair.to_pkcs8v1", 0, "output", "core::result::Result", ""},
		{"aws_lc_rs::signature::PqdsaKeyPair.public_key", 0, "output", "&aws_lc_rs::signature::PqdsaPublicKey", ""},

		// Verification path shared by every signature algorithm.
		{"aws_lc_rs::signature::UnparsedPublicKey.new", 2, "factory", "aws_lc_rs::signature::UnparsedPublicKey", "algorithm"},
		{"aws_lc_rs::signature::UnparsedPublicKey.verify", 2, "operation", "core::result::Result", ""},
		{"aws_lc_rs::signature::ParsedPublicKey.new", 2, "factory", "core::result::Result", "algorithm"},
		{"aws_lc_rs::signature::ParsedPublicKey.verify_sig", 2, "operation", "core::result::Result", ""},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			got := kb.ContractsFor(tc.method, tc.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tc.method, tc.arity, len(got))
			}
			c := got[0]
			if c.SourceLibrary != "aws-lc-rs" {
				t.Errorf("library = %q, want aws-lc-rs", c.SourceLibrary)
			}
			if c.Role != tc.role {
				t.Errorf("role = %q, want %q", c.Role, tc.role)
			}
			if c.Return.Type != tc.ret || c.Return.Confidence != "high" {
				t.Errorf("return = %q/%s, want %q/high", c.Return.Type, c.Return.Confidence, tc.ret)
			}
			if len(c.ParameterTypes) > 0 && len(c.ParameterTypes) != tc.arity {
				t.Errorf("parameter_types = %v, want %d entries", c.ParameterTypes, tc.arity)
			}
			if tc.property == "" {
				return
			}
			for _, p := range c.Parameters {
				if p.Contributes != nil && p.Contributes.Property == tc.property {
					return
				}
			}
			t.Errorf("parameters = %#v, want a contribution for %q", c.Parameters, tc.property)
		})
	}
}

// The algorithm argument is the `&'static` constant a consumer names
// (`&kem::ML_KEM_768`, `&signature::ML_DSA_65_SIGNING`), so it must be
// operation-determining at index 0 with derivation argument_value: that is the
// position the rules read the parameter set from.
func TestAwsLcPqcAlgorithmArgumentIsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, key := range []struct {
		method string
		arity  int
	}{
		{"aws_lc_rs::kem::DecapsulationKey.generate", 1},
		{"aws_lc_rs::kem::EncapsulationKey.new", 2},
		{"aws_lc_rs::unstable::kem.get_algorithm", 1},
		{"aws_lc_rs::unstable::signature::PqdsaKeyPair.generate", 1},
		{"aws_lc_rs::signature::PqdsaKeyPair.generate", 1},
		{"aws_lc_rs::signature::UnparsedPublicKey.new", 2},
	} {
		got := kb.ContractsFor(key.method, key.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", key.method, key.arity, len(got))
		}
		found := false
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == 0 && p.Role == "operation-determining" &&
				p.Contributes != nil && p.Contributes.Property == "algorithm" &&
				p.Contributes.Derivation == "argument_value" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: parameters = %#v, want index 0 operation-determining algorithm/argument_value", key.method, got[0].Parameters)
		}
	}
}

// The keys must resolve from the shapes the Rust parser emits: a method on a
// type in a nested module carries two dots
// (`aws_lc_rs::unstable::signature.PqdsaKeyPair.generate`) and the key
// normalisation rewrites the second-to-last one; a free function in a nested
// module (`aws_lc_rs::unstable::kem.get_algorithm`) carries one and is left
// unchanged. Both forms are exercised, plus the arity-agnostic lookup.
func TestAwsLcPqcContractsResolveFromEmittedCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		callSiteKey string
		arity       int
	}{
		{"aws_lc_rs::kem.DecapsulationKey.generate", 1},
		{"aws_lc_rs::kem.DecapsulationKey.generate", -1},
		{"aws_lc_rs::kem.EncapsulationKey.encapsulate", 0},
		{"aws_lc_rs::unstable::kem.get_algorithm", 1},
		{"aws_lc_rs::unstable::signature.PqdsaKeyPair.generate", 1},
		{"aws_lc_rs::unstable::signature.PqdsaKeyPair.generate", -1},
		{"aws_lc_rs::signature.PqdsaKeyPair.generate", 1},
		{"aws_lc_rs::signature.UnparsedPublicKey.verify", 2},
	} {
		got := kb.ContractsFor(tc.callSiteKey, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for an emitted call-site key", tc.callSiteKey, tc.arity)
			continue
		}
		if got[0].SourceLibrary != "aws-lc-rs" {
			t.Errorf("%s: library = %q, want aws-lc-rs", tc.callSiteKey, got[0].SourceLibrary)
		}
	}
}

// Negative examples: a wrong arity, a method spelled as a module-level free
// function, and the private `aws_lc_rs::pqdsa` path (`mod pqdsa;`, never
// `pub`) must all resolve to nothing. A contract that answered any of them
// would attribute calls that cannot exist in consumer code.
func TestAwsLcPqcContractsRejectWrongShapes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, bogus := range []struct {
		method string
		arity  int
		why    string
	}{
		{"aws_lc_rs::kem::DecapsulationKey.generate", 2, "generate takes one argument"},
		{"aws_lc_rs::kem.generate", 1, "generate is a method on DecapsulationKey, not a module function"},
		{"aws_lc_rs::pqdsa::PqdsaKeyPair.generate", 1, "the pqdsa module is private; the public path is signature::PqdsaKeyPair"},
		{"aws_lc_rs::pqdsa::key_pair::PqdsaKeyPair.generate", 1, "the pqdsa module is private"},
		{"aws_lc_rs::unstable::kem::DecapsulationKey.generate", 1, "unstable::kem never re-exported the key types"},
		{"aws_lc_rs::signature::PqdsaKeyPair.to_pkcs8", 0, "to_pkcs8 is the era-1 name; era 2 is to_pkcs8v1"},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %#v, want none: %s", bogus.method, bogus.arity, got, bogus.why)
		}
	}
}
