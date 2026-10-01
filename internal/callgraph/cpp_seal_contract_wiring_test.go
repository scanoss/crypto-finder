// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The seal contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestSEALContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "seal/seal.h"

void flows(seal::KeyGenerator& kg, seal::Encryptor& enc, seal::Decryptor& dec, seal::EncryptionParameters& parms, int x) {
    kg.secret_key();
    kg.public_key();
    kg.create_public_key();
    kg.create_public_key(x);
    kg.create_relin_keys();
    kg.create_relin_keys(x);
    kg.create_galois_keys();
    kg.create_galois_keys(x);
    kg.create_galois_keys(x, x);
    kg.relin_keys();
    kg.galois_keys();
    kg.galois_keys(x);
    enc.set_public_key(x);
    enc.set_secret_key(x);
    enc.encrypt(x);
    enc.encrypt(x, x);
    enc.encrypt(x, x, x);
    enc.encrypt_symmetric(x);
    enc.encrypt_symmetric(x, x);
    enc.encrypt_symmetric(x, x, x);
    enc.encrypt_zero();
    enc.encrypt_zero(x);
    enc.encrypt_zero(x, x);
    enc.encrypt_zero(x, x, x);
    enc.encrypt_zero_symmetric();
    enc.encrypt_zero_symmetric(x);
    enc.encrypt_zero_symmetric(x, x);
    enc.encrypt_zero_symmetric(x, x, x);
    dec.decrypt(x, x);
    dec.invariant_noise_budget(x);
    parms.set_poly_modulus_degree(x);
    parms.set_coeff_modulus(x);
    parms.set_plain_modulus(x);
    enc.is_valid_for(x);
    parms.poly_modulus_degree();
    dec.pool();
}
`
	if err := os.WriteFile(filepath.Join(dir, "he.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"seal::KeyGenerator.secret_key#0":                      "output",
		"seal::KeyGenerator.public_key#0":                      "output",
		"seal::KeyGenerator.create_public_key#0":               "operation",
		"seal::KeyGenerator.create_public_key#1":               "operation",
		"seal::KeyGenerator.create_relin_keys#0":               "operation",
		"seal::KeyGenerator.create_relin_keys#1":               "operation",
		"seal::KeyGenerator.create_galois_keys#0":              "operation",
		"seal::KeyGenerator.create_galois_keys#1":              "operation",
		"seal::KeyGenerator.create_galois_keys#2":              "operation",
		"seal::KeyGenerator.relin_keys#0":                      "operation",
		"seal::KeyGenerator.galois_keys#0":                     "operation",
		"seal::KeyGenerator.galois_keys#1":                     "operation",
		"seal::Encryptor.set_public_key#1":                     "config",
		"seal::Encryptor.set_secret_key#1":                     "config",
		"seal::Encryptor.encrypt#1":                            "operation",
		"seal::Encryptor.encrypt#2":                            "operation",
		"seal::Encryptor.encrypt#3":                            "operation",
		"seal::Encryptor.encrypt_symmetric#1":                  "operation",
		"seal::Encryptor.encrypt_symmetric#2":                  "operation",
		"seal::Encryptor.encrypt_symmetric#3":                  "operation",
		"seal::Encryptor.encrypt_zero#0":                       "operation",
		"seal::Encryptor.encrypt_zero#1":                       "operation",
		"seal::Encryptor.encrypt_zero#2":                       "operation",
		"seal::Encryptor.encrypt_zero#3":                       "operation",
		"seal::Encryptor.encrypt_zero_symmetric#0":             "operation",
		"seal::Encryptor.encrypt_zero_symmetric#1":             "operation",
		"seal::Encryptor.encrypt_zero_symmetric#2":             "operation",
		"seal::Encryptor.encrypt_zero_symmetric#3":             "operation",
		"seal::Decryptor.decrypt#2":                            "operation",
		"seal::Decryptor.invariant_noise_budget#1":             "operation",
		"seal::EncryptionParameters.set_poly_modulus_degree#1": "config",
		"seal::EncryptionParameters.set_coeff_modulus#1":       "config",
		"seal::EncryptionParameters.set_plain_modulus#1":       "config",
	}
	negative := map[string]bool{}
	for _, key := range []string{"seal::Encryptor.is_valid_for#1", "seal::EncryptionParameters.poly_modulus_degree#0", "seal::Decryptor.pool#0"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one seal contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "seal" {
					t.Fatalf("contract for %q = role %q library %q, want seal %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}
