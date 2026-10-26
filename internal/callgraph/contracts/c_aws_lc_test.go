// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesAwsLcContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, returnType, role, property string
		arity                              int
	}{
		// ML-KEM key material.
		{"EVP_PKEY_CTX_kem_set_params", "int", "config", "algorithm", 2},
		{"EVP_PKEY_kem_new_raw_public_key", "EVP_PKEY*", "factory", "algorithm", 3},
		{"EVP_PKEY_kem_new_raw_secret_key", "EVP_PKEY*", "factory", "algorithm", 3},
		{"EVP_PKEY_kem_new_raw_key", "EVP_PKEY*", "factory", "algorithm", 5},
		{"EVP_PKEY_kem_check_key", "int", "operation", "", 1},
		{"EVP_PKEY_kem_get_type", "int", "output", "", 1},
		{"EVP_PKEY_keygen_deterministic", "int", "operation", "", 4},
		{"EVP_PKEY_encapsulate_deterministic", "int", "operation", "", 7},
		// ML-DSA key material and signature context.
		{"EVP_PKEY_CTX_pqdsa_set_params", "int", "config", "algorithm", 2},
		{"EVP_PKEY_pqdsa_new_raw_public_key", "EVP_PKEY*", "factory", "algorithm", 3},
		{"EVP_PKEY_pqdsa_new_raw_private_key", "EVP_PKEY*", "factory", "algorithm", 3},
		{"EVP_PKEY_pqdsa_get_type", "int", "output", "", 1},
		{"EVP_PKEY_CTX_set1_signature_context_string", "int", "config", "contextLength", 3},
		{"EVP_PKEY_CTX_set_signature_context", "int", "config", "contextLength", 3},
		{"EVP_PKEY_CTX_get0_signature_context", "int", "output", "", 3},
		// TLS groups by SSL_GROUP_* identifier, and the negotiated group.
		{"SSL_CTX_set1_group_ids", "int", "config", "keyExchangeGroups", 3},
		{"SSL_set1_group_ids", "int", "config", "keyExchangeGroups", 3},
		{"SSL_get_group_id", "uint16_t", "output", "", 1},
		{"SSL_get_group_name", "const char*", "output", "", 1},
		{"SSL_get_curve_id", "uint16_t", "output", "", 1},
		{"SSL_get_curve_name", "const char*", "output", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "aws-lc" || contract.Return.Type != tt.returnType ||
				contract.Return.Confidence != "high" || contract.Role != tt.role {
				t.Fatalf("contract = %#v, want aws-lc %s %s/high", contract, tt.role, tt.returnType)
			}
			if tt.property == "" {
				return
			}
			for _, parameter := range contract.Parameters {
				if parameter.Contributes != nil && parameter.Contributes.Property == tt.property {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want contribution for %q", contract.Parameters, tt.property)
		})
	}
}

// The NID is what selects ML-KEM-512/768/1024 or ML-DSA-44/65/87, and the rules
// read it from the exact position the contract names: second argument of the
// *_set_params configurators, first argument of the raw-key factories.
func TestAwsLcParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property, derivation string
		arity, index                       int
	}{
		{"EVP_PKEY_CTX_kem_set_params", "operation-determining", "algorithm", "argument_value", 2, 1},
		{"EVP_PKEY_kem_new_raw_public_key", "operation-determining", "algorithm", "argument_value", 3, 0},
		{"EVP_PKEY_kem_new_raw_public_key", "metadata-contributing", "keyLength", "argument_value", 3, 2},
		{"EVP_PKEY_kem_new_raw_key", "operation-determining", "algorithm", "argument_value", 5, 0},
		{"EVP_PKEY_CTX_pqdsa_set_params", "operation-determining", "algorithm", "argument_value", 2, 1},
		{"EVP_PKEY_pqdsa_new_raw_private_key", "operation-determining", "algorithm", "argument_value", 3, 0},
		{"EVP_PKEY_CTX_set1_signature_context_string", "metadata-contributing", "contextLength", "argument_value", 3, 2},
		{"SSL_CTX_set1_group_ids", "metadata-contributing", "keyExchangeGroups", "argument_value", 3, 1},
		{"SSL_set1_group_ids", "metadata-contributing", "keyExchangeGroups", "argument_value", 3, 1},
	}

	for _, tt := range tests {
		t.Run(tt.method+"/"+tt.property, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Index != nil && *parameter.Index == tt.index && parameter.Role == tt.role &&
					parameter.Contributes != nil && parameter.Contributes.Property == tt.property &&
					parameter.Contributes.Derivation == tt.derivation {
					return
				}
			}
			t.Fatalf("parameters = %#v, want index=%d role=%s contribution=%s/%s",
				got[0].Parameters, tt.index, tt.role, tt.property, tt.derivation)
		})
	}
}

// AWS-LC shares its OpenSSL-named symbols with openssl-evp.yaml and
// openssl-ssl.yaml. aws-lc.yaml deliberately declares none of them, so the
// merged C KB must (a) load without a conflict, (b) keep those keys attributed
// to the OpenSSL files, and (c) still model the configured and negotiated hybrid
// group for an AWS-LC consumer through them: the groups list carries
// keyExchangeGroups and the negotiated group is an output.
func TestAwsLcMergesCleanlyWithOpenSSL(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c) must merge aws-lc with openssl-evp and openssl-ssl: %v", err)
	}

	shared := []struct {
		method, library, role, property string
		arity                           int
	}{
		{"EVP_PKEY_encapsulate", "openssl-evp", "operation", "", 5},
		{"EVP_PKEY_decapsulate", "openssl-evp", "operation", "", 5},
		{"SSL_CTX_set1_groups_list", "openssl-ssl", "config", "keyExchangeGroups", 2},
		{"SSL_set1_groups_list", "openssl-ssl", "config", "keyExchangeGroups", 2},
		{"SSL_CTX_set1_groups", "openssl-ssl", "config", "keyExchangeGroups", 3},
		{"SSL_set1_groups", "openssl-ssl", "config", "keyExchangeGroups", 3},
		{"SSL_get_negotiated_group", "openssl-ssl", "output", "", 1},
	}
	for _, tt := range shared {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want 1 after the merge", tt.method, tt.arity, len(got))
			continue
		}
		if got[0].SourceLibrary != tt.library || got[0].Role != tt.role {
			t.Errorf("%s: library/role = %q/%q, want %q/%q", tt.method, got[0].SourceLibrary, got[0].Role, tt.library, tt.role)
		}
		if tt.property == "" {
			continue
		}
		found := false
		for _, p := range got[0].Parameters {
			if p.Contributes != nil && p.Contributes.Property == tt.property {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: parameters = %#v, want contribution for %q", tt.method, got[0].Parameters, tt.property)
		}
	}

	// Negative examples: a wrong arity on the five-argument factory, the
	// OpenSSL 3 provider-era names AWS-LC does not declare, and the pure
	// OpenSSL getter spellings.
	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"EVP_PKEY_kem_new_raw_key", 3},
		{"EVP_PKEY_kem_new_raw_public_key", 2},
		{"EVP_PKEY_encapsulate_init", 2},
		{"SSL_get_group_name", 2},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			for _, c := range got {
				if c.SourceLibrary == "aws-lc" {
					t.Errorf("ContractsFor(%q, %d) = %#v, want no aws-lc contract", bogus.method, bogus.arity, got)
				}
			}
		}
	}
}
