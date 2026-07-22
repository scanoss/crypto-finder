// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesOpenSSLEVPContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, returnType, role, property string
		arity                              int
	}{
		{"EVP_aes_256_gcm", "const EVP_CIPHER*", "factory", "", 0},
		{"EVP_CIPHER_fetch", "EVP_CIPHER*", "factory", "algorithm", 3},
		{"EVP_CipherInit_ex", "int", "config", "algorithm", 6},
		{"EVP_sha256", "const EVP_MD*", "factory", "", 0},
		{"EVP_DigestInit_ex2", "int", "config", "algorithm", 3},
		{"EVP_Digest", "int", "operation", "algorithm", 6},
		{"EVP_PKEY_CTX_new_from_name", "EVP_PKEY_CTX*", "factory", "algorithm", 3},
		{"EVP_PKEY_Q_keygen", "EVP_PKEY*", "factory", "algorithm", 4},
		{"EVP_PKEY_CTX_set_rsa_pss_saltlen", "int", "config", "saltLength", 2},
		{"EVP_PBE_scrypt", "int", "operation", "iterations", 10},
		{"EVP_DigestFinal_ex", "int", "operation", "", 3},
		{"EVP_PKEY_get_raw_public_key", "int", "output", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "openssl-evp" || contract.Return.Type != tt.returnType ||
				contract.Return.Confidence != "high" || contract.Role != tt.role {
				t.Fatalf("contract = %#v, want openssl-evp %s %s/high", contract, tt.role, tt.returnType)
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

func TestOpenSSLEVPParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property, derivation string
		arity, index                       int
	}{
		{"PKCS5_PBKDF2_HMAC", "operation-determining", "algorithm", "argument_value", 8, 5},
		{"PKCS5_PBKDF2_HMAC", "metadata-contributing", "outputLength", "argument_value", 8, 6},
		{"EVP_CipherInit_ex", "operation-determining", "algorithm", "argument_value", 6, 1},
		{"EVP_PKEY_Q_keygen", "operation-determining", "algorithm", "argument_value", 4, 2},
		{"EVP_PKEY_Q_keygen", "metadata-contributing", "parameterSet", "argument_value", 4, 3},
		{"EVP_PBE_scrypt", "metadata-contributing", "iterations", "argument_value", 10, 4},
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
