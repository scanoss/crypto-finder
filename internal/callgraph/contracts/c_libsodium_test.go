// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesLibsodiumContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, returnType, role, property string
		arity                              int
	}{
		{"crypto_aead_xchacha20poly1305_ietf_encrypt", "int", "operation", "", 9},
		{"crypto_box_keypair", "int", "factory", "", 2},
		{"crypto_generichash_init", "int", "config", "keySize", 4},
		{"crypto_kdf_derive_from_key", "int", "operation", "subkeyId", 5},
		{"crypto_kx_client_session_keys", "int", "operation", "", 5},
		{"crypto_pwhash_alg_default", "int", "factory", "", 0},
		{"crypto_pwhash", "int", "operation", "algorithm", 8},
		{"crypto_secretbox_keygen", "void", "factory", "", 1},
		{"crypto_secretstream_xchacha20poly1305_init_push", "int", "config", "", 3},
		{"crypto_secretstream_xchacha20poly1305_push", "int", "operation", "operation", 8},
		{"crypto_sign_detached", "int", "operation", "", 5},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "libsodium" || contract.Return.Type != tt.returnType ||
				contract.Return.Confidence != "high" || contract.Role != tt.role {
				t.Fatalf("contract = %#v, want libsodium %s %s/high", contract, tt.role, tt.returnType)
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

func TestLibsodiumParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity, index           int
	}{
		{"crypto_generichash_init", "metadata-contributing", "keySize", 4, 2},
		{"crypto_kdf_derive_from_key", "metadata-contributing", "subkeyId", 5, 2},
		{"crypto_pwhash", "operation-determining", "algorithm", 8, 7},
		{"crypto_secretstream_xchacha20poly1305_push", "operation-determining", "operation", 8, 7},
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
					parameter.Contributes.Derivation == "argument_value" {
					return
				}
			}
			t.Fatalf("parameters = %#v, want index=%d role=%s contribution=%s/argument_value",
				got[0].Parameters, tt.index, tt.role, tt.property)
		})
	}
}
