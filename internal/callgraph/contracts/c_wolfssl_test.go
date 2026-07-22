// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesWolfSSLContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	roleCounts := map[string]int{}
	var inventory []string
	for _, candidates := range kb.Contracts {
		for _, contract := range candidates {
			if contract.SourceLibrary != "wolfssl-wolfcrypt" {
				continue
			}
			roleCounts[contract.Role]++
			var parameters []string
			for _, parameter := range contract.Parameters {
				index := -1
				if parameter.Index != nil {
					index = *parameter.Index
				}
				parameters = append(parameters, fmt.Sprintf("%d:%s:%s:%s", index, parameter.Role,
					parameter.Contributes.Property, parameter.Contributes.Derivation))
			}
			inventory = append(inventory, fmt.Sprintf("%s#%d:%s:%s:%s:%s", contract.Method, contract.Arity,
				contract.Role, contract.Return.Type, contract.Return.Confidence, strings.Join(parameters, ",")))
		}
	}
	if len(inventory) != 621 {
		t.Fatalf("wolfSSL contracts = %d, want 257 rule APIs plus 364 lifecycle calls", len(inventory))
	}
	wantRoles := map[string]int{"factory": 122, "config": 154, "operation": 274, "output": 71}
	for role, want := range wantRoles {
		if roleCounts[role] != want {
			t.Fatalf("wolfSSL %s contracts = %d, want %d", role, roleCounts[role], want)
		}
	}
	sort.Strings(inventory)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(inventory, "\n"))))
	if digest != "978aa8fb72a2d580a5b28e0d31d37a28de16df5e36ce5393698f7c9804dc83ed" {
		t.Fatalf("wolfSSL inventory digest = %s; update only after auditing the pinned rules and headers", digest)
	}

	tests := []struct {
		method, role string
		arity        int
	}{
		{"wc_AesGcmEncrypt", "operation", 10},
		{"wc_Sha256Final", "operation", 2},
		{"wc_RsaPSS_Sign", "operation", 8},
		{"wc_MlKemKey_MakeKey", "factory", 2},
		{"wc_AesGcmSetKey", "config", 3},
		{"wc_RsaExportKey", "output", 11},
		{"wc_ecc_init", "factory", 1},
		{"wc_ecc_export_x963", "output", 3},
		{"wc_AesXtsSetKeyNoInit", "config", 4},
		{"wc_ecc_set_deterministic_ex", "config", 3},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "wolfssl-wolfcrypt" || contract.Role != tt.role ||
				contract.Return.Type != "int" || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want wolfssl-wolfcrypt %s returning int with high confidence", contract, tt.role)
			}
		})
	}
}

func TestWolfSSLParameterDerivations(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity, index           int
	}{
		{"wc_HKDF", "operation-determining", "algorithm", 9, 0},
		{"wc_HKDF", "metadata-contributing", "outputLength", 9, 8},
		{"wc_PBKDF2", "metadata-contributing", "iterations", 8, 5},
		{"wc_PBKDF2", "operation-determining", "algorithm", 8, 7},
		{"wc_MakeRsaKey", "metadata-contributing", "keySize", 4, 1},
		{"wc_AesGcmEncrypt", "metadata-contributing", "ivSize", 10, 5},
		{"wc_AesGcmEncrypt", "metadata-contributing", "authenticationTagSize", 10, 7},
		{"wc_AesCmacGenerate", "metadata-contributing", "keySize", 6, 5},
		{"wc_Shake128Hash", "metadata-contributing", "digestLength", 4, 3},
		{"wc_ed25519_sign_msg_ex", "operation-determining", "variant", 8, 5},
		{"wc_scrypt", "metadata-contributing", "cost", 9, 5},
		{"wc_RsaPublicEncrypt_ex", "operation-determining", "padding", 11, 6},
		{"wc_ChaCha20Poly1305_Init", "operation-determining", "operation", 4, 3},
		{"wc_MlKemKey_Init", "operation-determining", "parameterSet", 4, 1},
		{"wc_MlDsaKey_SetParams", "operation-determining", "parameterSet", 2, 1},
		{"wc_SlhDsaKey_Init", "operation-determining", "parameterSet", 4, 1},
		{"wc_AesSetKey", "metadata-contributing", "keySize", 5, 2},
		{"wc_HmacSetKey", "metadata-contributing", "keySize", 4, 3},
		{"wc_InitBlake2b_WithKey", "metadata-contributing", "keySize", 4, 3},
		{"wc_ecc_set_curve", "operation-determining", "parameterSet", 3, 2},
		{"wc_AesGcmSetExtIV", "metadata-contributing", "ivSize", 3, 2},
		{"wc_AsconAEAD128_SetAD", "metadata-contributing", "associatedDataLength", 3, 2},
		{"wc_DhSetNamedKey", "operation-determining", "parameterSet", 2, 1},
		{"wc_falcon_set_level", "operation-determining", "parameterSet", 2, 1},
		{"wc_LmsKey_SetParameters", "operation-determining", "parameterSet", 4, 1},
		{"wc_XChaCha20Poly1305_Init", "metadata-contributing", "nonceSize", 8, 4},
		{"wc_XChaCha20Poly1305_Init", "metadata-contributing", "keySize", 8, 6},
		{"wc_XChaCha20Poly1305_Init", "operation-determining", "operation", 8, 7},
		{"wc_XChaCha20Poly1305_Encrypt", "metadata-contributing", "nonceSize", 10, 7},
		{"wc_XChaCha20Poly1305_Encrypt", "metadata-contributing", "keySize", 10, 9},
		{"wc_ed25519_sign_msg_ex", "metadata-contributing", "contextLength", 8, 7},
		{"wc_ecc_verify_hash", "metadata-contributing", "signatureLength", 6, 1},
		{"wc_ecc_verify_hash", "metadata-contributing", "digestLength", 6, 3},
		{"wc_ecc_export_point_der", "operation-determining", "parameterSet", 4, 0},
		{"wc_ecc_import_raw", "operation-determining", "parameterSet", 5, 4},
		{"wc_HashGetDigestSize", "operation-determining", "algorithm", 1, 0},
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
