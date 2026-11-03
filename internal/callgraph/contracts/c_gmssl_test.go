// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesGmSSLContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, returnType, role string
		arity                    int
	}{
		// SM2 signing, encryption and key agreement.
		{"sm2_key_generate", "int", "operation", 1},
		{"sm2_sign_init", "int", "config", 4},
		{"sm2_sign_update", "int", "operation", 3},
		{"sm2_sign_finish", "int", "operation", 3},
		{"sm2_sign", "int", "operation", 4},
		{"sm2_verify_init", "int", "config", 4},
		{"sm2_verify", "int", "operation", 4},
		{"sm2_encrypt", "int", "operation", 5},
		{"sm2_encrypt_finish", "int", "operation", 4},
		{"sm2_decrypt", "int", "operation", 5},
		{"sm2_ecdh", "int", "operation", 3},
		// SM3 HMAC, KDFs and the keyed/unkeyed digest context.
		{"sm3_finish", "void", "operation", 2},
		{"sm3_hmac_init", "void", "config", 3},
		{"sm3_hmac_finish", "void", "operation", 2},
		{"sm3_pbkdf2", "int", "operation", 7},
		{"sm3_digest_init", "int", "config", 3},
		{"sm3_hkdf_extract", "int", "operation", 5},
		// SM4 modes and AEAD.
		{"sm4_cbc_padding_encrypt", "int", "operation", 6},
		{"sm4_cbc_encrypt_init", "int", "config", 3},
		{"sm4_ctr_encrypt", "void", "operation", 5},
		{"sm4_gcm_encrypt", "int", "operation", 10},
		{"sm4_gcm_decrypt_init", "int", "config", 8},
		{"sm4_ccm_encrypt", "int", "operation", 10},
		{"sm4_xts_encrypt", "int", "operation", 6},
		{"sm4_cbc_sm3_hmac_encrypt_init", "int", "config", 5},
		{"sm4_cbc_mac_init", "int", "config", 2},
		// ZUC.
		{"zuc_init", "void", "config", 3},
		{"zuc_eea_encrypt", "void", "operation", 7},
		{"zuc_eia_generate_mac", "ZUC_UINT32", "operation", 6},
		{"zuc256_mac_init", "void", "config", 4},
		// SM9.
		{"sm9_sign_master_key_generate", "int", "operation", 1},
		{"sm9_sign_finish", "int", "operation", 4},
		{"sm9_do_verify", "int", "operation", 5},
		{"sm9_kem_encrypt", "int", "operation", 6},
		{"sm9_encrypt", "int", "operation", 7},
		{"sm9_exch_step_1A", "int", "operation", 5},
		// TLCP / TLS 1.3 context.
		{"tls_ctx_init", "int", "config", 3},
		{"tls_ctx_set_cipher_suites", "int", "config", 3},
		{"tls_ctx_set_tlcp_server_certificate_and_keys", "int", "config", 6},
		// GmSSL 3.1 spellings and arities.
		{"sm3_hmac", "void", "operation", 5},
		{"sm4_cbc_encrypt", "void", "operation", 5},
		{"sm2_ecdh", "int", "operation", 4},
		{"sm3_hkdf_extract", "int", "operation", 6},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.SourceLibrary != "gmssl" || c.Return.Type != tt.returnType || c.Return.Confidence != "high" || c.Role != tt.role {
				t.Fatalf("contract = %#v, want gmssl %s %s/high", c, tt.role, tt.returnType)
			}
		})
	}
}

// Lengths, tag sizes, iteration counts and the protocol version are read from
// the argument positions the GmSSL 3.2.0 headers declare.
func TestGmSSLParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property, derivation string
		arity, index                       int
	}{
		{"sm3_pbkdf2", "metadata-contributing", "iterations", "argument_value", 7, 4},
		{"sm3_pbkdf2", "metadata-contributing", "outputLength", "argument_value", 7, 5},
		{"sm3_kdf_init", "metadata-contributing", "outputLength", "argument_value", 2, 1},
		{"sm2_sign_fixlen", "metadata-contributing", "signatureLength", "argument_value", 4, 2},
		{"sm4_gcm_encrypt", "metadata-contributing", "authenticationTagSize", "argument_value", 10, 8},
		{"sm4_gcm_encrypt_init", "metadata-contributing", "keySize", "argument_byte_length", 8, 2},
		{"sm4_gcm_encrypt_init", "metadata-contributing", "authenticationTagSize", "argument_value", 8, 7},
		{"zuc256_mac_init", "metadata-contributing", "authenticationTagSize", "argument_value", 4, 3},
		{"tls_ctx_init", "operation-determining", "protocolVersion", "argument_value", 3, 1},
		{"tls_ctx_set_cipher_suites", "metadata-contributing", "cipherSuite", "argument_value", 3, 1},
	}

	for _, tt := range tests {
		t.Run(tt.method+"/"+tt.property, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			for _, p := range got[0].Parameters {
				if p.Index != nil && *p.Index == tt.index && p.Role == tt.role && p.Contributes != nil &&
					p.Contributes.Property == tt.property && p.Contributes.Derivation == tt.derivation {
					return
				}
			}
			t.Fatalf("parameters = %#v, want index=%d role=%s %s/%s", got[0].Parameters, tt.index, tt.role, tt.property, tt.derivation)
		})
	}
}

// GmSSL and Nettle declare sm3_init, sm3_update, sm3_digest and the SM4 key
// schedule with the same shape. gmssl.yaml leaves them to nettle.yaml, so the
// merged KB loads and a GmSSL call still resolves.
func TestGmSSLSharesSM3AndSM4KeyScheduleWithNettle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c) must merge gmssl with nettle: %v", err)
	}

	for _, tt := range []struct {
		method, role string
		arity        int
	}{
		{"sm3_init", "config", 1},
		{"sm3_update", "operation", 3},
		{"sm3_digest", "operation", 3},
		{"sm4_set_encrypt_key", "config", 2},
		{"sm4_set_decrypt_key", "config", 2},
	} {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 || got[0].SourceLibrary != "nettle" || got[0].Role != tt.role || got[0].Return.Type != "void" {
			t.Errorf("ContractsFor(%q, %d) = %#v, want one nettle void %s contract", tt.method, tt.arity, got, tt.role)
		}
	}
}
