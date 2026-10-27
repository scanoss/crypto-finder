// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The OpenSSL 3.5 post-quantum surface (ML-KEM, ML-DSA, SLH-DSA) lives in
// openssl-evp.yaml (libcrypto) and the TLS key-exchange group and signature
// algorithm configuration in openssl-ssl.yaml (libssl). Both merge with the
// other C knowledge bases through LoadEmbedded("c").
func TestLoadEmbeddedCIncludesOpenSSLPQCContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, library, returnType, role, property string
		arity                                       int
	}{
		// Rule sinks: the argument the ML-KEM, ML-DSA and SLH-DSA rules focus on.
		{"EVP_PKEY_CTX_new_from_name", "openssl-evp", "EVP_PKEY_CTX*", "factory", "algorithm", 3},
		{"EVP_PKEY_Q_keygen", "openssl-evp", "EVP_PKEY*", "factory", "algorithm", 3},
		{"EVP_KEM_fetch", "openssl-evp", "EVP_KEM*", "factory", "algorithm", 3},
		{"EVP_SIGNATURE_fetch", "openssl-evp", "EVP_SIGNATURE*", "factory", "algorithm", 3},
		{"EVP_PKEY_new_raw_private_key_ex", "openssl-evp", "EVP_PKEY*", "factory", "algorithm", 5},
		{"EVP_PKEY_new_raw_public_key_ex", "openssl-evp", "EVP_PKEY*", "factory", "algorithm", 5},
		{"EVP_PKEY_sign_message_init", "openssl-evp", "int", "config", "algorithm", 3},
		{"EVP_PKEY_verify_message_init", "openssl-evp", "int", "config", "algorithm", 3},
		{"SSL_CTX_set1_groups_list", "openssl-ssl", "int", "config", "keyExchangeGroups", 2},
		{"SSL_set1_groups_list", "openssl-ssl", "int", "config", "keyExchangeGroups", 2},
		// OpenSSL 3.4 signature contexts over a fetched EVP_SIGNATURE.
		{"EVP_PKEY_sign_init_ex", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_sign_init_ex2", "openssl-evp", "int", "config", "algorithm", 3},
		{"EVP_PKEY_verify_init_ex", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_verify_init_ex2", "openssl-evp", "int", "config", "algorithm", 3},
		{"EVP_PKEY_CTX_set_signature", "openssl-evp", "int", "config", "signatureLength", 3},
		{"EVP_PKEY_sign_message_update", "openssl-evp", "int", "operation", "dataLength", 3},
		{"EVP_PKEY_sign_message_final", "openssl-evp", "int", "operation", "", 3},
		{"EVP_PKEY_verify_message_update", "openssl-evp", "int", "operation", "dataLength", 3},
		{"EVP_PKEY_verify_message_final", "openssl-evp", "int", "operation", "", 1},
		// EVP_DigestSign / EVP_DigestVerify.
		{"EVP_DigestSignInit", "openssl-evp", "int", "config", "digest", 5},
		{"EVP_DigestSignInit_ex", "openssl-evp", "int", "config", "digest", 7},
		{"EVP_DigestSignUpdate", "openssl-evp", "int", "operation", "dataLength", 3},
		{"EVP_DigestSignFinal", "openssl-evp", "int", "operation", "", 3},
		{"EVP_DigestSign", "openssl-evp", "int", "operation", "dataLength", 5},
		{"EVP_DigestVerifyInit", "openssl-evp", "int", "config", "digest", 5},
		{"EVP_DigestVerifyInit_ex", "openssl-evp", "int", "config", "digest", 7},
		{"EVP_DigestVerifyUpdate", "openssl-evp", "int", "operation", "dataLength", 3},
		{"EVP_DigestVerifyFinal", "openssl-evp", "int", "operation", "signatureLength", 3},
		{"EVP_DigestVerify", "openssl-evp", "int", "operation", "signatureLength", 5},
		// KEM lifecycle.
		{"EVP_PKEY_encapsulate_init", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_encapsulate", "openssl-evp", "int", "operation", "", 5},
		{"EVP_PKEY_decapsulate_init", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_decapsulate", "openssl-evp", "int", "operation", "", 5},
		{"EVP_PKEY_auth_encapsulate_init", "openssl-evp", "int", "config", "", 3},
		{"EVP_PKEY_auth_decapsulate_init", "openssl-evp", "int", "config", "", 3},
		{"EVP_PKEY_CTX_set_kem_op", "openssl-evp", "int", "config", "operation", 2},
		{"EVP_PKEY_derive_init_ex", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_derive_set_peer_ex", "openssl-evp", "int", "config", "", 3},
		{"EVP_PKEY_encrypt_init_ex", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_decrypt_init_ex", "openssl-evp", "int", "config", "", 2},
		// Algorithm handles and key contexts.
		{"EVP_KEYMGMT_fetch", "openssl-evp", "EVP_KEYMGMT*", "factory", "algorithm", 3},
		{"EVP_KEM_get0_name", "openssl-evp", "const char*", "output", "", 1},
		{"EVP_KEM_is_a", "openssl-evp", "int", "output", "algorithm", 2},
		{"EVP_SIGNATURE_get0_name", "openssl-evp", "const char*", "output", "", 1},
		{"EVP_SIGNATURE_is_a", "openssl-evp", "int", "output", "algorithm", 2},
		{"EVP_PKEY_CTX_new", "openssl-evp", "EVP_PKEY_CTX*", "factory", "", 2},
		{"EVP_PKEY_CTX_new_from_pkey", "openssl-evp", "EVP_PKEY_CTX*", "factory", "", 3},
		{"EVP_PKEY_CTX_is_a", "openssl-evp", "int", "output", "algorithm", 2},
		{"EVP_PKEY_CTX_set_params", "openssl-evp", "int", "config", "", 2},
		{"EVP_PKEY_CTX_get_params", "openssl-evp", "int", "output", "", 2},
		{"EVP_PKEY_paramgen_init", "openssl-evp", "int", "config", "", 1},
		{"EVP_PKEY_paramgen", "openssl-evp", "int", "operation", "", 2},
		{"EVP_PKEY_generate", "openssl-evp", "int", "operation", "", 2},
		{"EVP_PKEY_check", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_public_check", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_public_check_quick", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_private_check", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_pairwise_check", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_param_check", "openssl-evp", "int", "operation", "", 1},
		{"EVP_PKEY_param_check_quick", "openssl-evp", "int", "operation", "", 1},
		// Key import, export and introspection.
		{"EVP_PKEY_fromdata_init", "openssl-evp", "int", "config", "", 1},
		{"EVP_PKEY_fromdata", "openssl-evp", "int", "factory", "selection", 4},
		{"EVP_PKEY_todata", "openssl-evp", "int", "output", "selection", 3},
		{"EVP_PKEY_get_params", "openssl-evp", "int", "output", "", 2},
		{"EVP_PKEY_get_octet_string_param", "openssl-evp", "int", "output", "parameter", 5},
		{"EVP_PKEY_get_utf8_string_param", "openssl-evp", "int", "output", "parameter", 5},
		{"EVP_PKEY_new_raw_private_key", "openssl-evp", "EVP_PKEY*", "factory", "algorithm", 4},
		{"EVP_PKEY_new_raw_public_key", "openssl-evp", "EVP_PKEY*", "factory", "algorithm", 4},
		{"EVP_PKEY_set1_encoded_public_key", "openssl-evp", "int", "config", "keyLength", 3},
		{"EVP_PKEY_get1_encoded_public_key", "openssl-evp", "size_t", "output", "", 2},
		{"EVP_PKEY_get0_type_name", "openssl-evp", "const char*", "output", "", 1},
		{"EVP_PKEY_is_a", "openssl-evp", "int", "output", "algorithm", 2},
		{"EVP_PKEY_get_id", "openssl-evp", "int", "output", "", 1},
		{"EVP_PKEY_get_base_id", "openssl-evp", "int", "output", "", 1},
		{"EVP_PKEY_get_bits", "openssl-evp", "int", "output", "", 1},
		{"EVP_PKEY_get_security_bits", "openssl-evp", "int", "output", "", 1},
		{"EVP_PKEY_get_security_category", "openssl-evp", "int", "output", "", 1},
		{"EVP_PKEY_get_size", "openssl-evp", "int", "output", "", 1},
		// libssl: context, handshake, group and sigalg lists, negotiated values.
		{"SSL_CTX_new", "openssl-ssl", "SSL_CTX*", "factory", "", 1},
		{"SSL_CTX_new_ex", "openssl-ssl", "SSL_CTX*", "factory", "", 3},
		{"SSL_new", "openssl-ssl", "SSL*", "factory", "", 1},
		{"SSL_connect", "openssl-ssl", "int", "operation", "", 1},
		{"SSL_accept", "openssl-ssl", "int", "operation", "", 1},
		{"SSL_do_handshake", "openssl-ssl", "int", "operation", "", 1},
		{"SSL_CTX_set1_groups", "openssl-ssl", "int", "config", "keyExchangeGroups", 3},
		{"SSL_set1_groups", "openssl-ssl", "int", "config", "keyExchangeGroups", 3},
		{"SSL_CTX_set1_curves_list", "openssl-ssl", "int", "config", "keyExchangeGroups", 2},
		{"SSL_set1_curves_list", "openssl-ssl", "int", "config", "keyExchangeGroups", 2},
		{"SSL_CTX_set1_curves", "openssl-ssl", "int", "config", "keyExchangeGroups", 3},
		{"SSL_set1_curves", "openssl-ssl", "int", "config", "keyExchangeGroups", 3},
		{"SSL_CTX_set1_sigalgs_list", "openssl-ssl", "int", "config", "signatureAlgorithms", 2},
		{"SSL_set1_sigalgs_list", "openssl-ssl", "int", "config", "signatureAlgorithms", 2},
		{"SSL_CTX_set1_client_sigalgs_list", "openssl-ssl", "int", "config", "signatureAlgorithms", 2},
		{"SSL_set1_client_sigalgs_list", "openssl-ssl", "int", "config", "signatureAlgorithms", 2},
		{"SSL_CTX_set1_sigalgs", "openssl-ssl", "int", "config", "signatureAlgorithms", 3},
		{"SSL_set1_sigalgs", "openssl-ssl", "int", "config", "signatureAlgorithms", 3},
		{"SSL_CTX_set1_client_sigalgs", "openssl-ssl", "int", "config", "signatureAlgorithms", 3},
		{"SSL_set1_client_sigalgs", "openssl-ssl", "int", "config", "signatureAlgorithms", 3},
		{"SSL_get_negotiated_group", "openssl-ssl", "int", "output", "", 1},
		{"SSL_get0_group_name", "openssl-ssl", "const char*", "output", "", 1},
		{"SSL_group_to_name", "openssl-ssl", "const char*", "output", "", 2},
		{"SSL_get_shared_group", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_shared_curve", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get1_groups", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get1_curves", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get0_iana_groups", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get0_signature_name", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get0_peer_signature_name", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_signature_nid", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_peer_signature_nid", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_peer_tmp_key", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_server_tmp_key", "openssl-ssl", "int", "output", "", 2},
		{"SSL_get_tmp_key", "openssl-ssl", "int", "output", "", 2},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != tt.library || contract.Return.Type != tt.returnType ||
				contract.Return.Confidence != "high" || contract.Role != tt.role {
				t.Fatalf("contract = %#v, want %s %s %s/high", contract, tt.library, tt.role, tt.returnType)
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

func TestOpenSSLPQCParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, property, derivation string
		arity, index                       int
	}{
		// The algorithm string ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s")
		// is the argument the rules capture at each sink.
		{"EVP_PKEY_CTX_new_from_name", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_Q_keygen", "operation-determining", "algorithm", "argument_value", 3, 2},
		{"EVP_KEM_fetch", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_SIGNATURE_fetch", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_new_raw_private_key_ex", "operation-determining", "algorithm", "argument_value", 5, 1},
		{"EVP_PKEY_new_raw_public_key_ex", "operation-determining", "algorithm", "argument_value", 5, 1},
		{"EVP_PKEY_sign_message_init", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_verify_message_init", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_sign_init_ex2", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_verify_init_ex2", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_KEYMGMT_fetch", "operation-determining", "algorithm", "argument_value", 3, 1},
		{"EVP_PKEY_CTX_set_kem_op", "operation-determining", "operation", "argument_value", 2, 1},
		{"EVP_DigestSignInit_ex", "operation-determining", "digest", "argument_value", 7, 2},
		{"EVP_PKEY_is_a", "metadata-contributing", "algorithm", "argument_value", 2, 1},
		{"EVP_PKEY_get_octet_string_param", "metadata-contributing", "parameter", "argument_value", 5, 1},
		{"EVP_PKEY_fromdata", "metadata-contributing", "selection", "argument_value", 4, 2},
		// The TLS group list ("X25519MLKEM768:SecP256r1MLKEM768:X25519") and the
		// signature-algorithm list are configuration metadata on the context.
		{"SSL_CTX_set1_groups_list", "metadata-contributing", "keyExchangeGroups", "argument_value", 2, 1},
		{"SSL_set1_groups_list", "metadata-contributing", "keyExchangeGroups", "argument_value", 2, 1},
		{"SSL_CTX_set1_groups", "metadata-contributing", "keyExchangeGroups", "argument_value", 3, 1},
		{"SSL_CTX_set1_sigalgs_list", "metadata-contributing", "signatureAlgorithms", "argument_value", 2, 1},
		{"SSL_set1_client_sigalgs_list", "metadata-contributing", "signatureAlgorithms", "argument_value", 2, 1},
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

// A call with the wrong arity is not an OpenSSL contract: the PQC entries
// must not resolve a near-miss spelling to a positive.
func TestOpenSSLPQCNegatives(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method string
		arity  int
	}{
		{"EVP_PKEY_sign_message_init", 2},
		{"EVP_PKEY_sign_message_init", 1},
		{"EVP_PKEY_verify_message_init", 2},
		{"EVP_PKEY_sign_init_ex2", 2},
		{"EVP_PKEY_verify_message_final", 3},
		{"EVP_PKEY_encapsulate", 4},
		{"EVP_KEM_fetch", 2},
		{"SSL_CTX_set1_groups_list", 1},
		{"SSL_CTX_set1_groups_list", 3},
		{"SSL_set1_groups_list", 1},
		{"SSL_get_negotiated_group", 2},
		{"SSL_get0_group_name", 0},
	}

	for _, tt := range tests {
		if got := kb.ContractsFor(tt.method, tt.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %#v, want none", tt.method, tt.arity, got)
		}
	}
}
