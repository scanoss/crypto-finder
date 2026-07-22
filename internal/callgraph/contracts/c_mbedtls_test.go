// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesMbedTLSContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, role, returnType string
		arity                    int
	}{
		{"mbedtls_lms_export_public_key", "output", "int", 4},
		{"mbedtls_lms_generate_private_key", "factory", "int", 7},
		{"mbedtls_lms_import_public_key", "config", "int", 3},
		{"mbedtls_lms_private_init", "factory", "void", 1},
		{"mbedtls_lms_public_init", "factory", "void", 1},
		{"mbedtls_lms_sign", "operation", "int", 8},
		{"mbedtls_lms_verify", "operation", "int", 5},
		{"mbedtls_pk_import_into_psa", "factory", "int", 3},
		{"mbedtls_pk_init", "factory", "void", 1},
		{"mbedtls_pk_sign", "operation", "int", 9},
		{"mbedtls_pk_verify", "operation", "int", 6},
		{"mbedtls_pkcs7_init", "factory", "void", 1},
		{"mbedtls_pkcs7_signed_data_verify", "operation", "int", 4},
		{"mbedtls_pkcs7_signed_hash_verify", "operation", "int", 4},
		{"mbedtls_ssl_init", "factory", "void", 1},
		{"mbedtls_ssl_setup", "config", "int", 2},
		{"mbedtls_x509_crl_init", "factory", "void", 1},
		{"mbedtls_x509_crl_parse", "config", "int", 3},
		{"mbedtls_x509_crl_parse_der", "config", "int", 3},
		{"mbedtls_x509_crl_parse_file", "config", "int", 2},
		{"mbedtls_x509_crt_init", "factory", "void", 1},
		{"mbedtls_x509_crt_parse", "config", "int", 3},
		{"mbedtls_x509_crt_parse_der", "config", "int", 3},
		{"mbedtls_x509_crt_parse_file", "config", "int", 2},
		{"mbedtls_x509_csr_init", "factory", "void", 1},
		{"mbedtls_x509_csr_parse", "config", "int", 3},
		{"mbedtls_x509_csr_parse_der", "config", "int", 3},
		{"mbedtls_x509_csr_parse_file", "config", "int", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "mbedtls" || contract.Role != tt.role || contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want mbedtls %s returning %s with high confidence", contract, tt.role, tt.returnType)
			}
		})
	}
}

func TestMbedTLSParameterDerivations(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	tests := []struct {
		method, property, role string
		arity                  int
		index                  int
	}{
		{"mbedtls_lms_generate_private_key", "parameterSet", "operation-determining", 7, 1},
		{"mbedtls_lms_generate_private_key", "parameterSet", "operation-determining", 7, 2},
		{"mbedtls_lms_generate_private_key", "seedLength", "metadata-contributing", 7, 6},
		{"mbedtls_lms_import_public_key", "keyLength", "metadata-contributing", 3, 2},
		{"mbedtls_lms_sign", "dataLength", "metadata-contributing", 8, 4},
		{"mbedtls_lms_verify", "dataLength", "metadata-contributing", 5, 2},
		{"mbedtls_lms_verify", "signatureLength", "metadata-contributing", 5, 4},
		{"mbedtls_pk_sign", "algorithm", "operation-determining", 9, 1},
		{"mbedtls_pk_sign", "digestLength", "metadata-contributing", 9, 3},
		{"mbedtls_pk_verify", "algorithm", "operation-determining", 6, 1},
		{"mbedtls_pk_verify", "digestLength", "metadata-contributing", 6, 3},
		{"mbedtls_pk_verify", "signatureLength", "metadata-contributing", 6, 5},
		{"mbedtls_pkcs7_signed_data_verify", "dataLength", "metadata-contributing", 4, 3},
		{"mbedtls_pkcs7_signed_hash_verify", "digestLength", "metadata-contributing", 4, 3},
		{"mbedtls_x509_crl_parse", "dataLength", "metadata-contributing", 3, 2},
		{"mbedtls_x509_crl_parse_der", "dataLength", "metadata-contributing", 3, 2},
		{"mbedtls_x509_crt_parse", "dataLength", "metadata-contributing", 3, 2},
		{"mbedtls_x509_crt_parse_der", "dataLength", "metadata-contributing", 3, 2},
		{"mbedtls_x509_csr_parse", "dataLength", "metadata-contributing", 3, 2},
		{"mbedtls_x509_csr_parse_der", "dataLength", "metadata-contributing", 3, 2},
	}
	for _, tt := range tests {
		t.Run(tt.method+"/"+tt.property, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			for _, parameter := range got[0].Parameters {
				if parameter.Index != nil && *parameter.Index == tt.index && parameter.Role == tt.role && parameter.Contributes != nil && parameter.Contributes.Property == tt.property && parameter.Contributes.Derivation == "argument_value" {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want index %d with role %q contributing %q", got[0].Parameters, tt.index, tt.role, tt.property)
		})
	}
}
