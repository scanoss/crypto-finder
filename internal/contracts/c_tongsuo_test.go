// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"testing"

	"github.com/scanoss/static-engine/callgraph/contracts"
)

func TestLoadEmbeddedCIncludesTongsuoContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("c")
	if err != nil {
		t.Fatalf("Load(c): %v", err)
	}

	tests := []struct {
		method, returnType, role, property string
		arity                              int
	}{
		{"EVP_sm4_gcm", "const EVP_CIPHER*", "factory", "", 0},
		{"EVP_sm4_ccm", "const EVP_CIPHER*", "factory", "", 0},
		{"EVP_eea3", "const EVP_CIPHER*", "factory", "", 0},
		{"EVP_wbsm4_xiaolai_cbc", "const EVP_CIPHER*", "factory", "", 0},
		{"EVP_wbsm4_wsise_gcm", "const EVP_CIPHER*", "factory", "", 0},
		{"SM3_Init", "int", "config", "", 1},
		{"SM3_Final", "int", "operation", "", 2},
		{"TSAPI_SM3", "unsigned char*", "operation", "", 3},
		{"TSAPI_SM2Keygen", "EVP_PKEY*", "operation", "", 0},
		{"TSAPI_SM2Sign", "unsigned char*", "operation", "", 4},
		{"TSAPI_SM2Verify", "int", "operation", "", 5},
		{"TSAPI_SM2EncryptWithISK", "unsigned char*", "operation", "", 4},
		{"TSAPI_SM4Encrypt", "unsigned char*", "operation", "mode", 8},
		{"TSAPI_SM4Decrypt", "unsigned char*", "operation", "keySize", 8},
		{"TSAPI_SDF_InternalSign_ECC", "int", "operation", "", 5},
		{"SM2_THRESHOLD_sign1_init", "int", "config", "digest", 5},
		{"SM2_THRESHOLD_sign3", "int", "operation", "", 6},
		{"SM2_THRESHOLD_decrypt3", "int", "operation", "", 7},
		{"PAILLIER_KEY_generate_key", "int", "operation", "keySize", 2},
		{"PAILLIER_encrypt", "int", "operation", "", 3},
		{"EC_ELGAMAL_decrypt", "int", "operation", "", 3},
		{"NTLS_client_method", "const SSL_METHOD*", "factory", "", 0},
		{"SSL_CTX_enable_ntls", "void", "config", "", 1},
		{"SSL_CTX_enable_sm_tls13_strict", "void", "config", "", 1},
		{"SSL_CTX_use_sign_certificate", "int", "config", "", 2},
		{"SSL_CTX_use_enc_PrivateKey_file", "int", "config", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.SourceLibrary != "tongsuo" || c.Return.Type != tt.returnType || c.Return.Confidence != "high" || c.Role != tt.role {
				t.Fatalf("contract = %#v, want tongsuo %s %s/high", c, tt.role, tt.returnType)
			}
			if tt.property == "" {
				return
			}
			for _, p := range c.Parameters {
				if p.Contributes != nil && p.Contributes.Property == tt.property {
					return
				}
			}
			t.Fatalf("parameters = %#v, want contribution for %q", c.Parameters, tt.property)
		})
	}
}

// tongsuo.yaml declares only symbols OpenSSL lacks: no method it owns may also
// be declared by the OpenSSL files, and the shared EVP names stay theirs.
func TestTongsuoDeclaresNoOpenSSLSymbol(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("c")
	if err != nil {
		t.Fatalf("Load(c): %v", err)
	}

	tongsuo, openssl := map[string]bool{}, map[string]bool{}
	for _, cs := range kb.Contracts {
		for i := range cs {
			switch cs[i].SourceLibrary {
			case "tongsuo":
				tongsuo[cs[i].Method] = true
			case "openssl-evp", "openssl-ssl":
				openssl[cs[i].Method] = true
			}
		}
	}
	if len(tongsuo) == 0 {
		t.Fatal("no tongsuo contracts loaded")
	}
	for method := range tongsuo {
		if openssl[method] {
			t.Errorf("tongsuo.yaml declares %q, which an OpenSSL contract file also declares", method)
		}
	}

	for _, shared := range []string{"EVP_sm4_cbc", "EVP_sm4_ctr", "EVP_sm3"} {
		got := kb.ContractsFor(shared, 0)
		if len(got) != 1 || got[0].SourceLibrary != "openssl-evp" {
			t.Errorf("ContractsFor(%q, 0) = %#v, want the openssl-evp contract", shared, got)
		}
	}
}
