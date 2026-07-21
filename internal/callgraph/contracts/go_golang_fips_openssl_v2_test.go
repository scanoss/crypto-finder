// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGolangFIPSOpenSSLV2Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"github.com/golang-fips/openssl/v2.NewAESCipher", "factory", "keySize", 1},
		{"github.com/golang-fips/openssl/v2.NewGCMTLS13", "config", "", 1},
		{"github.com/golang-fips/openssl/v2.PBKDF2", "operation", "password", 5},
		{"github.com/golang-fips/openssl/v2.(*PrivateKeyEd25519).Public", "output", "", 0},
		{"github.com/golang-fips/openssl/v2.GenerateKeyMLDSA", "factory", "parameterSet", 1},
		{"github.com/golang-fips/openssl/v2.(*PrivateKeyMLDSA).Sign", "operation", "plaintext", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "golang-fips-openssl-v2" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want golang-fips-openssl-v2 %s/high", contract, tt.role)
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
