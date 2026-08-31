// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesCrypto11Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/ThalesIgnite/crypto11"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".Configure", "factory", "*" + m + ".Context", "options", 1},
		{m + ".(*Context).GenerateRSAKeyPair", "operation", m + ".SignerDecrypter", "keySize", 2},
		{m + ".(*Context).GenerateECDSAKeyPair", "operation", m + ".Signer", "curve", 2},
		{m + ".(*Context).GenerateSecretKey", "operation", "*" + m + ".SecretKey", "cipher", 3},
		{m + ".(*Context).FindKeyPair", "factory", m + ".Signer", "", 2},
		{m + ".(*Context).NewRandomReader", "factory", "io.Reader", "", 0},
		{m + ".(*SecretKey).NewCBCEncrypter", "factory", "crypto/cipher.BlockMode", "iv", 1},
		{m + ".(*SecretKey).NewGCM", "factory", "crypto/cipher.AEAD", "", 0},
		{m + ".(*SecretKey).NewHMAC", "factory", "hash.Hash", "algorithm", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "crypto11" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want crypto11 %s -> %s/high", contract, tt.role, tt.returnType)
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
