// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGmsmContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		library, method, role, returnType, property string
		arity                                       int
	}{
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm2.GenerateKey", "factory", "*github.com/tjfoc/gmsm/sm2.PrivateKey", "", 1},
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm2.Sm2Sign", "operation", "*math/big.Int", "", 4},
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm2.(*PublicKey).EncryptAsn1", "operation", "[]byte", "", 2},
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm3.New", "factory", "hash.Hash", "", 0},
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm4.NewCipher", "factory", "crypto/cipher.Block", "keySize", 1},
		{"tjfoc-gmsm", "github.com/tjfoc/gmsm/sm4.Sm4Cbc", "operation", "[]byte", "", 3},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm2.(*PrivateKey).SignWithSM2", "operation", "[]byte", "", 3},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm2.Encrypt", "operation", "[]byte", "", 4},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm3.Sum", "operation", "[32]byte", "", 1},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm4.NewCipher", "factory", "crypto/cipher.Block", "keySize", 1},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/cipher.NewCCM", "factory", "crypto/cipher.AEAD", "cipher", 1},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/cipher.NewXTSEncrypter", "factory", "crypto/cipher.BlockMode", "cipher", 4},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm9.GenerateEncryptMasterKey", "factory", "*github.com/emmansun/gmsm/sm9.EncryptMasterPrivateKey", "", 1},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm9.(*EncryptMasterPrivateKey).GenerateUserKey", "factory", "*github.com/emmansun/gmsm/sm9.EncryptPrivateKey", "", 2},
		{"emmansun-gmsm", "github.com/emmansun/gmsm/sm9.(*EncryptMasterPublicKey).WrapKey", "operation", "[]byte", "", 4},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != tt.library || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
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
