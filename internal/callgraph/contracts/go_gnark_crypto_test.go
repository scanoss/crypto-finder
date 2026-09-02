// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGnarkCryptoContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role string
		arity        int
	}{
		{"github.com/consensys/gnark-crypto/ecc/bn254/ecdsa.GenerateKey", "operation", 1},
		{"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa.(*PrivateKey).Sign", "operation", 2},
		{"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa.(*PublicKey).Verify", "operation", 3},
		{"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc.NewMiMC", "factory", 0},
		{"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg.Commit", "operation", 3},
		{"github.com/consensys/gnark-crypto/hash.(Hash).New", "factory", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "gnark-crypto" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want gnark-crypto %s/high", contract, tt.role)
			}
		})
	}
}
