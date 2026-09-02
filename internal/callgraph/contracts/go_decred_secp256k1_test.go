// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesDecredSecp256k1Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/decred/dcrd/dcrec/secp256k1/v4"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".GeneratePrivateKey", "factory", "*" + m + ".PrivateKey", "", 0},
		{m + ".PrivKeyFromBytes", "factory", "*" + m + ".PrivateKey", "keyMaterial", 1},
		{m + ".GenerateSharedSecret", "operation", "[]byte", "privateKey", 2},
		{m + ".NonceRFC6979", "operation", "*" + m + ".ModNScalar", "keyMaterial", 5},
		{m + ".(PublicKey).SerializeCompressed", "output", "[]byte", "", 0},
		{m + "/ecdsa.Sign", "operation", "*" + m + "/ecdsa.Signature", "digest", 2},
		{m + "/ecdsa.RecoverCompact", "operation", "*" + m + ".PublicKey", "signature", 2},
		{m + "/ecdsa.(*Signature).Verify", "operation", "bool", "publicKey", 2},
		{m + "/schnorr.Sign", "operation", "*" + m + "/schnorr.Signature", "privateKey", 2},
		{m + "/schnorr.ParsePubKey", "factory", "*" + m + ".PublicKey", "publicKey", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "decred-secp256k1" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want decred-secp256k1 %s -> %s/high", contract, tt.role, tt.returnType)
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
