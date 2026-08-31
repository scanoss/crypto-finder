// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesBtcecContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/btcsuite/btcd/btcec/v2"
	const dec = "github.com/decred/dcrd/dcrec/secp256k1/v4"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".NewPrivateKey", "factory", "*" + dec + ".PrivateKey", "", 0},
		{m + ".PrivKeyFromBytes", "factory", "*" + dec + ".PrivateKey", "keyMaterial", 1},
		{m + ".GenerateSharedSecret", "operation", "[]byte", "privateKey", 2},
		{m + ".SignCompact", "operation", "[]byte", "digest", 3},
		{m + "/ecdsa.Sign", "operation", "*" + dec + "/ecdsa.Signature", "privateKey", 2},
		{m + "/ecdsa.VerifyLowS", "operation", "error", "signature", 1},
		{m + "/schnorr.Sign", "operation", "*" + m + "/schnorr.Signature", "digest", 3},
		{m + "/schnorr.(*Signature).Verify", "operation", "bool", "publicKey", 2},
		{m + "/ellswift.EllswiftCreate", "factory", "*" + dec + ".PrivateKey", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "btcec" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want btcec %s -> %s/high", contract, tt.role, tt.returnType)
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
