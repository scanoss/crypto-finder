// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesJamesruanSodiumContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/jamesruan/sodium"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".MakeBoxKP", "factory", m + ".BoxKP", "", 0},
		{m + ".SeedSignKP", "factory", m + ".SignKP", "seed", 1},
		{m + ".PWHashStore", "operation", m + ".PWHashStr", "password", 1},
		{m + ".CryptoScalarmult", "operation", m + ".ScalarMult", "privateKey", 2},
		{m + ".(Bytes).Box", "operation", m + ".Bytes", "nonce", 3},
		{m + ".(Bytes).SignDetached", "operation", m + ".Signature", "privateKey", 1},
		{m + ".(Bytes).AEADXCPEncrypt", "operation", m + ".Bytes", "associatedData", 3},
		{m + ".(Bytes).Auth", "operation", m + ".MAC", "keyMaterial", 1},
		{m + ".(PWHashStr).PWHashVerify", "operation", "error", "password", 1},
		{m + ".(MasterKey).Derive", "operation", m + ".SubKey", "outputLength", 3},
		{m + ".(KXKP).ClientSessionKeys", "operation", "*" + m + ".KXSessionKeys", "publicKey", 1},
		{m + ".NewGenericHashKeyed", "factory", "hash.Hash", "keyMaterial", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "jamesruan-sodium" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want jamesruan-sodium %s -> %s/high", contract, tt.role, tt.returnType)
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
