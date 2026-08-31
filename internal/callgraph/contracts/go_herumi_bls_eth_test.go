// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesHerumiBlsEthContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/herumi/bls-eth-go-binary/bls"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".Init", "config", "error", "curve", 1},
		{m + ".(*SecretKey).SetByCSPRNG", "factory", "()", "", 0},
		{m + ".(*SecretKey).SignByte", "operation", "*" + m + ".Sign", "input", 1},
		{m + ".(*Sign).VerifyByte", "operation", "bool", "publicKey", 2},
		{m + ".(*Sign).FastAggregateVerify", "operation", "bool", "", 2},
		{m + ".DHKeyExchange", "operation", m + ".PublicKey", "privateKey", 2},
		{m + ".(*Sign).Serialize", "output", "[]byte", "", 0},
		{m + ".(*SecretKey).Deserialize", "factory", "error", "keyMaterial", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "herumi-bls-eth" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want herumi-bls-eth %s -> %s/high", contract, tt.role, tt.returnType)
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
