// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesFlynnNoiseContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{"github.com/flynn/noise.NewCipherSuite", "factory", "github.com/flynn/noise.CipherSuite", "cipher", 3},
		{"github.com/flynn/noise.NewHandshakeState", "factory", "*github.com/flynn/noise.HandshakeState", "options", 1},
		{"github.com/flynn/noise.(*HandshakeState).WriteMessage", "operation", "[]byte", "plaintext", 2},
		{"github.com/flynn/noise.(*HandshakeState).ReadMessage", "operation", "[]byte", "ciphertext", 2},
		{"github.com/flynn/noise.(*HandshakeState).SetPresharedKey", "config", "error", "keyMaterial", 1},
		{"github.com/flynn/noise.(*HandshakeState).ChannelBinding", "output", "[]byte", "", 0},
		{"github.com/flynn/noise.(*CipherState).Encrypt", "operation", "[]byte", "plaintext", 3},
		{"github.com/flynn/noise.(*CipherState).Decrypt", "operation", "[]byte", "ciphertext", 3},
		{"github.com/flynn/noise.(*CipherState).Rekey", "operation", "()", "", 0},
		{"github.com/flynn/noise.(*CipherState).SetNonce", "config", "()", "nonce", 1},
		{"github.com/flynn/noise.UnsafeNewCipherState", "factory", "*github.com/flynn/noise.CipherState", "keyMaterial", 3},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "flynn-noise" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want flynn-noise %s -> %s/high", contract, tt.role, tt.returnType)
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
