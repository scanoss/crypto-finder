// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGopenpgpContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"github.com/ProtonMail/gopenpgp/v2/helper.EncryptMessageArmored", "operation", "keyMaterial", 2},
		{"github.com/ProtonMail/gopenpgp/v2/helper.GenerateKey", "factory", "algorithm", 5},
		{"github.com/ProtonMail/gopenpgp/v2/crypto.GenerateKey", "factory", "keySize", 4},
		{"github.com/ProtonMail/gopenpgp/v2/crypto.NewKeyRing", "factory", "", 1},
		{"github.com/ProtonMail/gopenpgp/v2/crypto.(*KeyRing).SignDetached", "operation", "", 1},
		{"github.com/ProtonMail/gopenpgp/v2/crypto.(*KeyRing).DecryptSessionKey", "operation", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "gopenpgp" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want gopenpgp %s/high", contract, tt.role)
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
