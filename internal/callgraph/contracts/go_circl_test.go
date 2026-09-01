// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesCIRCLContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"github.com/cloudflare/circl/kem/schemes.ByName", "factory", "algorithm", 1},
		{"github.com/cloudflare/circl/kem.(Scheme).Encapsulate", "operation", "keyMaterial", 1},
		{"github.com/cloudflare/circl/sign/schemes.ByName", "factory", "algorithm", 1},
		{"github.com/cloudflare/circl/sign.(Scheme).Verify", "operation", "keyMaterial", 4},
		{"github.com/cloudflare/circl/hpke.NewSuite", "factory", "kdf", 3},
		{"github.com/cloudflare/circl/dh/x25519.Shared", "operation", "", 3},
		{"github.com/cloudflare/circl/sign/ed448.Sign", "operation", "keyMaterial", 3},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "circl" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want circl %s/high", contract, tt.role)
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
