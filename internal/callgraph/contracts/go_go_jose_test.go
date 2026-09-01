// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestLoadEmbeddedGoIncludesGoJoseContracts asserts representative entries
// from all four go-jose lineage KBs.
func TestLoadEmbeddedGoIncludesGoJoseContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, library, role, property string
		arity                           int
	}{
		{"github.com/square/go-jose.NewSigner", "square-go-jose", "factory", "algorithm", 2},
		{"gopkg.in/square/go-jose.v2.NewEncrypter", "go-jose-v2", "factory", "algorithm", 3},
		{"gopkg.in/square/go-jose.v2/jwt.Signed", "go-jose-v2", "factory", "", 1},
		{"github.com/go-jose/go-jose/v3.(JSONWebSignature).Verify", "go-jose-v3", "operation", "keyMaterial", 1},
		{"github.com/go-jose/go-jose/v3.ParseSigned", "go-jose-v3", "operation", "", 1},
		{"github.com/go-jose/go-jose/v4.ParseSigned", "go-jose-v4", "operation", "", 2},
		{"github.com/go-jose/go-jose/v4.ParseEncrypted", "go-jose-v4", "operation", "", 3},
		{"github.com/go-jose/go-jose/v4/jwt.ParseSigned", "go-jose-v4", "operation", "", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != tt.library || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want %s %s/high", contract, tt.library, tt.role)
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
