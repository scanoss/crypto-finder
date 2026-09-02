// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestLoadEmbeddedGoIncludesJWXContracts asserts representative entries from
// both jwx major-version KBs (github.com/lestrrat-go/jwx and its /v2 path).
// The majors are separate libraries and must resolve independently.
func TestLoadEmbeddedGoIncludesJWXContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, library, role, property string
		arity                           int
	}{
		{"github.com/lestrrat-go/jwx/jws.Sign", "jwx", "operation", "algorithm", 4},
		{"github.com/lestrrat-go/jwx/jwe.Encrypt", "jwx", "operation", "contentEncryption", 6},
		{"github.com/lestrrat-go/jwx/jwt.WithVerify", "jwx", "config", "algorithm", 2},
		{"github.com/lestrrat-go/jwx/jwk.New", "jwx", "factory", "keyMaterial", 1},
		{"github.com/lestrrat-go/jwx/jwk.PublicKeyOf", "jwx", "output", "", 1},
		{"github.com/lestrrat-go/jwx/v2/jws.Sign", "jwx-v2", "operation", "", 2},
		{"github.com/lestrrat-go/jwx/v2/jws.WithKey", "jwx-v2", "config", "algorithm", 3},
		{"github.com/lestrrat-go/jwx/v2/jwt.Parse", "jwx-v2", "operation", "", 2},
		{"github.com/lestrrat-go/jwx/v2/jwk.FromRaw", "jwx-v2", "factory", "keyMaterial", 1},
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
