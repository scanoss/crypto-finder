// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestLoadEmbeddedGoIncludesJWTLineageContracts asserts representative entries
// from both JWT lineage KBs: the archived github.com/dgrijalva/jwt-go and its
// maintained successor github.com/golang-jwt/jwt/v5. The two are separate
// libraries and must resolve independently.
func TestLoadEmbeddedGoIncludesJWTLineageContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, library, role, property string
		arity                           int
	}{
		{"github.com/dgrijalva/jwt-go.NewWithClaims", "jwt-go", "factory", "algorithm", 2},
		{"github.com/dgrijalva/jwt-go.(*Token).SignedString", "jwt-go", "operation", "keyMaterial", 1},
		{"github.com/dgrijalva/jwt-go.Parse", "jwt-go", "operation", "", 2},
		{"github.com/dgrijalva/jwt-go.(*SigningMethodHMAC).Sign", "jwt-go", "operation", "", 2},
		{"github.com/dgrijalva/jwt-go.ParseECPrivateKeyFromPEM", "jwt-go", "factory", "keyMaterial", 1},
		{"github.com/golang-jwt/jwt/v5.NewWithClaims", "golang-jwt", "factory", "algorithm", 3},
		{"github.com/golang-jwt/jwt/v5.Parse", "golang-jwt", "operation", "", 3},
		{"github.com/golang-jwt/jwt/v5.NewParser", "golang-jwt", "factory", "", 1},
		{"github.com/golang-jwt/jwt/v5.(*SigningMethodEd25519).Verify", "golang-jwt", "operation", "", 3},
		{"github.com/golang-jwt/jwt/v5.ParseEdPublicKeyFromPEM", "golang-jwt", "factory", "keyMaterial", 1},
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
