// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesPquernaOTPContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{"github.com/pquerna/otp.NewKeyFromURL", "factory", "*github.com/pquerna/otp.Key", "keyMaterial", 1},
		{"github.com/pquerna/otp.(*Key).Secret", "output", "string", "", 0},
		{"github.com/pquerna/otp.(*Key).URL", "output", "string", "", 0},
		{"github.com/pquerna/otp.(*Key).Image", "output", "image.Image", "", 2},
		{"github.com/pquerna/otp/totp.GenerateCode", "operation", "string", "keyMaterial", 2},
		{"github.com/pquerna/otp/totp.ValidateCustom", "operation", "bool", "options", 4},
		{"github.com/pquerna/otp/totp.Generate", "factory", "*github.com/pquerna/otp.Key", "options", 1},
		{"github.com/pquerna/otp/hotp.Validate", "operation", "bool", "input", 3},
		{"github.com/pquerna/otp/hotp.GenerateCodeCustom", "operation", "string", "keyMaterial", 3},
		{"github.com/pquerna/otp/hotp.Generate", "factory", "*github.com/pquerna/otp.Key", "options", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "pquerna-otp" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want pquerna-otp %s -> %s/high", contract, tt.role, tt.returnType)
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
