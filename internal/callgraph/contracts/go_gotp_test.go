// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGotpContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{"github.com/xlzd/gotp.NewTOTP", "factory", "*github.com/xlzd/gotp.TOTP", "keyMaterial", 4},
		{"github.com/xlzd/gotp.NewDefaultTOTP", "factory", "*github.com/xlzd/gotp.TOTP", "keyMaterial", 1},
		{"github.com/xlzd/gotp.NewHOTP", "factory", "*github.com/xlzd/gotp.HOTP", "keyMaterial", 3},
		{"github.com/xlzd/gotp.NewDefaultHOTP", "factory", "*github.com/xlzd/gotp.HOTP", "keyMaterial", 1},
		{"github.com/xlzd/gotp.(*TOTP).Now", "operation", "string", "", 0},
		{"github.com/xlzd/gotp.(*TOTP).Verify", "operation", "bool", "input", 2},
		{"github.com/xlzd/gotp.(*HOTP).At", "operation", "string", "", 1},
		{"github.com/xlzd/gotp.(*TOTP).ProvisioningUri", "output", "string", "", 2},
		{"github.com/xlzd/gotp.(*HOTP).ProvisioningUri", "output", "string", "", 3},
		{"github.com/xlzd/gotp.BuildUri", "output", "string", "algorithm", 8},
		{"github.com/xlzd/gotp.RandomSecret", "factory", "string", "outputLength", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "gotp" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want gotp %s -> %s/high", contract, tt.role, tt.returnType)
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
