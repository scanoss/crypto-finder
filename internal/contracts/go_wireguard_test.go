// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"testing"

	"github.com/scanoss/static-engine/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesWireGuardContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("go")
	if err != nil {
		t.Fatalf("Load(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"golang.zx2c4.com/wireguard/device.NewDevice", "factory", "", 2},
		{"golang.zx2c4.com/wireguard/device.(*Device).SetPrivateKey", "config", "keyMaterial", 1},
		{"golang.zx2c4.com/wireguard/device.(*Device).NewPeer", "factory", "keyMaterial", 1},
		{"golang.zx2c4.com/wireguard/device.(*Device).CreateMessageInitiation", "operation", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "wireguard" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want wireguard %s/high", contract, tt.role)
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
