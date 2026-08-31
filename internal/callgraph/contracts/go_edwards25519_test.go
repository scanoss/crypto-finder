// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesEdwards25519Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{"filippo.io/edwards25519.NewGeneratorPoint", "factory", "*filippo.io/edwards25519.Point", "", 0},
		{"filippo.io/edwards25519.(*Point).SetBytes", "factory", "*filippo.io/edwards25519.Point", "input", 1},
		{"filippo.io/edwards25519.(*Scalar).SetBytesWithClamping", "factory", "*filippo.io/edwards25519.Scalar", "keyMaterial", 1},
		{"filippo.io/edwards25519.(*Point).ScalarBaseMult", "operation", "*filippo.io/edwards25519.Point", "keyMaterial", 1},
		{"filippo.io/edwards25519.(*Point).ScalarMult", "operation", "*filippo.io/edwards25519.Point", "keyMaterial", 2},
		{"filippo.io/edwards25519.(*Point).VarTimeDoubleScalarBaseMult", "operation", "*filippo.io/edwards25519.Point", "", 3},
		{"filippo.io/edwards25519.(*Scalar).Invert", "operation", "*filippo.io/edwards25519.Scalar", "", 1},
		{"filippo.io/edwards25519.(*Point).BytesMontgomery", "output", "[]byte", "", 0},
		{"filippo.io/edwards25519.(*Scalar).Bytes", "output", "[]byte", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "edwards25519" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want edwards25519 %s -> %s/high", contract, tt.role, tt.returnType)
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
