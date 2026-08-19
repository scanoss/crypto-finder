// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

func TestResolveContractKeyBits_Derivations(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		derivation string
		wantBits   int
		wantOK     bool
	}{
		{name: "raw bit count", value: "2048", derivation: "argument_value", wantBits: 2048, wantOK: true},
		{name: "non-numeric value", value: "keyBits", derivation: "argument_value"},
		{name: "non-positive value", value: "0", derivation: "argument_value"},
		{name: "byte array allocation", value: "new byte[32]", derivation: "argument_bit_length", wantBits: 256, wantOK: true},
		{name: "spaced byte array allocation", value: "new  byte [ 16 ]", derivation: "argument_bit_length", wantBits: 128, wantOK: true},
		{name: "string literal key material", value: `"0123456789abcdef"`, derivation: "argument_bit_length", wantBits: 128, wantOK: true},
		{name: "opaque key material", value: "material", derivation: "argument_bit_length"},
		{name: "oversized allocation", value: "new byte[999999]", derivation: "argument_bit_length"},
		{name: "sec curve name", value: `"secp256r1"`, derivation: "argument_curve_bits", wantBits: 256, wantOK: true},
		{name: "nist curve alias", value: `"P-521"`, derivation: "argument_curve_bits", wantBits: 521, wantOK: true},
		{name: "x9.62 curve alias", value: `"prime256v1"`, derivation: "argument_curve_bits", wantBits: 256, wantOK: true},
		{name: "brainpool curve", value: `"brainpoolP384r1"`, derivation: "argument_curve_bits", wantBits: 384, wantOK: true},
		{name: "binary curve", value: `"sect571k1"`, derivation: "argument_curve_bits", wantBits: 571, wantOK: true},
		{name: "unknown curve name", value: `"curveX"`, derivation: "argument_curve_bits"},
		{name: "unquoted curve name", value: "secp256r1", derivation: "argument_curve_bits"},
		{name: "unmodelled derivation", value: "2048", derivation: "argument_type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bits, ok := resolveContractKeyBits(tt.value, tt.derivation)
			if ok != tt.wantOK {
				t.Fatalf("resolveContractKeyBits(%q, %q) ok = %v, want %v", tt.value, tt.derivation, ok, tt.wantOK)
			}
			if ok && bits != tt.wantBits {
				t.Fatalf("resolveContractKeyBits(%q, %q) bits = %d, want %d", tt.value, tt.derivation, bits, tt.wantBits)
			}
		})
	}
}
