// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package converter

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestMapPrimitiveToCycloneDX(t *testing.T) {
	tests := []struct {
		name      string
		primitive string
		want      cdx.CryptoPrimitive
		wantErr   bool
	}{
		// Valid primitives
		{
			name:      "Authenticated Encryption",
			primitive: "ae",
			want:      cdx.CryptoPrimitiveAE,
			wantErr:   false,
		},
		{
			name:      "Block Cipher",
			primitive: "block-cipher",
			want:      cdx.CryptoPrimitiveBlockCipher,
			wantErr:   false,
		},
		{
			name:      "Stream Cipher",
			primitive: "stream-cipher",
			want:      cdx.CryptoPrimitiveStreamCipher,
			wantErr:   false,
		},
		{
			name:      "Hash Function",
			primitive: "hash",
			want:      cdx.CryptoPrimitiveHash,
			wantErr:   false,
		},
		{
			name:      "Signature",
			primitive: "signature",
			want:      cdx.CryptoPrimitiveSignature,
			wantErr:   false,
		},
		{
			name:      "Message Authentication Code",
			primitive: "mac",
			want:      cdx.CryptoPrimitiveMAC,
			wantErr:   false,
		},
		{
			name:      "Key Derivation Function",
			primitive: "kdf",
			want:      cdx.CryptoPrimitiveKDF,
			wantErr:   false,
		},
		{
			name:      "Public Key Encryption",
			primitive: "pke",
			want:      cdx.CryptoPrimitivePKE,
			wantErr:   false,
		},
		{
			name:      "Key Encapsulation Mechanism",
			primitive: "kem",
			want:      cdx.CryptoPrimitiveKEM,
			wantErr:   false,
		},
		{
			name:      "Deterministic Random Bit Generator",
			primitive: "drbg",
			want:      cdx.CryptoPrimitiveDRBG,
			wantErr:   false,
		},
		{
			name:      "Other",
			primitive: "other",
			want:      cdx.CryptoPrimitiveOther,
			wantErr:   false,
		},

		// Case insensitivity
		{
			name:      "Uppercase AE",
			primitive: "AE",
			want:      cdx.CryptoPrimitiveAE,
			wantErr:   false,
		},
		{
			name:      "Mixed Case Block-Cipher",
			primitive: "Block-Cipher",
			want:      cdx.CryptoPrimitiveBlockCipher,
			wantErr:   false,
		},
		{
			name:      "Uppercase HASH",
			primitive: "HASH",
			want:      cdx.CryptoPrimitiveHash,
			wantErr:   false,
		},

		// Whitespace handling
		{
			name:      "Primitive with leading whitespace",
			primitive: "  ae",
			want:      cdx.CryptoPrimitiveAE,
			wantErr:   false,
		},
		{
			name:      "Primitive with trailing whitespace",
			primitive: "hash  ",
			want:      cdx.CryptoPrimitiveHash,
			wantErr:   false,
		},
		{
			name:      "Primitive with both leading and trailing whitespace",
			primitive: "  signature  ",
			want:      cdx.CryptoPrimitiveSignature,
			wantErr:   false,
		},

		// Invalid primitives
		{
			name:      "Unknown primitive",
			primitive: "unknown",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "Empty primitive",
			primitive: "",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "Invalid format",
			primitive: "block_cipher",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "Typo in primitive",
			primitive: "hassh",
			want:      "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mapPrimitiveToCycloneDX(tt.primitive)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("mapPrimitiveToCycloneDX(%q) error = %v, wantErr %v", tt.primitive, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// For error cases, verify error message contains the primitive
				if err == nil {
					t.Error("Expected error but got none")
				} else if !contains(err.Error(), "primitive") {
					t.Errorf("Error message should mention 'primitive', got: %v", err)
				}
				return
			}

			// Check result
			if got != tt.want {
				t.Errorf("mapPrimitiveToCycloneDX(%q) = %q, want %q", tt.primitive, got, tt.want)
			}
		})
	}
}

func TestAllPrimitivesAreCovered(t *testing.T) {
	// Test that all standard CycloneDX primitives are supported
	standardPrimitives := []struct {
		input string
		want  cdx.CryptoPrimitive
	}{
		{"ae", cdx.CryptoPrimitiveAE},
		{"block-cipher", cdx.CryptoPrimitiveBlockCipher},
		{"stream-cipher", cdx.CryptoPrimitiveStreamCipher},
		{"hash", cdx.CryptoPrimitiveHash},
		{"signature", cdx.CryptoPrimitiveSignature},
		{"mac", cdx.CryptoPrimitiveMAC},
		{"kdf", cdx.CryptoPrimitiveKDF},
		{"pke", cdx.CryptoPrimitivePKE},
		{"kem", cdx.CryptoPrimitiveKEM},
		{"drbg", cdx.CryptoPrimitiveDRBG},
		{"other", cdx.CryptoPrimitiveOther},
	}

	for _, prim := range standardPrimitives {
		t.Run(string(prim.want), func(t *testing.T) {
			got, err := mapPrimitiveToCycloneDX(prim.input)
			if err != nil {
				t.Errorf("Standard primitive %q should not error: %v", prim.input, err)
			}
			if got != prim.want {
				t.Errorf("mapPrimitiveToCycloneDX(%q) = %q, want %q", prim.input, got, prim.want)
			}
		})
	}
}

func TestPrimitiveRoundTrip(t *testing.T) {
	// Test that mapping and back produces consistent results
	primitives := []string{
		"ae", "block-cipher", "stream-cipher", "hash",
		"signature", "mac", "kdf", "pke", "kem", "drbg", "other",
	}

	for _, primitive := range primitives {
		t.Run(primitive, func(t *testing.T) {
			// Map to CycloneDX
			cdxPrimitive, err := mapPrimitiveToCycloneDX(primitive)
			if err != nil {
				t.Fatalf("Unexpected error for %q: %v", primitive, err)
			}

			// Verify the CycloneDX value is not empty
			if cdxPrimitive == "" {
				t.Errorf("mapPrimitiveToCycloneDX(%q) returned empty string", primitive)
			}

			// Verify it matches the expected constant string value
			expectedValue := string(cdxPrimitive)
			if expectedValue != primitive {
				t.Errorf("CycloneDX primitive value = %q, want %q", expectedValue, primitive)
			}
		})
	}
}
