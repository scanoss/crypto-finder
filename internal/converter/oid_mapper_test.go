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
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestNewOIDMapper(t *testing.T) {
	mapper := NewOIDMapper()

	if mapper == nil {
		t.Fatal("NewOIDMapper() returned nil")
	}

	if mapper.nameToOID == nil {
		t.Error("nameToOID map is nil")
	}

	if mapper.familyToOID == nil {
		t.Error("familyToOID map is nil")
	}

	// Verify mappings were initialized
	if mapper.GetNameOIDCount() == 0 {
		t.Error("nameToOID map is empty")
	}

	if mapper.GetFamilyOIDCount() == 0 {
		t.Error("familyToOID map is empty")
	}
}

func TestOIDMapper_ResolveOIDAESVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		paramSet string
		mode     string
		wantOID  string
	}{
		// AES-128 variants - specific names
		{"AES-128-CBC", "AES-128-CBC", "", "", "", OIDAES128CBC},
		{"AES-128-GCM", "AES-128-GCM", "", "", "", OIDAES128GCM},
		{"AES-128-ECB", "AES-128-ECB", "", "", "", OIDAES128ECB},
		{"AES-128-CCM", "AES-128-CCM", "", "", "", OIDAES128CCM},

		// AES-192 variants
		{"AES-192-CBC", "AES-192-CBC", "", "", "", OIDAES192CBC},
		{"AES-192-GCM", "AES-192-GCM", "", "", "", OIDAES192GCM},

		// AES-256 variants
		{"AES-256-CBC", "AES-256-CBC", "", "", "", OIDAES256CBC},
		{"AES-256-GCM", "AES-256-GCM", "", "", "", OIDAES256GCM},
		{"AES-256-ECB", "AES-256-ECB", "", "", "", OIDAES256ECB},

		// AES via constructed name (family + paramSet + mode)
		{"AES-128-CBC constructed", "", "AES", "128", "CBC", OIDAES128CBC},
		{"AES-256-GCM constructed", "", "AES", "256", "GCM", OIDAES256GCM},

		// AES family fallback
		{"AES family only", "", "AES", "", "", OIDAES},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":                   tt.algoName,
					"algorithmFamily":                 tt.family,
					"algorithmParameterSetIdentifier": tt.paramSet,
					"algorithmMode":                   tt.mode,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOIDSHAVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		// SHA-2 variants
		{"SHA-256", "SHA-256", "", OIDSHA256},
		{"SHA-384", "SHA-384", "", OIDSHA384},
		{"SHA-512", "SHA-512", "", OIDSHA512},
		{"SHA-224", "SHA-224", "", OIDSHA224},

		// SHA-3 variants
		{"SHA3-256", "SHA3-256", "", OIDSHA3256},
		{"SHA3-512", "SHA3-512", "", OIDSHA3512},

		// SHAKE variants
		{"SHAKE128", "SHAKE128", "", OIDSHAKE128},
		{"SHAKE256", "SHAKE256", "", OIDSHAKE256},

		// Family fallback
		{"SHA family", "", "SHA", OIDHashAlgs},
		{"SHA2 family", "", "SHA2", OIDHashAlgs},
		{"SHA3 family", "", "SHA3", OIDHashAlgs},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":   tt.algoName,
					"algorithmFamily": tt.family,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOIDRSAVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		{"RSA base", "RSA", "", OIDRSA},
		{"RSA family", "", "RSA", OIDRSA},
		{"RSA-SHA256", "RSA-SHA256", "", OIDRSASHA256},
		{"RSA-SHA384", "RSA-SHA384", "", OIDRSASHA384},
		{"RSA-SHA512", "RSA-SHA512", "", OIDRSASHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":   tt.algoName,
					"algorithmFamily": tt.family,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_ECDSAVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		{"ECDSA base", "ECDSA", "", OIDECPublicKey},
		{"ECDSA family", "", "ECDSA", OIDECPublicKey},
		{"ECDSA-SHA256", "ECDSA-SHA256", "", OIDECDSASHA256},
		{"ECDSA-SHA384", "ECDSA-SHA384", "", OIDECDSASHA384},
		{"ECDSA-SHA512", "ECDSA-SHA512", "", OIDECDSASHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":   tt.algoName,
					"algorithmFamily": tt.family,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_HMACVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		wantOID  string
	}{
		{"HMAC-SHA256", "HMAC-SHA256", OIDHMACSHA256},
		{"HMAC-SHA384", "HMAC-SHA384", OIDHMACSHA384},
		{"HMAC-SHA512", "HMAC-SHA512", OIDHMACSHA512},
		{"HMAC-SHA1", "HMAC-SHA1", OIDHMACSHA1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName": tt.algoName,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_LegacyAlgorithms(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		// DES variants
		{"DES", "DES", "", OIDDESCDC},
		{"DES family", "", "DES", OIDDESCDC},
		{"DES-ECB", "DES-ECB", "", OIDDESECB},
		{"DES-CBC", "DES-CBC", "", OIDDESCDC},

		// 3DES variants with aliases
		{"3DES", "3DES", "", OIDDESEDE},
		{"DES-EDE", "DES-EDE", "", OIDDESEDE},
		{"TRIPLEDES", "TRIPLEDES", "", OIDDESEDE},

		// SHA-1
		{"SHA-1", "SHA-1", "", OIDSHA1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":   tt.algoName,
					"algorithmFamily": tt.family,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID() = %v, want %v", got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_CaseInsensitive(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		input   string
		wantOID string
	}{
		{"aes-128-cbc", OIDAES128CBC},
		{"AES-128-CBC", OIDAES128CBC},
		{"Aes-128-Cbc", OIDAES128CBC},
		{"sha-256", OIDSHA256},
		{"SHA-256", OIDSHA256},
		{"ShA-256", OIDSHA256},
		{"rsa-sha256", OIDRSASHA256},
		{"RSA-SHA256", OIDRSASHA256},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName": tt.input,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID(%q) = %v, want %v", tt.input, got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_SeparatorNormalization(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		input   string
		wantOID string
	}{
		{"AES_128_CBC", OIDAES128CBC},   // underscores
		{"AES 128 CBC", OIDAES128CBC},   // spaces
		{"AES__128__CBC", OIDAES128CBC}, // double underscores
		{"SHA_256", OIDSHA256},          // underscore
		{"RSA_SHA256", OIDRSASHA256},    // underscore
		{"AES-128--CBC", OIDAES128CBC},  // double hyphen
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName": tt.input,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID(%q) = %v, want %v", tt.input, got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_FamilyAliases(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		family  string
		wantOID string
	}{
		{"SHA", OIDHashAlgs},
		{"SHA2", OIDHashAlgs},     // alias
		{"SHA-2", OIDHashAlgs},    // alias with hyphen
		{"SHA3", OIDHashAlgs},     // alias
		{"SHA-3", OIDHashAlgs},    // alias with hyphen
		{"3DES", OIDDESEDE},       // alias
		{"TRIPLEDES", OIDDESEDE},  // alias
		{"3-DES", OIDDESEDE},      // alias with hyphen
		{"TRIPLE-DES", OIDDESEDE}, // alias with hyphen
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmFamily": tt.family,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != tt.wantOID {
				t.Errorf("ResolveOID(family=%q) = %v, want %v", tt.family, got, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_UnknownAlgorithm(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		paramSet string
		mode     string
	}{
		{"completely unknown", "UNKNOWN-ALGO-999", "", "", ""},
		{"unknown family", "", "UNKNOWN-FAMILY", "", ""},
		// Note: "unknown variant with known family" is handled by hybrid approach
		// It should return the family OID (AES), not empty string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: map[string]string{
					"algorithmName":                   tt.algoName,
					"algorithmFamily":                 tt.family,
					"algorithmParameterSetIdentifier": tt.paramSet,
					"algorithmMode":                   tt.mode,
				},
			}

			got := mapper.ResolveOID(asset)
			if got != "" {
				t.Errorf("ResolveOID() = %v, want empty string for unknown algorithm", got)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_UnknownVariantWithKnownFamily(t *testing.T) {
	mapper := NewOIDMapper()

	// Test that unknown variants with known families fall back to family OID
	asset := &entities.CryptographicAsset{
		Metadata: map[string]string{
			"algorithmName":                   "AES-999-XYZ",
			"algorithmFamily":                 "AES",
			"algorithmParameterSetIdentifier": "999",
			"algorithmMode":                   "XYZ",
		},
	}

	got := mapper.ResolveOID(asset)
	// Should return the AES family OID, not empty
	if got != OIDAES {
		t.Errorf("ResolveOID() = %v, want %v (AES family OID)", got, OIDAES)
	}
}

func TestOIDMapper_AllOIDs_ValidFormat(t *testing.T) {
	mapper := NewOIDMapper()

	// Check all name mappings
	for name, oid := range mapper.nameToOID {
		// OID should not be empty
		if oid == "" {
			t.Errorf("OID for %q is empty", name)
		}

		// OID should match expected format (dot-separated numbers)
		parts := strings.Split(oid, ".")
		if len(parts) < 2 {
			t.Errorf("OID for %q has invalid format: %s (expected at least 2 parts)", name, oid)
		}

		// Each part should be numeric
		for _, part := range parts {
			if part == "" {
				t.Errorf("OID for %q has empty part: %s", name, oid)
				break
			}
			// Check if numeric
			for _, r := range part {
				if r < '0' || r > '9' {
					t.Errorf("OID for %q has non-numeric part: %s", name, oid)
					break
				}
			}
		}
	}

	// Check all family mappings
	for family, oid := range mapper.familyToOID {
		if oid == "" {
			t.Errorf("OID for family %q is empty", family)
		}

		parts := strings.Split(oid, ".")
		if len(parts) < 2 {
			t.Errorf("OID for family %q has invalid format: %s", family, oid)
		}
	}
}

func TestOIDMapper_NIST_CSOR_AES_OIDs(t *testing.T) {
	// Verify specific NIST CSOR AES OIDs match expected values
	tests := []struct {
		oid     string
		wantOID string
		desc    string
	}{
		{OIDAES, "2.16.840.1.101.3.4.1", "AES parent"},
		{OIDAES128CBC, "2.16.840.1.101.3.4.1.2", "AES-128-CBC"},
		{OIDAES128GCM, "2.16.840.1.101.3.4.1.6", "AES-128-GCM"},
		{OIDAES256CBC, "2.16.840.1.101.3.4.1.42", "AES-256-CBC"},
		{OIDAES256GCM, "2.16.840.1.101.3.4.1.46", "AES-256-GCM"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if tt.oid != tt.wantOID {
				t.Errorf("OID constant = %v, want %v", tt.oid, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_NIST_CSOR_SHA_OIDs(t *testing.T) {
	// Verify specific NIST CSOR SHA OIDs match expected values
	tests := []struct {
		oid     string
		wantOID string
		desc    string
	}{
		{OIDHashAlgs, "2.16.840.1.101.3.4.2", "Hash algorithms parent"},
		{OIDSHA256, "2.16.840.1.101.3.4.2.1", "SHA-256"},
		{OIDSHA384, "2.16.840.1.101.3.4.2.2", "SHA-384"},
		{OIDSHA512, "2.16.840.1.101.3.4.2.3", "SHA-512"},
		{OIDSHA3256, "2.16.840.1.101.3.4.2.8", "SHA3-256"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if tt.oid != tt.wantOID {
				t.Errorf("OID constant = %v, want %v", tt.oid, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_IsKnownAlgorithm(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		expected bool
	}{
		{"AES-128-CBC", true},
		{"SHA-256", true},
		{"RSA-SHA256", true},
		{"UNKNOWN-ALGORITHM", false},
		{"FOOBAR-999", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapper.IsKnownAlgorithm(tt.name)
			if got != tt.expected {
				t.Errorf("IsKnownAlgorithm(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestOIDMapper_IsKnownFamily(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		family   string
		expected bool
	}{
		{"AES", true},
		{"SHA", true},
		{"RSA", true},
		{"ECDSA", true},
		{"UNKNOWN", false},
		{"FOOBAR", false},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			got := mapper.IsKnownFamily(tt.family)
			if got != tt.expected {
				t.Errorf("IsKnownFamily(%q) = %v, want %v", tt.family, got, tt.expected)
			}
		})
	}
}

func TestOIDMapper_GetCounts(t *testing.T) {
	mapper := NewOIDMapper()

	nameCount := mapper.GetNameOIDCount()
	familyCount := mapper.GetFamilyOIDCount()

	// We should have a reasonable number of mappings
	if nameCount < 50 {
		t.Errorf("Expected at least 50 name mappings, got %d", nameCount)
	}

	if familyCount < 7 {
		t.Errorf("Expected at least 7 unique family mappings after normalization, got %d", familyCount)
	}

	t.Logf("OID Mapper initialized with %d specific name mappings and %d family mappings",
		nameCount, familyCount)
}

func TestNormalizeAlgorithmName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Case normalization
		{"aes-128-cbc", "AES-128-CBC"},
		{"AES-128-CBC", "AES-128-CBC"},
		{"Aes-128-Cbc", "AES-128-CBC"},

		// Separator normalization
		{"AES_128_CBC", "AES-128-CBC"},
		{"AES 128 CBC", "AES-128-CBC"},

		// Whitespace trimming
		{"  AES-128-CBC  ", "AES-128-CBC"},
		{"AES-128-CBC\t", "AES-128-CBC"},

		// Duplicate separators
		{"AES__128__CBC", "AES-128-CBC"},
		{"AES--128--CBC", "AES-128-CBC"},
		{"AES_ 128 _CBC", "AES-128-CBC"},

		// Aliases
		{"SHA2", "SHA"},
		{"sha2", "SHA"},
		{"SHA-2", "SHA"},
		{"3DES", "DES-EDE"},
		{"3des", "DES-EDE"},
		{"TRIPLEDES", "DES-EDE"},
		{"3-DES", "DES-EDE"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeAlgorithmName(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeAlgorithmName(%q) = %q, want %q",
					tt.input, got, tt.expected)
			}
		})
	}
}

func TestConstructAlgorithmName(t *testing.T) {
	tests := []struct {
		family   string
		paramSet string
		mode     string
		expected string
	}{
		{"AES", "128", "CBC", "AES-128-CBC"},
		{"AES", "256", "GCM", "AES-256-GCM"},
		{"SHA", "256", "", "SHA-256"},
		{"RSA", "2048", "", "RSA-2048"},
		{"AES", "", "ECB", "AES-ECB"},
		{"AES", "", "", "AES"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := constructAlgorithmName(tt.family, tt.paramSet, tt.mode)
			if got != tt.expected {
				t.Errorf("constructAlgorithmName(%q, %q, %q) = %q, want %q",
					tt.family, tt.paramSet, tt.mode, got, tt.expected)
			}
		})
	}
}
