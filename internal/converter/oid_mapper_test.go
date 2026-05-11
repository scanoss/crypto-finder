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
	if len(mapper.nameToOID) == 0 {
		t.Error("nameToOID map is empty")
	}

	if len(mapper.familyToOID) == 0 {
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

func TestOIDMapper_NameMapContainsExpectedAlgorithms(t *testing.T) {
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
			_, got := mapper.nameToOID[normalizeAlgorithmName(tt.name)]
			if got != tt.expected {
				t.Errorf("nameToOID[%q] presence = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestOIDMapper_FamilyMapContainsExpectedFamilies(t *testing.T) {
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
			_, got := mapper.familyToOID[normalizeAlgorithmName(tt.family)]
			if got != tt.expected {
				t.Errorf("familyToOID[%q] presence = %v, want %v", tt.family, got, tt.expected)
			}
		})
	}
}

func TestOIDMapper_ResolveOID_PostQuantumVariants(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		// ML-DSA variants (FIPS 204 / RFC 9881)
		{"ML-DSA-44 by name", "ML-DSA-44", "", OIDMLDSA44},
		{"ML-DSA-65 by name", "ML-DSA-65", "", OIDMLDSA65},
		{"ML-DSA-87 by name", "ML-DSA-87", "", OIDMLDSA87},
		{"ML-DSA family", "", "ML-DSA", OIDSigAlgs},
		{"MLDSA family alias", "", "MLDSA", OIDSigAlgs},

		// ML-KEM variants (FIPS 203)
		{"ML-KEM-512 by name", "ML-KEM-512", "", OIDMLKEM512},
		{"ML-KEM-768 by name", "ML-KEM-768", "", OIDMLKEM768},
		{"ML-KEM-1024 by name", "ML-KEM-1024", "", OIDMLKEM1024},
		{"ML-KEM family", "", "ML-KEM", OIDKEMs},
		{"MLKEM family alias", "", "MLKEM", OIDKEMs},

		// SLH-DSA SHA2 variants (FIPS 205 / RFC 9814/9909)
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", "", OIDSLHDSASHA2128s},
		{"SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", "", OIDSLHDSASHA2128f},
		{"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s", "", OIDSLHDSASHA2192s},
		{"SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f", "", OIDSLHDSASHA2192f},
		{"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s", "", OIDSLHDSASHA2256s},
		{"SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f", "", OIDSLHDSASHA2256f},

		// SLH-DSA SHAKE variants
		{"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", "", OIDSLHDSASHAKE128s},
		{"SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", "", OIDSLHDSASHAKE128f},
		{"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", "", OIDSLHDSASHAKE192s},
		{"SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", "", OIDSLHDSASHAKE192f},
		{"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", "", OIDSLHDSASHAKE256s},
		{"SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", "", OIDSLHDSASHAKE256f},

		// SLH-DSA family fallback
		{"SLH-DSA family", "", "SLH-DSA", OIDSigAlgs},
		{"SLHDSA family alias", "", "SLHDSA", OIDSigAlgs},
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

func TestOIDMapper_ResolveOID_ClassicMissing(t *testing.T) {
	mapper := NewOIDMapper()

	tests := []struct {
		name     string
		algoName string
		family   string
		wantOID  string
	}{
		// Hash algorithms
		{"MD5 by name", "MD5", "", OIDMD5},
		{"MD5 family", "", "MD5", OIDMD5},
		{"MD4 by name", "MD4", "", OIDMD4},
		{"MD4 family", "", "MD4", OIDMD4},

		// Key derivation functions
		{"PBKDF2 by name", "PBKDF2", "", OIDPBKDF2},
		{"PBKDF2 family", "", "PBKDF2", OIDPBKDF2},
		{"scrypt by name", "scrypt", "", OIDScrypt},
		{"scrypt family", "", "scrypt", OIDScrypt},

		// Curve25519/448 key exchange
		{"X25519 by name", "X25519", "", OIDX25519},
		{"X25519 family", "", "X25519", OIDX25519},
		{"X448 by name", "X448", "", OIDX448},
		{"X448 family", "", "X448", OIDX448},

		// EdDSA signatures
		{"Ed25519 by name", "Ed25519", "", OIDEd25519},
		{"Ed448 by name", "Ed448", "", OIDEd448},
		{"EdDSA family", "", "EdDSA", OIDCurves25519448},

		// Diffie-Hellman
		{"DH by name", "DH", "", OIDDH},
		{"DH family", "", "DH", OIDDH},
		{"FFDH by name", "FFDH", "", OIDDH},
		{"FFDH family", "", "FFDH", OIDDH},

		// ECDH
		{"ECDH by name", "ECDH", "", OIDECPublicKey},
		{"ECDH family", "", "ECDH", OIDECPublicKey},

		// Chinese standards
		{"SM2 by name", "SM2", "", OIDSM2},
		{"SM2 family", "", "SM2", OIDSM2},
		{"SM3 by name", "SM3", "", OIDSM3},
		{"SM3 family", "", "SM3", OIDSM3},

		// Deprecated ciphers
		{"RC4 by name", "RC4", "", OIDRC4},
		{"RC4 family", "", "RC4", OIDRC4},

		// RSA-OAEP
		{"RSA-OAEP by name", "RSA-OAEP", "", OIDRSAOAEP},
		{"RSAES-OAEP by name", "RSAES-OAEP", "", OIDRSAOAEP},

		// HMAC family
		{"HMAC family", "", "HMAC", OIDHMACBase},
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

func TestOIDMapper_NIST_CSOR_PostQuantum_OIDs(t *testing.T) {
	// Verify specific NIST CSOR post-quantum OIDs match expected values.
	tests := []struct {
		oid     string
		wantOID string
		desc    string
	}{
		// ML-DSA (RFC 9881)
		{OIDMLDSA44, "2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
		{OIDMLDSA65, "2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
		{OIDMLDSA87, "2.16.840.1.101.3.4.3.19", "ML-DSA-87"},

		// ML-KEM (NIST CSOR)
		{OIDKEMs, "2.16.840.1.101.3.4.4", "KEMs parent"},
		{OIDMLKEM512, "2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
		{OIDMLKEM768, "2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{OIDMLKEM1024, "2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},

		// SLH-DSA SHA2 (RFC 9814/9909)
		{OIDSLHDSASHA2128s, "2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"},
		{OIDSLHDSASHA2128f, "2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"},
		{OIDSLHDSASHA2192s, "2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s"},
		{OIDSLHDSASHA2192f, "2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f"},
		{OIDSLHDSASHA2256s, "2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"},
		{OIDSLHDSASHA2256f, "2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f"},

		// SLH-DSA SHAKE (RFC 9814/9909)
		{OIDSLHDSASHAKE128s, "2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"},
		{OIDSLHDSASHAKE128f, "2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f"},
		{OIDSLHDSASHAKE192s, "2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s"},
		{OIDSLHDSASHAKE192f, "2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f"},
		{OIDSLHDSASHAKE256s, "2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s"},
		{OIDSLHDSASHAKE256f, "2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if tt.oid != tt.wantOID {
				t.Errorf("OID constant = %v, want %v", tt.oid, tt.wantOID)
			}
		})
	}
}

func TestOIDMapper_GetCounts(t *testing.T) {
	mapper := NewOIDMapper()

	nameCount := len(mapper.nameToOID)
	familyCount := len(mapper.familyToOID)

	// We should have a reasonable number of mappings
	if nameCount < 85 {
		t.Errorf("Expected at least 85 name mappings, got %d", nameCount)
	}

	if familyCount < 20 {
		t.Errorf("Expected at least 20 unique family mappings after normalization, got %d", familyCount)
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
