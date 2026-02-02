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

package entities

import (
	"testing"
)

func TestCryptographicAsset_GetKey_Algorithm(t *testing.T) {
	tests := []struct {
		name        string
		family      string
		algoName    string
		expectedKey string
	}{
		{
			name:        "AES-256-GCM with family and name",
			family:      "AES",
			algoName:    "AES-256-GCM",
			expectedKey: "algorithm:AES-256-GCM",
		},
		{
			name:        "SHA-256 with family and name",
			family:      "SHA",
			algoName:    "SHA-256",
			expectedKey: "algorithm:SHA-256",
		},
		{
			name:        "RSA with family only",
			family:      "RSA",
			algoName:    "",
			expectedKey: "algorithm:RSA",
		},
		{
			name:        "ECDSA with family and name",
			family:      "ECDSA",
			algoName:    "ECDSA-P256",
			expectedKey: "algorithm:ECDSA-P256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "algorithm",
					"algorithmFamily": tt.family,
					"algorithmName":   tt.algoName,
				},
			}

			key := asset.GetKey()
			if key != tt.expectedKey {
				t.Errorf("GetKey() = %q, want %q", key, tt.expectedKey)
			}
		})
	}
}

func TestCryptographicAsset_GetKey_RelatedCryptoMaterial(t *testing.T) {
	tests := []struct {
		name         string
		materialType string
		expectedKey  string
	}{
		{
			name:         "Private key",
			materialType: "private-key",
			expectedKey:  "related-crypto-material:private-key",
		},
		{
			name:         "Initialization vector",
			materialType: "initialization-vector",
			expectedKey:  "related-crypto-material:initialization-vector",
		},
		{
			name:         "Digest",
			materialType: "digest",
			expectedKey:  "related-crypto-material:digest",
		},
		{
			name:         "Token",
			materialType: "token",
			expectedKey:  "related-crypto-material:token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := CryptographicAsset{
				Metadata: map[string]string{
					"assetType":    "related-crypto-material",
					"materialType": tt.materialType,
				},
			}

			key := asset.GetKey()
			if key != tt.expectedKey {
				t.Errorf("GetKey() = %q, want %q", key, tt.expectedKey)
			}
		})
	}
}

func TestCryptographicAsset_GetKey_Protocol(t *testing.T) {
	tests := []struct {
		name         string
		protocolType string
		expectedKey  string
	}{
		{
			name:         "TLS",
			protocolType: "tls",
			expectedKey:  "protocol:tls",
		},
		{
			name:         "SSH",
			protocolType: "ssh",
			expectedKey:  "protocol:ssh",
		},
		{
			name:         "IPsec",
			protocolType: "ipsec",
			expectedKey:  "protocol:ipsec",
		},
		{
			name:         "DTLS",
			protocolType: "dtls",
			expectedKey:  "protocol:dtls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := CryptographicAsset{
				Metadata: map[string]string{
					"assetType":    "protocol",
					"protocolType": tt.protocolType,
				},
			}

			key := asset.GetKey()
			if key != tt.expectedKey {
				t.Errorf("GetKey() = %q, want %q", key, tt.expectedKey)
			}
		})
	}
}

func TestCryptographicAsset_GetKey_Certificate(t *testing.T) {
	tests := []struct {
		name         string
		serialNumber string
		startLine    int
		endLine      int
		certType     string
		certFormat   string
		expectedKey  string
	}{
		{
			name:         "Certificate with serial number",
			serialNumber: "1234567890ABCDEF",
			expectedKey:  "certificate:1234567890ABCDEF",
		},
		{
			name:         "Certificate with empty serial uses location and type/format",
			serialNumber: "",
			startLine:    10,
			endLine:      12,
			certType:     "X.509",
			certFormat:   "generation",
			expectedKey:  "certificate:10:12:X.509:generation",
		},
		{
			name:         "Certificate with empty serial and no type/format uses location",
			serialNumber: "",
			startLine:    5,
			endLine:      6,
			expectedKey:  "certificate:5:6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := CryptographicAsset{
				StartLine: tt.startLine,
				EndLine:   tt.endLine,
				Metadata: map[string]string{
					"assetType":               "certificate",
					"certificateSerialNumber": tt.serialNumber,
					"certificateType":         tt.certType,
					"certificateFormat":       tt.certFormat,
				},
			}

			key := asset.GetKey()
			if key != tt.expectedKey {
				t.Errorf("GetKey() = %q, want %q", key, tt.expectedKey)
			}
		})
	}
}

func TestCryptographicAsset_GetKey_UnknownAssetType(t *testing.T) {
	// For unknown asset types, should use fallback location-based key
	asset := CryptographicAsset{
		StartLine: 10,
		EndLine:   15,
		Metadata: map[string]string{
			"assetType": "unknown-type",
		},
	}

	key := asset.GetKey()
	expected := "10:15:unknown-type"
	if key != expected {
		t.Errorf("GetKey() = %q, want %q", key, expected)
	}
}

func TestCryptographicAsset_GetKey_EmptyAssetType(t *testing.T) {
	// For empty asset type, should use fallback location-based key
	asset := CryptographicAsset{
		StartLine: 10,
		EndLine:   15,
		Metadata:  map[string]string{},
	}

	key := asset.GetKey()
	expected := "10:15:"
	if key != expected {
		t.Errorf("GetKey() = %q, want %q", key, expected)
	}
}

func TestCryptographicAsset_GetKey_Uniqueness(t *testing.T) {
	// Test that different assets get different keys
	assets := []struct {
		asset CryptographicAsset
		key   string
	}{
		{
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "algorithm",
					"algorithmFamily": "AES",
					"algorithmName":   "AES-256-GCM",
				},
			},
			key: "algorithm:AES-256-GCM",
		},
		{
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "algorithm",
					"algorithmFamily": "AES",
					"algorithmName":   "AES-128-CBC",
				},
			},
			key: "algorithm:AES-128-CBC",
		},
		{
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "algorithm",
					"algorithmFamily": "RSA",
					"algorithmName":   "RSA-2048",
				},
			},
			key: "algorithm:RSA-2048",
		},
		{
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":    "related-crypto-material",
					"materialType": "private-key",
				},
			},
			key: "related-crypto-material:private-key",
		},
		{
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":    "protocol",
					"protocolType": "tls",
				},
			},
			key: "protocol:tls",
		},
	}

	// Verify all keys are unique
	seenKeys := make(map[string]bool)
	for _, tc := range assets {
		key := tc.asset.GetKey()
		if key != tc.key {
			t.Errorf("Expected key %q, got %q", tc.key, key)
		}
		if seenKeys[key] {
			t.Errorf("Duplicate key found: %q", key)
		}
		seenKeys[key] = true
	}

	if len(seenKeys) != len(assets) {
		t.Errorf("Expected %d unique keys, got %d", len(assets), len(seenKeys))
	}
}
