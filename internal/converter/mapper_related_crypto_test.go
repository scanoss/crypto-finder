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

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Helper function for string matching.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestRelatedCryptoMapper_MapToComponent(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	tests := []struct {
		name        string
		fixtureFile string
		wantName    string
		wantErr     bool
		errContains string
	}{
		{
			name:        "SHA-256 digest",
			fixtureFile: "digest_sha256.json",
			wantName:    "digest",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := loadFixture(t, tt.fixtureFile)
			if len(report.Findings) == 0 {
				t.Fatal("Fixture has no findings")
			}

			finding := &report.Findings[0]
			if len(finding.CryptographicAssets) == 0 {
				t.Fatal("Finding has no assets")
			}

			asset := &finding.CryptographicAssets[0]

			// Run mapper
			component, err := mapper.MapToComponentWithEvidence(asset)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("MapToComponent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			// Validate component
			if component == nil {
				t.Fatal("MapToComponent() returned nil component")
			}

			// Check name matches expected material type
			if component.Name != tt.wantName {
				t.Errorf("Component name = %q, want %q", component.Name, tt.wantName)
			}

			// Check BOM ref
			if component.BOMRef == "" {
				t.Error("Component BOMRef is empty")
			}

			// Check description
			if component.Description == "" {
				t.Error("Component Description is empty for digest")
			}

			// Check crypto properties
			if component.CryptoProperties == nil {
				t.Fatal("Component missing CryptoProperties")
			}

			if string(component.CryptoProperties.AssetType) != "related-crypto-material" {
				t.Errorf("AssetType = %q, want %q", component.CryptoProperties.AssetType, "related-crypto-material")
			}

			// Note: Properties are no longer set by MapToComponentWithEvidence
			// They are built by the converter's buildEvidence method instead
		})
	}
}

func TestRelatedCryptoMapper_ValidateRequiredFields(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	tests := []struct {
		name        string
		metadata    map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name: "Complete required fields",
			metadata: map[string]string{
				"assetType":    "related-crypto-material",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr: false,
		},
		{
			name: "Missing assetType",
			metadata: map[string]string{
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Wrong assetType",
			metadata: map[string]string{
				"assetType":    "algorithm",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "assetType",
		},
		{
			name: "Missing materialType",
			metadata: map[string]string{
				"assetType": "related-crypto-material",
				"algorithm": "SHA-256",
			},
			wantErr:     true,
			errContains: "materialType",
		},
		{
			name: "Empty materialType",
			metadata: map[string]string{
				"assetType":    "related-crypto-material",
				"materialType": "  ",
				"algorithm":    "SHA-256",
			},
			wantErr:     true,
			errContains: "materialType",
		},
		{
			name: "Case-insensitive assetType",
			metadata: map[string]string{
				"assetType":    "RELATED-CRYPTO-MATERIAL",
				"materialType": "digest",
				"algorithm":    "SHA-256",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: tt.metadata,
			}

			err := mapper.validateRequiredFields(asset)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequiredFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestRelatedCryptoMapper_SetsRawCryptoFunctionProperty(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	asset := &entities.CryptographicAsset{
		Metadata: map[string]string{
			"assetType":         "related-crypto-material",
			"materialType":      "private-key",
			"cryptoFunction":    "load",
			"materialAlgorithm": "RSA",
		},
	}

	component, err := mapper.MapToComponentWithEvidence(asset)
	if err != nil {
		t.Fatalf("MapToComponentWithEvidence() unexpected error: %v", err)
	}

	if component.Properties == nil || len(*component.Properties) != 1 {
		t.Fatalf("Properties = %v, want one property", component.Properties)
	}

	property := (*component.Properties)[0]
	if property != (cdx.Property{Name: scanossCryptoFunctionPropertyName, Value: "load"}) {
		t.Fatalf("Property = %#v, want raw cryptoFunction property", property)
	}
}

func TestRelatedCryptoMapper_SetsPublicKeySize(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	asset := &entities.CryptographicAsset{
		Metadata: map[string]string{
			"assetType":     "related-crypto-material",
			"materialType":  "public-key",
			"materialSize":  "2048",
			"publicKeySize": "2048",
		},
	}

	component, err := mapper.MapToComponentWithEvidence(asset)
	if err != nil {
		t.Fatalf("MapToComponentWithEvidence() unexpected error: %v", err)
	}

	props := component.CryptoProperties.RelatedCryptoMaterialProperties
	if props == nil || props.Size == nil {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %v, want 2048", props)
	}
	if *props.Size != 2048 {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %d, want 2048", *props.Size)
	}

	if component.Properties == nil || len(*component.Properties) != 1 {
		t.Fatalf("Properties = %v, want one property", component.Properties)
	}

	property := (*component.Properties)[0]
	if property != (cdx.Property{Name: scanossPublicKeySizePropertyName, Value: "2048"}) {
		t.Fatalf("Property = %#v, want public key size property", property)
	}
}

func TestRelatedCryptoMapper_SetsPrivateKeySizeWithoutMaterialSize(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	asset := &entities.CryptographicAsset{
		Metadata: map[string]string{
			"assetType":      "related-crypto-material",
			"materialType":   "private-key",
			"privateKeySize": "4096",
		},
	}

	component, err := mapper.MapToComponentWithEvidence(asset)
	if err != nil {
		t.Fatalf("MapToComponentWithEvidence() unexpected error: %v", err)
	}

	props := component.CryptoProperties.RelatedCryptoMaterialProperties
	if props == nil || props.Size == nil {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %v, want 4096", props)
	}
	if *props.Size != 4096 {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %d, want 4096", *props.Size)
	}

	if component.Properties == nil || len(*component.Properties) != 1 {
		t.Fatalf("Properties = %v, want one property", component.Properties)
	}

	property := (*component.Properties)[0]
	if property != (cdx.Property{Name: scanossPrivateKeySizePropertyName, Value: "4096"}) {
		t.Fatalf("Property = %#v, want private key size property", property)
	}
}

func TestRelatedCryptoMapper_DoesNotInferSideSpecificSizeForAmbiguousMaterial(t *testing.T) {
	mapper := NewRelatedCryptoMapper()

	asset := &entities.CryptographicAsset{
		Metadata: map[string]string{
			"assetType":    "related-crypto-material",
			"materialType": "key-pair",
			"materialSize": "256",
		},
	}

	component, err := mapper.MapToComponentWithEvidence(asset)
	if err != nil {
		t.Fatalf("MapToComponentWithEvidence() unexpected error: %v", err)
	}

	props := component.CryptoProperties.RelatedCryptoMaterialProperties
	if props == nil || props.Size == nil {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %v, want 256", props)
	}
	if *props.Size != 256 {
		t.Fatalf("RelatedCryptoMaterialProperties.Size = %d, want 256", *props.Size)
	}

	if component.Properties != nil {
		t.Fatalf("Properties = %v, want nil for ambiguous material", component.Properties)
	}
}
