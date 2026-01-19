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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestConverter_Convert(t *testing.T) {
	converter := NewConverter()

	tests := []struct {
		name           string
		fixtureFile    string
		wantComponents int
		wantSkipped    int
		wantErr        bool
	}{
		{
			name:           "AES-256-GCM algorithm",
			fixtureFile:    "algorithm_aes256_gcm.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "RSA-2048 algorithm",
			fixtureFile:    "algorithm_rsa_2048.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "ECDSA P-256 algorithm",
			fixtureFile:    "algorithm_ecdsa_p256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "SHA-256 hash algorithm",
			fixtureFile:    "algorithm_sha256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "SHA-256 digest asset",
			fixtureFile:    "digest_sha256.json",
			wantComponents: 1,
			wantSkipped:    0,
			wantErr:        false,
		},
		{
			name:           "Incomplete asset - missing primitive",
			fixtureFile:    "incomplete_missing_primitive.json",
			wantComponents: 0,
			wantSkipped:    1,
			wantErr:        false,
		},
		{
			name:           "Multiple assets in multiple files",
			fixtureFile:    "multi_assets.json",
			wantComponents: 4,
			wantSkipped:    0,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test fixture
			report := loadFixture(t, tt.fixtureFile)

			// Run conversion
			bom, err := converter.Convert(report)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("Convert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return // Expected error, test passed
			}

			// Check BOM format
			if bom.BOMFormat != "CycloneDX" {
				t.Errorf("BOM format = %q, want %q", bom.BOMFormat, "CycloneDX")
			}

			// Check spec version
			if bom.SpecVersion.String() != "1.6" {
				t.Errorf("Spec version = %q, want %q", bom.SpecVersion, "1.6")
			}

			// Check serial number
			if bom.SerialNumber == "" {
				t.Error("Serial number is empty")
			}

			// Check components count
			componentCount := 0
			if bom.Components != nil {
				componentCount = len(*bom.Components)
			}

			if componentCount != tt.wantComponents {
				t.Errorf("Component count = %d, want %d", componentCount, tt.wantComponents)
			}

			// Validate each component has required fields
			if bom.Components != nil {
				for i, component := range *bom.Components {
					if component.BOMRef == "" {
						t.Errorf("Component[%d] missing BOMRef", i)
					}
					if component.Name == "" {
						t.Errorf("Component[%d] missing Name", i)
					}
					if component.CryptoProperties == nil {
						t.Errorf("Component[%d] missing CryptoProperties", i)
					}
				}
			}
		})
	}
}

func TestConverter_ConvertNilReport(t *testing.T) {
	converter := NewConverter()
	_, err := converter.Convert(nil)
	if err == nil {
		t.Error("Convert(nil) should return error")
	}
}

func TestConverter_EmptyReport(t *testing.T) {
	converter := NewConverter()
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{
			Name:    "test",
			Version: "1.0",
		},
		Findings: []entities.Finding{},
	}

	bom, err := converter.Convert(report)
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}

	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("Empty report should produce 0 components, got %d", len(*bom.Components))
	}
}

func TestCountTotalAssets(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  int
	}{
		{
			name:  "Single file with one asset",
			files: []string{"algorithm_aes256_gcm.json"},
			want:  1,
		},
		{
			name:  "Multiple files with multiple assets",
			files: []string{"multi_assets.json"},
			want:  4,
		},
		{
			name:  "File with incomplete asset",
			files: []string{"incomplete_missing_primitive.json"},
			want:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allFindings := make([]entities.Finding, 0, len(tt.files))
			for _, file := range tt.files {
				report := loadFixture(t, file)
				allFindings = append(allFindings, report.Findings...)
			}

			report := &entities.InterimReport{Findings: allFindings}
			got := countTotalAssets(report)

			if got != tt.want {
				t.Errorf("countTotalAssets() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestConverter_ConvertAggregatedAsset_ErrorPaths(t *testing.T) {
	converter := NewConverter()

	tests := []struct {
		name        string
		aggregated  *AggregatedAsset
		wantErr     bool
		errContains string
	}{
		{
			name: "Protocol asset - not implemented",
			aggregated: &AggregatedAsset{
				Name:      "TLS-1.3",
				AssetType: AssetTypeProtocol,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "protocol",
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "protocol",
		},
		{
			name: "Certificate asset - not implemented",
			aggregated: &AggregatedAsset{
				Name:      "X.509-Cert",
				AssetType: AssetTypeCertificate,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "certificate",
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "certificate",
		},
		{
			name: "Unknown asset type",
			aggregated: &AggregatedAsset{
				Name:      "Unknown",
				AssetType: "unknown-type",
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "unknown-type",
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "unsupported asset type",
		},
		{
			name: "Algorithm with missing required fields",
			aggregated: &AggregatedAsset{
				Name:      "InvalidAlgorithm",
				AssetType: AssetTypeAlgorithm,
				ReferenceAsset: &entities.CryptographicAsset{
					Metadata: map[string]string{
						"assetType": "algorithm",
						// Missing algorithmPrimitive and algorithmFamily
					},
				},
				ReferenceFinding: &entities.Finding{},
				Occurrences:      []AssetOccurrence{},
				Identities:       []AssetIdentity{},
			},
			wantErr:     true,
			errContains: "missing required field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component, err := converter.convertAggregatedAsset(tt.aggregated)

			if (err != nil) != tt.wantErr {
				t.Errorf("convertAggregatedAsset() error = %v, wantErr %v", err, tt.wantErr)
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

			if component == nil {
				t.Error("Expected component but got nil")
			}
		})
	}
}

// Helper function to load test fixtures.
func loadFixture(t *testing.T, filename string) *entities.InterimReport {
	t.Helper()

	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read fixture %q: %v", filename, err)
	}

	var report entities.InterimReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Failed to parse fixture %q: %v", filename, err)
	}

	return &report
}
