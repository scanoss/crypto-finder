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

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestAggregator_AggregateAssets(t *testing.T) {
	tests := []struct {
		name                string
		report              *entities.InterimReport
		expectedAssetCount  int
		expectedFirstName   string
		expectedOccurrences int
		expectedIdentities  int
	}{
		{
			name: "Single asset - no aggregation needed",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/hash.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 42,
								EndLine:   42,
								Rule:      entities.RuleInfo{ID: "go-sha256", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "SHA-2",
									"algorithmPrimitive":              "hash",
									"algorithmParameterSetIdentifier": "256",
									"api":                             "crypto/sha256.New",
								},
							},
						},
					},
				},
			},
			expectedAssetCount:  1,
			expectedFirstName:   "SHA-2-256",
			expectedOccurrences: 1,
			expectedIdentities:  1,
		},
		{
			name: "Multiple occurrences of same asset - aggregated",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/hash1.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 10,
								EndLine:   10,
								Rule:      entities.RuleInfo{ID: "go-sha256", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "SHA-2",
									"algorithmPrimitive":              "hash",
									"algorithmParameterSetIdentifier": "256",
									"api":                             "crypto/sha256.New",
								},
							},
						},
					},
					{
						FilePath: "crypto/hash2.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 20,
								EndLine:   20,
								Rule:      entities.RuleInfo{ID: "go-sha256", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "SHA-2",
									"algorithmPrimitive":              "hash",
									"algorithmParameterSetIdentifier": "256",
									"api":                             "crypto/sha256.New",
								},
							},
						},
					},
					{
						FilePath: "crypto/hash3.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 30,
								EndLine:   30,
								Rule:      entities.RuleInfo{ID: "go-sha256-alt", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "SHA-2",
									"algorithmPrimitive":              "hash",
									"algorithmParameterSetIdentifier": "256",
									"api":                             "crypto/sha256.Sum256",
								},
							},
						},
					},
				},
			},
			expectedAssetCount:  1,
			expectedFirstName:   "SHA-2-256",
			expectedOccurrences: 3,
			expectedIdentities:  2, // Two different rules detected it
		},
		{
			name: "Multiple different assets - no aggregation",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/aes.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 10,
								EndLine:   10,
								Rule:      entities.RuleInfo{ID: "go-aes-gcm", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "AES",
									"algorithmPrimitive":              "ae",
									"algorithmParameterSetIdentifier": "256",
									"algorithmMode":                   "gcm",
									"api":                             "cipher.NewGCM",
								},
							},
						},
					},
					{
						FilePath: "crypto/hash.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 20,
								EndLine:   20,
								Rule:      entities.RuleInfo{ID: "go-sha256", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":                       "algorithm",
									"algorithmFamily":                 "SHA-2",
									"algorithmPrimitive":              "hash",
									"algorithmParameterSetIdentifier": "256",
									"api":                             "crypto/sha256.New",
								},
							},
						},
					},
				},
			},
			expectedAssetCount:  2,
			expectedFirstName:   "AES-256-GCM",
			expectedOccurrences: 1,
			expectedIdentities:  1,
		},
		{
			name: "CSPRNG - multiple APIs aggregated by name",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/rand1.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 10,
								EndLine:   10,
								Rule:      entities.RuleInfo{ID: "go-secrets-choice", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":          "algorithm",
									"algorithmName":      "CSPRNG",
									"algorithmFamily":    "CSPRNG",
									"algorithmPrimitive": "drbg",
									"api":                "secrets.choice",
								},
							},
						},
					},
					{
						FilePath: "crypto/rand2.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 20,
								EndLine:   20,
								Rule:      entities.RuleInfo{ID: "go-secrets-randbelow", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":          "algorithm",
									"algorithmName":      "CSPRNG",
									"algorithmFamily":    "CSPRNG",
									"algorithmPrimitive": "drbg",
									"api":                "secrets.randbelow",
								},
							},
						},
					},
					{
						FilePath: "crypto/rand3.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 30,
								EndLine:   30,
								Rule:      entities.RuleInfo{ID: "go-os-urandom", Severity: "INFO"},
								Metadata: map[string]string{
									"assetType":          "algorithm",
									"algorithmName":      "CSPRNG",
									"algorithmFamily":    "CSPRNG",
									"algorithmPrimitive": "drbg",
									"api":                "os.urandom",
								},
							},
						},
					},
				},
			},
			expectedAssetCount:  1,
			expectedFirstName:   "CSPRNG",
			expectedOccurrences: 3,
			expectedIdentities:  3, // Three different rules (one per API)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aggregator := NewAggregator()
			aggregated, err := aggregator.AggregateAssets(tt.report)
			if err != nil {
				t.Fatalf("AggregateAssets() error = %v", err)
			}

			if len(aggregated) != tt.expectedAssetCount {
				t.Errorf("Expected %d aggregated assets, got %d", tt.expectedAssetCount, len(aggregated))
			}

			if len(aggregated) > 0 {
				firstAsset := aggregated[0]

				if firstAsset.Name != tt.expectedFirstName {
					t.Errorf("Expected first asset name '%s', got '%s'", tt.expectedFirstName, firstAsset.Name)
				}

				if len(firstAsset.Occurrences) != tt.expectedOccurrences {
					t.Errorf("Expected %d occurrences, got %d", tt.expectedOccurrences, len(firstAsset.Occurrences))
				}

				if len(firstAsset.Identities) != tt.expectedIdentities {
					t.Errorf("Expected %d identities, got %d", tt.expectedIdentities, len(firstAsset.Identities))
				}

				// Verify occurrences have required fields
				for i, occ := range firstAsset.Occurrences {
					if occ.FilePath == "" {
						t.Errorf("Occurrence %d missing FilePath", i)
					}
					if occ.StartLine == 0 {
						t.Errorf("Occurrence %d missing StartLine", i)
					}
					if occ.EndLine == 0 {
						t.Errorf("Occurrence %d missing EndLine", i)
					}
					if occ.RuleID == "" {
						t.Errorf("Occurrence %d missing RuleID", i)
					}
				}

				// Verify identities have required fields
				for i, identity := range firstAsset.Identities {
					if identity.RuleID == "" {
						t.Errorf("Identity %d missing RuleID", i)
					}
				}
			}
		})
	}
}

func TestAggregator_GetAssetKey(t *testing.T) {
	aggregator := NewAggregator()

	tests := []struct {
		name        string
		asset       *entities.CryptographicAsset
		expectedKey string
	}{
		{
			name: "Algorithm with explicit name",
			asset: &entities.CryptographicAsset{
				Metadata: map[string]string{
					"assetType":          "algorithm",
					"algorithmName":      "CSPRNG",
					"algorithmFamily":    "CSPRNG",
					"algorithmPrimitive": "drbg",
				},
			},
			expectedKey: "CSPRNG",
		},
		{
			name: "Algorithm with constructed name",
			asset: &entities.CryptographicAsset{
				Metadata: map[string]string{
					"assetType":                       "algorithm",
					"algorithmFamily":                 "AES",
					"algorithmPrimitive":              "ae",
					"algorithmParameterSetIdentifier": "256",
					"algorithmMode":                   "gcm",
				},
			},
			expectedKey: "AES-256-GCM",
		},
		{
			name: "Related crypto material",
			asset: &entities.CryptographicAsset{
				Metadata: map[string]string{
					"assetType":    "related-crypto-material",
					"materialType": "secret-key",
				},
			},
			expectedKey: "secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := aggregator.getAssetKey(tt.asset)

			if key != tt.expectedKey {
				t.Errorf("Expected key '%s', got '%s'", tt.expectedKey, key)
			}
		})
	}
}
