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
								Rules:     []entities.RuleInfo{{ID: "go-sha256", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-sha256", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-sha256", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-sha256-alt", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-aes-gcm", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-sha256", Severity: "INFO"}},
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
			expectedFirstName:   "", // Order is non-deterministic due to map iteration
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
								Rules:     []entities.RuleInfo{{ID: "go-secrets-choice", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-secrets-randbelow", Severity: "INFO"}},
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
								Rules:     []entities.RuleInfo{{ID: "go-os-urandom", Severity: "INFO"}},
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
		{
			name: "Multi-rule asset - single asset with multiple rules creates multiple identities",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/multi.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 42,
								EndLine:   42,
								Match:     "crypto/sha256.New()",
								Rules: []entities.RuleInfo{
									{ID: "go-sha256-primary", Message: "SHA-256 detected via primary rule", Severity: "INFO"},
									{ID: "go-sha256-secondary", Message: "SHA-256 detected via secondary rule", Severity: "WARNING"},
									{ID: "go-hash-generic", Message: "Generic hash function detected", Severity: "INFO"},
								},
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
			expectedIdentities:  3, // Three rules in one asset = three identities
		},
		{
			name: "Multi-rule deduplication - same rule+API combination appears only once",
			report: &entities.InterimReport{
				Version: "1.0",
				Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
				Findings: []entities.Finding{
					{
						FilePath: "crypto/file1.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 10,
								EndLine:   10,
								Match:     "crypto/sha256.New()",
								Rules: []entities.RuleInfo{
									{ID: "go-sha256-rule", Message: "SHA-256 detected", Severity: "INFO"},
									{ID: "go-hash-generic", Message: "Generic hash", Severity: "INFO"},
								},
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
						FilePath: "crypto/file2.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								StartLine: 20,
								EndLine:   20,
								Match:     "crypto/sha256.Sum256(data)",
								Rules: []entities.RuleInfo{
									{ID: "go-sha256-rule", Message: "SHA-256 detected", Severity: "INFO"},
									{ID: "go-sha256-sum", Message: "SHA-256 sum function", Severity: "INFO"},
								},
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
			expectedOccurrences: 2,
			expectedIdentities:  3, // go-sha256-rule (deduplicated), go-hash-generic, go-sha256-sum
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

			//nolint:nestif // Test validation requires nested checks to verify all fields of aggregated results
			if len(aggregated) > 0 {
				firstAsset := aggregated[0]

				// Only check name if expectedFirstName is set (non-empty)
				// Empty string means order is non-deterministic
				if tt.expectedFirstName != "" && firstAsset.Name != tt.expectedFirstName {
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
					if len(occ.RuleIDs) == 0 {
						t.Errorf("Occurrence %d missing RuleIDs", i)
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

func TestAggregator_MultiRuleIdentityMetadata(t *testing.T) {
	// This test verifies that when a single asset has multiple rules,
	// each rule's metadata (message, severity) is properly preserved in separate identities
	aggregator := NewAggregator()

	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto/test.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 42,
						EndLine:   42,
						Match:     "crypto/sha256.New()",
						Rules: []entities.RuleInfo{
							{ID: "rule-1", Message: "Message from rule 1", Severity: "INFO"},
							{ID: "rule-2", Message: "Message from rule 2", Severity: "WARNING"},
							{ID: "rule-3", Message: "Message from rule 3", Severity: "ERROR"},
						},
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
	}

	aggregated, err := aggregator.AggregateAssets(report)
	if err != nil {
		t.Fatalf("AggregateAssets() error = %v", err)
	}

	if len(aggregated) != 1 {
		t.Fatalf("Expected 1 aggregated asset, got %d", len(aggregated))
	}

	asset := aggregated[0]

	if len(asset.Identities) != 3 {
		t.Fatalf("Expected 3 identities, got %d", len(asset.Identities))
	}

	// Verify each identity has the correct metadata
	expectedIdentities := map[string]struct {
		message  string
		severity string
	}{
		"rule-1": {message: "Message from rule 1", severity: "INFO"},
		"rule-2": {message: "Message from rule 2", severity: "WARNING"},
		"rule-3": {message: "Message from rule 3", severity: "ERROR"},
	}

	for _, identity := range asset.Identities {
		expected, found := expectedIdentities[identity.RuleID]
		if !found {
			t.Errorf("Unexpected rule ID: %s", identity.RuleID)
			continue
		}

		if identity.Message != expected.message {
			t.Errorf("Rule %s: expected message '%s', got '%s'", identity.RuleID, expected.message, identity.Message)
		}

		if identity.Severity != expected.severity {
			t.Errorf("Rule %s: expected severity '%s', got '%s'", identity.RuleID, expected.severity, identity.Severity)
		}

		if identity.API != "crypto/sha256.New" {
			t.Errorf("Rule %s: expected API 'crypto/sha256.New', got '%s'", identity.RuleID, identity.API)
		}

		if identity.Match != "crypto/sha256.New()" {
			t.Errorf("Rule %s: expected match 'crypto/sha256.New()', got '%s'", identity.RuleID, identity.Match)
		}
	}

	// Verify occurrence has all rule IDs
	if len(asset.Occurrences) != 1 {
		t.Fatalf("Expected 1 occurrence, got %d", len(asset.Occurrences))
	}

	occurrence := asset.Occurrences[0]
	if len(occurrence.RuleIDs) != 3 {
		t.Errorf("Expected 3 rule IDs in occurrence, got %d", len(occurrence.RuleIDs))
	}

	expectedRuleIDs := map[string]bool{"rule-1": true, "rule-2": true, "rule-3": true}
	for _, ruleID := range occurrence.RuleIDs {
		if !expectedRuleIDs[ruleID] {
			t.Errorf("Unexpected rule ID in occurrence: %s", ruleID)
		}
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
