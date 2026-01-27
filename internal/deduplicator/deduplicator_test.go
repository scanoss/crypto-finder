// Copyright 2025 SCANOSS
//
// SPDX-License-Identifier: Apache-2.0

package deduplicator

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestDeduplicateInterimReport_NilReport tests that a nil report is handled gracefully.
func TestDeduplicateInterimReport_NilReport(t *testing.T) {
	result := DeduplicateInterimReport(nil)
	if result != nil {
		t.Errorf("Expected nil result for nil input, got %v", result)
	}
}

// TestDeduplicateInterimReport_EmptyReport tests that an empty report is handled correctly.
func TestDeduplicateInterimReport_EmptyReport(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool: entities.ToolInfo{
			Name:    "test",
			Version: "1.0",
		},
		Findings: []entities.Finding{},
	}

	result := DeduplicateInterimReport(report)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}
}

// TestDeduplicateInterimReport_NoOverlap tests that assets with different locations are not merged.
func TestDeduplicateInterimReport_NoOverlap(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes",
							Message:  "AES encryption detected",
							Severity: "WARNING",
						}},
						Metadata: map[string]string{
							"algorithmName": "AES-256-GCM",
						},
						Status: "pending",
					},
					{
						StartLine: 20,
						EndLine:   25,
						Match:     "SHA256.hash(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.sha256",
							Message:  "SHA256 hash detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName": "SHA-256",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}
	if len(result.Findings[0].CryptographicAssets) != 2 {
		t.Errorf("Expected 2 assets (no duplicates), got %d", len(result.Findings[0].CryptographicAssets))
	}
}

// TestDeduplicateInterimReport_ExactDuplicates tests merging of exact duplicates at same location.
func TestDeduplicateInterimReport_ExactDuplicates(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes.encrypt",
							Message:  "AES encryption detected",
							Severity: "WARNING",
						}},
						Metadata: map[string]string{
							"algorithmName": "AES-256-GCM",
							"library":       "OpenSSL",
						},
						Status: "pending",
					},
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes.generic",
							Message:  "AES algorithm usage",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName": "AES-256-GCM",
							"library":       "OpenSSL",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}

	assets := result.Findings[0].CryptographicAssets
	if len(assets) != 1 {
		t.Fatalf("Expected 1 deduplicated asset, got %d", len(assets))
	}

	// Verify the merged asset preserves the first asset's properties
	merged := assets[0]
	if merged.StartLine != 10 || merged.EndLine != 15 {
		t.Errorf("Expected lines 10-15, got %d-%d", merged.StartLine, merged.EndLine)
	}
	if merged.Rules[0].ID != "go.crypto.aes.encrypt" {
		t.Errorf("Expected first rule ID to be preserved, got %s", merged.Rules[0].ID)
	}
	if merged.Metadata["algorithmName"] != "AES-256-GCM" {
		t.Errorf("Expected algorithmName to be preserved, got %s", merged.Metadata["algorithmName"])
	}
	if merged.Metadata["library"] != "OpenSSL" {
		t.Errorf("Expected library to be preserved, got %s", merged.Metadata["library"])
	}
}

// TestDeduplicateInterimReport_MergeMetadata tests merging of assets with complementary metadata.
func TestDeduplicateInterimReport_MergeMetadata(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes.mode",
							Message:  "AES with mode detected",
							Severity: "WARNING",
						}},
						Metadata: map[string]string{
							"algorithmName":   "AES-256-GCM",
							"algorithmMode":   "GCM",
							"algorithmFamily": "AES",
						},
						Status: "pending",
					},
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes.keysize",
							Message:  "AES key size detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName":                   "AES-256-GCM",
							"algorithmParameterSetIdentifier": "256",
							"library":                         "crypto/aes",
						},
						Status: "pending",
					},
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes.padding",
							Message:  "AES padding detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName":    "AES-256-GCM",
							"algorithmPadding": "PKCS7",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}

	assets := result.Findings[0].CryptographicAssets
	if len(assets) != 1 {
		t.Fatalf("Expected 1 deduplicated asset, got %d", len(assets))
	}

	// Verify all unique metadata was merged
	merged := assets[0]
	expectedMetadata := map[string]string{
		"algorithmName":                   "AES-256-GCM",
		"algorithmMode":                   "GCM",
		"algorithmFamily":                 "AES",
		"algorithmParameterSetIdentifier": "256",
		"library":                         "crypto/aes",
		"algorithmPadding":                "PKCS7",
	}

	for key, expectedValue := range expectedMetadata {
		if actualValue, exists := merged.Metadata[key]; !exists {
			t.Errorf("Expected metadata key %s to exist", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected metadata[%s] = %s, got %s", key, expectedValue, actualValue)
		}
	}
}

// TestDeduplicateInterimReport_ConflictingMetadata tests handling of conflicting metadata values.
func TestDeduplicateInterimReport_ConflictingMetadata(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "hash(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.hash.sha",
							Message:  "SHA hash detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName":   "SHA-256",
							"algorithmFamily": "SHA2",
						},
						Status: "pending",
					},
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "hash(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.hash.generic",
							Message:  "Hash function detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"algorithmName":   "SHA-256",
							"algorithmFamily": "SHA-2", // Slightly different value
							"outputSize":      "256",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets
	if len(assets) != 1 {
		t.Fatalf("Expected 1 deduplicated asset, got %d", len(assets))
	}

	merged := assets[0]

	// algorithmName should remain the same (both have "SHA-256")
	if merged.Metadata["algorithmName"] != "SHA-256" {
		t.Errorf("Expected algorithmName = SHA-256, got %s", merged.Metadata["algorithmName"])
	}

	// algorithmFamily should contain both values (comma-separated)
	familyValue := merged.Metadata["algorithmFamily"]
	if familyValue != "SHA2,SHA-2" {
		t.Errorf("Expected algorithmFamily to contain both values, got %s", familyValue)
	}

	// outputSize should be added from the second asset
	if merged.Metadata["outputSize"] != "256" {
		t.Errorf("Expected outputSize = 256, got %s", merged.Metadata["outputSize"])
	}
}

// TestDeduplicateInterimReport_MultipleFiles tests deduplication across multiple files.
func TestDeduplicateInterimReport_MultipleFiles(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto1.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt()",
						Rules:     []entities.RuleInfo{{ID: "rule1"}},
						Metadata:  map[string]string{"key": "value1"},
						Status:    "pending",
					},
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt()",
						Rules:     []entities.RuleInfo{{ID: "rule2"}},
						Metadata:  map[string]string{"key": "value1"},
						Status:    "pending",
					},
				},
			},
			{
				FilePath: "crypto2.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 20,
						EndLine:   25,
						Match:     "SHA256.hash()",
						Rules:     []entities.RuleInfo{{ID: "rule3"}},
						Metadata:  map[string]string{"key": "value2"},
						Status:    "pending",
					},
					{
						StartLine: 20,
						EndLine:   25,
						Match:     "SHA256.hash()",
						Rules:     []entities.RuleInfo{{ID: "rule4"}},
						Metadata:  map[string]string{"key": "value2"},
						Status:    "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	if len(result.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(result.Findings))
	}

	// Each file should have exactly 1 deduplicated asset
	for i, finding := range result.Findings {
		if len(finding.CryptographicAssets) != 1 {
			t.Errorf("File %d: Expected 1 deduplicated asset, got %d", i, len(finding.CryptographicAssets))
		}
	}
}

// TestDeduplicateInterimReport_SingleAsset tests that a single asset is returned unchanged.
func TestDeduplicateInterimReport_SingleAsset(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.0",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   15,
						Match:     "AES.encrypt(data)",
						Rules: []entities.RuleInfo{{
							ID:       "go.crypto.aes",
							Message:  "AES encryption",
							Severity: "WARNING",
						}},
						Metadata: map[string]string{
							"algorithmName": "AES-256-GCM",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets
	if len(assets) != 1 {
		t.Fatalf("Expected 1 asset, got %d", len(assets))
	}

	// Verify the asset is unchanged
	asset := assets[0]
	if asset.StartLine != 10 || asset.EndLine != 15 {
		t.Errorf("Asset location changed")
	}
	if asset.Rules[0].ID != "go.crypto.aes" {
		t.Errorf("Rule ID changed")
	}
	if asset.Metadata["algorithmName"] != "AES-256-GCM" {
		t.Errorf("Metadata changed")
	}
}

// TestLocationKey_String tests the string representation of locationKey.
func TestLocationKey_String(t *testing.T) {
	key := locationKey{
		filePath:  "crypto.go",
		startLine: 10,
		endLine:   15,
	}

	expected := "crypto.go:10-15"
	actual := key.String()

	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}
