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
							"algorithmFamily":                 "AES",
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
							"algorithmFamily":  "AES",
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

// TestDeduplicateInterimReport_ConflictingMetadata tests that assets with different
// identifying metadata (algorithmFamily, algorithmName) are NOT merged.
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
							"assetType":       "algorithm",
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
							"assetType":       "algorithm",
							"algorithmName":   "SHA-256",
							"algorithmFamily": "SHA-2", // Different value - should NOT merge
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
	// Assets with different algorithmFamily should NOT be merged
	if len(assets) != 2 {
		t.Fatalf("Expected 2 separate assets (different algorithmFamily), got %d", len(assets))
	}

	// Each asset should retain its original metadata
	foundSHA2 := false
	foundSHA2Dash := false
	for _, asset := range assets {
		switch asset.Metadata["algorithmFamily"] {
		case "SHA2":
			foundSHA2 = true
		case "SHA-2":
			foundSHA2Dash = true
		}
	}

	if !foundSHA2 {
		t.Error("Expected to find asset with algorithmFamily = SHA2")
	}
	if !foundSHA2Dash {
		t.Error("Expected to find asset with algorithmFamily = SHA-2")
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

// TestDeduplicateInterimReport_DifferentAssetTypesSameLine tests that assets
// of different types at the same location are NOT merged.
func TestDeduplicateInterimReport_DifferentAssetTypesSameLine(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 23,
						EndLine:   23,
						Match:     "GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.related-crypto-material.initialization-vector",
							Message:  "Detected GCM initialization vector usage",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":    "related-crypto-material",
							"materialType": "initialization-vector",
							"api":          "GCMParameterSpec",
						},
						Status: "pending",
					},
					{
						StartLine: 23,
						EndLine:   23,
						Match:     "GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.algorithm.ae.aes-gcm-parameterspec",
							Message:  "Detected AES-GCM parameter specification",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":                       "algorithm",
							"algorithmFamily":                 "AES",
							"algorithmMode":                   "GCM",
							"algorithmPrimitive":              "ae",
							"algorithmParameterSetIdentifier": "128",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets

	// Should have 2 separate assets, not merged
	if len(assets) != 2 {
		t.Fatalf("Expected 2 separate assets (different types), got %d", len(assets))
	}

	// Verify first asset is related-crypto-material
	if assets[0].Metadata["assetType"] != "related-crypto-material" {
		t.Errorf("First asset should be related-crypto-material, got %s", assets[0].Metadata["assetType"])
	}
	if assets[0].Metadata["materialType"] != "initialization-vector" {
		t.Errorf("First asset should have materialType")
	}
	if len(assets[0].Rules) != 1 {
		t.Errorf("First asset should have 1 rule, got %d", len(assets[0].Rules))
	}

	// Verify second asset is algorithm
	if assets[1].Metadata["assetType"] != "algorithm" {
		t.Errorf("Second asset should be algorithm, got %s", assets[1].Metadata["assetType"])
	}
	if assets[1].Metadata["algorithmFamily"] != "AES" {
		t.Errorf("Second asset should have algorithmFamily")
	}
	if len(assets[1].Rules) != 1 {
		t.Errorf("Second asset should have 1 rule, got %d", len(assets[1].Rules))
	}
}

// TestDeduplicateInterimReport_SameAssetTypeSameLine tests that assets
// of the SAME type at the same location ARE merged when they have consistent metadata.
// This simulates two different rules detecting the same algorithm with the same properties.
func TestDeduplicateInterimReport_SameAssetTypeSameLine(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 42,
						EndLine:   42,
						Match:     "cipher.NewGCM(block)",
						Rules: []entities.RuleInfo{{
							ID:       "go-crypto-aes-gcm",
							Message:  "AES-GCM encryption detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":                       "algorithm",
							"algorithmFamily":                 "AES",
							"algorithmMode":                   "GCM",
							"algorithmPrimitive":              "ae",
							"algorithmParameterSetIdentifier": "256",
							"library":                         "crypto/aes",
						},
						Status: "pending",
					},
					{
						StartLine: 42,
						EndLine:   42,
						Match:     "cipher.NewGCM(block)",
						Rules: []entities.RuleInfo{{
							ID:       "go-crypto-authenticated-encryption",
							Message:  "Authenticated encryption pattern detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":                       "algorithm",
							"algorithmFamily":                 "AES",
							"algorithmMode":                   "GCM",
							"algorithmPrimitive":              "ae",
							"algorithmParameterSetIdentifier": "256",
							"library":                         "crypto/aes",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets

	// Should have 1 merged asset (same type, same location)
	if len(assets) != 1 {
		t.Fatalf("Expected 1 merged asset (same type), got %d", len(assets))
	}

	// Verify the merged asset has both rules
	if len(assets[0].Rules) != 2 {
		t.Errorf("Merged asset should have 2 rules, got %d", len(assets[0].Rules))
	}

	// Verify both rule IDs are present
	ruleIDs := make(map[string]bool)
	for _, rule := range assets[0].Rules {
		ruleIDs[rule.ID] = true
	}
	if !ruleIDs["go-crypto-aes-gcm"] {
		t.Errorf("Missing rule 'go-crypto-aes-gcm'")
	}
	if !ruleIDs["go-crypto-authenticated-encryption"] {
		t.Errorf("Missing rule 'go-crypto-authenticated-encryption'")
	}

	// Verify metadata is preserved
	if assets[0].Metadata["assetType"] != "algorithm" {
		t.Errorf("assetType should be 'algorithm', got %s", assets[0].Metadata["assetType"])
	}
	if assets[0].Metadata["algorithmFamily"] != "AES" {
		t.Errorf("algorithmFamily should be 'AES', got %s", assets[0].Metadata["algorithmFamily"])
	}
}

// TestDeduplicateInterimReport_SupportingCallsSameLineDifferentAPIs tests that
// fluent supporting calls on the same source line remain separate when they
// describe different APIs.
func TestDeduplicateInterimReport_SupportingCallsSameLineDifferentAPIs(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "PasswordService.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 26,
						EndLine:   26,
						Match:     `Password.hash(password).addRandomSalt(16).withBcrypt();`,
						Rules:     []entities.RuleInfo{{ID: "java.password4j.supporting.hash-start"}},
						Metadata: map[string]string{
							"assetType": "supporting-call",
							"api":       "com.password4j.Password.hash",
							"library":   "Password4J",
						},
						Status: "pending",
					},
					{
						StartLine: 26,
						EndLine:   26,
						Match:     `Password.hash(password).addRandomSalt(16).withBcrypt();`,
						Rules:     []entities.RuleInfo{{ID: "java.password4j.supporting.add-random-salt"}},
						Metadata: map[string]string{
							"assetType": "supporting-call",
							"api":       "com.password4j.HashBuilder.addRandomSalt",
							"library":   "Password4J",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets
	if len(assets) != 2 {
		t.Fatalf("Expected 2 supporting calls with different APIs, got %d", len(assets))
	}

	apis := make(map[string]bool)
	for _, asset := range assets {
		apis[asset.Metadata["api"]] = true
	}
	if !apis["com.password4j.Password.hash"] {
		t.Errorf("Missing Password.hash supporting call")
	}
	if !apis["com.password4j.HashBuilder.addRandomSalt"] {
		t.Errorf("Missing HashBuilder.addRandomSalt supporting call")
	}
}

// TestDeduplicateInterimReport_DifferentSemanticProperties ensures assets with
// different semantic properties (different algorithms) remain separate even at the same location.
func TestDeduplicateInterimReport_DifferentSemanticProperties(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "crypto.go",
				Language: "go",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 10,
						EndLine:   10,
						Match:     "cipher.NewGCM(block)",
						Rules: []entities.RuleInfo{{
							ID:       "go-crypto-aes-256-gcm",
							Message:  "AES-256-GCM detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":                       "algorithm",
							"algorithmFamily":                 "AES",
							"algorithmName":                   "AES-256-GCM",
							"algorithmMode":                   "GCM",
							"algorithmPrimitive":              "ae",
							"algorithmParameterSetIdentifier": "256",
							"library":                         "crypto/aes",
						},
						Status: "pending",
					},
					{
						StartLine: 10,
						EndLine:   10,
						Match:     "cipher.NewCBCEncrypter(block, iv)",
						Rules: []entities.RuleInfo{{
							ID:       "go-crypto-aes-128-cbc",
							Message:  "AES-128-CBC detected",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":                       "algorithm",
							"algorithmFamily":                 "AES",
							"algorithmName":                   "AES-128-CBC",
							"algorithmMode":                   "CBC",
							"algorithmPrimitive":              "block-cipher",
							"algorithmParameterSetIdentifier": "128",
							"library":                         "crypto/aes",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets

	// Should have 2 separate assets (different algorithms should NOT merge)
	if len(assets) != 2 {
		t.Fatalf("Expected 2 separate assets (different algorithms), got %d", len(assets))
	}

	// Verify each asset has only its own rule
	if len(assets[0].Rules) != 1 {
		t.Errorf("First asset should have 1 rule, got %d", len(assets[0].Rules))
	}
	if len(assets[1].Rules) != 1 {
		t.Errorf("Second asset should have 1 rule, got %d", len(assets[1].Rules))
	}

	// Verify both algorithm names are present (order may vary)
	algorithmNames := make(map[string]bool)
	algorithmNames[assets[0].Metadata["algorithmName"]] = true
	algorithmNames[assets[1].Metadata["algorithmName"]] = true

	if !algorithmNames["AES-256-GCM"] {
		t.Errorf("Missing AES-256-GCM algorithm")
	}
	if !algorithmNames["AES-128-CBC"] {
		t.Errorf("Missing AES-128-CBC algorithm")
	}
}

// TestDeduplicateInterimReport_CertificateDifferentLines ensures certificate findings
// without serial numbers are not merged across lines.
func TestDeduplicateInterimReport_CertificateDifferentLines(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "EncryptionUtils.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 43,
						EndLine:   43,
						Match:     "CertificateFactory.getInstance(\"X.509\")",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.certificate.x509.factory",
							Message:  "Detected certificate factory usage",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":         "certificate",
							"certificateType":   "X.509",
							"certificateFormat": "X.509",
							"library":           "JCA/JCE",
						},
						Status: "pending",
					},
					{
						StartLine: 44,
						EndLine:   44,
						Match:     "factory.generateCertificate(certificateStream)",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.certificate.x509.generate",
							Message:  "Detected certificate generation from input stream",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":         "certificate",
							"certificateType":   "generation",
							"certificateFormat": "X.509",
							"library":           "JCA/JCE",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets

	if len(assets) != 2 {
		t.Fatalf("Expected 2 certificate assets (no merge across lines), got %d", len(assets))
	}
}

// TestDeduplicateInterimReport_SameAlgorithmDifferentLines tests that algorithm
// assets with the same algorithmFamily and algorithmName but at different line
// numbers are NOT merged. This ensures distinct usages of the same algorithm
// are properly reported at their correct locations.
func TestDeduplicateInterimReport_SameAlgorithmDifferentLines(t *testing.T) {
	report := &entities.InterimReport{
		Version: "1.1",
		Tool:    entities.ToolInfo{Name: "test", Version: "1.0"},
		Findings: []entities.Finding{
			{
				FilePath: "AESGCM.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{
					{
						StartLine: 23,
						EndLine:   23,
						Match:     "GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.algorithm.ae.aes-gcm-parameterspec",
							Message:  "Detected AES-GCM parameter specification",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":       "algorithm",
							"algorithmFamily": "AES",
							"algorithmName":   "AES-GCM",
							"algorithmMode":   "gcm",
						},
						Status: "pending",
					},
					{
						StartLine: 30,
						EndLine:   30,
						Match:     "cipher.init(mode, key, gcpSpec);",
						Rules: []entities.RuleInfo{{
							ID:       "java.jca.algorithm.ae.aes-gcm",
							Message:  "Detected AES-GCM authenticated encryption usage",
							Severity: "INFO",
						}},
						Metadata: map[string]string{
							"assetType":       "algorithm",
							"algorithmFamily": "AES",
							"algorithmName":   "AES-GCM",
							"algorithmMode":   "gcm",
						},
						Status: "pending",
					},
				},
			},
		},
	}

	result := DeduplicateInterimReport(report)
	assets := result.Findings[0].CryptographicAssets

	// Should have 2 separate assets, not merged (different locations)
	if len(assets) != 2 {
		t.Fatalf("Expected 2 separate algorithm assets at different lines, got %d", len(assets))
	}

	// Verify first asset is at line 23
	if assets[0].StartLine != 23 || assets[0].EndLine != 23 {
		t.Errorf("First asset should be at line 23, got %d:%d", assets[0].StartLine, assets[0].EndLine)
	}
	if assets[0].Metadata["algorithmFamily"] != "AES" {
		t.Errorf("First asset should have algorithmFamily AES")
	}
	if len(assets[0].Rules) != 1 {
		t.Errorf("First asset should have 1 rule, got %d", len(assets[0].Rules))
	}
	if assets[0].Rules[0].ID != "java.jca.algorithm.ae.aes-gcm-parameterspec" {
		t.Errorf("First asset should have rule java.jca.algorithm.ae.aes-gcm-parameterspec")
	}

	// Verify second asset is at line 30
	if assets[1].StartLine != 30 || assets[1].EndLine != 30 {
		t.Errorf("Second asset should be at line 30, got %d:%d", assets[1].StartLine, assets[1].EndLine)
	}
	if assets[1].Metadata["algorithmFamily"] != "AES" {
		t.Errorf("Second asset should have algorithmFamily AES")
	}
	if len(assets[1].Rules) != 1 {
		t.Errorf("Second asset should have 1 rule, got %d", len(assets[1].Rules))
	}
	if assets[1].Rules[0].ID != "java.jca.algorithm.ae.aes-gcm" {
		t.Errorf("Second asset should have rule java.jca.algorithm.ae.aes-gcm")
	}
}

// TestAssetGroupKey_String tests the string representation of assetGroupKey.
func TestAssetGroupKey_String(t *testing.T) {
	key := assetGroupKey{
		filePath:  "crypto.go",
		assetKey:  "algorithm:AES:AES-256-GCM",
		startLine: 42,
		endLine:   42,
	}

	expected := "crypto.go[algorithm:AES:AES-256-GCM@42:42]"
	actual := key.String()

	if actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}
