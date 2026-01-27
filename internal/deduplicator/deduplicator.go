// Copyright 2025 SCANOSS
//
// SPDX-License-Identifier: Apache-2.0

// Package deduplicator provides functionality to deduplicate cryptographic assets
// based on their location in the source code.
package deduplicator

import (
	"fmt"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// locationKey represents a unique location in a file based on line positions.
type locationKey struct {
	filePath  string
	startLine int
	endLine   int
}

// String returns a string representation of the location key for debugging.
func (k locationKey) String() string {
	return fmt.Sprintf("%s:%d-%d", k.filePath, k.startLine, k.endLine)
}

// DeduplicateInterimReport removes duplicate CryptographicAssets that share
// the same file path and line position. When duplicates are found, their
// metadata and rule information are merged into a single asset.
//
// The deduplication process:
// 1. Groups assets by (file_path, start_line, end_line) tuple
// 2. For each group, merges all assets into one representative asset
// 3. Preserves all unique metadata values from merged assets
// 4. Maintains the first rule's information as the primary rule
//
// This function modifies the report in-place and returns it for convenience.
func DeduplicateInterimReport(report *entities.InterimReport) *entities.InterimReport {
	if report == nil {
		return nil
	}

	// Process each finding (file) in the report
	for i := range report.Findings {
		finding := &report.Findings[i]
		finding.CryptographicAssets = deduplicateAssets(finding.FilePath, finding.CryptographicAssets)
	}

	return report
}

// deduplicateAssets deduplicates a slice of cryptographic assets based on their line positions.
func deduplicateAssets(filePath string, assets []entities.CryptographicAsset) []entities.CryptographicAsset {
	if len(assets) <= 1 {
		return assets
	}

	// Group assets by their location
	assetGroups := make(map[locationKey][]entities.CryptographicAsset)
	firstSeenKeys := make([]locationKey, 0)

	for _, asset := range assets {
		key := locationKey{
			filePath:  filePath,
			startLine: asset.StartLine,
			endLine:   asset.EndLine,
		}

		if _, exists := assetGroups[key]; !exists {
			firstSeenKeys = append(firstSeenKeys, key)
		}

		assetGroups[key] = append(assetGroups[key], asset)
	}

	deduplicated := make([]entities.CryptographicAsset, 0, len(assetGroups))
	for _, key := range firstSeenKeys {
		group := assetGroups[key]
		mergedAsset := mergeAssets(group)
		deduplicated = append(deduplicated, mergedAsset)
	}

	return deduplicated
}

// mergeAssets merges multiple CryptographicAssets with the same location into one.
// It preserves all unique metadata from all assets in the group.
//
// Merge strategy:
// - Uses the first asset as the base
// - Preserves the first asset's match text (they should be identical for same location)
// - Merges all rules from all assets into the Rules array, preserving unique rules
// - Merges all unique metadata key-value pairs from all assets
// - Maintains the most severe status if different.
func mergeAssets(assets []entities.CryptographicAsset) entities.CryptographicAsset {
	if len(assets) == 1 {
		return assets[0]
	}

	// Use the first asset as the base
	merged := assets[0]

	// Ensure metadata map is initialized
	if merged.Metadata == nil {
		merged.Metadata = make(map[string]string)
	}

	// Track unique rule IDs to avoid duplicates
	seenRules := make(map[string]bool)
	for _, rule := range merged.Rules {
		seenRules[rule.ID] = true
	}

	// Merge metadata and rules from all assets
	for i := 1; i < len(assets); i++ {
		asset := assets[i]

		// Merge unique metadata values
		for key, value := range asset.Metadata {
			// Only add if the key doesn't exist or if the value is different
			if existingValue, exists := merged.Metadata[key]; !exists {
				merged.Metadata[key] = value
			} else if existingValue != value {
				// If values differ, append the new value (comma-separated)
				// This preserves all detected variants
				merged.Metadata[key] = existingValue + "," + value
			}
		}

		// Merge rules - add any new unique rules
		for _, rule := range asset.Rules {
			if !seenRules[rule.ID] {
				merged.Rules = append(merged.Rules, rule)
				seenRules[rule.ID] = true
			}
		}
	}

	return merged
}
