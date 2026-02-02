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

// Package entities defines the domain data structures for SCANOSS crypto-finder.
package entities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// InterimFormatVersion is the current version of the interim report schema.
const InterimFormatVersion = "1.1"

// InterimReport is the standardized output format for all scanners.
// This format provides a unified representation of cryptographic findings
// that can be consumed by the SCANOSS ecosystem and other downstream tools.
type InterimReport struct {
	// Version of the interim report schema (e.g., "1.0")
	Version string `json:"version"`

	// Tool contains information about the scanner that generated this report
	Tool ToolInfo `json:"tool"`

	// Findings contains all detected cryptographic assets grouped by file
	Findings []Finding `json:"findings"`
}

// ToolInfo contains metadata about the scanner that produced the report.
type ToolInfo struct {
	// Name of the scanner tool (e.g., "crypto-finder", "cbom-toolkit", etc)
	Name string `json:"name"`

	// Version of the scanner tool (e.g., "1.45.0")
	Version string `json:"version"`
}

// Finding represents all cryptographic assets discovered in a single file.
// Each file that contains cryptographic material will have one Finding entry.
type Finding struct {
	// FilePath is the path to the file containing cryptographic assets
	FilePath string `json:"file_path"`

	// Language is the programming language of the file (e.g., "java", "python", "go")
	Language string `json:"language"`

	// CryptographicAssets contains all cryptographic materials found in this file
	CryptographicAssets []CryptographicAsset `json:"cryptographic_assets"`

	// TimestampUTC is the ISO 8601 timestamp when this file was scanned
	TimestampUTC string `json:"timestamp_utc"`
}

// CryptographicAsset represents a single detected cryptographic element.
type CryptographicAsset struct {
	// MatchType indicates the detection method used
	// Values: "semgrep", "cbom_toolkit", "keyword_search"
	MatchType string `json:"match_type"`

	// StartLine is the first line number where the asset was detected
	StartLine int `json:"start_line"`

	// EndLine is the last line number where the asset was detected
	EndLine int `json:"end_line"`

	// Match is the actual code snippet that was matched
	Match string `json:"match"`

	// Rules contains information about all detection rules that triggered this finding
	// This allows multiple rules to detect the same cryptographic asset
	Rules []RuleInfo `json:"rules"`

	// Status represents the current state of this finding
	// Values: "pending", "identified", "dismissed", "reviewed"
	Status string `json:"status"`

	// Metadata contains metadata extracted from the cryptographic asset
	// such as key length, algorithm, etc.
	Metadata map[string]string `json:"metadata"`

	// OID is the Object Identifier for the cryptographic algorithm.
	// Sources: NIST CSOR, PKCS#1, ANSI X9.62, etc.
	// Example: "2.16.840.1.101.3.4.1.2" for AES-128-CBC
	OID string `json:"oid,omitempty"`
}

// RuleInfo contains information about the detection rule that identified the cryptographic asset.
type RuleInfo struct {
	// ID is the unique identifier for the rule
	// Example: "<language>.crypto.<library>.<operation>-<specifics>"
	ID string `json:"id"`

	// Message is a human-readable description of what was detected
	Message string `json:"message"`

	// Severity indicates the importance level of the finding
	// Values: "WARNING", "ERROR", "INFO"
	Severity string `json:"severity"`

	// Version is the ruleset version when known (e.g., "latest", "v1.0.1")
	Version string `json:"version,omitempty"`
}

// GetKey generates a unique key for deduplication based on asset type and identifying metadata.
// Assets with the same key are considered the same cryptographic entity and will be merged.
// The key is constructed using asset-type-specific identifying fields:
//   - algorithm: algorithmName if available, otherwise algorithmFamily + mode + padding, otherwise algorithmFamily
//   - related-crypto-material: materialType
//   - protocol: protocolType
//   - certificate: certificateSerialNumber (or location-based fallback when missing)
//
// This method provides a single source of truth for asset identity across the codebase,
// used by both the deduplicator (per-file) and aggregator (cross-file).
func (c *CryptographicAsset) GetKey() string {
	assetType := c.Metadata["assetType"]

	switch assetType {
	case "algorithm":
		return c.getAlgorithmKey()
	case "related-crypto-material":
		return c.getRelatedCryptoMaterialKey()
	case "protocol":
		return c.getProtocolKey()
	case "certificate":
		return c.getCertificateKey()
	default:
		return fmt.Sprintf("%d:%d:%s", c.StartLine, c.EndLine, assetType)
	}
}

// getAlgorithmKey generates a key for algorithm assets using algorithmName or using algorithmFamily with mode and padding if available.
// Additional metadata fields are appended as sorted key=value pairs for enhanced uniqueness.
// Format: "algorithm:<name>:<metadata>" or "algorithm:<family>:<mode>:<padding>:<metadata>" or "algorithm:<family>:<metadata>".
func (c *CryptographicAsset) getAlgorithmKey() string {
	family := c.Metadata["algorithmFamily"]
	name := c.Metadata["algorithmName"]
	mode := c.Metadata["algorithmMode"]
	padding := c.Metadata["algorithmPadding"]

	// Exclude fields already used in the primary key
	excludeKeys := []string{"algorithmFamily", "algorithmName", "algorithmMode", "algorithmPadding"}
	metadataSuffix := c.getMetadataKeySuffix(excludeKeys)

	if name != "" {
		return fmt.Sprintf("algorithm:%s%s", name, metadataSuffix)
	}

	if mode != "" && padding != "" {
		return fmt.Sprintf("algorithm:%s:%s:%s%s", family, mode, padding, metadataSuffix)
	}
	if mode != "" {
		return fmt.Sprintf("algorithm:%s:%s%s", family, mode, metadataSuffix)
	}

	return fmt.Sprintf("algorithm:%s%s", family, metadataSuffix)
}

// getRelatedCryptoMaterialKey generates a key for related-crypto-material assets using materialType.
// Additional metadata fields are appended as sorted key=value pairs for enhanced uniqueness.
// Format: "related-crypto-material:<type>:<metadata>".
func (c *CryptographicAsset) getRelatedCryptoMaterialKey() string {
	materialType := c.Metadata["materialType"]

	// Exclude fields already used in the primary key
	excludeKeys := []string{"materialType"}
	metadataSuffix := c.getMetadataKeySuffix(excludeKeys)

	return fmt.Sprintf("related-crypto-material:%s%s", materialType, metadataSuffix)
}

// getProtocolKey generates a key for protocol assets using protocolType and optional version.
// Additional metadata fields are appended as sorted key=value pairs for enhanced uniqueness.
// Format: "protocol:<type>:<version>:<metadata>" or "protocol:<type>:<metadata>".
func (c *CryptographicAsset) getProtocolKey() string {
	protocolType := c.Metadata["protocolType"]
	protocolVersion := c.Metadata["protocolVersion"]

	// Exclude fields already used in the primary key
	excludeKeys := []string{"protocolType", "protocolVersion"}
	metadataSuffix := c.getMetadataKeySuffix(excludeKeys)

	if protocolVersion != "" {
		return fmt.Sprintf("protocol:%s:%s%s", protocolType, protocolVersion, metadataSuffix)
	}

	return fmt.Sprintf("protocol:%s%s", protocolType, metadataSuffix)
}

// getCertificateKey generates a key for certificate assets using certificateSerialNumber.
// Additional metadata fields are appended as sorted key=value pairs for enhanced uniqueness.
// Format: "certificate:<serialNumber>:<metadata>".
// If serial number is missing, fall back to a location-based key to avoid merging
// distinct certificate-related findings in the same file.
func (c *CryptographicAsset) getCertificateKey() string {
	serialNumber := strings.TrimSpace(c.Metadata["certificateSerialNumber"])
	certType := strings.TrimSpace(c.Metadata["certificateType"])
	certFormat := strings.TrimSpace(c.Metadata["certificateFormat"])

	// Exclude fields already used in the primary key
	excludeKeys := []string{"certificateSerialNumber", "certificateType", "certificateFormat"}
	metadataSuffix := c.getMetadataKeySuffix(excludeKeys)

	if serialNumber != "" {
		return fmt.Sprintf("certificate:%s%s", serialNumber, metadataSuffix)
	}

	if certType != "" || certFormat != "" {
		return fmt.Sprintf("certificate:%d:%d:%s:%s%s", c.StartLine, c.EndLine, certType, certFormat, metadataSuffix)
	}

	return fmt.Sprintf("certificate:%d:%d%s", c.StartLine, c.EndLine, metadataSuffix)
}

// getMetadataKeySuffix generates sorted key=value pairs from metadata fields.
// This enhances asset keys with additional identifying metadata beyond the primary identifier.
// Excludes: assetType, filePath, startLine, endLine (always excluded)
// Additional exclusions can be provided via excludeKeys parameter (e.g., algorithmName, protocolType).
// Returns a string of colon-separated key=value pairs in alphabetical order.
// Example: ":api=Cipher.getInstance:library=JCA:primitive=ae".
func (c *CryptographicAsset) getMetadataKeySuffix(excludeKeys []string) string {
	// Always exclude these fields from the suffix
	alwaysExclude := map[string]bool{
		"assetType": true,
		"filePath":  true,
		"startLine": true,
		"endLine":   true,
	}

	// Add custom exclude keys
	for _, key := range excludeKeys {
		alwaysExclude[key] = true
	}

	// Collect remaining metadata keys
	var keys []string
	for key, value := range c.Metadata {
		if !alwaysExclude[key] && value != "" {
			keys = append(keys, key)
		}
	}

	// Sort keys alphabetically for consistent ordering
	sort.Strings(keys)

	// Build the key=value suffix
	var suffix strings.Builder
	for _, key := range keys {
		suffix.WriteString(":")
		suffix.WriteString(key)
		suffix.WriteString("=")
		suffix.WriteString(c.Metadata[key])
	}

	return suffix.String()
}

// UnmarshalJSON provides backward compatibility for the old "rule" field format.
// It handles both:
//   - Old format: {"rule": {...}}  -> converted to {"rules": [{...}]}
//   - New format: {"rules": [{...}, {...}]}.
func (c *CryptographicAsset) UnmarshalJSON(data []byte) error {
	// Create a temporary type to avoid recursion
	type Alias CryptographicAsset

	// Try to unmarshal with the new format first
	aux := &struct {
		Rule *RuleInfo `json:"rule,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// If old "rule" field is present and Rules array is empty, migrate it
	if aux.Rule != nil && len(c.Rules) == 0 {
		c.Rules = []RuleInfo{*aux.Rule}
	}

	return nil
}
