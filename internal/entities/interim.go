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
)

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

// UnmarshalJSON provides backward compatibility for the old "rule" field format.
// It handles both:
// - Old format: {"rule": {...}}  -> converted to {"rules": [{...}]}
// - New format: {"rules": [{...}, {...}]}.
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
