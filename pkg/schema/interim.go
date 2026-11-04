// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package schema defines the public interim report contract for SCANOSS crypto-finder.
//
// It forwards to github.com/scanoss/static-engine/schema, which holds the
// implementation; the names here are aliases so both paths share one type.
package schema

import (
	engineschema "github.com/scanoss/static-engine/schema"
)

type (
	// InterimReport is the standardized output format for all scanners.
	// This format provides a unified representation of cryptographic findings
	// that can be consumed by the SCANOSS ecosystem and other downstream tools.
	InterimReport = engineschema.InterimReport
	// ToolInfo contains metadata about the scanner that produced the report.
	ToolInfo = engineschema.ToolInfo
	// RulesInfo describes the ruleset that fed a scan. The Source field is
	// always set when Rules is populated; Name / Version / ChecksumSHA256 are
	// best-effort and may be empty depending on the source type.
	//
	// For remote rulesets, Version is the manifest version returned by the
	// SCANOSS API (e.g. "v1.0.0", "latest") and ChecksumSHA256 is the manifest
	// checksum, both lifted from .cache-meta.json. For local rulesets, Version
	// is empty and ChecksumSHA256 is a hash of the loaded rule file contents
	// in deterministic order.
	RulesInfo = engineschema.RulesInfo
	// Finding represents all cryptographic assets discovered in a single file.
	// Each file that contains cryptographic material will have one Finding entry.
	Finding = engineschema.Finding
	// CryptographicAsset represents a single detected cryptographic element.
	CryptographicAsset = engineschema.CryptographicAsset
	// DependencyInfo contains attribution metadata for findings originating from dependencies.
	DependencyInfo = engineschema.DependencyInfo
	// RuleInfo contains information about the detection rule that identified the cryptographic asset.
	RuleInfo = engineschema.RuleInfo
)

const (
	// InterimFormatVersion is the current version of the interim report schema.
	InterimFormatVersion = engineschema.InterimFormatVersion
)
