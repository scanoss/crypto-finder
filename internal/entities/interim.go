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

// Package entities defines implementation-only scanner input structures.
package entities

import "github.com/scanoss/crypto-finder/pkg/schema"

// InterimFormatVersion is the current version of the interim report schema.
const InterimFormatVersion = schema.InterimFormatVersion

type (
	// InterimReport is the standardized output format for all scanners.
	InterimReport = schema.InterimReport
	// ToolInfo contains metadata about the scanner that produced a report.
	ToolInfo = schema.ToolInfo
	// RulesInfo describes the ruleset that fed a scan.
	RulesInfo = schema.RulesInfo
	// Finding represents all cryptographic assets discovered in a single file.
	Finding = schema.Finding
	// CryptographicAsset represents a single detected cryptographic element.
	CryptographicAsset = schema.CryptographicAsset
	// DependencyInfo contains attribution metadata for dependency findings.
	DependencyInfo = schema.DependencyInfo
	// RuleInfo contains information about the detection rule that identified an asset.
	RuleInfo = schema.RuleInfo
)
