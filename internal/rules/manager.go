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

// Package rules manages cryptographic detection rules, including loading, validation,
// and filtering of both local and remote rule sets.
package rules

// Manager orchestrates rule loading from multiple sources.
// It provides a central coordination point for aggregating rules from various sources
// (local files, remote URLs, etc.) and will handle caching and validation in the future.
type Manager struct {
	sources []RuleSource
	// Future: Add cache directory and HTTP client for remote rules
}

// NewManager creates a new rules manager with the specified sources.
// Sources are loaded and aggregated when Load() is called.
//
// Parameters:
//   - sources: Variable number of RuleSource implementations to aggregate
//
// Returns:
//   - *Manager: Manager configured with the specified sources
//
// Example:
//
//	manager := rules.NewManager(
//	    rules.NewLocalRuleSource(rulePaths, ruleDirs),
//	    // Future: rules.NewRemoteRuleSource(url, cache),
//	)
func NewManager(sources ...RuleSource) *Manager {
	return &Manager{
		sources: sources,
	}
}

// Load aggregates and returns rule file paths from all configured sources.
// Uses MultiSource internally to handle deduplication and error handling.
//
// Returns:
//   - []string: Deduplicated absolute paths to all rule files
//   - error: If any source fails to load
func (m *Manager) Load() ([]string, error) {
	// Use MultiSource to aggregate all sources
	multiSource := NewMultiSource(m.sources...)
	return multiSource.Load()
}
