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

package rules

import (
	"context"
	"fmt"

	"github.com/scanoss/crypto-finder/internal/cache"
)

// RemoteRuleSource loads rules from a remote ruleset via API and caches them locally.
// It returns the path to the cached ruleset directory.
type RemoteRuleSource struct {
	rulesetName  string
	version      string
	cacheManager *cache.Manager
	ctx          context.Context
}

// NewRemoteRuleSource creates a new remote rule source
//
// Parameters:
//   - ctx: Context for API requests and cancellation
//   - rulesetName: Name of the ruleset to fetch (e.g., "dca")
//   - version: Version of the ruleset (e.g., "latest", "v1.0.0")
//   - cacheManager: Cache manager for downloading and caching rulesets
//
// Returns:
//   - *RemoteRuleSource: Configured remote rule source
func NewRemoteRuleSource(
	ctx context.Context,
	rulesetName string,
	version string,
	cacheManager *cache.Manager,
) *RemoteRuleSource {
	return &RemoteRuleSource{
		rulesetName:  rulesetName,
		version:      version,
		cacheManager: cacheManager,
		ctx:          ctx,
	}
}

// Load retrieves the path to the cached ruleset directory.
// If the ruleset is not cached or has expired, it will be downloaded.
// The returned path points to a directory containing the ruleset's .yaml files.
//
// Returns:
//   - []string: Slice containing the absolute path to the cached ruleset directory
//   - error: Error if download/cache retrieval fails
func (r *RemoteRuleSource) Load() ([]string, error) {
	rulesetPath, err := r.cacheManager.GetRulesetPath(
		r.ctx,
		r.rulesetName,
		r.version,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get ruleset '%s@%s': %w", r.rulesetName, r.version, err)
	}

	return []string{rulesetPath}, nil
}

// Name returns a human-readable identifier for this source.
func (r *RemoteRuleSource) Name() string {
	return fmt.Sprintf("remote:%s@%s", r.rulesetName, r.version)
}
