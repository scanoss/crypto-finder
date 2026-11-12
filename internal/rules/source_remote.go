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
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// RemoteRuleSource loads rules from a remote ruleset via API and caches them locally.
// It returns the path to the cached ruleset directory.
type RemoteRuleSource struct {
	rulesetName  string
	version      string
	cacheManager *cache.Manager
	ctx          context.Context

	// loadedPath is the cached ruleset directory recorded by the most recent
	// successful Load(). Info() reads .cache-meta.json from here. Empty
	// before Load() completes.
	loadedPath string

	// runDir is where the ruleset was decrypted for this run, and cleanup
	// removes it. Load() opens the ruleset once per run.
	runDir  string
	cleanup func()
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
// The ruleset is decrypted into a per-run directory, once per run, and that
// directory, holding the ruleset's .yaml files, is returned; Close removes it.
//
// Returns:
//   - []string: Slice containing the absolute path to the cached ruleset directory
//   - error: Error if download/cache retrieval fails
func (r *RemoteRuleSource) Load() ([]string, error) {
	if r.runDir != "" {
		return []string{r.runDir}, nil
	}
	rulesetPath, err := r.cacheManager.GetRulesetPath(
		r.ctx,
		r.rulesetName,
		r.version,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get ruleset '%s@%s': %w", r.rulesetName, r.version, err)
	}

	r.loadedPath = rulesetPath
	runDir, cleanup, err := r.cacheManager.OpenLeased(r.rulesetName, r.version)
	if err != nil {
		return nil, fmt.Errorf("failed to open ruleset '%s@%s': %w", r.rulesetName, r.version, err)
	}
	r.runDir, r.cleanup = runDir, cleanup
	return []string{runDir}, nil
}

// Close removes the per-run directory of the ruleset. It is safe to
// call more than once and when Load() was not called.
func (r *RemoteRuleSource) Close() {
	if r.cleanup != nil {
		r.cleanup()
	}
	r.runDir, r.cleanup = "", nil
}

// Name returns a human-readable identifier for this source.
func (r *RemoteRuleSource) Name() string {
	return fmt.Sprintf("remote:%s@%s", r.rulesetName, r.version)
}

// Info returns the ruleset version and checksum recorded in .cache-meta.json
// alongside the cached ruleset. Call after Load(); before Load() it returns
// the zero RulesInfo.
//
// Failure modes (missing metadata file, parse error) are logged at warn but
// returned as an empty RulesInfo rather than as an error — the scan itself
// already succeeded; missing metadata is a degraded telemetry state, not a
// scan failure.
func (r *RemoteRuleSource) Info() entities.RulesInfo {
	if r.loadedPath == "" {
		return entities.RulesInfo{}
	}
	meta, err := cache.LoadMetadata(filepath.Join(r.loadedPath, ".cache-meta.json"))
	if err != nil {
		log.Warn().
			Err(err).
			Str("ruleset", r.rulesetName).
			Str("version", r.version).
			Msg("RulesInfo unavailable: failed to read cache metadata")
		return entities.RulesInfo{Source: "remote", Name: r.rulesetName, Version: r.version}
	}
	info := entities.RulesInfo{
		Source:  "remote",
		Name:    meta.RulesetName,
		Version: meta.Version,
	}
	// The bundle is personalised per tenant, so its own hash would tell
	// copies apart. Report the release payload's hash, the same for every
	// tenant, and nothing that names the key or tenant.
	if l, err := cache.ReadLease(r.loadedPath); err == nil {
		info.ChecksumSHA256 = l.PayloadSHA
		info.Lease = &entities.RulesLease{ExpiresAt: l.ExpiresAt, SigningKeyID: l.SigningKeyID}
	}
	return info
}
