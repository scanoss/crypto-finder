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

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/cache"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
)

// ProfileBuilder computes, against a ruleset index, the profile of the
// sources a scan reads: the languages they have files of and the index
// modules they use.
type ProfileBuilder func(ctx context.Context, index *prefilter.Index) (prefilter.Profile, error)

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

	// buildProfile, when set, lets Load() download only the rules the scan
	// can use. Nil loads the full ruleset.
	buildProfile ProfileBuilder
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

// SetProfileBuilder makes Load() download the ruleset reduced to the
// profile build computes from the ruleset index. Any failure on the way
// (index, profile, filtered download) falls back to the full ruleset.
func (r *RemoteRuleSource) SetProfileBuilder(build ProfileBuilder) {
	r.buildProfile = build
}

// Load retrieves the path to the cached ruleset directory.
// If the ruleset is not cached or has expired, it will be downloaded.
// The returned path points to a directory containing the ruleset's .yaml files.
//
// Returns:
//   - []string: Slice containing the absolute path to the cached ruleset directory
//   - error: Error if download/cache retrieval fails
func (r *RemoteRuleSource) Load() ([]string, error) {
	if r.buildProfile != nil {
		rulesetPath, err := r.loadFiltered()
		if err == nil {
			r.loadedPath = rulesetPath
			return []string{rulesetPath}, nil
		}
		log.Warn().
			Err(err).
			Str("ruleset", r.rulesetName).
			Str("version", r.version).
			Msg("Filtered ruleset unavailable; falling back to the full ruleset")
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
	return []string{rulesetPath}, nil
}

// loadFiltered fetches the index, builds the profile and returns the cached
// filtered ruleset for it. A profile without languages, for a target the
// ruleset has no rules for, loads the full ruleset instead.
func (r *RemoteRuleSource) loadFiltered() (string, error) {
	index, err := r.cacheManager.GetRulesetIndex(r.ctx, r.rulesetName, r.version)
	if err != nil {
		return "", err
	}
	profile, err := r.buildProfile(r.ctx, indexOf(index))
	if err != nil {
		return "", fmt.Errorf("rules: build ruleset profile: %w", err)
	}
	if profile.IsEmpty() {
		return "", fmt.Errorf("rules: the target has no files of a ruleset language")
	}
	request := api.RulesetProfile{Languages: profile.Languages, Modules: make(map[string][]string, len(profile.Modules))}
	for family, modules := range profile.Modules {
		request.Modules[string(family)] = modules
	}
	rulesetPath, err := r.cacheManager.GetFilteredRulesetPath(r.ctx, r.rulesetName, r.version, request)
	if err != nil {
		return "", err
	}
	event := log.Info().
		Str("ruleset", r.rulesetName).
		Str("version", r.version).
		Strs("languages", profile.Languages).
		Int("modules", profile.ModuleCount()).
		Str("profile", profile.Hash())
	for family, modules := range profile.Modules {
		event = event.Int("modules_"+string(family), len(modules))
	}
	if manifest, err := cache.LoadManifest(rulesetPath); err == nil {
		event = event.Str("rules", manifest.Rules)
	}
	event.Msg("Remote ruleset filtered to the scan's languages and libraries")
	return rulesetPath, nil
}

func indexOf(index *api.RulesetIndex) *prefilter.Index {
	out := &prefilter.Index{Languages: index.Languages, Modules: make(map[prefilter.Family][]string, len(index.Modules))}
	for family, modules := range index.Modules {
		out.Modules[prefilter.Family(family)] = modules
	}
	return out
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
	return entities.RulesInfo{
		Source:         "remote",
		Name:           meta.RulesetName,
		Version:        meta.Version,
		ChecksumSHA256: meta.ChecksumSHA256,
		Profile:        meta.Profile,
	}
}
