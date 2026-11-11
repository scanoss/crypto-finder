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

package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/ruleset"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// A leased ruleset is cached as the encrypted bundle and its lease; its rule
// files exist only in a per-run directory (OpenLeased) while a scan runs.
const (
	bundleFileName = "bundle.enc"
	leaseFileName  = "lease.json"

	// leaseRefreshWindow is how close to expiry a lease is renewed even when
	// the release has not changed.
	leaseRefreshWindow = 7 * 24 * time.Hour

	latestVersion = "latest"
)

// IsLeased reports whether the cached ruleset at rulesetPath is a leased one.
func IsLeased(rulesetPath string) bool {
	_, err := os.Stat(filepath.Join(rulesetPath, bundleFileName))
	return err == nil
}

// ReadLease returns the lease stored beside a leased ruleset, without
// verifying it.
func ReadLease(rulesetPath string) (ruleset.Lease, error) {
	data, err := os.ReadFile(filepath.Join(rulesetPath, leaseFileName))
	if err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: read lease: %w", err)
	}
	l, err := ruleset.DecodeUnverified(data)
	if err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: %w", err)
	}
	return l, nil
}

// ExpiredLeaseError explains an expired lease and how to get rules again.
type ExpiredLeaseError struct {
	Name, Version string
	ExpiresAt     time.Time
}

func (e *ExpiredLeaseError) Error() string {
	return fmt.Sprintf("cache: the lease of ruleset %s@%s expired on %s; refresh it by running online with a valid API key (or importing a new bundle), or scan with --rules-dir",
		e.Name, e.Version, e.ExpiresAt.UTC().Format(time.RFC3339))
}

// Unwrap lets errors.Is match ruleset.ErrExpired.
func (e *ExpiredLeaseError) Unwrap() error { return ruleset.ErrExpired }

// verifyLease checks the lease signature against the trusted keys, its
// expiry, that it names the requested ruleset, and that it vouches for
// exactly the bundle bytes (bundle_sha256).
func verifyLease(name, version string, leaseJSON, bundle []byte) (ruleset.Lease, error) {
	verifier, err := ruleset.NewVerifier()
	if err != nil {
		return ruleset.Lease{}, err
	}
	l, err := verifier.Parse(leaseJSON)
	if err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: verify lease of %s@%s: %w", name, version, err)
	}
	if l.Name != name || (version != latestVersion && l.Version != version) {
		return ruleset.Lease{}, fmt.Errorf("cache: lease is for %s@%s, not %s@%s", l.Name, l.Version, name, version)
	}
	if !time.Now().Before(l.ExpiresAt) {
		return ruleset.Lease{}, &ExpiredLeaseError{Name: name, Version: version, ExpiresAt: l.ExpiresAt}
	}
	if err := verifier.Check(l, bundle); err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: verify bundle of %s@%s: %w", name, version, err)
	}
	return l, nil
}

// persistLeasedRuleset verifies a downloaded leased bundle and stores it
// encrypted with its lease.
func (m *Manager) persistLeasedRuleset(name, version, targetPath string, bundle []byte, manifest *api.Manifest) error {
	l, err := verifyLease(name, version, manifest.Lease, bundle)
	if err != nil {
		return err
	}
	return m.storeLeased(name, targetPath, bundle, manifest.Lease, l, int64(m.getTTL(version).Seconds()))
}

// storeLeased writes bundle.enc, lease.json and .cache-meta.json to
// targetPath, replacing what was there.
func (m *Manager) storeLeased(name, targetPath string, bundle, leaseJSON []byte, l ruleset.Lease, ttlSeconds int64) error {
	sealed, err := ruleset.Seal(m.apiKey(), name, bundle)
	if err != nil {
		return fmt.Errorf("cache: encrypt ruleset %s: %w", name, err)
	}
	tempPath := targetPath + tempSuffix
	if err := os.RemoveAll(tempPath); err != nil {
		return fmt.Errorf("cache: clear %s: %w", tempPath, err)
	}
	if err := os.MkdirAll(tempPath, 0o750); err != nil {
		return fmt.Errorf("cache: create %s: %w", tempPath, err)
	}
	// The checksum recorded is the release payload's, the one the report
	// carries: the same for every tenant, unlike the personalised bundle's.
	metadata := NewMetadata(name, l.Version, l.PayloadSHA, ttlSeconds)
	metadata.Leased = true
	metadata.ExpiresAt = l.ExpiresAt
	err = os.WriteFile(filepath.Join(tempPath, bundleFileName), sealed, 0o600)
	if err == nil {
		err = os.WriteFile(filepath.Join(tempPath, leaseFileName), leaseJSON, 0o600)
	}
	if err == nil {
		err = metadata.Save(filepath.Join(tempPath, metadataFileName))
	}
	if err == nil {
		err = m.replaceCachedRuleset(targetPath, tempPath)
	}
	if err != nil {
		m.cleanupTempPath(tempPath, name, l.Version)
		return fmt.Errorf("cache: store leased ruleset %s@%s: %w", name, l.Version, err)
	}
	return nil
}

func (m *Manager) apiKey() string {
	if m.apiClient == nil {
		return ""
	}
	return m.apiClient.APIKey()
}

// leasedCacheUsable reports whether a leased cache directory holds its files.
func leasedCacheUsable(rulesetPath string) error {
	for _, name := range []string{bundleFileName, leaseFileName} {
		if _, err := os.Stat(filepath.Join(rulesetPath, name)); err != nil {
			return fmt.Errorf("cache: leased ruleset is missing %s: %w", name, err)
		}
	}
	return nil
}

// validateCachedRuleset checks that a cached ruleset holds its content: the
// rule files of a legacy ruleset, the bundle and lease of a leased one.
func validateCachedRuleset(rulesetPath string) error {
	if IsLeased(rulesetPath) {
		return leasedCacheUsable(rulesetPath)
	}
	return utils.ValidateRuleDirNotEmpty(rulesetPath)
}

// confirmCurrentRelease handles an expired TTL of a leased cache without a
// download: when the API reports the same release as the cached lease and
// the lease does not expire within leaseRefreshWindow, it records the check
// and returns true. Any other outcome (an API error included) returns false
// so the caller downloads.
func (m *Manager) confirmCurrentRelease(ctx context.Context, name, version, rulesetPath, metadataPath string) bool {
	if m.apiClient == nil || !IsLeased(rulesetPath) || leasedCacheUsable(rulesetPath) != nil {
		return false
	}
	metadata, err := LoadMetadata(metadataPath)
	if err != nil || !metadata.Leased || time.Until(metadata.ExpiresAt) < leaseRefreshWindow {
		return false
	}
	l, err := ReadLease(rulesetPath)
	if err != nil {
		return false
	}
	release, err := m.apiClient.GetRelease(ctx, name, version)
	if err != nil {
		log.Debug().Err(err).Str("ruleset", name).Str("version", version).Msg("Ruleset release check failed")
		return false
	}
	if release.Version != l.Version || release.PayloadSHA != l.PayloadSHA {
		log.Info().Str("ruleset", name).Str("cached", l.Version).Str("current", release.Version).Msg("A new ruleset release is available")
		return false
	}
	metadata.CheckedAt = time.Now()
	if err := metadata.Save(metadataPath); err != nil {
		log.Warn().Err(err).Msg("Failed to record the ruleset release check")
		return false
	}
	log.Debug().Str("ruleset", name).Str("version", l.Version).Msg("Cached ruleset is the current release")
	return true
}

// OpenLeased decrypts the cached leased ruleset name@version, verifies its
// lease again and extracts it into a new per-run directory beside the
// filtered rule copies. It returns that directory and a func that removes
// it; the caller must call it when the run ends. Run directories left by a
// killed process are pruned by later runs.
func (m *Manager) OpenLeased(name, version string) (string, func(), error) {
	rulesetPath := m.getRulesetCachePath(name, version)
	lock, err := m.acquireLock(rulesetPath)
	if err != nil {
		return "", nil, fmt.Errorf("cache: %w", err)
	}
	leaseJSON, err := os.ReadFile(filepath.Join(rulesetPath, leaseFileName))
	var sealed []byte
	if err == nil {
		sealed, err = os.ReadFile(filepath.Join(rulesetPath, bundleFileName))
	}
	m.releaseLock(lock)
	if err != nil {
		return "", nil, fmt.Errorf("cache: read leased ruleset %s@%s: %w", name, version, err)
	}

	bundle, err := ruleset.Open(m.apiKey(), name, sealed)
	if err != nil {
		return "", nil, fmt.Errorf("cache: decrypt ruleset %s@%s (it opens only with the API key it was downloaded with; use --no-cache to download it again): %w", name, version, err)
	}
	if _, err := verifyLease(name, version, leaseJSON, bundle); err != nil {
		return "", nil, err
	}

	runDir, err := NewRunDir(RunsDir(m.cacheDir, name, version))
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		if err := os.RemoveAll(runDir); err != nil {
			log.Warn().Err(err).Str("path", runDir).Msg("Failed to remove the per-run ruleset directory")
		}
	}
	if err := m.extractTarball(bundle, runDir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("cache: extract ruleset %s@%s: %w", name, version, err)
	}
	if err := utils.ValidateRuleDirNotEmpty(runDir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("cache: ruleset %s@%s: %w", name, version, err)
	}
	return runDir, cleanup, nil
}

// ImportBundle verifies an offline bundle against its lease (the signed lease
// JSON issued with it) and stores it encrypted under the name and version
// the lease names. The imported ruleset counts as current until its lease
// expires.
func (m *Manager) ImportBundle(bundle, leaseJSON []byte) (ruleset.Lease, error) {
	unverified, err := ruleset.DecodeUnverified(leaseJSON)
	if err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: %w", err)
	}
	name, version := unverified.Name, unverified.Version
	if err := validateRulesetSegment(name); err != nil {
		return ruleset.Lease{}, err
	}
	if err := validateRulesetSegment(version); err != nil {
		return ruleset.Lease{}, err
	}
	l, err := verifyLease(name, version, leaseJSON, bundle)
	if err != nil {
		return ruleset.Lease{}, err
	}
	targetPath := m.getRulesetCachePath(name, version)
	lock, err := m.acquireLock(targetPath)
	if err != nil {
		return ruleset.Lease{}, fmt.Errorf("cache: %w", err)
	}
	defer m.releaseLock(lock)
	ttl := int64(time.Until(l.ExpiresAt).Seconds())
	if err := m.storeLeased(name, targetPath, bundle, leaseJSON, l, ttl); err != nil {
		return ruleset.Lease{}, err
	}
	return l, nil
}

// validateRulesetSegment refuses a name or version that would leave the
// cache directory.
func validateRulesetSegment(segment string) error {
	if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) {
		return fmt.Errorf("cache: invalid ruleset name or version %q in lease", segment)
	}
	return nil
}

// CachedRuleset describes one cached ruleset version for `rules status`.
type CachedRuleset struct {
	Name, Version string
	Leased        bool
	ExpiresAt     time.Time
	SigningKeyID  string
}

// List returns the cached rulesets, by name then version label.
func (m *Manager) List() ([]CachedRuleset, error) {
	names, err := os.ReadDir(m.cacheDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cache: list %s: %w", m.cacheDir, err)
	}
	var out []CachedRuleset
	for _, nameEntry := range names {
		if nameEntry.IsDir() {
			out = append(out, m.listVersions(nameEntry.Name())...)
		}
	}
	return out, nil
}

// listVersions returns the cached versions of ruleset name: the directories
// that hold cache metadata.
func (m *Manager) listVersions(name string) []CachedRuleset {
	versions, err := os.ReadDir(filepath.Join(m.cacheDir, name))
	if err != nil {
		return nil
	}
	var out []CachedRuleset
	for _, versionEntry := range versions {
		rulesetPath := filepath.Join(m.cacheDir, name, versionEntry.Name())
		metadata, err := LoadMetadata(filepath.Join(rulesetPath, metadataFileName))
		if err != nil {
			continue
		}
		entry := CachedRuleset{Name: name, Version: versionEntry.Name(), Leased: IsLeased(rulesetPath), ExpiresAt: metadata.ExpiresAt}
		if l, err := ReadLease(rulesetPath); entry.Leased && err == nil {
			entry.SigningKeyID = l.SigningKeyID
			entry.ExpiresAt = l.ExpiresAt
		}
		out = append(out, entry)
	}
	return out
}

// RunsDir is the parent of the per-run directories of ruleset name@version:
// the decrypted copies of a leased ruleset and the language-filtered copies.
func RunsDir(rulesetsDir, name, version string) string {
	return filepath.Join(rulesetsDir, name, config.FilteredRulesDirName, version)
}

// runDirTTL is how old a run-* directory must be before PruneStaleRuns
// reclaims it. It must comfortably exceed the longest scan a concurrent
// process could still be running against its own run-* dir, so a live one is
// never deleted. Scans are bounded by the caller's --timeout (the mining
// worker uses 30m); 2h leaves a wide margin while still reclaiming disk from
// SIGKILLed jobs within the same day.
const runDirTTL = 2 * time.Hour

// NewRunDir prunes stale run-* directories under parent and creates a new one.
func NewRunDir(parent string) (string, error) {
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", fmt.Errorf("cache: create run directory parent: %w", err)
	}
	PruneStaleRuns(parent)
	dir, err := os.MkdirTemp(parent, "run-*")
	if err != nil {
		return "", fmt.Errorf("cache: create run directory: %w", err)
	}
	return dir, nil
}

// PruneStaleRuns removes run-* directories under parent left by runs that
// never cleaned up (for example a job SIGKILLed on timeout). Only dirs whose
// mtime is older than runDirTTL are removed. Best effort: errors are ignored.
func PruneStaleRuns(parent string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-runDirTTL)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		stale := filepath.Join(parent, entry.Name())
		if rmErr := os.RemoveAll(stale); rmErr != nil {
			log.Debug().Err(rmErr).Str("path", stale).Msg("Failed to prune stale run directory")
		}
	}
}
