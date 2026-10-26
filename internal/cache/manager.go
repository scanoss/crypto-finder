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

// Package cache manages the local cache of downloaded rulesets.
package cache

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog/log"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	metadataFileName = ".cache-meta.json"
	manifestFileName = "manifest.json"
	indexFileName    = "index.json"
	profilesDirName  = "profiles"
	tempSuffix       = ".tmp"
	lockSuffix       = ".lock"
)

// Manager manages the local cache of downloaded rulesets.
type Manager struct {
	apiClient        *api.Client
	cacheDir         string
	noCache          bool
	strictMode       bool
	maxStaleCacheAge time.Duration
}

// NewManager creates a new cache manager.
func NewManager(apiClient *api.Client) (*Manager, error) {
	cacheDir, err := config.GetRulesetsDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache directory: %w", err)
	}

	return &Manager{
		apiClient:        apiClient,
		cacheDir:         cacheDir,
		noCache:          false,
		strictMode:       false,
		maxStaleCacheAge: config.DefaultMaxStaleCacheAge,
	}, nil
}

// SetNoCache enables or disables cache bypass mode.
// When enabled, the manager will always download fresh rulesets and update the cache,
// ignoring any existing cached rulesets.
func (m *Manager) SetNoCache(enabled bool) {
	m.noCache = enabled
}

// SetStrictMode enables or disables strict mode.
// When enabled, the manager will fail if cache is expired and API is unreachable,
// instead of falling back to stale cache.
func (m *Manager) SetStrictMode(enabled bool) {
	m.strictMode = enabled
}

// SetMaxStaleCacheAge sets the maximum age for stale cache fallback.
// If the cached rules are older than this duration, they will not be used as fallback.
func (m *Manager) SetMaxStaleCacheAge(maxAge time.Duration) {
	m.maxStaleCacheAge = maxAge
}

// rulesetRequest names one cached ruleset: the full ruleset of a version,
// or the subset a profile keeps.
type rulesetRequest struct {
	name    string
	version string
	// path is the cache directory of this ruleset.
	path string
	// profile is the hash of the profile a filtered ruleset was reduced
	// with; empty for the full ruleset.
	profile string
	// fetch downloads the ruleset tarball and its manifest.
	fetch func(ctx context.Context) ([]byte, *api.Manifest, error)
}

// GetRulesetPath returns the path to a cached ruleset
// If the ruleset is not cached or expired, it downloads it first.
// If noCache is enabled, it always downloads a fresh copy and updates the cache.
func (m *Manager) GetRulesetPath(ctx context.Context, name, version string) (string, error) {
	return m.resolve(ctx, rulesetRequest{
		name:    name,
		version: version,
		path:    m.getRulesetCachePath(name, version),
		fetch: func(ctx context.Context) ([]byte, *api.Manifest, error) {
			return m.apiClient.DownloadRuleset(ctx, name, version)
		},
	})
}

// GetFilteredRulesetPath returns the path to the cached subset of a ruleset
// that profile keeps, downloading it first when it is not cached or has
// expired. Each profile has its own cache directory, named by the profile
// hash, with the TTL, locking and stale fallback of the full ruleset. Any
// failure is returned, so the caller can fall back to GetRulesetPath.
func (m *Manager) GetFilteredRulesetPath(ctx context.Context, name, version string, profile api.RulesetProfile) (string, error) {
	hash := profileHash(profile)
	return m.resolve(ctx, rulesetRequest{
		name:    name,
		version: version,
		path:    filepath.Join(m.getProfilesCachePath(name, version), hash),
		profile: hash,
		fetch: func(ctx context.Context) ([]byte, *api.Manifest, error) {
			return m.apiClient.DownloadFilteredRuleset(ctx, name, version, profile)
		},
	})
}

// GetRulesetIndex returns the ruleset's index, from the cache while it is
// younger than the ruleset TTL, otherwise from the API. A fresh index is
// written beside the ruleset's profiles; a failed write is only logged.
func (m *Manager) GetRulesetIndex(ctx context.Context, name, version string) (*api.RulesetIndex, error) {
	indexPath := filepath.Join(m.getProfilesCachePath(name, version), indexFileName)
	if !m.noCache {
		if index, err := m.cachedIndex(indexPath, m.getTTL(version)); err == nil {
			log.Debug().Str("ruleset", name).Str("version", version).Msg("Using cached ruleset index")
			return index, nil
		}
	}
	index, err := m.apiClient.GetRulesetIndex(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ruleset index: %w", err)
	}
	if err := m.saveIndex(index, indexPath); err != nil {
		log.Warn().Err(err).Str("path", indexPath).Msg("Failed to cache ruleset index")
	}
	return index, nil
}

// cachedIndex reads an index file no older than ttl.
func (m *Manager) cachedIndex(path string, ttl time.Duration) (*api.RulesetIndex, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) > ttl {
		return nil, fmt.Errorf("cache: ruleset index expired")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a file below the cache directory.
	if err != nil {
		return nil, err
	}
	var index api.RulesetIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("cache: failed to parse ruleset index: %w", err)
	}
	return &index, nil
}

func (m *Manager) saveIndex(index *api.RulesetIndex, path string) error {
	data, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("cache: failed to marshal ruleset index: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("cache: failed to create index directory: %w", err)
	}
	tempPath := path + tempSuffix
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return fmt.Errorf("cache: failed to write ruleset index: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("cache: failed to replace ruleset index: %w", err)
	}
	return nil
}

// LoadManifest reads the manifest.json saved with a cached ruleset.
func LoadManifest(rulesetPath string) (*api.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(rulesetPath, manifestFileName)) // #nosec G304 -- a file below the cache directory.
	if err != nil {
		return nil, fmt.Errorf("cache: failed to read manifest file: %w", err)
	}
	var manifest api.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("cache: failed to parse manifest JSON: %w", err)
	}
	return &manifest, nil
}

// resolve serves the request from the cache when it is valid, otherwise
// downloads and caches it, falling back to a stale cache entry when the
// download fails outside strict mode.
func (m *Manager) resolve(ctx context.Context, req rulesetRequest) (string, error) {
	rulesetPath := req.path
	metadataPath := filepath.Join(rulesetPath, metadataFileName)

	// Skip cache check if noCache is enabled
	//nolint:nestif // Cache validation and fallback logic requires nested conditionals for proper error handling
	if !m.noCache {
		// Check if cache exists and is valid
		if m.isCacheValid(rulesetPath, metadataPath) {
			log.Debug().
				Str("ruleset", req.name).
				Str("version", req.version).
				Str("profile", req.profile).
				Str("path", rulesetPath).
				Msg("Using cached ruleset")

			// Update last accessed time
			if err := m.updateLastAccessed(metadataPath); err != nil {
				log.Warn().Err(err).Msg("Failed to update last accessed time")
			}

			// Validate that cached ruleset contains rule files
			if err := utils.ValidateRuleDirNotEmpty(rulesetPath); err != nil {
				log.Warn().
					Err(err).
					Str("ruleset", req.name).
					Str("version", req.version).
					Msg("Cached ruleset is invalid, will re-download")
				// Cache is corrupted, proceed to download
			} else {
				return rulesetPath, nil
			}
		}
	} else {
		log.Info().
			Str("ruleset", req.name).
			Str("version", req.version).
			Msg("Cache bypass enabled, forcing fresh download")
	}

	// Cache is invalid, doesn't exist, or noCache is enabled - download and cache the ruleset
	log.Info().
		Str("ruleset", req.name).
		Str("version", req.version).
		Str("profile", req.profile).
		Msg("Downloading ruleset")

	if err := m.downloadAndCache(ctx, req); err != nil {
		// Download failed - try stale cache fallback if not in strict mode
		if !m.strictMode {
			if stalePath, staleErr := m.tryStaleCache(rulesetPath, metadataPath, req.name, req.version); staleErr == nil {
				// Successfully using stale cache
				return stalePath, nil
			}
			// Stale cache fallback also failed, log why and return original error
			log.Debug().Msg("Stale cache fallback unavailable")
		}
		return "", fmt.Errorf("failed to download ruleset: %w", err)
	}

	if err := utils.ValidateRuleDirNotEmpty(rulesetPath); err != nil {
		return "", fmt.Errorf("downloaded ruleset validation failed: %w", err)
	}

	return rulesetPath, nil
}

// getRulesetCachePath returns the cache path for a specific ruleset.
func (m *Manager) getRulesetCachePath(name, version string) string {
	return filepath.Join(m.cacheDir, name, version)
}

// getProfilesCachePath returns the directory holding the filtered subsets
// of a ruleset version, one per profile hash, and its index. It stands
// beside the full ruleset's directory, which is replaced whole on every
// download and loaded whole by the scanner.
func (m *Manager) getProfilesCachePath(name, version string) string {
	return filepath.Join(m.cacheDir, name, profilesDirName, version)
}

// profileHash is the sha256 hex of the canonical profile JSON: sorted keys
// and lists, no whitespace.
func profileHash(profile api.RulesetProfile) string {
	canonical := api.RulesetProfile{Languages: append([]string{}, profile.Languages...), Modules: make(map[string][]string, len(profile.Modules))}
	sort.Strings(canonical.Languages)
	for family, modules := range profile.Modules {
		sorted := append([]string{}, modules...)
		sort.Strings(sorted)
		canonical.Modules[family] = sorted
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// acquireLock acquires an exclusive file lock for the given ruleset path.
// Returns the lock which must be released via releaseLock.
// This prevents race conditions when multiple processes try to update the same cache.
func (m *Manager) acquireLock(rulesetPath string) (*flock.Flock, error) {
	lockPath := rulesetPath + lockSuffix

	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}

	lock := flock.New(lockPath)
	if err := lock.Lock(); err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return lock, nil
}

// releaseLock releases the file lock.
func (m *Manager) releaseLock(lock *flock.Flock) {
	if lock == nil {
		return
	}
	if err := lock.Unlock(); err != nil {
		log.Warn().
			Err(err).
			Str("path", lock.Path()).
			Msg("Failed to unlock cache lock file")
	}
}

// isCacheValid checks if the cached ruleset is valid (exists, not expired, checksum matches).
func (m *Manager) isCacheValid(rulesetPath, metadataPath string) bool {
	// Check if ruleset directory exists
	if _, err := os.Stat(rulesetPath); os.IsNotExist(err) {
		return false
	}

	// Check if metadata exists
	metadata, err := LoadMetadata(metadataPath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to load cache metadata")
		return false
	}

	// Check if cache has expired
	if metadata.IsExpired() {
		log.Debug().
			Str("ruleset", metadata.RulesetName).
			Str("version", metadata.Version).
			Time("downloaded_at", metadata.DownloadedAt).
			Msg("Cache expired")
		return false
	}

	return true
}

// updateLastAccessed updates the last accessed timestamp in the metadata.
func (m *Manager) updateLastAccessed(metadataPath string) error {
	metadata, err := LoadMetadata(metadataPath)
	if err != nil {
		return err
	}

	metadata.UpdateLastAccessed()
	return metadata.Save(metadataPath)
}

// downloadAndCache downloads a ruleset and caches it.
// Uses file locking to prevent race conditions when multiple processes try to
// update the same cache simultaneously.
func (m *Manager) downloadAndCache(ctx context.Context, req rulesetRequest) error {
	targetPath := req.path
	// Acquire exclusive lock to prevent race conditions
	lockFile, err := m.acquireLock(targetPath)
	if err != nil {
		return fmt.Errorf("failed to acquire cache lock: %w", err)
	}
	defer m.releaseLock(lockFile)

	// Re-check if cache is valid after acquiring lock - another process may have
	// updated it while we were waiting for the lock
	metadataPath := filepath.Join(targetPath, metadataFileName)
	if m.hasUsableCache(targetPath, metadataPath) {
		log.Debug().
			Str("ruleset", req.name).
			Str("version", req.version).
			Msg("Cache was updated by another process while waiting for lock")
		return nil
	}

	// Download tarball and manifest
	tarball, manifest, err := req.fetch(ctx)
	if err != nil {
		return err
	}

	// Verify checksum
	if err := VerifyChecksum(tarball, manifest.ChecksumSHA256); err != nil {
		log.Error().
			Err(err).
			Str("ruleset", req.name).
			Str("version", req.version).
			Msg("Checksum verification failed")
		return fmt.Errorf("%w: %s", api.ErrInvalidChecksum, err.Error())
	}

	log.Debug().
		Str("ruleset", req.name).
		Str("version", req.version).
		Str("checksum", manifest.ChecksumSHA256).
		Msg("Checksum verified successfully")

	if err := m.persistDownloadedRuleset(req, tarball, manifest); err != nil {
		return err
	}

	log.Info().
		Str("ruleset", req.name).
		Str("version", req.version).
		Str("profile", req.profile).
		Str("rules", manifest.Rules).
		Str("path", targetPath).
		Msg("Ruleset cached successfully")

	return nil
}

func (m *Manager) hasUsableCache(rulesetPath, metadataPath string) bool {
	if !m.isCacheValid(rulesetPath, metadataPath) {
		return false
	}
	return utils.ValidateRuleDirNotEmpty(rulesetPath) == nil
}

func (m *Manager) persistDownloadedRuleset(req rulesetRequest, tarball []byte, manifest *api.Manifest) error {
	targetPath := req.path
	tempPath := targetPath + tempSuffix
	if err := m.extractTarball(tarball, tempPath); err != nil {
		m.cleanupTempPath(tempPath, req.name, req.version)
		return fmt.Errorf("failed to extract tarball: %w", err)
	}

	if err := m.writeCacheMetadata(req, tempPath, manifest); err != nil {
		m.cleanupTempPath(tempPath, req.name, req.version)
		return err
	}

	manifestPath := filepath.Join(tempPath, manifestFileName)
	if err := m.saveManifest(manifest, manifestPath); err != nil {
		m.cleanupTempPath(tempPath, req.name, req.version)
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	if err := m.replaceCachedRuleset(targetPath, tempPath); err != nil {
		m.cleanupTempPath(tempPath, req.name, req.version)
		return err
	}

	return nil
}

func (m *Manager) writeCacheMetadata(req rulesetRequest, tempPath string, manifest *api.Manifest) error {
	// Create cache metadata. The version we record is the *manifest* version
	// returned by the SCANOSS API (concrete, e.g. "v1.0.4"), NOT the operator's
	// request label (which can be "latest" — opaque, indistinguishable across
	// upstream rule pack updates). Using the manifest version makes the
	// metadata file a faithful audit trail of what was actually downloaded;
	// downstream consumers can stamp it on scan results so a rules update is
	// detectable.
	ttl := m.getTTL(req.version)
	metadata := NewMetadata(req.name, manifest.Version, manifest.ChecksumSHA256, int64(ttl.Seconds()))
	metadata.Profile = req.profile
	tempMetadataPath := filepath.Join(tempPath, metadataFileName)
	if err := metadata.Save(tempMetadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}
	return nil
}

func (m *Manager) replaceCachedRuleset(targetPath, tempPath string) error {
	if _, err := os.Stat(targetPath); err == nil {
		if err := os.RemoveAll(targetPath); err != nil {
			log.Warn().
				Err(err).
				Str("path", targetPath).
				Msg("Failed to remove old cache")
		}
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("failed to move cache to final location: %w", err)
	}

	return nil
}

func (m *Manager) cleanupTempPath(tempPath, name, version string) {
	if err := os.RemoveAll(tempPath); err != nil {
		log.Error().
			Err(err).
			Str("ruleset", name).
			Str("version", version).
			Msg("Failed to clean up temporary directory")
	}
}

// extractTarball extracts a .tar.gz tarball to the specified directory.
//
//nolint:gocognit,gocyclo // Ignore complexity
func (m *Manager) extractTarball(tarball []byte, targetDir string) error {
	// Create target directory
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Create gzip reader
	gzr, err := gzip.NewReader(newBytesReader(tarball))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close gzip reader")
		}
	}()

	// Create tar reader
	tr := tar.NewReader(gzr)

	// Extract all files
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Clean the path to prevent directory traversal
		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") {
			log.Warn().
				Str("file", header.Name).
				Msg("Skipping file with invalid path")
			continue
		}

		// Skip macOS metadata files
		baseName := filepath.Base(cleanName)
		if strings.HasPrefix(baseName, "._") || baseName == ".DS_Store" {
			log.Debug().
				Str("file", header.Name).
				Msg("Skipping macOS metadata file")
			continue
		}

		target := filepath.Join(targetDir, cleanName)

		switch header.Typeflag {
		case tar.TypeDir:
			// #nosec G115 -- Safe conversion: header.Mode & 0o777 max value is 511, well within uint32 range
			mode := os.FileMode(uint32(header.Mode & 0o777))
			if err := os.MkdirAll(target, mode); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", target, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", target, err)
			}

			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", target, err)
			}

			// Limit file size to prevent decompression bomb attacks (100MB per file)
			const maxFileSize = 100 * 1024 * 1024 // 100MB
			limitedReader := io.LimitReader(tr, maxFileSize)

			if _, err := io.Copy(outFile, limitedReader); err != nil {
				if closeErr := outFile.Close(); closeErr != nil {
					log.Warn().Err(closeErr).Str("file", target).Msg("Failed to close file after write error")
				}
				return fmt.Errorf("failed to write file %s: %w", target, err)
			}

			if err := outFile.Close(); err != nil {
				return fmt.Errorf("failed to close file %s: %w", target, err)
			}

			// #nosec G115 -- Safe conversion: header.Mode & 0o777 max value is 511, well within uint32 range
			mode := os.FileMode(uint32(header.Mode & 0o777))
			if err := os.Chmod(target, mode); err != nil {
				log.Warn().
					Err(err).
					Str("file", target).
					Msg("Failed to set file permissions")
			}
		}
	}

	return nil
}

// saveManifest saves the manifest to a JSON file.
func (m *Manager) saveManifest(manifest *api.Manifest, path string) error {
	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}

	log.Debug().
		Str("path", path).
		Msg("Manifest saved successfully")

	return nil
}

// getTTL returns the appropriate TTL for a version
// "latest" gets 24 hours, pinned versions get 7 days.
func (m *Manager) getTTL(version string) time.Duration {
	if version == "latest" {
		return config.DefaultLatestCacheTTL
	}
	return config.DefaultCacheTTL
}

// tryStaleCache attempts to use stale (expired) cache as a fallback when API is unreachable.
// Returns the cached ruleset path if valid stale cache exists and is within max age limit.
// Returns an error if no stale cache exists, cache is too old, or validation fails.
func (m *Manager) tryStaleCache(rulesetPath, metadataPath, name, version string) (string, error) {
	// Check if ruleset directory exists
	if _, err := os.Stat(rulesetPath); os.IsNotExist(err) {
		return "", fmt.Errorf("no cached ruleset found")
	}

	// Load metadata
	metadata, err := LoadMetadata(metadataPath)
	if err != nil {
		return "", fmt.Errorf("failed to load cache metadata: %w", err)
	}

	// Check if cache is too stale
	if metadata.IsTooStale(m.maxStaleCacheAge) {
		cacheAge := metadata.Age()
		return "", fmt.Errorf("cached ruleset is too old (age: %s, max: %s)",
			cacheAge.Round(time.Hour),
			m.maxStaleCacheAge.Round(time.Hour))
	}

	// Validate that cached ruleset contains rule files
	if err := utils.ValidateRuleDirNotEmpty(rulesetPath); err != nil {
		return "", fmt.Errorf("cached ruleset is invalid: %w", err)
	}

	// Cache is usable, log warning and return
	cacheAge := metadata.Age()
	log.Warn().
		Str("ruleset", name).
		Str("version", version).
		Dur("age", cacheAge.Round(time.Hour)).
		Time("cached_at", metadata.DownloadedAt).
		Msg("Failed to download remote rules. Using stale cache")

	// Update last accessed time
	if err := m.updateLastAccessed(metadataPath); err != nil {
		log.Warn().Err(err).Msg("Failed to update last accessed time")
	}

	return rulesetPath, nil
}

// newBytesReader creates an io.Reader from a byte slice.
func newBytesReader(data []byte) io.Reader {
	return &bytesReader{data: data, pos: 0}
}

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
