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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	api "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/utils"
)

const (
	metadataFileName = ".cache-meta.json"
	manifestFileName = "manifest.json"
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

// GetRulesetPath returns the path to a cached ruleset
// If the ruleset is not cached or expired, it downloads it first.
// If noCache is enabled, it always downloads a fresh copy and updates the cache.
func (m *Manager) GetRulesetPath(ctx context.Context, name, version string) (string, error) {
	rulesetPath := m.getRulesetCachePath(name, version)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)

	// Skip cache check if noCache is enabled
	//nolint:nestif // Cache validation and fallback logic requires nested conditionals for proper error handling
	if !m.noCache {
		// Check if cache exists and is valid
		if m.isCacheValid(rulesetPath, metadataPath) {
			log.Debug().
				Str("ruleset", name).
				Str("version", version).
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
					Str("ruleset", name).
					Str("version", version).
					Msg("Cached ruleset is invalid, will re-download")
				// Cache is corrupted, proceed to download
			} else {
				return rulesetPath, nil
			}
		}
	} else {
		log.Info().
			Str("ruleset", name).
			Str("version", version).
			Msg("Cache bypass enabled, forcing fresh download")
	}

	// Cache is invalid, doesn't exist, or noCache is enabled - download and cache the ruleset
	log.Info().
		Str("ruleset", name).
		Str("version", version).
		Msg("Downloading ruleset")

	if err := m.downloadAndCache(ctx, name, version, rulesetPath); err != nil {
		// Download failed - try stale cache fallback if not in strict mode
		if !m.strictMode {
			if stalePath, staleErr := m.tryStaleCache(rulesetPath, metadataPath, name, version); staleErr == nil {
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

// acquireLock acquires an exclusive file lock for the given ruleset path.
// Returns the lock file which must be closed to release the lock.
// This prevents race conditions when multiple processes try to update the same cache.
func (m *Manager) acquireLock(rulesetPath string) (*os.File, error) {
	lockPath := rulesetPath + lockSuffix

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	// Acquire exclusive lock (blocking)
	lockFD, err := fileDescriptor(lockFile)
	if err != nil {
		if closeErr := lockFile.Close(); closeErr != nil {
			log.Warn().
				Err(closeErr).
				Str("path", lockPath).
				Msg("Failed to close lock file after descriptor error")
		}
		return nil, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX); err != nil {
		if closeErr := lockFile.Close(); closeErr != nil {
			log.Warn().
				Err(closeErr).
				Str("path", lockPath).
				Msg("Failed to close lock file after lock acquisition error")
		}
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return lockFile, nil
}

// releaseLock releases the file lock and closes the lock file.
func (m *Manager) releaseLock(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	// Unlock before closing (best practice, though close also releases)
	lockFD, err := fileDescriptor(lockFile)
	if err != nil {
		log.Warn().
			Err(err).
			Str("path", lockFile.Name()).
			Msg("Failed to resolve cache lock file descriptor")
	} else if err := syscall.Flock(lockFD, syscall.LOCK_UN); err != nil {
		log.Warn().
			Err(err).
			Str("path", lockFile.Name()).
			Msg("Failed to unlock cache lock file")
	}
	if err := lockFile.Close(); err != nil {
		log.Warn().
			Err(err).
			Str("path", lockFile.Name()).
			Msg("Failed to close cache lock file")
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
func (m *Manager) downloadAndCache(ctx context.Context, name, version, targetPath string) error {
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
			Str("ruleset", name).
			Str("version", version).
			Msg("Cache was updated by another process while waiting for lock")
		return nil
	}

	// Download tarball and manifest
	tarball, manifest, err := m.apiClient.DownloadRuleset(ctx, name, version)
	if err != nil {
		return err
	}

	// Verify checksum
	if err := VerifyChecksum(tarball, manifest.ChecksumSHA256); err != nil {
		log.Error().
			Err(err).
			Str("ruleset", name).
			Str("version", version).
			Msg("Checksum verification failed")
		return fmt.Errorf("%w: %s", api.ErrInvalidChecksum, err.Error())
	}

	log.Debug().
		Str("ruleset", name).
		Str("version", version).
		Str("checksum", manifest.ChecksumSHA256).
		Msg("Checksum verified successfully")

	if err := m.persistDownloadedRuleset(name, version, targetPath, tarball, manifest); err != nil {
		return err
	}

	log.Info().
		Str("ruleset", name).
		Str("version", version).
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

func (m *Manager) persistDownloadedRuleset(name, version, targetPath string, tarball []byte, manifest *api.Manifest) error {
	tempPath := targetPath + tempSuffix
	if err := m.extractTarball(tarball, tempPath); err != nil {
		m.cleanupTempPath(tempPath, name, version)
		return fmt.Errorf("failed to extract tarball: %w", err)
	}

	if err := m.writeCacheMetadata(name, version, tempPath, manifest); err != nil {
		m.cleanupTempPath(tempPath, name, version)
		return err
	}

	manifestPath := filepath.Join(tempPath, manifestFileName)
	if err := m.saveManifest(manifest, manifestPath); err != nil {
		m.cleanupTempPath(tempPath, name, version)
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	if err := m.replaceCachedRuleset(targetPath, tempPath); err != nil {
		m.cleanupTempPath(tempPath, name, version)
		return err
	}

	return nil
}

func (m *Manager) writeCacheMetadata(name, version, tempPath string, manifest *api.Manifest) error {
	// Create cache metadata. The version we record is the *manifest* version
	// returned by the SCANOSS API (concrete, e.g. "v1.0.4"), NOT the operator's
	// request label (which can be "latest" — opaque, indistinguishable across
	// upstream rule pack updates). Using the manifest version makes the
	// metadata file a faithful audit trail of what was actually downloaded;
	// downstream consumers (e.g. crypto-mining-service) stamp it on every
	// scan result so a re-mine after a rules update is detectable.
	ttl := m.getTTL(version)
	metadata := NewMetadata(name, manifest.Version, manifest.ChecksumSHA256, int64(ttl.Seconds()))
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

func fileDescriptor(file *os.File) (int, error) {
	if file == nil {
		return 0, fmt.Errorf("resolve file descriptor: nil file")
	}

	fd := file.Fd()
	maxInt := uintptr(^uint(0) >> 1)
	if fd > maxInt {
		return 0, fmt.Errorf("resolve file descriptor: %d exceeds int range", fd)
	}

	return int(fd), nil
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
