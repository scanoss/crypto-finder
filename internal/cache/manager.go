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
)

// Manager manages the local cache of downloaded rulesets.
type Manager struct {
	apiClient *api.Client
	cacheDir  string
	noCache   bool
}

// NewManager creates a new cache manager.
func NewManager(apiClient *api.Client) (*Manager, error) {
	cacheDir, err := config.GetRulesetsDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache directory: %w", err)
	}

	return &Manager{
		apiClient: apiClient,
		cacheDir:  cacheDir,
		noCache:   false,
	}, nil
}

// SetNoCache enables or disables cache bypass mode.
// When enabled, the manager will always download fresh rulesets and update the cache,
// ignoring any existing cached rulesets.
func (m *Manager) SetNoCache(enabled bool) {
	m.noCache = enabled
}

// GetRulesetPath returns the path to a cached ruleset
// If the ruleset is not cached or expired, it downloads it first.
// If noCache is enabled, it always downloads a fresh copy and updates the cache.
func (m *Manager) GetRulesetPath(ctx context.Context, name, version string) (string, error) {
	rulesetPath := m.getRulesetCachePath(name, version)
	metadataPath := filepath.Join(rulesetPath, metadataFileName)

	// Skip cache check if noCache is enabled
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
func (m *Manager) downloadAndCache(ctx context.Context, name, version, targetPath string) error {
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

	// Extract to temporary directory first (atomic operation)
	tempPath := targetPath + tempSuffix
	if err := m.extractTarball(tarball, tempPath); err != nil {
		if err := os.RemoveAll(tempPath); err != nil {
			log.Error().
				Err(err).
				Str("ruleset", name).
				Str("version", version).
				Msg("Failed to clean up temporary directory")
		}
		return fmt.Errorf("failed to extract tarball: %w", err)
	}

	// Create cache metadata
	ttl := m.getTTL(version)
	metadata := NewMetadata(name, version, manifest.ChecksumSHA256, int64(ttl.Seconds()))
	metadataPath := filepath.Join(tempPath, metadataFileName)
	if err := metadata.Save(metadataPath); err != nil {
		if err := os.RemoveAll(tempPath); err != nil {
			log.Error().
				Err(err).
				Str("ruleset", name).
				Str("version", version).
				Msg("Failed to clean up temporary directory")
		}
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	// Save manifest.json reconstructed from response headers
	manifestPath := filepath.Join(tempPath, manifestFileName)
	if err := m.saveManifest(manifest, manifestPath); err != nil {
		if err := os.RemoveAll(tempPath); err != nil {
			log.Error().
				Err(err).
				Str("ruleset", name).
				Str("version", version).
				Msg("Failed to clean up temporary directory")
		}
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	// Remove old cache if it exists
	if _, err := os.Stat(targetPath); err == nil {
		if err := os.RemoveAll(targetPath); err != nil {
			log.Warn().
				Err(err).
				Str("path", targetPath).
				Msg("Failed to remove old cache")
		}
	}

	// Atomic rename from temp to final location
	if err := os.Rename(tempPath, targetPath); err != nil {
		if err := os.RemoveAll(tempPath); err != nil {
			log.Error().
				Err(err).
				Str("ruleset", name).
				Str("version", version).
				Msg("Failed to clean up temporary directory")
		}
		return fmt.Errorf("failed to move cache to final location: %w", err)
	}

	log.Info().
		Str("ruleset", name).
		Str("version", version).
		Str("path", targetPath).
		Msg("Ruleset cached successfully")

	return nil
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
