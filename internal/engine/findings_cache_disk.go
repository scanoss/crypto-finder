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

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	findingsCacheDirName = "findings"
)

var (
	findingsCacheFilenameUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	removeFindingsCacheFile          = os.Remove
)

// findingsCacheEnvelope is the JSON shape the disk implementation writes to
// each cache file. The version field allows future schema changes to
// invalidate older entries without renaming or relocating the cache.
type findingsCacheEnvelope struct {
	Version int                     `json:"version"`
	Report  *entities.InterimReport `json:"report"`
}

// DiskFindingsCache implements FindingsCache using local JSON files.
type DiskFindingsCache struct {
	dir string
}

// NewDiskFindingsCache creates a new disk-based findings cache under
// ~/.scanoss/crypto-finder/cache/findings/.
func NewDiskFindingsCache() (*DiskFindingsCache, error) {
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache dir: %w", err)
	}

	dir := filepath.Join(cacheDir, findingsCacheDirName)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create findings cache dir: %w", err)
	}

	return &DiskFindingsCache{dir: dir}, nil
}

// NewDiskFindingsCacheWithDir creates a disk-based findings cache at a custom directory.
// Useful for testing.
func NewDiskFindingsCacheWithDir(dir string) (*DiskFindingsCache, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create findings cache dir: %w", err)
	}
	return &DiskFindingsCache{dir: dir}, nil
}

// Get retrieves a cached report by key.
// Corrupted cache files are treated as cache misses and are removed.
func (c *DiskFindingsCache) Get(_ context.Context, key string) (*entities.InterimReport, bool, error) {
	path := filepath.Join(c.dir, cacheKeyToFilename(key))

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read cache file: %w", err)
	}

	var envelope findingsCacheEnvelope
	if json.Unmarshal(data, &envelope) != nil || envelope.Version != findingsCacheVersion || envelope.Report == nil {
		// Corrupted cache file — treat as miss and remove it
		if removeErr := removeFindingsCacheFile(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, false, fmt.Errorf("failed to remove corrupted cache file: %w", removeErr)
		}
		return nil, false, nil
	}

	return envelope.Report, true, nil
}

// Put stores a report in the cache using an atomic write-then-rename flow.
func (c *DiskFindingsCache) Put(_ context.Context, key string, report *entities.InterimReport) error {
	data, err := json.Marshal(findingsCacheEnvelope{
		Version: findingsCacheVersion,
		Report:  report,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	path := filepath.Join(c.dir, cacheKeyToFilename(key))
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write to a unique temp file in the same directory, then rename atomically.
	if _, err := tmpFile.Write(data); err != nil {
		return findingsCacheTempFileError("failed to write cache file", err, tmpFile, tmpPath)
	}
	if err := tmpFile.Sync(); err != nil {
		return findingsCacheTempFileError("failed to sync cache file", err, tmpFile, tmpPath)
	}
	if err := tmpFile.Close(); err != nil {
		// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			joinedErr := errors.Join(err, fmt.Errorf("cleanup failed: %w", removeErr))
			return fmt.Errorf("failed to close temp cache file: %w", joinedErr)
		}
		return fmt.Errorf("failed to close temp cache file: %w", err)
	}

	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	if err := os.Rename(tmpPath, path); err != nil {
		// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			joinedErr := errors.Join(err, fmt.Errorf("cleanup failed: %w", removeErr))
			return fmt.Errorf("failed to rename cache file: %w", joinedErr)
		}
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

func findingsCacheTempFileError(message string, baseErr error, tmpFile *os.File, tmpPath string) error {
	joinedErr := baseErr
	if closeErr := tmpFile.Close(); closeErr != nil {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("close temp file: %w", closeErr))
	}
	// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
	if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("cleanup failed: %w", removeErr))
	}
	return fmt.Errorf("%s: %w", message, joinedErr)
}

// cacheKeyToFilename converts a cache key to a filesystem-safe filename.
// Replaces characters outside [A-Za-z0-9._-] with "_" and appends ".json".
func cacheKeyToFilename(key string) string {
	safe := findingsCacheFilenameUnsafeChars.ReplaceAllString(key, "_")
	return safe + ".json"
}
