package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	findingsCacheDirName = "findings"
	findingsCacheVersion = 1
)

var (
	findingsCacheFilenameUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	removeFindingsCacheFile          = os.Remove
)

type findingsCacheEnvelope struct {
	Version int                     `json:"version"`
	Report  *entities.InterimReport `json:"report"`
}

// FindingsCache stores and retrieves scan results for dependencies.
// Implementations can back this with disk, memory, Redis, S3, etc.
type FindingsCache interface {
	// Get retrieves cached scan results for the given cache key.
	// Returns the report and true if found, or nil and false if not cached.
	Get(ctx context.Context, key string) (*entities.InterimReport, bool, error)

	// Put stores scan results under the given cache key.
	Put(ctx context.Context, key string, report *entities.InterimReport) error
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

// ComputeRulesHash computes a SHA-256 hash of the sorted rule file contents.
// The hash is truncated to 16 hex characters. This captures rule content changes
// so the cache invalidates when rules are edited even if filenames stay the same.
func ComputeRulesHash(rulePaths []string) (string, error) {
	expandedRulePaths, err := expandRulePathsForHash(rulePaths)
	if err != nil {
		return "", err
	}
	sort.Strings(expandedRulePaths)

	h := sha256.New()
	for _, p := range expandedRulePaths {
		content, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("failed to read rule file %s: %w", p, err)
		}
		if _, err := h.Write(content); err != nil {
			return "", fmt.Errorf("failed to hash rule file %s: %w", p, err)
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// expandRulePathsForHash normalizes rule paths for hashing.
// Directory paths are expanded recursively to .yaml/.yml files, while file paths
// are kept as-is so direct rule file usage remains backward-compatible.
func expandRulePathsForHash(rulePaths []string) ([]string, error) {
	files := make([]string, 0, len(rulePaths))
	seen := make(map[string]struct{})

	for _, p := range rulePaths {
		found, _, err := expandRulePathForHash(p, &files, seen)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("no rule files found in directory %s", p)
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files provided")
	}

	return files, nil
}

func expandRulePathForHash(path string, files *[]string, seen map[string]struct{}) (bool, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, false, fmt.Errorf("failed to stat rule path %s: %w", path, err)
	}

	if !info.IsDir() {
		return true, addUniqueRulePath(path, files, seen), nil
	}

	found := false
	added := false
	walkErr := filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isRuleFile(walkPath) {
			return nil
		}
		found = true
		if addUniqueRulePath(walkPath, files, seen) {
			added = true
		}
		return nil
	})
	if walkErr != nil {
		return false, false, fmt.Errorf("failed to walk rule directory %s: %w", path, walkErr)
	}
	return found, added, nil
}

func addUniqueRulePath(path string, files *[]string, seen map[string]struct{}) bool {
	if _, exists := seen[path]; exists {
		return false
	}
	seen[path] = struct{}{}
	*files = append(*files, path)
	return true
}

func isRuleFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
