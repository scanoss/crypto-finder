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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// findingsCacheVersion is the schema version of the cached payload.
// Bump this constant when the on-the-wire shape of cached entries changes
// in a way that older readers cannot understand. Both the disk and Postgres
// implementations treat a version mismatch as a cache miss.
const findingsCacheVersion = 1

// FindingsCache stores and retrieves scan results for dependencies.
// Implementations can back this with disk, memory, Redis, S3, etc.
type FindingsCache interface {
	// Get retrieves cached scan results for the given cache key.
	// Returns the report and true if found, or nil and false if not cached.
	Get(ctx context.Context, key string) (*entities.InterimReport, bool, error)

	// Put stores scan results under the given cache key.
	Put(ctx context.Context, key string, report *entities.InterimReport) error
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
