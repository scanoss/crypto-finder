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

// Package rules manages cryptographic detection rules, including loading, validation,
// and filtering of both local and remote rule sets.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// LocalRuleSource handles loading and validation of local rule files.
type LocalRuleSource struct {
	rulePaths []string
	ruleDirs  []string

	// loadedPaths is the result of the most recent successful Load(). Info()
	// reads it to compute a deterministic content fingerprint. Empty before
	// Load() completes.
	loadedPaths []string
}

// NewLocalRuleSource creates a new local rule source.
//
// Parameters:
//   - rulePaths: Individual rule file paths (from --rules flags)
//   - ruleDirs: Rule directory paths (from --rules-dir flags)
//
// Returns:
//   - *LocalRuleSource: Source configured to load from local paths and directories
func NewLocalRuleSource(rulePaths, ruleDirs []string) *LocalRuleSource {
	return &LocalRuleSource{
		rulePaths: rulePaths,
		ruleDirs:  ruleDirs,
	}
}

// Load validates and collects all rule file paths from individual files and directories.
// Returns absolute paths to all valid YAML rule files.
//
// Returns:
//   - []string: All validated rule file paths (absolute paths)
//   - error: If any path is invalid or doesn't exist
func (l *LocalRuleSource) Load() ([]string, error) {
	allRules := make([]string, 0)

	// Process individual rule files
	for _, rulePath := range l.rulePaths {
		absPath, err := l.validateRuleFile(rulePath)
		if err != nil {
			return nil, fmt.Errorf("invalid rule file '%s': %w", rulePath, err)
		}
		allRules = append(allRules, absPath)
	}

	// Process rule directories
	for _, ruleDir := range l.ruleDirs {
		rules, err := l.loadRulesFromDirectory(ruleDir)
		if err != nil {
			return nil, fmt.Errorf("invalid rule directory '%s': %w", ruleDir, err)
		}
		allRules = append(allRules, rules...)
	}

	// Ensure at least one rule is provided
	if len(allRules) == 0 {
		return nil, fmt.Errorf("no rules specified: use --rules <file> or --rules-dir <directory>")
	}

	l.loadedPaths = allRules
	return allRules, nil
}

// Name returns a descriptive name for this rule source.
func (l *LocalRuleSource) Name() string {
	totalFiles := len(l.rulePaths)
	totalDirs := len(l.ruleDirs)

	switch {
	case totalFiles > 0 && totalDirs > 0:
		return fmt.Sprintf("local(%d files, %d dirs)", totalFiles, totalDirs)
	case totalFiles > 0:
		return fmt.Sprintf("local(%d files)", totalFiles)
	case totalDirs > 0:
		return fmt.Sprintf("local(%d dirs)", totalDirs)
	default:
		return "local(empty)"
	}
}

// validateRuleFile validates a single rule file path.
//
// It checks:
//   - File exists
//   - File has .yaml or .yml extension
//   - File is readable
//
// Returns absolute path if valid, error otherwise.
func (l *LocalRuleSource) validateRuleFile(path string) (string, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check file exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist")
		}
		return "", fmt.Errorf("cannot access file: %w", err)
	}

	// Check it's a file, not a directory
	if info.IsDir() {
		return "", fmt.Errorf("path is a directory, not a file (use --rules-dir for directories)")
	}

	// Check file extension
	if !l.isValidRuleExtension(absPath) {
		return "", fmt.Errorf("invalid file extension (expected .yaml or .yml)")
	}

	return absPath, nil
}

// loadRulesFromDirectory recursively finds all rule files in a directory.
func (l *LocalRuleSource) loadRulesFromDirectory(dirPath string) ([]string, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist")
		}
		return nil, fmt.Errorf("cannot access directory: %w", err)
	}

	// Check it's a directory
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory")
	}

	// Find all rule files recursively
	rules := make([]string, 0)

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Skip files we can't read (intentionally ignoring error to continue walking)
			return nil //nolint:nilerr // Skip inaccessible files gracefully
		}

		// Skip directories
		if info.IsDir() {
			// Never descend into materialized filtered-rules dirs, including
			// copies left inside ruleset trees by older versions.
			if info.Name() == config.FilteredRulesDirName {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a rule file
		if l.isValidRuleExtension(path) {
			rules = append(rules, path)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Ensure we found at least one rule file
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule files found (expected .yaml or .yml files)")
	}

	return rules, nil
}

// isValidRuleExtension checks if a file has a valid rule file extension (.yaml or .yml).
func (l *LocalRuleSource) isValidRuleExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// Info returns a content fingerprint of the loaded rule files. The
// ChecksumSHA256 is computed deterministically: paths are sorted, then each
// file's SHA256 is concatenated into a single hash. Two scans with the same
// rule files produce the same checksum regardless of `--rules-dir` argument
// order or filesystem walk order.
//
// For local rules there is no manifest, so Name and Version are empty.
// Source is "local" whenever Load() has been called and produced at least
// one path; the zero RulesInfo is returned before Load(). I/O errors during
// hashing degrade to an empty RulesInfo with a warning log — the scan
// already succeeded.
func (l *LocalRuleSource) Info() entities.RulesInfo {
	if len(l.loadedPaths) == 0 {
		return entities.RulesInfo{}
	}
	paths := make([]string, len(l.loadedPaths))
	copy(paths, l.loadedPaths)
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			log.Warn().Err(err).Str("rule_path", p).Msg("RulesInfo: skipping unreadable rule file")
			continue
		}
		// Length-prefix each file so two files concatenated can't collide
		// with a single file containing their concatenation.
		if _, err := fmt.Fprintf(h, "%d:", len(data)); err != nil {
			log.Warn().Err(err).Str("rule_path", p).Msg("RulesInfo: failed to hash rule file size prefix")
			return entities.RulesInfo{Source: "local"}
		}
		if _, err := h.Write(data); err != nil {
			log.Warn().Err(err).Str("rule_path", p).Msg("RulesInfo: failed to hash rule file contents")
			return entities.RulesInfo{Source: "local"}
		}
	}
	return entities.RulesInfo{
		Source:         "local",
		ChecksumSHA256: hex.EncodeToString(h.Sum(nil)),
	}
}
