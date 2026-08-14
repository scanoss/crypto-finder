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

// Package utils provides general utility functions used across the application.
//
//revive:disable:var-naming // utils is a conventional package name for shared utilities
package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes a file completely before replacing its destination.
// The temporary file is created beside the destination so the rename is atomic.
func WriteFileAtomic(path string, perm os.FileMode, write func(*os.File) error) (retErr error) {
	if write == nil {
		return fmt.Errorf("utils: atomic write callback is nil")
	}

	parentDir := filepath.Dir(path)
	if err := os.MkdirAll(parentDir, 0o750); err != nil {
		return fmt.Errorf("utils: failed to create parent directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(parentDir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("utils: failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			// #nosec G703 -- tmpPath is created by os.CreateTemp in this function.
			if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("utils: failed to clean temporary file: %w", removeErr))
			}
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("utils: failed to set temporary file permissions: %w", errors.Join(err, closeErr))
		}
		return fmt.Errorf("utils: failed to set temporary file permissions: %w", err)
	}
	if err := write(tmpFile); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("utils: failed to write temporary file: %w", errors.Join(err, closeErr))
		}
		return fmt.Errorf("utils: failed to write temporary file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			return fmt.Errorf("utils: failed to sync temporary file: %w", errors.Join(err, closeErr))
		}
		return fmt.Errorf("utils: failed to sync temporary file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("utils: failed to close temporary file: %w", err)
	}
	// #nosec G703 -- path is the explicit output destination and tmpPath is created beside it.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("utils: failed to replace destination: %w", err)
	}

	removeTemp = false
	return nil
}

// DeduplicateSliceOfStrings removes duplicate strings and empty strings from a slice.
func DeduplicateSliceOfStrings(duplicates []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(duplicates))

	for _, duplicate := range duplicates {
		if duplicate == "" {
			continue
		}
		if !seen[duplicate] {
			seen[duplicate] = true
			result = append(result, duplicate)
		}
	}

	return result
}

// ValidateRuleDirNotEmpty checks if a directory exists, is a directory, and contains rule files.
// Returns an error if the directory doesn't exist, is not a directory, or contains no .yaml/.yml files.
func ValidateRuleDirNotEmpty(dirPath string) error {
	info, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("rules directory '%s' does not exist", dirPath)
	}
	if err != nil {
		return fmt.Errorf("failed to check rules directory '%s': %w", dirPath, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("rules directory '%s' is not a directory", dirPath)
	}

	hasRuleFiles := false
	walkErr := filepath.WalkDir(dirPath, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			hasRuleFiles = true
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("failed to read rules directory '%s': %w", dirPath, walkErr)
	}

	if !hasRuleFiles {
		return fmt.Errorf("rules directory '%s' contains no rule files (.yaml or .yml)", dirPath)
	}

	return nil
}
