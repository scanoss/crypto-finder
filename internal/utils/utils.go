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
package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	walkErr := filepath.WalkDir(dirPath, func(path string, entry os.DirEntry, err error) error {
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
