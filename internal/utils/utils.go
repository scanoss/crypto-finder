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

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read rules directory '%s': %w", dirPath, err)
	}

	hasRuleFiles := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			hasRuleFiles = true
			break
		}
	}

	if !hasRuleFiles {
		return fmt.Errorf("rules directory '%s' contains no rule files (.yaml or .yml)", dirPath)
	}

	return nil
}
