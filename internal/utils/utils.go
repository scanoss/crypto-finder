// Package utils provides general utility functions used across the application.
//
//nolint:revive // utils is a conventional package name for shared utilities
package utils

import (
	"strings"
	"unicode"
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

// CamelToSnake converts a camelCase string to snake_case.
//
// Example: "algorithmName" -> "algorithm_name".
func CamelToSnake(s string) string {
	var result strings.Builder

	for i, r := range s {
		if unicode.IsUpper(r) {
			// Add underscore before uppercase letter (except at the start)
			if i > 0 {
				result.WriteRune('_')
			}
			// Convert to lowercase
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}
