// Package utils provides general utility functions used across the application.
//
//nolint:revive // utils is a conventional package name for shared utilities
package utils

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
