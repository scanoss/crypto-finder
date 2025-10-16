// Package skip provides utilities for determining which files and directories should be excluded from scanning.
package skip

// SkipMatcher is an interface that defines a matcher for skipping files and directories.
//
//nolint:revive // SkipMatcher name is intentional for clarity and consistency with package API
type SkipMatcher interface {
	// ShouldSkip returns true if the given path should be skipped.
	ShouldSkip(path string, isDir bool) bool
}
