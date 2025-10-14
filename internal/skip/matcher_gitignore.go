package skip

import (
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
)

// GitIgnoreMatcher determines whether files or directories match a given gitignore-style pattern
type GitIgnoreMatcher struct {
	ignorer *ignore.GitIgnore
}

// NewGitIgnoreMatcher creates a new GitIgnoreMatcher with the provided patterns.
// Patterns follow gitignore syntax and are deduplicated automatically.
//
// Patterns can be:
//   - Directory names (e.g., "node_modules", "vendor")
//   - Glob patterns (e.g., "*.min.js", "build/")
//   - Path segments (e.g., "test/", ".git/")
//   - Negation patterns (e.g., "!important.js")
//   - ** recursive wildcards (e.g., "**/test/**")
//
// Parameters:
//   - patterns: List of gitignore-style skip patterns
//
// Returns:
//   - *SkipMatcher: Configured matcher
func NewGitIgnoreMatcher(patterns []string) *GitIgnoreMatcher {
	// Deduplicate patterns
	seen := make(map[string]bool)
	unique := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if !seen[pattern] {
			seen[pattern] = true
			unique = append(unique, pattern)
		}
	}

	// Create gitignore matcher from patterns
	ignorer := ignore.CompileIgnoreLines(unique...)

	return &GitIgnoreMatcher{
		ignorer: ignorer,
	}
}

// ShouldSkip checks if a file or directory path should be skipped.
// It uses gitignore-style pattern matching and also automatically skips hidden directories.
//
// Parameters:
//   - path: Full or relative path to check
//   - isDir: Whether the path is a directory
//
// Returns:
//   - bool: true if the path should be skipped
func (m *GitIgnoreMatcher) ShouldSkip(path string, isDir bool) bool {
	// Automatically skip hidden directories (starting with ., except "." itself)
	if isDir {
		// Get the last component of the path
		lastSlash := strings.LastIndex(path, "/")
		basename := path
		if lastSlash >= 0 {
			basename = path[lastSlash+1:]
		}

		if strings.HasPrefix(basename, ".") && basename != "." {
			return true
		}

		// For gitignore matching, directories need trailing slash
		if !strings.HasSuffix(path, "/") {
			path = path + "/"
		}
	}

	return m.ignorer.MatchesPath(path)
}
