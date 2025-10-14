// Package rules manages cryptographic detection rules, including loading, validation,
// and filtering of both local and remote rule sets.
package rules

// Manager orchestrates rule loading, validation, and filtering.
// For MVP, it handles local rules only. Future versions will support remote rules.
type Manager struct {
	// Future: Add cache directory and HTTP client for remote rules
}

// NewManager creates a new rules manager.
func NewManager() *Manager {
	return &Manager{}
}

// LoadLocal validates and returns local rule paths.
// This is the MVP implementation that handles --rules and --rules-dir flags.
//
// Parameters:
//   - rulePaths: Individual rule file paths (from --rules flags)
//   - ruleDirs: Rule directory paths (from --rules-dir flags)
//
// Returns:
//   - []string: All validated rule file paths (absolute paths)
//   - error: If any path is invalid or doesn't exist
func (m *Manager) LoadLocal(rulePaths []string, ruleDirs []string) ([]string, error) {
	loader := &LocalRulesLoader{}
	return loader.Load(rulePaths, ruleDirs)
}
