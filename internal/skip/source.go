package skip

import "fmt"

// PatternSource defines an interface for loading skip patterns from various sources.
// Implementations can load patterns from files, remote URLs, databases, environment variables, etc.
type PatternSource interface {
	// Load retrieves skip patterns from the source.
	// Returns an empty slice if the source has no patterns (not an error).
	// Returns an error only if the source exists but cannot be read/parsed.
	Load() ([]string, error)

	// Name returns a human-readable identifier for this source.
	// Used for logging and debugging purposes.
	Name() string
}

// MultiSource aggregates patterns from multiple sources.
// It loads patterns from all sources and merges them, removing duplicates.
type MultiSource struct {
	sources []PatternSource
}

// NewMultiSource creates a new MultiSource that aggregates patterns from multiple sources.
// Sources are loaded in the order provided. Patterns are deduplicated automatically.
//
// Parameters:
//   - sources: Variable number of PatternSource implementations
//
// Returns:
//   - *MultiSource: Aggregator for multiple pattern sources
func NewMultiSource(sources ...PatternSource) *MultiSource {
	return &MultiSource{
		sources: sources,
	}
}

// Load retrieves and merges patterns from all configured sources.
// If any source fails to load, the error is returned immediately.
// Empty patterns from sources are filtered out automatically.
//
// Returns:
//   - []string: Deduplicated merged patterns from all sources
//   - error: First error encountered while loading sources, if any
func (m *MultiSource) Load() ([]string, error) {
	allPatterns := make([]string, 0)

	// Load from each source
	for _, source := range m.sources {
		patterns, err := source.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load patterns from %s: %w", source.Name(), err)
		}
		allPatterns = append(allPatterns, patterns...)
	}

	// Deduplicate patterns
	return deduplicatePatterns(allPatterns), nil
}

// Name returns a descriptive name for this multi-source.
func (m *MultiSource) Name() string {
	if len(m.sources) == 0 {
		return "MultiSource(empty)"
	}
	if len(m.sources) == 1 {
		return m.sources[0].Name()
	}
	return fmt.Sprintf("MultiSource(%d sources)", len(m.sources))
}

// deduplicatePatterns removes duplicate patterns and empty strings.
func deduplicatePatterns(patterns []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if !seen[pattern] {
			seen[pattern] = true
			result = append(result, pattern)
		}
	}

	return result
}
