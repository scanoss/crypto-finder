package rules

import (
	"fmt"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// RuleSource defines an interface for loading rule file paths from various sources.
// Implementations can load rules from local files, remote URLs, databases, etc.
// Each source returns absolute paths to YAML rule files.
type RuleSource interface {
	// Load retrieves absolute paths to rule files from the source.
	// Returns an empty slice if the source has no rules (not an error).
	// Returns an error only if the source exists but cannot be read/parsed.
	Load() ([]string, error)

	// Name returns a human-readable identifier for this source.
	// Used for logging and debugging purposes.
	Name() string
}

// MultiSource aggregates rule paths from multiple sources.
// It loads rules from all sources and merges them, removing duplicates.
type MultiSource struct {
	sources []RuleSource
}

// NewMultiSource creates a new MultiSource that aggregates rules from multiple sources.
// Sources are loaded in the order provided. Rule paths are deduplicated automatically.
//
// Parameters:
//   - sources: Variable number of RuleSource implementations
//
// Returns:
//   - *MultiSource: Aggregator for multiple rule sources
func NewMultiSource(sources ...RuleSource) *MultiSource {
	return &MultiSource{
		sources: sources,
	}
}

// Load retrieves and merges rule paths from all configured sources.
// If any source fails to load, the error is returned immediately.
// Empty paths from sources are filtered out automatically.
//
// Returns:
//   - []string: Deduplicated merged rule paths from all sources
//   - error: First error encountered while loading sources, if any
func (m *MultiSource) Load() ([]string, error) {
	allRules := make([]string, 0)

	// Load from each source
	for _, source := range m.sources {
		rulePaths, err := source.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from %s: %w", source.Name(), err)
		}
		allRules = append(allRules, rulePaths...)
	}

	// Deduplicate paths
	return utils.DeduplicateSliceOfStrings(allRules), nil
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
