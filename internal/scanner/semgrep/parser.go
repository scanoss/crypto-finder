package semgrep

import (
	"encoding/json"
	"fmt"

	"github.com/scanoss/crypto-finder/pkg/schema"
)

// parseSemgrepOutput parses Semgrep's JSON output into the SemgrepOutput schema.
func parseSemgrepOutput(data []byte) (*schema.SemgrepOutput, error) {
	if len(data) == 0 {
		// Empty output means no findings, which is valid
		return &schema.SemgrepOutput{
			Results: []schema.SemgrepResult{},
			Errors:  []schema.SemgrepError{},
		}, nil
	}

	var output schema.SemgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal semgrep JSON: %w", err)
	}

	// Check for errors reported by semgrep
	if len(output.Errors) > 0 {
		// Log errors but don't fail - we still want to return any findings
		// Future: Add logging infrastructure to log these warnings
	}

	return &output, nil
}
