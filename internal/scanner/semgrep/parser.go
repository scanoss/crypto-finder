package semgrep

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// parseSemgrepOutput parses Semgrep's JSON output into the SemgrepOutput schema.
func parseSemgrepOutput(data []byte) (*entities.SemgrepOutput, error) {
	if len(data) == 0 {
		// Empty output means no findings, which is valid
		return &entities.SemgrepOutput{
			Results: []entities.SemgrepResult{},
			Errors:  []entities.SemgrepError{},
		}, nil
	}

	var output entities.SemgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal semgrep JSON: %w", err)
	}

	// Check for errors reported by semgrep
	if len(output.Errors) > 0 {
		log.Error().Msgf("There were %d errors reported by Semgrep", len(output.Errors))

		for _, err := range output.Errors {
			if err.Type == "error" {
				log.Error().Msg(err.Message)
			}
		}
	}

	return &output, nil
}
