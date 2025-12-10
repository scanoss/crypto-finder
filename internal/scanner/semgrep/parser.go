package semgrep

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// ParseSemgrepCompatibleOutput parses Semgrep's JSON output into the SemgrepOutput schema.
// This function can be reused by other compatible scanners (e.g., OpenGrep).
func ParseSemgrepCompatibleOutput(data []byte) (*entities.SemgrepOutput, error) {
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
			// Type can be a string or an array [string, locations]
			errType := getErrorType(err.Type)
			if errType == "error" {
				log.Error().Msg(err.Message)
			}
		}
	}

	return &output, nil
}

// getErrorType extracts the error type string from the Type field.
// Type can be either a string or an array [string, locations].
func getErrorType(typeField any) string {
	if typeField == nil {
		return ""
	}

	// If it's a string, return it directly
	if typeStr, ok := typeField.(string); ok {
		return typeStr
	}

	// If it's an array, extract the first element
	if typeSlice, ok := typeField.([]any); ok && len(typeSlice) > 0 {
		if typeStr, ok := typeSlice[0].(string); ok {
			return typeStr
		}
	}

	return ""
}
