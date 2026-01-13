package semgrep

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
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

// LogSemgrepCompatibleErrors displays opengrep errors in a user-friendly format.
// Returns true if there were any errors logged.
func LogSemgrepCompatibleErrors(errors []entities.SemgrepError) bool {
	if len(errors) == 0 {
		return false
	}

	var errorItems, warnItems []pterm.BulletListItem

	for _, e := range errors {
		errType := "Unknown"

		if e.Type != nil {
			errType = getErrorType(e.Type)
		}

		msg := e.Message
		if e.Path != "" {
			if len(e.Spans) > 0 {
				msg += pterm.Gray(fmt.Sprintf(" → %s:%d:%d", e.Path, e.Spans[0].Start.Line, e.Spans[0].Start.Col))
			} else {
				msg += pterm.Gray(fmt.Sprintf(" → %s", e.Path))
			}
		}

		item := pterm.BulletListItem{
			Level:  1,
			Text:   msg,
			Bullet: errType,
		}

		switch e.Level {
		case "warn", "warning":
			item.BulletStyle = pterm.NewStyle(pterm.FgYellow)
			warnItems = append(warnItems, item)
		default:
			item.BulletStyle = pterm.NewStyle(pterm.FgRed)
			errorItems = append(errorItems, item)
		}
	}

	pterm.Println()

	// Display errors
	if len(errorItems) > 0 {
		pterm.Error.Println("Scanner Errors")
		err := pterm.DefaultBulletList.WithItems(errorItems).Render()
		if err != nil {
			log.Error().Err(err).Msg("failed while displaying output errors")
		}
	}

	// Display warnings
	if len(warnItems) > 0 {
		pterm.Warning.Println("Warnings")
		err := pterm.DefaultBulletList.WithItems(warnItems).Render()
		if err != nil {
			log.Error().Err(err).Msg("failed while displaying output warnings")
		}
	}

	return true
}

// HandleSemgrepCompatibleErrors displays semgrep compatible errors in a user-friendly format.
// Returns true if there were any errors logged.
func HandleSemgrepCompatibleErrors(stdout []byte, duration time.Duration, exitCode int, scannerName string) error {
	parsedOutput, err := ParseSemgrepCompatibleOutput(stdout)
	if err != nil {
		log.Error().Err(err).Msgf("failed to parse %s output", scannerName)
		return err
	}

	if LogSemgrepCompatibleErrors(parsedOutput.Errors) {
		return fmt.Errorf("%s execution failed with exit code %d", scannerName, exitCode)
	}

	log.Error().
		Int("exit_code", exitCode).
		Dur("duration", duration).
		Msgf("%s failed with no error details", scannerName)
	return fmt.Errorf("%s execution failed with exit code %d", scannerName, exitCode)
}
