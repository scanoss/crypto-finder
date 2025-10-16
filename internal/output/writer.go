package output

import (
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Writer defines the interface for formatting and writing scan results
// to various output formats.
//
// Implementations exist for:
//   - JSON (default format)
type Writer interface {
	// Write formats and writes the report to the specified destination.
	//
	// The destination parameter determines where output is written:
	//   - "" (empty string): Write to stdout
	//   - "-": Write to stdout (Unix convention)
	//   - file path: Write to the specified file
	//
	// Parameters:
	//   - report: The scan results to write
	//   - destination: Output location (empty/"" for stdout, or file path)
	//
	// Returns an error if writing fails.
	Write(report *entities.InterimReport, destination string) error
}
