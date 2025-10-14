package output

import (
	"github.com/scanoss/crypto-finder/pkg/schema"
)

// Writer defines the interface for formatting and writing scan results
// to various output formats.
//
// Implementations exist for:
//   - JSON (MVP)
//   - SARIF (Future)
//   - HTML (Future)
type Writer interface {
	// Write formats and writes the report to the specified destination.
	//
	// Parameters:
	//   - report: The scan results to write
	//   - destination: Output file path
	//
	// Returns an error if writing fails.
	Write(report *schema.InterimReport, destination string) error
}
