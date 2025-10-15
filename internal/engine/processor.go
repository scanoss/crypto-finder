package engine

import (
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Processor handles result aggregation and enrichment.
// For MVP, it performs basic validation and metadata enrichment.
type Processor struct{}

// NewProcessor creates a new result processor.
func NewProcessor() *Processor {
	return &Processor{}
}

// Process enriches and validates the scan results.
//
// Current processing:
//   - Validates report structure
//   - Ensures all required fields are present
func (p *Processor) Process(report *entities.InterimReport, detectedLanguages []string) (*entities.InterimReport, error) {
	if report == nil {
		// Return empty report if scanner found nothing
		return &entities.InterimReport{
			Version:  "1.0",
			Tool:     entities.ToolInfo{Name: "unknown", Version: "unknown"},
			Findings: []entities.Finding{},
		}, nil
	}

	// Validate report structure
	if report.Version == "" {
		report.Version = "1.0"
	}

	if report.Findings == nil {
		report.Findings = []entities.Finding{}
	}

	return report, nil
}
