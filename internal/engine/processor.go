package engine

import (
	"github.com/scanoss/crypto-finder/pkg/schema"
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
//   - Future: Add file-level language detection override
//   - Future: Add FIPS compliance checking
//   - Future: Add vulnerability correlation
func (p *Processor) Process(report *schema.InterimReport, detectedLanguages []string) (*schema.InterimReport, error) {
	if report == nil {
		// Return empty report if scanner found nothing
		return &schema.InterimReport{
			Version:  "1.0",
			Tool:     schema.ToolInfo{Name: "unknown", Version: "unknown"},
			Findings: []schema.Finding{},
		}, nil
	}

	// Validate report structure
	if report.Version == "" {
		report.Version = "1.0"
	}

	if report.Findings == nil {
		report.Findings = []schema.Finding{}
	}

	// Future enhancements:
	// - Override file languages with more accurate detection
	// - Add FIPS approval status based on algorithm database
	// - Correlate with CVE database for known vulnerabilities
	// - Add risk scoring based on algorithm strength

	return report, nil
}
