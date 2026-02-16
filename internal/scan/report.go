package scan

import "github.com/scanoss/crypto-finder/internal/entities"

// CountFindings counts total cryptographic assets across all findings.
func CountFindings(report *entities.InterimReport) int {
	if report == nil {
		return 0
	}

	count := 0
	for _, finding := range report.Findings {
		count += len(finding.CryptographicAssets)
	}
	return count
}
