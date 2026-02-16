package scan

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
)

// PrintSummary displays scan summary in a user-friendly format.
func PrintSummary(outputPath string, filesCount, findingsCount int) error {
	stats := make([]pterm.BulletListItem, 0, 3)
	stats = append(stats,
		pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Files with findings: %d", filesCount)},
		pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Total crypto assets: %d", findingsCount)},
	)

	scanOutputLocation := "<stdout>"
	if outputPath != "" && outputPath != "-" {
		scanOutputLocation = outputPath
	}

	stats = append(stats, pterm.BulletListItem{Level: 1, Text: fmt.Sprintf("Output: %s", scanOutputLocation)})

	pterm.DefaultSection.WithWriter(os.Stderr).Println("Scan Summary")
	if err := pterm.DefaultBulletList.WithItems(stats).WithWriter(os.Stderr).Render(); err != nil {
		return fmt.Errorf("failed to render scan summary: %w", err)
	}

	return nil
}
