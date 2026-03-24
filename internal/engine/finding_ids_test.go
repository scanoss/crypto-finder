package engine

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestAssignFindingIDs(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{
		Findings: []entities.Finding{
			{
				FilePath: "src/main.go",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 12,
					Rules:     []entities.RuleInfo{{ID: "go.crypto.aes"}},
				}},
			},
			{
				FilePath: "lib.go",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 10,
					Rules:     []entities.RuleInfo{{ID: "rule.dep"}},
					DependencyInfo: &entities.DependencyInfo{
						Module:  "dep/mod",
						Version: "v1.0.0",
					},
				}},
			},
		},
	}

	AssignFindingIDs(report)

	if got, want := report.Findings[0].CryptographicAssets[0].FindingID, generateFindingID("src/main.go", 12, []entities.RuleInfo{{ID: "go.crypto.aes"}}); got != want {
		t.Fatalf("direct finding_id = %q, want %q", got, want)
	}

	if got, want := report.Findings[1].CryptographicAssets[0].FindingID, generateFindingID("dep/mod@v1.0.0/lib.go", 10, []entities.RuleInfo{{ID: "rule.dep"}}); got != want {
		t.Fatalf("dependency finding_id = %q, want %q", got, want)
	}
}
