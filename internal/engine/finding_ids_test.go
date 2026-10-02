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

	if got, want := report.Findings[0].CryptographicAssets[0].FindingID, generateFindingID("src/main.go", 12, []entities.RuleInfo{{ID: "go.crypto.aes"}}, ""); got != want {
		t.Fatalf("direct finding_id = %q, want %q", got, want)
	}

	if got, want := report.Findings[1].CryptographicAssets[0].FindingID, generateFindingID("dep/mod@v1.0.0/lib.go", 10, []entities.RuleInfo{{ID: "rule.dep"}}, ""); got != want {
		t.Fatalf("dependency finding_id = %q, want %q", got, want)
	}
}

// Native findings keep the id they have always had.
func TestGenerateFindingID_NativeIDIsPinned(t *testing.T) {
	t.Parallel()

	if got, want := generateFindingID("src/main.go", 12, []entities.RuleInfo{{ID: "go.crypto.aes"}}, ""), "0229f6cc"; got != want {
		t.Fatalf("native finding_id = %q, want pinned %q", got, want)
	}
}

// Two values of one rule at one call differ only in the resolved condition.
func TestAssignFindingIDs_PerValueAssetsGetDistinctIDs(t *testing.T) {
	t.Parallel()

	rule := []entities.RuleInfo{{ID: "java.jca.algorithm.hash.sha-2"}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "src/App.java",
		CryptographicAssets: []entities.CryptographicAsset{
			{StartLine: 7, Rules: rule, ConditionedValue: "param[0]==SHA-256"},
			{StartLine: 7, Rules: rule, ConditionedValue: "param[0]==SHA-512"},
			{StartLine: 7, Rules: rule},
		},
	}}}

	AssignFindingIDs(report)

	assets := report.Findings[0].CryptographicAssets
	if assets[0].FindingID == assets[1].FindingID || assets[0].FindingID == assets[2].FindingID || assets[1].FindingID == assets[2].FindingID {
		t.Fatalf("finding ids = %q, %q, %q; want three distinct ids", assets[0].FindingID, assets[1].FindingID, assets[2].FindingID)
	}
	if want := generateFindingID("src/App.java", 7, rule, ""); assets[2].FindingID != want {
		t.Fatalf("asset without a resolved value changed id: %q, want %q", assets[2].FindingID, want)
	}
	if want := "d7427939"; generateFindingID("src/main.go", 12, []entities.RuleInfo{{ID: "go.crypto.aes"}}, "param[0]==SHA-256") != want {
		t.Fatalf("per-value finding_id is not stable, want %q", want)
	}
}
