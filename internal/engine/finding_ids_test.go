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

// CF-GEN-002: the deduplicator keeps two calls one rule matched on one line
// apart (bcrypt.hashpw(pw, bcrypt.gensalt())), so their ids must differ too.
// The first in source order keeps the id it always had.
func TestAssignFindingIDs_SameRuleSameLineAssetsGetDistinctIDs(t *testing.T) {
	t.Parallel()

	rule := []entities.RuleInfo{{ID: "python.bcrypt"}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "hashpw/main.py",
		CryptographicAssets: []entities.CryptographicAsset{
			{StartLine: 6, EndLine: 6, StartCol: 38, EndCol: 63, Rules: rule},
			{StartLine: 6, EndLine: 6, StartCol: 14, EndCol: 64, Rules: rule},
			{StartLine: 6, EndLine: 6, StartCol: 14, EndCol: 64, Rules: rule},
		},
	}}}

	AssignFindingIDs(report)
	assets := report.Findings[0].CryptographicAssets
	first := []string{assets[0].FindingID, assets[1].FindingID, assets[2].FindingID}
	if first[0] == first[1] || first[0] == first[2] || first[1] == first[2] {
		t.Fatalf("finding ids = %q, want three distinct ids", first)
	}
	if want := generateFindingID("hashpw/main.py", 6, rule, ""); first[1] != want {
		t.Fatalf("outer hashpw id = %q, want the line id %q it always had", first[1], want)
	}

	AssignFindingIDs(report)
	for i := range assets {
		if assets[i].FindingID != first[i] {
			t.Fatalf("second pass changed asset %d id %q -> %q", i, first[i], assets[i].FindingID)
		}
	}
}
