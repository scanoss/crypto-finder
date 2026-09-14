package oid

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

type curatedDisposition struct {
	Signature string            `json:"signature_sha256"`
	Selector  map[string]string `json:"selector"`
	Outcome   string            `json:"outcome"`
	Record    string            `json:"record"`
	Reference string            `json:"record_reference"`
	Evidence  string            `json:"evidence"`
}

// TestFixtureDispositions compares implementation output to a frozen, curated
// expectation file. The expectation is not regenerated through Resolver.
func TestFixtureDispositions_AgreeWithCuratedExpectations(t *testing.T) {
	raw, err := os.ReadFile("testdata/fixture-dispositions.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []curatedDisposition
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	resolver := NewDefaultResolver()
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Reference == "" || row.Evidence == "" {
			t.Fatalf("%s has no curated evidence", row.Signature)
		}
		if len(row.Signature) != 64 {
			t.Fatalf("invalid signature %q", row.Signature)
		}
		if seen[row.Signature] {
			t.Fatalf("duplicate signature %q", row.Signature)
		}
		seen[row.Signature] = true
		got := resolver.ResolveAsset(&entities.CryptographicAsset{Metadata: row.Selector})
		if outcome(got.Outcome) != row.Outcome || got.Record != row.Record {
			t.Fatalf("%s (%s): got %s/%q, want %s/%q (%s)", row.Signature, row.Selector["algorithmName"], outcome(got.Outcome), got.Record, row.Outcome, row.Record, row.Reference)
		}
	}
	if len(rows) != 759 {
		t.Fatalf("curated snapshot has %d rows, want 759", len(rows))
	}
}

func outcome(value Outcome) string {
	return []string{"exact", "rejected_claim", "invalid_evidence", "no_exact_selection", "ambiguous_selection", "no_standard", "unresolved"}[value]
}
