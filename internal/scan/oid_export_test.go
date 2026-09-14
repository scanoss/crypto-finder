package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

func TestExportCallGraph_PreservesPreparedExactOID(t *testing.T) {
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "main.go", Language: "go",
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "exact-oid", StartLine: 5, EndLine: 5, Match: "hmac.New()",
			Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "HMAC-SHA-256", "algorithmFamily": "HMAC", "algorithmPrimitive": "mac"},
		}},
	}}}
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.ReportClone()
	result := &engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem: "go",
	}
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := ExportResolvedCallGraph(path, "json", result, resolved, CallGraphExportOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var export struct {
		FindingGraphs []struct {
			MatchedOperation struct {
				OID string `json:"oid"`
			} `json:"matched_operation"`
		} `json:"finding_graphs"`
	}
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	if len(export.FindingGraphs) != 1 || export.FindingGraphs[0].MatchedOperation.OID != "1.2.840.113549.2.9" {
		t.Fatalf("callgraph OID = %#v", export.FindingGraphs)
	}
}

func prepareOIDFixtureReport(t *testing.T, report *entities.InterimReport) *oid.ResolvedReport {
	t.Helper()
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.ReportClone()
}
