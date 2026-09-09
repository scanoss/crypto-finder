package cli

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestPrepareAnnotateProjection_PreservesFinalFindingIdentity(t *testing.T) {
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "crypto.go",
		CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 17,
			Rules:     []entities.RuleInfo{{ID: "go.crypto.sha256"}},
			Metadata:  map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash"},
		}},
	}}}

	resolved, err := prepareAnnotateProjection(report)
	if err != nil {
		t.Fatal(err)
	}
	asset := resolved.Findings[0].CryptographicAssets[0]
	if resolved.Version != entities.InterimFormatVersion {
		t.Fatalf("resolved report version = %q, want %q", resolved.Version, entities.InterimFormatVersion)
	}
	if asset.Source != "direct" || asset.FindingID == "" {
		t.Fatalf("projected report lost final identity: %#v", asset)
	}
	if asset.OID != "2.16.840.1.101.3.4.2.1" {
		t.Fatalf("projected report OID = %q", asset.OID)
	}
	payload := scanutil.BuildAnnotateExport(resolved, graphfrag.Fragment{})
	if len(payload.CryptoAnnotations) != 1 || payload.CryptoAnnotations[0].FindingID != asset.FindingID || payload.CryptoAnnotations[0].Source != asset.Source || payload.CryptoAnnotations[0].OID != asset.OID {
		t.Fatalf("annotation projected stale identity: %#v", payload.CryptoAnnotations)
	}
}

func TestPrepareAnnotateProjection_LeavesOccurrenceKeyNotApplicable(t *testing.T) {
	report := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 1, Rules: []entities.RuleInfo{{ID: "go.crypto.sha256"}},
		Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash"},
	}}}}}
	resolved, err := prepareAnnotateProjection(report)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolved.Findings[0].CryptographicAssets[0].OccurrenceKey; got != "" {
		t.Fatalf("annotation has no callgraph anchor; occurrence key = %q, want N/A empty", got)
	}
}
