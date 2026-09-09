package cli

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestPrepareScanOIDProjection_FinalizesIdentityBeforeResolution(t *testing.T) {
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "crypto.go",
		CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 23,
			Rules:     []entities.RuleInfo{{ID: "go.crypto.sha256"}},
			Metadata:  map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256", "algorithmPrimitive": "hash"},
		}},
	}}}
	resolved, err := prepareScanOIDProjection(report, true)
	if err != nil {
		t.Fatal(err)
	}
	asset := resolved.Findings[0].CryptographicAssets[0]
	if resolved.Version != entities.InterimFormatVersion || asset.FindingID == "" || asset.Source != "direct" {
		t.Fatalf("resolved scan projection omitted final metadata: version=%q asset=%#v", resolved.Version, asset)
	}
	if asset.OID != "2.16.840.1.101.3.4.2.1" {
		t.Fatalf("resolved scan projection OID = %q", asset.OID)
	}
}
