package enricher

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestOIDEnricher_ExactOnlyReport(t *testing.T) {
	enricher := NewOIDEnricher()
	report := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{
		{Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "mac", "algorithmFamily": "HMAC", "algorithmName": "HMAC-SHA-256"}},
		{Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "block-cipher", "algorithmFamily": "AES", "algorithmMode": "CBC"}},
		{OID: "1.2.840.113549.2", Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "mac", "algorithmFamily": "HMAC", "algorithmName": "HMAC-SHA-256"}},
	}}}}

	prepared, err := enricher.PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Findings[0].CryptographicAssets[0].OID != "" {
		t.Fatal("PrepareReport mutated raw report")
	}
	assets := prepared.ReportClone().Findings[0].CryptographicAssets
	if got, want := assets[0].OID, "1.2.840.113549.2.9"; got != want {
		t.Fatalf("exact OID = %q, want %q", got, want)
	}
	if assets[1].OID != "" {
		t.Fatalf("incomplete AES acquired branch OID %q", assets[1].OID)
	}
	if assets[2].OID != "" {
		t.Fatalf("untrusted branch claim retained: %q", assets[2].OID)
	}
}

func TestOIDEnricher_NilAndAssetSeam(t *testing.T) {
	enricher := NewOIDEnricher()
	prepared, err := enricher.PrepareReport(nil)
	if err != nil || prepared != nil {
		t.Fatalf("nil preparation = %v, %v", prepared, err)
	}
	asset := &entities.CryptographicAsset{Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "hash", "algorithmFamily": "SHA", "algorithmName": "SHA-256"}}
	enricher.EnrichAsset(asset)
	if asset.OID != "2.16.840.1.101.3.4.2.1" {
		t.Fatalf("OID = %q", asset.OID)
	}
}
