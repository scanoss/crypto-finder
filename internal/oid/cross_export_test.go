package oid_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/converter"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	internalScan "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestPreparedReport_ExactOIDIsEqualAcrossJSONCBOMAndFragmentAnnotation(t *testing.T) {
	report := exactReport("HMAC-SHA-256", "HMAC", "mac")
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.ReportClone()
	want := "1.2.840.113549.2.9"
	if got := resolved.Findings[0].CryptographicAssets[0].OID; got != want {
		t.Fatalf("prepared OID = %q, want %q", got, want)
	}
	data, err := json.Marshal(resolved)
	if err != nil || !strings.Contains(string(data), want) {
		t.Fatalf("JSON omits prepared OID: %v %s", err, data)
	}
	bom, err := converter.NewConverter().Convert(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 || (*bom.Components)[0].CryptoProperties.OID != want {
		t.Fatalf("CBOM OID = %#v", bom.Components)
	}
	annotation := internalScan.BuildAnnotateExport(resolved, graphfrag.Fragment{})
	if len(annotation.CryptoAnnotations) != 1 || annotation.CryptoAnnotations[0].OID != want {
		t.Fatalf("annotation OID = %#v", annotation.CryptoAnnotations)
	}
}

func TestPreparedReport_RejectsClaimAcrossAllProjections(t *testing.T) {
	report := exactReport("HMAC-SHA-256", "HMAC", "mac")
	report.Findings[0].CryptographicAssets[0].OID = "1.2.840.113549.2"
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.ReportClone()
	if got := resolved.Findings[0].CryptographicAssets[0].OID; got != "" {
		t.Fatalf("rejected OID retained: %q", got)
	}
	bom, err := converter.NewConverter().Convert(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if (*bom.Components)[0].CryptoProperties.OID != "" {
		t.Fatal("CBOM restored rejected claim")
	}
	annotation := internalScan.BuildAnnotateExport(resolved, graphfrag.Fragment{})
	if annotation.CryptoAnnotations[0].OID != "" {
		t.Fatal("annotation restored rejected claim")
	}
}

func exactReport(name, family, primitive string) *entities.InterimReport {
	return &entities.InterimReport{Findings: []entities.Finding{{FilePath: "test.go", CryptographicAssets: []entities.CryptographicAsset{{Metadata: map[string]string{"assetType": "algorithm", "algorithmName": name, "algorithmFamily": family, "algorithmPrimitive": primitive}}}}}}
}
