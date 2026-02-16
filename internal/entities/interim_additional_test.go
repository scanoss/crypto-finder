package entities

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCryptographicAsset_GetKey_AdditionalBranches(t *testing.T) {
	tests := []struct {
		name         string
		asset        CryptographicAsset
		wantContains []string
	}{
		{
			name: "algorithm mode and padding",
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":        "algorithm",
					"algorithmFamily":  "AES",
					"algorithmMode":    "GCM",
					"algorithmPadding": "NoPadding",
					"library":          "JCA",
				},
			},
			wantContains: []string{"algorithm:AES:GCM:NoPadding", ":library=JCA"},
		},
		{
			name: "algorithm mode only",
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "algorithm",
					"algorithmFamily": "AES",
					"algorithmMode":   "CBC",
				},
			},
			wantContains: []string{"algorithm:AES:CBC"},
		},
		{
			name: "algorithm no family fallback location",
			asset: CryptographicAsset{
				StartLine: 7,
				EndLine:   9,
				Metadata: map[string]string{
					"assetType": "algorithm",
					"extra":     "x",
				},
			},
			wantContains: []string{"algorithm:location:7:9", ":extra=x"},
		},
		{
			name: "related crypto material fallback location",
			asset: CryptographicAsset{
				StartLine: 2,
				EndLine:   3,
				Metadata: map[string]string{
					"assetType": "related-crypto-material",
					"source":    "pem",
				},
			},
			wantContains: []string{"related-crypto-material:location:2:3", ":source=pem"},
		},
		{
			name: "protocol with version",
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":       "protocol",
					"protocolType":    "tls",
					"protocolVersion": "1.3",
					"role":            "server",
				},
			},
			wantContains: []string{"protocol:tls:1.3", ":role=server"},
		},
		{
			name: "protocol fallback location",
			asset: CryptographicAsset{
				StartLine: 11,
				EndLine:   14,
				Metadata: map[string]string{
					"assetType": "protocol",
					"context":   "cfg",
				},
			},
			wantContains: []string{"protocol:location:11:14", ":context=cfg"},
		},
		{
			name: "certificate with metadata suffix and trimmed serial",
			asset: CryptographicAsset{
				Metadata: map[string]string{
					"assetType":               "certificate",
					"certificateSerialNumber": "  ABC123  ",
					"issuer":                  "CA",
				},
			},
			wantContains: []string{"certificate:ABC123", ":issuer=CA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.asset.GetKey()
			for _, part := range tt.wantContains {
				if !strings.Contains(key, part) {
					t.Fatalf("key %q does not contain %q", key, part)
				}
			}
		})
	}
}

func TestCryptographicAsset_MetadataSuffixSortingAndExclusions(t *testing.T) {
	asset := CryptographicAsset{
		Metadata: map[string]string{
			"assetType":       "algorithm",
			"algorithmName":   "AES",
			"filePath":        "x.go",
			"startLine":       "1",
			"endLine":         "2",
			"zeta":            "z",
			"alpha":           "a",
			"empty":           "",
			"algorithmFamily": "AES",
		},
	}

	suffix := asset.getMetadataKeySuffix([]string{"algorithmName"})
	if suffix != ":algorithmFamily=AES:alpha=a:zeta=z" {
		t.Fatalf("unexpected suffix ordering/exclusions: %q", suffix)
	}
}

func TestCryptographicAsset_UnmarshalJSON_CompatAndErrors(t *testing.T) {
	var oldFormat CryptographicAsset
	oldJSON := []byte(`{"match_type":"semgrep","start_line":1,"end_line":1,"rule":{"id":"r1","message":"m","severity":"INFO"}}`)
	if err := json.Unmarshal(oldJSON, &oldFormat); err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if len(oldFormat.Rules) != 1 || oldFormat.Rules[0].ID != "r1" {
		t.Fatalf("old rule field was not migrated correctly: %#v", oldFormat.Rules)
	}

	var newFormat CryptographicAsset
	newJSON := []byte(`{"match_type":"semgrep","start_line":1,"end_line":1,"rules":[{"id":"r2","message":"m2","severity":"WARNING"}],"rule":{"id":"r1","message":"m","severity":"INFO"}}`)
	if err := json.Unmarshal(newJSON, &newFormat); err != nil {
		t.Fatalf("unmarshal new format: %v", err)
	}
	if len(newFormat.Rules) != 1 || newFormat.Rules[0].ID != "r2" {
		t.Fatalf("new rules array should take precedence: %#v", newFormat.Rules)
	}

	var bad CryptographicAsset
	if err := json.Unmarshal([]byte(`{not-json`), &bad); err == nil {
		t.Fatal("expected unmarshal error for invalid JSON")
	}
}

func TestInterimReport_SortHelpers(t *testing.T) {
	report := &InterimReport{
		Findings: []Finding{
			{FilePath: "b.go", CryptographicAssets: []CryptographicAsset{{StartLine: 20}, {StartLine: 5}}},
			{FilePath: "a.go", CryptographicAssets: []CryptographicAsset{{StartLine: 30}, {StartLine: 1}}},
		},
	}

	report.SortFindings()
	if report.Findings[0].FilePath != "a.go" || report.Findings[1].FilePath != "b.go" {
		t.Fatalf("findings were not sorted by file path: %#v", report.Findings)
	}

	report.SortAssets()
	if report.Findings[0].CryptographicAssets[0].StartLine != 1 {
		t.Fatalf("assets for first finding were not sorted: %#v", report.Findings[0].CryptographicAssets)
	}
	if report.Findings[1].CryptographicAssets[0].StartLine != 5 {
		t.Fatalf("assets for second finding were not sorted: %#v", report.Findings[1].CryptographicAssets)
	}
}
