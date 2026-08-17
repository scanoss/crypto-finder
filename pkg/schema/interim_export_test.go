// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package schema_test

import (
	"encoding/json"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/paramcondition"
	"github.com/scanoss/crypto-finder/pkg/schema"
)

func TestInterimReportPublicContract(t *testing.T) {
	report := schema.InterimReport{
		Version: "1.5",
		Tool:    schema.ToolInfo{Name: "crypto-finder", Version: "0.1.0"},
		Findings: []schema.Finding{{
			FilePath: "src/crypto.go",
			Language: "go",
			CryptographicAssets: []schema.CryptographicAsset{{
				StartLine: 1,
				EndLine:   1,
				Match:     "cipher.NewGCM(block)",
				Rules: []schema.RuleInfo{{
					ID: "go.crypto.aes", Message: "AES", Severity: "INFO", Version: "v1",
				}},
				Status:   "pending",
				Metadata: map[string]string{"assetType": "algorithm"},
				Source:   "direct",
			}},
		}},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["version"] != "1.5" || got["tool"] == nil || got["rules"] == nil || got["findings"] == nil {
		t.Fatalf("required report fields missing: %s", data)
	}

	asset := got["findings"].([]any)[0].(map[string]any)["cryptographic_assets"].([]any)[0].(map[string]any)
	for _, key := range []string{"start_col", "end_col", "parameter_conditions", "oid", "finding_id", "dependency_info"} {
		if _, ok := asset[key]; ok {
			t.Errorf("optional field %q present in %s", key, data)
		}
	}
	if asset["source"] != "direct" {
		t.Errorf("source = %v, want direct", asset["source"])
	}
	if _, ok := asset["terminal_start_col"]; ok {
		t.Errorf("internal field leaked in %s", data)
	}

	if schema.InterimFormatVersion != "1.5" {
		t.Errorf("InterimFormatVersion = %q, want 1.5", schema.InterimFormatVersion)
	}
}

func TestCryptographicAssetLegacyRuleCompatibility(t *testing.T) {
	var legacy schema.CryptographicAsset
	if err := json.Unmarshal([]byte(`{"rule":{"id":"legacy","message":"Legacy","severity":"WARNING"}}`), &legacy); err != nil {
		t.Fatalf("Unmarshal legacy asset: %v", err)
	}
	if len(legacy.Rules) != 1 || legacy.Rules[0].ID != "legacy" {
		t.Fatalf("legacy rule was not migrated: %#v", legacy.Rules)
	}

	var preferred schema.CryptographicAsset
	if err := json.Unmarshal([]byte(`{"rule":{"id":"legacy"},"rules":[{"id":"current"}]}`), &preferred); err != nil {
		t.Fatalf("Unmarshal current asset: %v", err)
	}
	if len(preferred.Rules) != 1 || preferred.Rules[0].ID != "current" {
		t.Fatalf("rules array did not take precedence: %#v", preferred.Rules)
	}
}

func TestInterimReportPublicJSONFieldNames(t *testing.T) {
	report := schema.InterimReport{
		Version: "1.5",
		Tool:    schema.ToolInfo{Name: "crypto-finder", Version: "0.1.0"},
		Rules:   schema.RulesInfo{Source: "remote", Name: "dca", Version: "v1", ChecksumSHA256: "abc"},
		Findings: []schema.Finding{{
			FilePath: "src/crypto.go", Language: "go",
			CryptographicAssets: []schema.CryptographicAsset{{
				StartLine: 1, EndLine: 2, StartCol: 3, EndCol: 4, Match: "cipher.NewGCM(block)",
				Rules:               []schema.RuleInfo{{ID: "go.crypto.aes", Message: "AES", Severity: "INFO", Version: "v1"}},
				Status:              "reviewed",
				Metadata:            map[string]string{"assetType": "algorithm"},
				ParameterConditions: []paramcondition.Condition{{Raw: "param[0]==true"}},
				OID:                 "2.16.840.1.101.3.4.1.2",
				FindingID:           "a1b2c3d4",
				Source:              "dependency",
				DependencyInfo:      &schema.DependencyInfo{Module: "golang.org/x/crypto", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/crypto@v0.1.0"},
			}},
		}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertJSONKeys(t, got, "report", "findings", "rules", "tool", "version")
	assertJSONKeys(t, got["tool"].(map[string]any), "tool", "name", "version")
	assertJSONKeys(t, got["rules"].(map[string]any), "rules", "checksum_sha256", "name", "source", "version")
	finding := got["findings"].([]any)[0].(map[string]any)
	assertJSONKeys(t, finding, "finding", "cryptographic_assets", "file_path", "language")
	asset := finding["cryptographic_assets"].([]any)[0].(map[string]any)
	assertJSONKeys(t, asset, "asset", "dependency_info", "end_col", "end_line", "finding_id", "match", "metadata", "oid", "parameter_conditions", "rules", "source", "start_col", "start_line", "status")
	assertJSONKeys(t, asset["rules"].([]any)[0].(map[string]any), "rule", "id", "message", "severity", "version")
	assertJSONKeys(t, asset["dependency_info"].(map[string]any), "dependency_info", "module", "purl", "version")
}

func assertJSONKeys(t *testing.T, object map[string]any, name string, want ...string) {
	t.Helper()
	if len(object) != len(want) {
		t.Fatalf("%s keys = %v, want %v", name, object, want)
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			t.Errorf("%s missing JSON key %q", name, key)
		}
	}
}
