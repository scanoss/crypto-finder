// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// nextSchema returns the version one minor above v, preserving any
// `graph-fragment-` style prefix.
//
// These probes assert that a stored schema NEWER than this build is rejected,
// which is a moving target: hardcoding the number meant every contract bump
// turned a passing test into a failing one and the "newer" case silently became
// the current one (#110). Deriving it keeps the probe testing the property.
func nextSchema(v string) string {
	prefix := ""
	if i := strings.LastIndex(v, "-"); i >= 0 {
		prefix, v = v[:i+1], v[i+1:]
	}
	major, minor, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(minor)
	if err != nil {
		return prefix + v
	}
	return prefix + major + "." + strconv.Itoa(n+1)
}

func TestValidateSchemaVersion(t *testing.T) {
	tests := []struct {
		name      string
		got       string
		supported string
		wantErr   bool
	}{
		{"current findings", FindingsSchemaVersion, FindingsSchemaVersion, false},
		{"older findings", "1.0", FindingsSchemaVersion, false},
		{"newer findings", nextSchema(FindingsSchemaVersion), FindingsSchemaVersion, true},
		{"current graph fragment", SchemaVersion, SchemaVersion, false},
		{"older graph fragment", "graph-fragment-1.2", SchemaVersion, false},
		{"newer graph fragment", nextSchema(SchemaVersion), SchemaVersion, true},
		{"different major", "7.0", CallgraphSchemaVersion, true},
		{"interned callgraph current", CallgraphInternedSchemaVersion, CallgraphInternedSchemaVersion, false},
		{"interned callgraph older inlined", "6.9", CallgraphInternedSchemaVersion, false},
		{"interned callgraph newer", nextSchema(CallgraphInternedSchemaVersion), CallgraphInternedSchemaVersion, true},
		{"malformed", "next", FindingsSchemaVersion, true},
		{"missing", "", FindingsSchemaVersion, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchemaVersion("test", tt.got, tt.supported)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSchemaVersion(%q, %q) error = %v, wantErr %v", tt.got, tt.supported, err, tt.wantErr)
			}
			if tt.wantErr {
				var unsupported *ErrUnsupportedSchema
				if !errors.As(err, &unsupported) {
					t.Fatalf("error = %T, want *ErrUnsupportedSchema", err)
				}
			}
		})
	}
}

func TestComponentBlockRejectsUnsupportedSchemas(t *testing.T) {
	tests := []struct {
		name      string
		findings  string
		callgraph string
	}{
		{"findings", fmt.Sprintf(`{"version":%q,"findings":[]}`, nextSchema(FindingsSchemaVersion)), `{"schema_version":"6.5"}`},
		{"callgraph", `{"version":"1.4","findings":[]}`, fmt.Sprintf(`{"schema_version":%q}`, nextSchema(CallgraphInternedSchemaVersion))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ComponentBlock(ComponentInput{Findings: []byte(tt.findings), Callgraph: []byte(tt.callgraph)})
			var unsupported *ErrUnsupportedSchema
			if !errors.As(err, &unsupported) {
				t.Fatalf("ComponentBlock error = %v, want *ErrUnsupportedSchema", err)
			}
		})
	}
}

func TestComponentBlockPreservesMetadata(t *testing.T) {
	const findings = `{
		"version":"1.3",
		"findings":[{
			"file_path":"Crypto.java",
			"language":"java",
			"cryptographic_assets":[
				{
					"finding_id":"f-1",
					"match":"Cipher.getInstance(\"AES\")",
					"source":"direct",
					"start_line":10,
					"end_line":10,
					"metadata":{"provider":"BC","futureKey":{"nested":true}}
				},
				{
					"finding_id":"f-2",
					"match":"Security.getProvider()",
					"source":"direct",
					"start_line":20,
					"end_line":20,
					"metadata":{"runtimeSelectedProvider":true}
				}
			]
		}]
	}`

	block, _, err := ComponentBlock(ComponentInput{Findings: []byte(findings)})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	assets := block.Findings[0].CryptographicAssets
	got := assets[0].Metadata
	var metadata map[string]any
	if err := json.Unmarshal(got, &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["provider"] != "BC" || metadata["futureKey"] == nil {
		t.Fatalf("metadata = %s, want provider and unknown keys unchanged", got)
	}

	var runtimeSelected map[string]any
	if err := json.Unmarshal(assets[1].Metadata, &runtimeSelected); err != nil {
		t.Fatalf("unmarshal runtime-selected metadata: %v", err)
	}
	if runtimeSelected["runtimeSelectedProvider"] != true {
		t.Fatalf("metadata = %s, runtime-selected marker was lost", assets[1].Metadata)
	}
	if _, synthesized := runtimeSelected["provider"]; synthesized {
		t.Fatalf("metadata = %s, provider must remain unresolved", assets[1].Metadata)
	}
	if _, synthesized := runtimeSelected["cryptoModule"]; synthesized {
		t.Fatalf("metadata = %s, cryptoModule must not be synthesized", assets[1].Metadata)
	}
}

func TestComponentBlockPreservesRules(t *testing.T) {
	const findings = `{
		"version":"1.4",
		"findings":[{
			"file_path":"Crypto.java",
			"language":"java",
			"cryptographic_assets":[
				{
					"finding_id":"f-1",
					"match":"Cipher.getInstance(\"AES\")",
					"source":"direct",
					"start_line":10,
					"end_line":10,
					"metadata":{},
					"rules":[{"id":"java.crypto.cipher.getinstance","message":"Prefer AES-GCM","severity":"WARNING","version":"v1.0.1","extra":"drop-me"}]
				},
				{
					"finding_id":"f-2",
					"match":"MessageDigest.getInstance(\"MD5\")",
					"source":"direct",
					"start_line":20,
					"end_line":20,
					"metadata":{}
				},
				{
					"finding_id":"f-3",
					"match":"Mac.getInstance(\"HmacSHA256\")",
					"source":"direct",
					"start_line":30,
					"end_line":30,
					"metadata":{},
					"rules":null
				}
			]
		}]
	}`

	block, _, err := ComponentBlock(ComponentInput{Findings: []byte(findings)})
	if err != nil {
		t.Fatalf("ComponentBlock: %v", err)
	}
	assets := block.Findings[0].CryptographicAssets
	if len(assets) != 3 {
		t.Fatalf("len(assets) = %d, want 3", len(assets))
	}

	got := assets[0].Rules
	if len(got) != 1 || got[0].ID != "java.crypto.cipher.getinstance" || got[0].Message != "Prefer AES-GCM" || got[0].Severity != "WARNING" {
		t.Fatalf("rules = %#v, want id/message/severity from the findings bytes", got)
	}
	raw, err := json.Marshal(assets[0])
	if err != nil {
		t.Fatalf("marshal asset: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal asset: %v", err)
	}
	rule := wire["rules"].([]any)[0].(map[string]any)
	if _, ok := rule["version"]; ok {
		t.Fatalf("version must drop, got %#v", rule)
	}
	if _, ok := rule["extra"]; ok {
		t.Fatalf("extra keys must drop, got %#v", rule)
	}

	if assets[1].Rules != nil {
		t.Fatalf("sibling with no rules = %#v, want nil", assets[1].Rules)
	}
	absent, err := json.Marshal(assets[1])
	if err != nil {
		t.Fatalf("marshal sibling: %v", err)
	}
	if strings.Contains(string(absent), `"rules"`) {
		t.Fatalf("sibling with no rules must omit the key, got %s", absent)
	}

	if assets[2].Rules != nil {
		t.Fatalf(`"rules":null = %#v, want nil`, assets[2].Rules)
	}
	nullRules, err := json.Marshal(assets[2])
	if err != nil {
		t.Fatalf("marshal null-rules asset: %v", err)
	}
	if strings.Contains(string(nullRules), `"rules"`) {
		t.Fatalf(`"rules":null must omit the key, got %s`, nullRules)
	}
}
