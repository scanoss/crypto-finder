// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/output"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestGeneratedExportsMatchSchemas(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "report.json")
	callgraphPath := filepath.Join(tempDir, "callgraph.json")
	graph, projectRoot := buildSupportingGraph(t)
	report := populatedExportReport(t)
	if err := output.NewJSONWriter().Write(report, reportPath); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := ExportCallGraph(callgraphPath, "json", &engine.DepScanResult{
		CallGraph:   graph,
		Report:      report,
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		RootModule:  "com.app:app",
	}); err != nil {
		t.Fatalf("export callgraph: %v", err)
	}

	for _, tc := range []struct {
		name             string
		schema           string
		document         string
		properties       []string
		outputProperties []string
		populatedArrays  []string
		invalidVersion   string
	}{
		{
			name:             "report",
			schema:           filepath.Join("..", "..", "schemas", "interim-report-schema.json"),
			document:         reportPath,
			properties:       []string{"findings", "rules", "tool", "version"},
			outputProperties: []string{"findings", "rules", "tool", "version"},
			populatedArrays:  []string{"findings"},
			invalidVersion:   "1.4",
		},
		{
			name:             "callgraph",
			schema:           filepath.Join("..", "..", "schemas", "callgraph-schema.json"),
			document:         callgraphPath,
			properties:       []string{"crypto_entry_points", "finding_graphs", "scan_metadata", "schema_version", "supporting_calls"},
			outputProperties: []string{"crypto_entry_points", "finding_graphs", "scan_metadata", "schema_version", "supporting_calls"},
			populatedArrays:  []string{"crypto_entry_points", "finding_graphs", "supporting_calls"},
			invalidVersion:   "6.7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSchemaTopLevelProperties(t, tc.schema, tc.properties)
			assertJSONMatchesSchema(t, tc.schema, tc.document)
			assertJSONTopLevelProperties(t, tc.document, tc.outputProperties)
			assertJSONHasPopulatedArrays(t, tc.document, tc.populatedArrays)
			assertSchemaRejectsVersion(t, tc.schema, tc.document, tc.invalidVersion)
		})
	}
}

func TestCallgraphSchema_ResolvedKeyLengthTypes(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join("..", "..", "schemas", "callgraph-schema.json")
	tests := []struct {
		name  string
		valid bool
		doc   map[string]any
	}{
		{
			name:  "constant with integer bits",
			valid: true,
			doc:   callgraphResolvedKeyLengthDocument("constant", 256),
		},
		{
			name:  "invalid provenance",
			valid: false,
			doc:   callgraphResolvedKeyLengthDocument("derived", 256),
		},
		{
			name:  "invalid bits type",
			valid: false,
			doc:   callgraphResolvedKeyLengthDocument("constant", "256"),
		},
		{
			name:  "terminal crypto call location is invalid",
			valid: false,
			doc:   callgraphResolvedKeyLengthInTerminalDocument(),
		},
		{
			name:  "conflict marker with integer rule bits",
			valid: true,
			doc:   callgraphResolvedKeyLengthConflictDocument(128, true),
		},
		{
			name:  "invalid rule declared bits type",
			valid: false,
			doc:   callgraphResolvedKeyLengthConflictDocument("128", true),
		},
		{
			name:  "invalid rule conflict type",
			valid: false,
			doc:   callgraphResolvedKeyLengthConflictDocument(128, "true"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.doc)
			if err != nil {
				t.Fatalf("marshal document: %v", err)
			}
			result, err := gojsonschema.Validate(
				gojsonschema.NewReferenceLoader("file://"+schemaPath),
				gojsonschema.NewBytesLoader(data),
			)
			if err != nil {
				t.Fatalf("validate document: %v", err)
			}
			if result.Valid() != tc.valid {
				t.Fatalf("schema validity = %v, want %v: %v", result.Valid(), tc.valid, result.Errors())
			}
		})
	}
}

// callgraphResolvedKeyLengthConflictDocument builds a resolved-key-length
// document carrying the rule-vs-callgraph conflict marker. ResolvedKeyLength is
// additionalProperties:false, so this keeps the Go json tags and the published
// schema from drifting apart unnoticed.
func callgraphResolvedKeyLengthConflictDocument(ruleDeclaredBits, ruleConflict any) map[string]any {
	doc := callgraphResolvedKeyLengthDocument("constant", 256)
	supportingCalls, _ := doc["supporting_calls"].([]any)
	supporting, _ := supportingCalls[0].(map[string]any)
	declaration, _ := supporting["supporting_call"].(map[string]any)
	resolved, _ := declaration["resolved_key_length"].(map[string]any)
	resolved["rule_declared_bits"] = ruleDeclaredBits
	resolved["rule_conflict"] = ruleConflict
	return doc
}

func callgraphResolvedKeyLengthDocument(provenance string, bits any) map[string]any {
	resolved := map[string]any{
		"provenance": provenance,
		"source_call": map[string]any{
			"function_name":   "javax.crypto.KeyGenerator.init",
			"line":            9,
			"parameter_index": 0,
		},
	}
	if bits != nil {
		resolved["bits"] = bits
	}
	return map[string]any{
		"schema_version": graphfrag.CallgraphSchemaVersion,
		"scan_metadata":  map[string]any{},
		"finding_graphs": []any{map[string]any{
			"finding_id":          "keygen-init",
			"supporting_call_ids": []any{"support-init"},
			"call_chains": []any{[]any{map[string]any{
				"function_name": "example.KeyFlow.configure",
				"file_path":     "KeyFlow.java",
				"crypto_call": map[string]any{
					"function_name": "javax.crypto.KeyGenerator.generateKey",
					"line":          10,
				},
			}}},
		}},
		"supporting_calls": []any{map[string]any{
			"supporting_id": "support-init",
			"supporting_call": map[string]any{
				"function_name":       "javax.crypto.KeyGenerator.init",
				"line":                9,
				"resolved_key_length": resolved,
			},
		}},
	}
}

func callgraphResolvedKeyLengthInTerminalDocument() map[string]any {
	doc := callgraphResolvedKeyLengthDocument("constant", 256)
	findingGraphs := doc["finding_graphs"].([]any)
	finding := findingGraphs[0].(map[string]any)
	chains := finding["call_chains"].([]any)
	chain := chains[0].([]any)
	node := chain[0].(map[string]any)
	cryptoCall := node["crypto_call"].(map[string]any)
	cryptoCall["resolved_key_length"] = map[string]any{
		"provenance": "constant",
		"source_call": map[string]any{
			"function_name":   "javax.crypto.KeyGenerator.init",
			"line":            9,
			"parameter_index": 0,
		},
	}
	return doc
}

func populatedExportReport(t *testing.T) *entities.InterimReport {
	t.Helper()

	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
	report.Version = entities.InterimFormatVersion
	report.Tool.Version = "test"
	report.Rules = entities.RulesInfo{Source: "local", ChecksumSHA256: "test"}
	asset := &report.Findings[0].CryptographicAssets[0]
	asset.Rules[0].ID = "java.jca.algorithm.aes"
	asset.Rules[0].Message = "AES algorithm"
	asset.Rules[0].Severity = "INFO"
	asset.Status = "identified"
	return report
}

func assertSchemaTopLevelProperties(t *testing.T, schemaPath string, want []string) {
	t.Helper()

	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	got := make([]string, 0, len(schema.Properties))
	for property := range schema.Properties {
		got = append(got, property)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("top-level schema properties = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("top-level schema properties = %v, want %v", got, want)
		}
	}
}

func assertJSONMatchesSchema(t *testing.T, schemaPath, documentPath string) {
	t.Helper()

	result, err := gojsonschema.Validate(
		gojsonschema.NewReferenceLoader("file://"+schemaPath),
		gojsonschema.NewReferenceLoader("file://"+documentPath),
	)
	if err != nil {
		t.Fatalf("validate JSON against schema: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("schema validation failed: %v", result.Errors())
	}
}

func assertJSONTopLevelProperties(t *testing.T, documentPath string, want []string) {
	t.Helper()

	data, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read generated JSON: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode generated JSON: %v", err)
	}
	for _, property := range want {
		if _, ok := document[property]; !ok {
			t.Errorf("generated JSON is missing top-level property %q", property)
		}
	}
}

func assertJSONHasPopulatedArrays(t *testing.T, documentPath string, properties []string) {
	t.Helper()

	data, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read generated JSON: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode generated JSON: %v", err)
	}
	for _, property := range properties {
		var values []json.RawMessage
		if err := json.Unmarshal(document[property], &values); err != nil {
			t.Errorf("decode generated %s array: %v", property, err)
			continue
		}
		if len(values) == 0 {
			t.Errorf("generated %s array is empty", property)
		}
	}
}

func assertSchemaRejectsVersion(t *testing.T, schemaPath, documentPath, version string) {
	t.Helper()

	data, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatalf("read generated JSON: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode generated JSON: %v", err)
	}
	if _, ok := document["version"]; ok {
		document["version"] = version
	} else {
		document["schema_version"] = version
	}
	invalid, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode invalid version fixture: %v", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewReferenceLoader("file://"+schemaPath),
		gojsonschema.NewBytesLoader(invalid),
	)
	if err != nil {
		t.Fatalf("validate invalid version fixture: %v", err)
	}
	if result.Valid() {
		t.Fatalf("schema accepted unsupported version %q", version)
	}
}
