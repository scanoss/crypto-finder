// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// writeNodeRules writes one rule per api, each carrying its own operation.
func writeNodeRules(t *testing.T, apis map[string]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("rules:\n")
	for api, op := range apis {
		b.WriteString("  - id: test." + op + "\n" +
			"    metadata:\n" +
			"      crypto:\n" +
			"        assetType: algorithm\n" +
			"        algorithmPrimitive: signature\n" +
			"        algorithmName: ECDSA\n" +
			"        operation: " + op + "\n" +
			"        api: \"" + api + "\"\n")
	}
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeNodeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func syntheticAssets(report *entities.InterimReport) map[string]*entities.CryptographicAsset {
	out := make(map[string]*entities.CryptographicAsset)
	for i := range report.Findings {
		for j := range report.Findings[i].CryptographicAssets {
			a := &report.Findings[i].CryptographicAssets[j]
			if isSyntheticEntryPointAsset(a) {
				out[report.Findings[i].FilePath+" "+a.Metadata["api"]] = a
			}
		}
	}
	return out
}

// A Node library exports a curve built by a factory, so the api has no function
// definition: the export line carries every api once, from one build, each
// with its own identity.
func TestSynthesizeNodeFactoryExport(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "@acme/curves", "exports": {"./ec": {"types": "./ec.d.ts", "import": "./esm/ec.js", "require": "./ec.js"}}}`,
		"esm/ec.js":    "import { make } from './utils.js';\nexport const ec = make('secp256k1');\n",
		"ec.js":        "\"use strict\";\nexports.ec = void 0;\nexports.ec = (0, utils_1.make)('secp256k1');\n",
		"src/ec.ts":    "export const ec = make('secp256k1');\n",
	})
	rules := writeNodeRules(t, map[string]string{
		"@acme/curves/ec.ec.sign":   "sign",
		"@acme/curves/ec.ec.verify": "verify",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules}); got != 2 {
		t.Fatalf("synthesized = %d, want 2 (one per api, from the import build only)", got)
	}
	AssignFindingIDs(result.Report)

	assets := syntheticAssets(result.Report)
	sign, verify := assets["esm/ec.js @acme/curves/ec.ec.sign"], assets["esm/ec.js @acme/curves/ec.ec.verify"]
	if sign == nil || verify == nil {
		t.Fatalf("assets = %v, want sign and verify on esm/ec.js", assets)
	}
	if sign.StartLine != 2 || sign.Metadata["operation"] != "sign" || verify.Metadata["operation"] != "verify" {
		t.Errorf("sign at line %d with %q, verify with %q", sign.StartLine, sign.Metadata["operation"], verify.Metadata["operation"])
	}
	if sign.FindingID == verify.FindingID {
		t.Errorf("sign and verify share finding id %s", sign.FindingID)
	}
	if lang := result.Report.Findings[0].Language; lang != "javascript" {
		t.Errorf("language = %q, want javascript", lang)
	}
}

// An unscoped package without an exports map is importable by its main file.
func TestSynthesizeNodeMainExportWithoutExportsMap(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "acme", "main": "lib/index.js"}`,
		"lib/index.js": "function sign() {}\nexports.sign = sign;\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.sign": "sign"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["lib/index.js acme.sign"]; a == nil || a.StartLine != 2 {
		t.Errorf("assets = %v, want acme.sign at lib/index.js:2", syntheticAssets(result.Report))
	}
}

// Apis on their own lines, the Java and Python case, keep the id they always had.
func TestMarkSyntheticVariantsKeepsIDsOfAPIsOnTheirOwnLines(t *testing.T) {
	t.Parallel()

	asset := func(line int, api string) entities.CryptographicAsset {
		return entities.CryptographicAsset{
			StartLine: line,
			Rules:     []entities.RuleInfo{{ID: SyntheticEntryPointRuleID}},
			Metadata:  map[string]string{"api": api},
		}
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "src/main/java/com/example/Builder.java",
		CryptographicAssets: []entities.CryptographicAsset{asset(10, "com.example.Builder.withBcrypt"), asset(20, "com.example.Builder.withScrypt")},
	}}}

	AssignFindingIDs(report)

	for _, a := range report.Findings[0].CryptographicAssets {
		if a.ConditionedValue != "" {
			t.Errorf("%s: conditioned value = %q, want none", a.Metadata["api"], a.ConditionedValue)
		}
		want := generateFindingID("src/main/java/com/example/Builder.java", a.StartLine, a.Rules, "")
		if a.FindingID != want {
			t.Errorf("%s: id = %s, want the unchanged %s", a.Metadata["api"], a.FindingID, want)
		}
	}
}
