// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// A call on an imported singleton and a call on a locally constructed object
// reach the crypto inside a class's methods, and a method nothing calls stays
// unreachable.
func TestNodeTypedReceiversReachFindingsInExport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	files := map[string]string{
		"service.ts": `import { createHash } from 'crypto';
class Service {
  viaSingleton(s: string) { return createHash('md5').update(s).digest('hex'); }
  viaLocal(s: string) { return createHash('sha256').update(s).digest('hex'); }
  unused(s: string) { return createHash('sha1').update(s).digest('hex'); }
}
export const service = new Service();
function local() { const s = new Service(); return s.viaLocal('b'); }
local();
`,
		"main.ts": `import { service } from './service';
function main() { service.viaSingleton('a'); }
main();
`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystemNode, callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	asset := func(line int, match string) entities.CryptographicAsset {
		return entities.CryptographicAsset{StartLine: line, EndLine: line, Match: match, Rules: []entities.RuleInfo{{ID: "ts.rule"}}, Metadata: map[string]string{"assetType": "algorithm"}}
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: filepath.Join(dir, "service.ts"),
		Language: "typescript",
		CryptographicAssets: []entities.CryptographicAsset{
			asset(3, "createHash('md5')"),
			asset(4, "createHash('sha256')"),
			asset(5, "createHash('sha1')"),
		},
	}}}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	outputPath := filepath.Join(t.TempDir(), "callgraph.json")
	if err := exportCallGraphWithOptions(outputPath, "json", &engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: ecosystemNode, ProjectRoot: dir,
	}, CallGraphExportOptions{ProjectReachability: true}); err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, fg := range payload.FindingGraphs {
		byID[fg.FindingID] = fg.Reachability
	}
	got := map[string]string{}
	for i := range report.Findings[0].CryptographicAssets {
		a := report.Findings[0].CryptographicAssets[i]
		got[a.Match] = byID[a.FindingID]
	}
	for match, want := range map[string]string{
		"createHash('md5')":    "reachable",
		"createHash('sha256')": "reachable",
		"createHash('sha1')":   "unreachable",
	} {
		if got[match] != want {
			t.Errorf("%s: reachability = %q, want %q", match, got[match], want)
		}
	}
}
