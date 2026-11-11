// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// A scan that resolves two ecosystems scans the second on top of the report
// the first returned. The findings of both accumulate, the ids the first run
// gave stay as they were, and the second ecosystem's resolution never
// rewrites the package URL of a finding written in the first one's language.
func TestScanWithDependencies_ChainsAcrossEcosystems(t *testing.T) {
	dir := t.TempDir()
	goRule := filepath.Join(dir, "go-rule.yaml")
	pyRule := filepath.Join(dir, "py-rule.yaml")
	for path, lang := range map[string]string{goRule: "go", pyRule: "python"} {
		body := "rules:\n- id: fixture." + lang + "\n  languages: [" + lang + "]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	goDep := filepath.Join(dir, "deps", "gocrypto")
	pyDep := filepath.Join(dir, "deps", "pycrypto")
	for _, d := range []string{goDep, pyDep} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &mockScanner{scanFunc: func(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
			file, lang := "hash.go", "go"
			if strings.Contains(target, "pycrypto") {
				file, lang = "hash.py", "python"
			}
			return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{
				FilePath: filepath.Join(target, file),
				Language: lang,
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 3,
					Rules:     []entities.RuleInfo{{ID: "fixture." + lang}},
					Metadata:  map[string]string{"assetType": "algorithm"},
				}},
			}}}, nil
		}}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) {
		return []string{goRule, pyRule}, nil
	}}), registry)

	goResolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{
			RootModule:   "example.com/app",
			Dependencies: []dependency.Dependency{{Module: "example.com/gocrypto", Version: "v1.0.0", Dir: goDep}},
			Graph:        map[string][]string{"example.com/app": {"example.com/gocrypto"}},
		}, nil
	}}
	pyResolver := &fakeResolver{ecosystem: ecosystemPython, resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{
			RootModule:   "app",
			Dependencies: []dependency.Dependency{{Module: "acme-lib", Version: "1.0", Dir: pyDep}},
			Graph:        map[string][]string{"app": {"acme-lib"}},
			VersionedGraph: map[string][]dependency.Ref{
				"app": {{Module: "acme-lib", Version: "1.0"}},
			},
		}, nil
	}}

	// The Go finding's rule names a PyPI package: only a resolution of its
	// own ecosystem may version it.
	userReport := &entities.InterimReport{Version: "1.0", Findings: []entities.Finding{
		{FilePath: "main.go", Language: "go", CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 1, PURL: "pkg:pypi/acme-lib", Rules: []entities.RuleInfo{{ID: "direct.go"}},
		}}},
		{FilePath: "app.py", Language: ecosystemPython, CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 2, PURL: "pkg:pypi/acme-lib", Rules: []entities.RuleInfo{{ID: "direct.py"}},
		}}},
	}}
	opts := DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture"}}

	first, err := NewDependencyScanner(orchestrator, goResolver, callgraph.NewBuilder(noopCallgraphParser{}), nil).ScanWithDependencies(t.Context(), userReport, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Report.Findings) != 3 {
		t.Fatalf("first ecosystem findings = %d, want 2 direct + 1 dependency", len(first.Report.Findings))
	}
	firstIDs := findingIDsByPath(first.Report)

	second, err := NewDependencyScanner(orchestrator, pyResolver, callgraph.NewBuilder(noopCallgraphParser{}), nil).ScanWithDependencies(t.Context(), first.Report, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(second.Report.Findings); got != 4 {
		t.Fatalf("chained findings = %d, want 2 direct + 1 Go dependency + 1 Python dependency", got)
	}
	secondIDs := findingIDsByPath(second.Report)
	for path, id := range firstIDs {
		if secondIDs[path] != id {
			t.Errorf("finding %s id = %q after the second ecosystem, want %q from the first", path, secondIDs[path], id)
		}
	}
	byPath := make(map[string]entities.CryptographicAsset)
	for _, finding := range second.Report.Findings {
		byPath[finding.FilePath] = finding.CryptographicAssets[0]
	}
	if got := byPath["main.go"].PURL; got != "pkg:pypi/acme-lib" {
		t.Errorf("Go finding PURL = %q, want the rule's versionless pkg:pypi/acme-lib: Python resolution must not version it", got)
	}
	if got := byPath["app.py"].PURL; got != "pkg:pypi/acme-lib@1.0" {
		t.Errorf("Python finding PURL = %q, want pkg:pypi/acme-lib@1.0 from the Python resolution", got)
	}
	var goDeps, pyDeps int
	for _, finding := range second.Report.Findings {
		asset := finding.CryptographicAssets[0]
		if asset.DependencyInfo == nil {
			continue
		}
		if asset.Source != findingSourceDependency || asset.FindingID == "" {
			t.Errorf("dependency finding %s = %+v, want source dependency and an id", finding.FilePath, asset)
		}
		switch asset.DependencyInfo.Module {
		case "example.com/gocrypto":
			goDeps++
		case "acme-lib":
			pyDeps++
		}
	}
	if goDeps != 1 || pyDeps != 1 {
		t.Fatalf("dependency findings: go=%d python=%d, want one of each", goDeps, pyDeps)
	}
	if second.Ecosystem != ecosystemPython || len(second.Dependencies) != 1 || second.CallGraph == nil {
		t.Fatalf("second result = ecosystem %q, %d dependencies, graph %v; want python, 1, a graph", second.Ecosystem, len(second.Dependencies), second.CallGraph != nil)
	}

	details := AggregateProgressDetails([]*DepScanResult{first, second})
	if details["deps_scanned"] != 2 || details["deps_with_findings"] != 2 || details["total_dep_findings"] != 2 {
		t.Fatalf("aggregated details = %v, want 2 scanned, 2 with findings, 2 findings", details)
	}
}

func findingIDsByPath(report *entities.InterimReport) map[string]string {
	out := make(map[string]string)
	for _, finding := range report.Findings {
		out[finding.FilePath] = finding.CryptographicAssets[0].FindingID
	}
	return out
}

func TestAggregateProgressDetailsSumsAndSortsAcrossEcosystems(t *testing.T) {
	node := &DepScanResult{summary: dependencyScanSummary{
		depsScanned: 3, depsSkippedSource: 1, depsFailed: 1, depsIncomplete: 1, depsWithFindings: 2, totalDepFindings: 5,
		skipped:    []DependencyOutcome{{Module: "zlib", Version: "1", Reason: DependencyOutcomeNoLocalSource}},
		failed:     []DependencyOutcome{{Module: "b", Version: "1", Reason: DependencyOutcomeScanFailed, ErrorCode: "scanner_failed"}},
		incomplete: []DependencyOutcome{{Module: "m", Version: "2", Reason: DependencyOutcomeTimeOrMemoryLimit}},
	}}
	python := &DepScanResult{summary: dependencyScanSummary{
		depsScanned: 2, depsSkippedSource: 1, depsWithFindings: 1, totalDepFindings: 1,
		skipped: []DependencyOutcome{{Module: "attrs", Version: "23", Reason: DependencyOutcomeNoLocalSource}},
	}}
	got := AggregateProgressDetails([]*DepScanResult{node, nil, python})
	want := progressWant(
		map[string]any{"deps_scanned": 5, "deps_skipped": 2, "deps_failed": 1, "deps_incomplete": 1, "deps_with_findings": 3, "total_dep_findings": 6},
		[]DependencyOutcome{
			{Module: "attrs", Version: "23", Reason: DependencyOutcomeNoLocalSource},
			{Module: "zlib", Version: "1", Reason: DependencyOutcomeNoLocalSource},
		},
		[]DependencyOutcome{{Module: "b", Version: "1", Reason: DependencyOutcomeScanFailed, ErrorCode: "scanner_failed"}},
		[]DependencyOutcome{{Module: "m", Version: "2", Reason: DependencyOutcomeTimeOrMemoryLimit}},
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregated details = %v, want %v", got, want)
	}
	if empty := AggregateProgressDetails(nil); !reflect.DeepEqual(empty, (*DepScanResult)(nil).ProgressDetails()) {
		t.Fatalf("aggregate of nothing = %v, want the zero details", empty)
	}
}

func TestLanguageEcosystem(t *testing.T) {
	cases := map[string]string{
		"go": "go", "java": "java", "python": "python", "rust": "rust",
		"javascript": "node", "typescript": "node", "tsx": "node", "jsx": "node", "node": "node",
		"c": "c", "cpp": "cpp", "c++": "cpp", "xml": "", "": "",
	}
	for language, want := range cases {
		if got := LanguageEcosystem(language); got != want {
			t.Errorf("LanguageEcosystem(%q) = %q, want %q", language, got, want)
		}
	}
}
