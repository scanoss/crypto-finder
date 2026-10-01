// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// TestScanWithDependencies_CarriesDependencyPaths: the scan result names each
// dependency's route from the application in the resolved graph, and marks a
// bridge that was not parsed, here one with no source directory.
func TestScanWithDependencies_CarriesDependencyPaths(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rules:\n- id: fixture\n  languages: [go]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cryptoDir := filepath.Join(dir, "crypto")
	if err := os.MkdirAll(cryptoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &mockScanner{scanFunc: func(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
			return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{
				FilePath:            filepath.Join(target, "hash.go"),
				CryptographicAssets: []entities.CryptographicAsset{{Metadata: map[string]string{"assetType": "algorithm"}}},
			}}}, nil
		}}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{
			RootModule: "app",
			Dependencies: []dependency.Dependency{
				{Module: "bridge", Version: "1"},
				{Module: "crypto", Version: "2", Dir: cryptoDir},
			},
			Graph: map[string][]string{"app": {"bridge"}, "bridge": {"crypto"}},
		}, nil
	}}
	consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), nil)

	result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	path, ok := result.DependencyPaths["crypto"]
	if !ok {
		t.Fatalf("no dependency path for crypto in %v", result.DependencyPaths)
	}
	want := []dependency.PathStep{{Module: "bridge", WithoutSource: true}, {Module: "crypto"}}
	if !path.WithoutSource || len(path.Steps) != 2 || path.Steps[0] != want[0] || path.Steps[1] != want[1] {
		t.Fatalf("crypto path = %+v, want %+v behind a dependency without source", path, want)
	}
}
