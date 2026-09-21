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

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

const reuseRule = "- id: fixture\n  languages: [go]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n  metadata:\n    crypto:\n      parameterCondition: 'param[0]==true'\n"

func rulesReuseConsumer(t *testing.T, path string, count int, scan func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error)) (*DependencyScanner, DepScanOptions) {
	t.Helper()
	dir := t.TempDir()
	deps := make([]dependency.Dependency, count)
	for i := range deps {
		deps[i] = dependency.Dependency{Module: fmt.Sprintf("dep%d", i), Version: "1", Dir: dir}
	}
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner { return &mockScanner{scanFunc: scan} })
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{path}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: deps}, nil
	}}
	return NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), nil), DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture"}}
}

func TestDependencyRulesSetupAllocationBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("rules:\n"+strings.Repeat(reuseRule, 256)), 0o600); err != nil {
		t.Fatal(err)
	}
	consumer, opts := rulesReuseConsumer(t, path, 6, func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
		return &entities.InterimReport{}, nil
	})
	// Fixed six-dependency setup must stay below 300,000 heap allocations.
	// A separate one-dependency baseline measured about 279,000 allocations.
	// This budget allows that unrelated setup, not repeated YAML per dependency.
	// Fixture construction is excluded; scanner and callgraph do no external work.
	allocations := testing.AllocsPerRun(3, func() {
		result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts)
		if err != nil || result.ProgressDetails()["deps_scanned"] != 6 {
			t.Fatalf("public scan: result=%v error=%v", result, err)
		}
	})
	t.Logf("public setup allocations: %.0f", allocations)
	if allocations > 300000 {
		t.Fatalf("six-dependency setup allocated %.0f objects; budget 300000", allocations)
	}
}

func TestDependencyRulesProofTracksCurrentBytes(t *testing.T) {
	for _, scenario := range []string{"raw-before-filter", "malformed-prepared", "unreadable-prepared", "valid-prepared", "added-malformed", "separate-invocations", "concurrent"} {
		t.Run(scenario, func(t *testing.T) {
			if scenario == "unreadable-prepared" && os.Geteuid() == 0 {
				t.Skip("permission fixture requires unprivileged file reads")
			}
			dir := t.TempDir()
			first := filepath.Join(dir, "first.yaml")
			original := "rules:\n" + reuseRule
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(first, original)
			write(filepath.Join(dir, "second.yaml"), strings.ReplaceAll(original, "fixture", "other"))
			if scenario == "raw-before-filter" {
				write(first, strings.ReplaceAll(strings.ReplaceAll(original, "[go]", "[python]"), "param[0]==true", "param[]==true "))
			}
			var observations []string
			var mu sync.Mutex
			consumer, opts := rulesReuseConsumer(t, dir, 3, func(_ context.Context, target string, paths []string, info entities.ToolInfo) (*entities.InterimReport, error) {
				mu.Lock()
				defer mu.Unlock()
				var selected string
				if err := filepath.WalkDir(paths[0], func(path string, entry os.DirEntry, err error) error {
					if err == nil && !entry.IsDir() && entry.Name() == "first.yaml" {
						selected = path
					}
					return err
				}); err != nil {
					return nil, err
				}
				data, err := os.ReadFile(selected)
				if err != nil {
					return nil, err
				}
				observations = append(observations, string(data))
				if len(observations) == 1 {
					stat, statErr := os.Stat(selected)
					if statErr != nil {
						return nil, statErr
					}
					replacement := string(data)
					switch scenario {
					case "malformed-prepared":
						replacement = strings.ReplaceAll(replacement, "param[0]==true", "param[]==true ")
						write(selected, replacement)
					case "valid-prepared":
						replacement = strings.ReplaceAll(replacement, "param[0]", "param[1]")
						write(selected, replacement)
					case "added-malformed":
						write(filepath.Join(paths[0], "new.yaml"), "rules: [")
					}
					if err := os.Chtimes(selected, stat.ModTime(), stat.ModTime()); err != nil {
						return nil, err
					}
					after, statErr := os.Stat(selected)
					if statErr != nil || after.Size() != stat.Size() || !after.ModTime().Equal(stat.ModTime()) {
						return nil, fmt.Errorf("mutation did not preserve size/mtime: %w", statErr)
					}
				}
				if scenario == "unreadable-prepared" {
					if err := os.Chmod(selected, 0); err != nil {
						return nil, err
					}
				}
				return &entities.InterimReport{Tool: info, Findings: []entities.Finding{{FilePath: filepath.Join(target, "dep.go"), CryptographicAssets: []entities.CryptographicAsset{{Metadata: map[string]string{"assetType": "algorithm", "primitive": "hash", "algorithmFamily": "SHA", "observed": string(data)}}}}}}, nil
			})
			if scenario == "concurrent" {
				opts.Workers = 3
			}
			result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts)
			if scenario == "raw-before-filter" {
				if err == nil || len(observations) != 0 || !strings.Contains(err.Error(), "param[]==true") {
					t.Fatalf("raw gate before filter: observations=%d error=%v", len(observations), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			failed := 0
			if scenario == "malformed-prepared" || scenario == "unreadable-prepared" || scenario == "added-malformed" {
				failed = 2
			}
			if result.ProgressDetails()["deps_failed"] != failed || len(observations) != 3-failed {
				t.Fatalf("current gate: details=%v observations=%d", result.ProgressDetails(), len(observations))
			}
			assets := 0
			for _, finding := range result.Report.Findings {
				assets += len(finding.CryptographicAssets)
			}
			if assets != 3-failed {
				t.Fatalf("successful findings lost: %d", assets)
			}
			if scenario == "valid-prepared" && (!strings.Contains(observations[1], "param[1]") || observations[1] == observations[0]) {
				t.Fatal("valid changed bytes were hidden")
			}
			if scenario == "separate-invocations" {
				write(first, strings.ReplaceAll(original, "param[0]==true", "param[]==true "))
				if _, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts); err == nil {
					t.Fatal("new invocation inherited stale proof")
				}
				write(first, original)
				repaired, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts)
				if err != nil || repaired.ProgressDetails()["deps_failed"] != 0 {
					t.Fatalf("repair inherited cached failure: %v", err)
				}
			}
		})
	}
}

func TestDependencyRulesRepairDoesNotReuseFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yaml")
	original := "rules:\n" + reuseRule
	write := func(body string) error { return os.WriteFile(path, []byte(body), 0o600) }
	if err := write(original); err != nil {
		t.Fatal(err)
	}
	cache, err := NewDiskFindingsCacheWithDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	initialized, scanned := 0, 0
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &mockScanner{
			getInfoFunc: func() scanner.Info { return scanner.Info{Name: "fixture", Version: "1"} },
			initializeFunc: func(context.Context, scanner.Config) error {
				initialized++
				if initialized == 3 {
					return write(strings.ReplaceAll(original, "param[0]", "param[1]"))
				}
				return nil
			},
			scanFunc: func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
				scanned++
				if scanned == 1 {
					if err := write(strings.ReplaceAll(original, "param[0]==true", "param[]==true ")); err != nil {
						return nil, err
					}
				}
				return &entities.InterimReport{}, nil
			},
		}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{path}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{Dependencies: []dependency.Dependency{{Module: "a", Dir: dir}, {Module: "b", Dir: dir}, {Module: "c", Dir: dir}}}, nil
	}}
	consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), cache)
	result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture"}})
	if err != nil || scanned != 2 || result.ProgressDetails()["deps_failed"] != 1 {
		t.Fatalf("repair within invocation: scans=%d error=%v result=%v", scanned, err, result)
	}
}

func TestDependencyRulesRetainUnavailablePathPolicy(t *testing.T) {
	for _, scenario := range []string{"missing", "unwalkable"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.yaml")
			if scenario == "unwalkable" {
				path = t.TempDir()
				if err := os.WriteFile(filepath.Join(path, "rule.yaml"), []byte("rules:\n"+reuseRule), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
			}
			consumer, opts := rulesReuseConsumer(t, path, 1, func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
				return &entities.InterimReport{}, nil
			})
			result, err := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, opts)
			// Preserve the existing gate's skipped missing/unwalkable path behavior.
			// The external scanner can still reject unavailable inputs independently.
			if err != nil || result.ProgressDetails()["deps_scanned"] != 1 {
				t.Fatalf("path policy: result=%v error=%v", result, err)
			}
		})
	}
}
