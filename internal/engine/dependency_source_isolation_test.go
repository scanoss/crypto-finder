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
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

// This exercises actual scanner path matching: an unanchored node_modules
// exclusion can hide the dependency target itself, not just its children.
func TestDependencyScanner_NpmSourceIsolationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires real OpenGrep subprocesses")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("OpenGrep not installed")
	}
	tests := []struct {
		name         string
		packagePath  string
		includeTests bool
	}{
		{"regular package", "library", false},
		{"scoped package including tests", "@scope/library", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "node_modules", filepath.FromSlash(tt.packagePath))
			child := filepath.Join(parent, "node_modules", "child")
			for _, rel := range []string{"index.js", "dist/index.js", "tests/index.js", "node_modules/child/index.js"} {
				path := filepath.Join(parent, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("const crypto = require('crypto'); crypto.createHash('sha256');\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rule := filepath.Join(root, "crypto.yaml")
			if err := os.WriteFile(rule, []byte(`rules:
  - id: node.hash
    languages: [javascript]
    message: Hash operation
    severity: INFO
    pattern: crypto.createHash(...)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-256
        algorithmFamily: SHA
        algorithmPrimitive: hash
        operation: digest
`), 0o600); err != nil {
				t.Fatal(err)
			}
			patterns := []string{"node_modules", "dist", "index.js"}
			if !tt.includeTests {
				patterns = skip.WithDefaultTestPatterns(patterns)
			}
			manifest := fmt.Sprintf(`{"name":"fixture","version":"1.0.0","dependencies":{%q:"1.0.0"}}`, tt.packagePath)
			lock := fmt.Sprintf(`{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{%q:"1.0.0"}},%q:{"version":"1.0.0","dependencies":{"child":"1.0.0"}},%q:{"version":"1.0.0"}}}`, tt.packagePath, "node_modules/"+tt.packagePath, "node_modules/"+tt.packagePath+"/node_modules/child")
			for name, contents := range map[string]string{"package.json": manifest, "package-lock.json": lock} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			resolver := dependency.NewNpmResolver()
			resolved, err := resolver.Resolve(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolved.Dependencies) != 2 {
				t.Fatalf("expected parent and child selected independently, got %+v", resolved.Dependencies)
			}
			ds := &DependencyScanner{resolver: resolver}
			workDir := root
			if tt.includeTests {
				// Also exercise absolute targets outside the scanner's cwd.
				workDir = ""
			}
			opts := DepScanOptions{ScanOptions: ScanOptions{ScannerConfig: scanner.Config{
				SkipPatterns: patterns, Timeout: 30 * time.Second, WorkDir: workDir, ExtraArgs: []string{"--jobs", "1"},
			}}}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			for _, dep := range resolved.Dependencies {
				target := dep.Dir
				if target != parent && target != child {
					t.Fatalf("unexpected resolved source directory %s", target)
				}
				depOpts := ds.buildDepScanOptions(&dep, []string{rule}, opts)
				s := opengrep.NewScanner()
				if err := s.Initialize(ctx, depOpts.ScannerConfig); err != nil {
					t.Fatal(err)
				}
				report, err := s.Scan(ctx, target, depOpts.RulePaths, entities.ToolInfo{Name: "opengrep"})
				if err != nil {
					t.Fatal(err)
				}
				got := []string{}
				for _, finding := range report.Findings {
					got = append(got, filepath.ToSlash(finding.FilePath))
				}
				sort.Strings(got)
				want := []string{"index.js"}
				if target == parent {
					want = []string{"dist/index.js", "index.js"}
					if tt.includeTests {
						want = append(want, "tests/index.js")
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("target %s: findings = %v, want %v", target, got, want)
				}
			}
		})
	}
}

func TestDependencyScanner_SourceScopeCache(t *testing.T) {
	for _, ecosystem := range []string{"node", "go", "java", "python", "rust"} {
		t.Run(ecosystem, func(t *testing.T) {
			dep := dependency.Dependency{Module: "library", Version: "1", Dir: t.TempDir()}
			key := "library@1"
			old := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "node_modules/child/index.js", CryptographicAssets: []entities.CryptographicAsset{{}}}}}
			fresh := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "index.js", CryptographicAssets: []entities.CryptographicAsset{{}}}}}
			cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{key + ":hash": old}}
			calls := 0
			reg := scanner.NewRegistry()
			reg.Register("fixture", &mockScanner{scanFunc: func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
				calls++
				return fresh, nil
			}})
			ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: ecosystem}, findingsCache: cache, orchestrator: NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{}), reg)}
			opts := DepScanOptions{ScanOptions: ScanOptions{ScannerName: "fixture"}}
			res := ds.scanSingleDep(context.Background(), dep, key, []string{"fixture.yaml"}, "hash", opts)
			if res.err != nil {
				t.Fatal(res.err)
			}
			if ecosystem != "node" {
				if calls != 0 || res.report != old {
					t.Fatal("other ecosystem cache compatibility changed")
				}
				return
			}
			if calls != 1 || res.report != fresh {
				t.Fatal("npm reused old nested-source findings instead of rescanning")
			}
			if cache.putLastKey == key+":hash" {
				t.Fatal("npm stored isolated report under legacy cache key")
			}
			cache.getMap[cache.putLastKey] = fresh
			res = ds.scanSingleDep(context.Background(), dep, key, []string{"fixture.yaml"}, "hash", opts)
			if res.err != nil || calls != 1 || res.report != fresh {
				t.Fatalf("fresh isolated cache not reusable: %+v, calls %d", res, calls)
			}
		})
	}
}

func TestDependencyScanner_SourceIsolationOptions(t *testing.T) {
	for _, ecosystem := range []string{"node", "go", "java", "python", "rust"} {
		for _, withTests := range []bool{false, true} {
			t.Run(ecosystem+"/include-tests="+strconv.FormatBool(withTests), func(t *testing.T) {
				patterns := []string{"node_modules", "dist", "index.js"}
				if !withTests {
					patterns = skip.WithDefaultTestPatterns(patterns)
				}
				original := append([]string(nil), patterns...)
				opts := DepScanOptions{ScanOptions: ScanOptions{ScannerConfig: scanner.Config{SkipPatterns: patterns}}}
				dep := &dependency.Dependency{Dir: filepath.Join(t.TempDir(), "node_modules", "@scope", "library")}
				ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: ecosystem}}
				got := ds.buildDepScanOptions(dep, nil, opts).ScannerConfig.SkipPatterns
				want := skip.OnlyDefaultTestPatterns(patterns)
				if ecosystem == "node" {
					want = append(want, filepath.ToSlash(filepath.Join(dep.Dir, "node_modules"))+"/")
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("exclusions = %v, want %v", got, want)
				}
				if !reflect.DeepEqual(patterns, original) {
					t.Fatal("dependency options mutated caller exclusions")
				}
			})
		}
	}
	// Disabling default exclusions does not disable artifact ownership.
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "node"}}
	dep := &dependency.Dependency{Dir: t.TempDir()}
	got := ds.buildDepScanOptions(dep, nil, DepScanOptions{}).ScannerConfig.SkipPatterns
	if len(got) != 1 {
		t.Fatalf("expected only source isolation with no default exclusions, got %v", got)
	}
}
