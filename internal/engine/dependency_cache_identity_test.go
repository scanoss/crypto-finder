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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/perf"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

func TestCacheIdentityEnvironmentDropsNonSemanticVariables(t *testing.T) {
	got := cacheIdentityEnvironment([]string{
		"SCANOSS_PHASE_TIMINGS=/out/run1.phases",
		"PATH=/bin",
		"OLDPWD=/somewhere",
		"_=/usr/bin/time",
		"SEMGREP_SETTINGS_FILE=/s.yml",
		"SSH_CONNECTION=10.0.0.1 51234 10.0.0.2 22",
		"SCANOSS_OPENGREP_CORE=/opt/opengrep-core",
		"SCANOSS_SCANNER_JOBS=8",
		"SCANOSS_CPUPROFILE=/tmp/cpu",
		"HOME=/home/u",
		"SHLVL=2",
		"PWD=/w",
		// Prefix of an excluded name: still keyed.
		"PWDX=1",
	})
	want := []string{
		"HOME=/home/u",
		"PATH=/bin",
		"PWDX=1",
		"SCANOSS_OPENGREP_CORE=/opt/opengrep-core",
		"SEMGREP_SETTINGS_FILE=/s.yml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cacheIdentityEnvironment = %q, want %q", got, want)
	}
}

// TestDependencyCacheIdentityKeyEncodingUnchanged pins the key material: an
// environment without excluded variables keys exactly as before the
// identity got a named type, so those caches stay warm.
func TestDependencyCacheIdentityKeyEncodingUnchanged(t *testing.T) {
	config := scanner.Config{Timeout: 3, SkipPatterns: []string{"test/"}, RuleTimeoutSeconds: 30, OpengrepMode: scanner.OpengrepModeCore, RulePrefilter: scanner.RulePrefilterImports}
	info := scanner.Info{Name: "opengrep", Version: "1.30.2"}
	env := []string{"HOME=/h", "PATH=/bin"}
	scope := &scanner.DetectionScope{Paths: []string{"a.go"}}
	for _, scope := range []*scanner.DetectionScope{nil, scope} {
		legacy, err := json.Marshal(struct {
			Package       string
			RulesHash     string
			JavaRuntime   string
			Name          string
			Scanner       scanner.Info
			FinderVersion string
			Config        scanner.Config
			Languages     []string
			Environment   []string
			CWD           string
			Scope         *scanner.DetectionScope `json:",omitempty"`
		}{"m@v1", "rh", "jdk-21", "opengrep", info, "0.9.0", config, []string{"go"}, env, "/w", scope})
		if err != nil {
			t.Fatal(err)
		}
		id := dependencyCacheIdentity{
			Package: "m@v1", RulesHash: "rh", JavaRuntime: "jdk-21", Name: "opengrep", Scanner: info,
			FinderVersion: "0.9.0", Config: config, Languages: []string{"go"},
			Environment: cacheIdentityEnvironment(env), CWD: "/w", Scope: scope,
		}
		got, err := id.key()
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("dependency-findings-v2:%x", sha256.Sum256(legacy)); got != want {
			t.Fatalf("key = %s, want legacy %s", got, want)
		}
	}
}

// TestDependencyCacheWarmAcrossPerRunDiagnostics runs the same dependency
// scan the way a benchmark does, with a timings file and a previous
// directory named per run: the second run must reuse the first run's
// findings, byte-identical, while a variable a scanner may read still
// partitions the cache.
func TestDependencyCacheWarmAcrossPerRunDiagnostics(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rules:\n- id: fixture\n  languages: [go]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewDiskFindingsCacheWithDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	// Open the timings sink before the variable changes, as one process does.
	perf.Enabled()
	calls := 0
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &mockScanner{
			getInfoFunc: func() scanner.Info { return scanner.Info{Name: "fixture", Version: "1"} },
			scanFunc: func(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
				calls++
				return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{FilePath: filepath.Join(target, "dep.go"), CryptographicAssets: []entities.CryptographicAsset{{Metadata: map[string]string{"assetType": "algorithm", "algorithmFamily": "SHA", "engineKnob": os.Getenv("OPENGREP_FIXTURE_KNOB")}}}}}}, nil
			},
		}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: []dependency.Dependency{{Module: "dep", Version: "1", Dir: dir}}}, nil
	}}
	run := func(backend FindingsCache) string {
		t.Helper()
		consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), backend)
		result, scanErr := consumer.ScanWithDependencies(t.Context(), &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture"}})
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		data, marshalErr := json.Marshal(result.Report)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return string(data)
	}
	perRun := func(name string) {
		t.Setenv("SCANOSS_PHASE_TIMINGS", filepath.Join(dir, name+".phases"))
		t.Setenv("OLDPWD", filepath.Join(dir, name))
		t.Setenv("_", "/usr/bin/"+name)
	}

	perRun("cold")
	uncached := run(nil)
	cold := run(cache)
	if cold != uncached {
		t.Fatal("cold cache differs from disabled")
	}
	count := calls
	perRun("warm")
	if warm := run(cache); warm != cold || calls != count {
		t.Fatalf("per-run diagnostics must not split the cache: rescans=%d identical=%v", calls-count, warm == cold)
	}

	t.Setenv("OPENGREP_FIXTURE_KNOB", "on")
	knob := run(nil)
	if knob == cold {
		t.Fatal("engine variable must change uncached output")
	}
	if got := run(cache); got != knob {
		t.Fatal("engine variable reused stale findings")
	}
}

func TestDependencyCacheStatsCountOutcomes(t *testing.T) {
	stats := newDepCacheStats()
	cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}
	scannerFactory := func() scanner.Scanner {
		return &mockScanner{
			getInfoFunc: func() scanner.Info { return scanner.Info{Name: "test-scanner", Version: "1"} },
			scanFunc: func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
				return &entities.InterimReport{}, nil
			},
		}
	}
	registry := scanner.NewRegistry()
	registry.RegisterFactory("test-scanner", scannerFactory)
	ds := NewDependencyScanner(NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{}), registry), &fakeResolver{ecosystem: "go"}, nil, cache)
	opts := DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}}
	dep := dependency.Dependency{Module: "m", Version: "1", Dir: t.TempDir()}
	rulePaths := []string{"rule.yaml"}

	item := depWork{key: dependencyKey(dep), dep: dep, cacheStats: stats}
	if _, hit := ds.lookupDependency(t.Context(), &item, rulePaths, "hash", opts); hit || item.cacheState != depCacheAbsent {
		t.Fatalf("cold lookup: hit=%v state=%s", hit, item.cacheState)
	}
	stats.lookup(item.cacheState)
	ds.scanDepAlone(t.Context(), &item, nil)
	cache.getMap[item.cacheKey] = &entities.InterimReport{}

	warm := depWork{key: dependencyKey(dep), dep: dep, cacheStats: stats}
	if _, hit := ds.lookupDependency(t.Context(), &warm, rulePaths, "hash", opts); !hit || warm.cacheState != depCacheHit {
		t.Fatalf("warm lookup: hit=%v state=%s", hit, warm.cacheState)
	}
	stats.lookup(warm.cacheState)

	noHash := depWork{key: dependencyKey(dep), dep: dep, cacheStats: stats}
	ds.lookupDependency(t.Context(), &noHash, rulePaths, "", opts)
	stats.lookup(noHash.cacheState)

	if got := formatCounts(stats.lookups); got != "absent:1,disabled:1,hit:1" {
		t.Fatalf("lookups = %s", got)
	}
	if got := formatCounts(stats.stores); got != "stored:1" {
		t.Fatalf("stores = %s", got)
	}
}
