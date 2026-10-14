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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/perf"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

// sessionNoise is what differs between two machines or sessions that run
// the same scan: none of it may split the findings cache.
var sessionNoise = map[string][2]string{
	"HOSTNAME":              {"runner-a", "runner-b"},
	"PATH":                  {"/opt/opengrep/bin:/usr/local/bin:/usr/bin:/bin", "/usr/bin:/opt/opengrep/bin:/bin:/usr/local/bin:/nonexistent"},
	"HOME":                  {"/home/alice", "/root"},
	"USER":                  {"alice", "root"},
	"SSH_CONNECTION":        {"10.0.0.1 51234 10.0.0.2 22", "10.0.0.9 40000 10.0.0.2 22"},
	"SSH_CLIENT":            {"10.0.0.1 51234 22", "10.0.0.9 40000 22"},
	"SSH_AUTH_SOCK":         {"/tmp/ssh-AbC/agent.1", "/tmp/ssh-XyZ/agent.2"},
	"SSH_TTY":               {"/dev/pts/1", "/dev/pts/7"},
	"GITHUB_RUN_ID":         {"1001", "1002"},
	"GITHUB_RUN_NUMBER":     {"7", "8"},
	"CI_JOB_ID":             {"55", "56"},
	"CI_PIPELINE_ID":        {"9", "10"},
	"BUILD_NUMBER":          {"300", "301"},
	"SCANOSS_PHASE_TIMINGS": {"/out/run1.phases", "/out/run2.phases"},
	"SCANOSS_SCANNER_JOBS":  {"8", "4"},
	"OLDPWD":                {"/a", "/b"},
	"PWD":                   {"/w", "/w"},
	"SHLVL":                 {"1", "3"},
	"_":                     {"/usr/bin/time", "/usr/bin/env"},
	"TERM_SESSION_ID":       {"w0t0p0", "w1t0p0"},
	"XDG_SESSION_ID":        {"3", "4"},
	"TMUX_PANE":             {"%1", "%2"},
}

func sessionEnv(which int) []string {
	env := make([]string, 0, len(sessionNoise))
	for name, values := range sessionNoise {
		env = append(env, name+"="+values[which])
	}
	return env
}

func TestCacheIdentityEnvironmentKeepsOnlyScanVariables(t *testing.T) {
	env := append(sessionEnv(0), "LC_ALL=C", "SEMGREP_FIXTURE=1", "LANG=en_US.UTF-8", "SEMGREP_CORE_EXTRA=-fast", "XDG_CONFIG_HOME=/c", "TMPDIR=/t")
	got := cacheIdentityEnvironment(opengrep.ScannerName, env)
	want := []string{"LANG=en_US.UTF-8", "LC_ALL=C", "SEMGREP_CORE_EXTRA=-fast"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cacheIdentityEnvironment = %q, want %q", got, want)
	}
}

// TestCacheIdentityEnvironmentUnauditedScannerKeepsDenylist pins the
// fallback for a scanner whose environment reads were not audited: every
// variable but crypto-finder's diagnostics and shell/login bookkeeping.
func TestCacheIdentityEnvironmentUnauditedScannerKeepsDenylist(t *testing.T) {
	got := cacheIdentityEnvironment("semgrep", []string{
		"SCANOSS_PHASE_TIMINGS=/out/run1.phases",
		"PATH=/bin",
		"OLDPWD=/somewhere",
		"_=/usr/bin/time",
		"SSH_CONNECTION=10.0.0.1 51234 10.0.0.2 22",
		"HOSTNAME=runner-a",
		"SHLVL=2",
		// Prefix of an excluded name: still keyed.
		"PWDX=1",
	})
	want := []string{"HOSTNAME=runner-a", "PATH=/bin", "PWDX=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cacheIdentityEnvironment = %q, want %q", got, want)
	}
}

// TestDependencyCacheKeyIgnoresSessionAndKeysScanInputs simulates two
// machines or sessions running the same scan: the key must be equal. Every
// allowlisted variable, the engine build and the dependency root must still
// change it.
func TestDependencyCacheKeyIgnoresSessionAndKeysScanInputs(t *testing.T) {
	keyOf := func(env []string, mutate func(*dependencyCacheIdentity)) string {
		t.Helper()
		id := dependencyCacheIdentity{
			Package: "m@v1", RulesHash: "rh", JavaRuntime: "jdk-21", Name: opengrep.ScannerName,
			Scanner:       scanner.Info{Name: "opengrep", Version: "1.30.2"},
			FinderVersion: "0.9.0", Config: scanner.Config{RuleTimeoutSeconds: 30, OpengrepMode: scanner.OpengrepModeCore},
			Languages: []string{"go"}, Environment: cacheIdentityEnvironment(opengrep.ScannerName, env), CWD: "/w",
			Engine: "e1", Root: "/cache/m/v1",
		}
		if mutate != nil {
			mutate(&id)
		}
		key, err := id.key()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	base := keyOf(sessionEnv(0), nil)
	if got := keyOf(sessionEnv(1), nil); got != base {
		t.Fatal("another machine or session must share the key")
	}
	for name := range opengrepEnvironment {
		set := keyOf(append(sessionEnv(0), name+"=x"), nil)
		if set == base {
			t.Errorf("setting %s must change the key", name)
		}
		if keyOf(append(sessionEnv(0), name+"=y"), nil) == set {
			t.Errorf("changing %s must change the key", name)
		}
		if keyOf(append(sessionEnv(1), name+"=x"), nil) != set {
			t.Errorf("session noise must not split keys with %s set", name)
		}
	}
	if keyOf(sessionEnv(0), func(id *dependencyCacheIdentity) { id.Engine = "e2" }) == base {
		t.Error("another engine build must change the key")
	}
	if keyOf(sessionEnv(0), func(id *dependencyCacheIdentity) { id.Source = "sha256-of-a-fork" }) == base {
		t.Fatal("the source digest must change the key")
	}
	if data, err := json.Marshal(&dependencyCacheIdentity{}); err != nil || strings.Contains(string(data), "Source") {
		t.Fatalf("an empty source digest must stay out of the key material, as for a verified store: %s", data)
	}
	if keyOf(sessionEnv(0), func(id *dependencyCacheIdentity) { id.Root = "/other/m/v1" }) == base {
		t.Error("another dependency root must change the key")
	}
}

// fingerprintedScanner is a mockScanner that fingerprints its engine.
type fingerprintedScanner struct {
	*mockScanner
	fingerprint func() (string, error)
}

func (s *fingerprintedScanner) EngineFingerprint(context.Context) (string, error) {
	return s.fingerprint()
}

// TestDependencyCacheWarmAcrossMachinesAndSessions runs the same dependency
// scan the way two hosts or CI runs do: the second must reuse the first's
// findings byte-identical, with no rescan, while each allowlisted variable,
// the engine build and the dependency root still partition the cache, and
// every cached output equals the cache-disabled output.
func TestDependencyCacheWarmAcrossMachinesAndSessions(t *testing.T) {
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
	names := make([]string, 0, len(opengrepEnvironment))
	for name := range opengrepEnvironment {
		names = append(names, name)
	}
	sort.Strings(names)
	calls := 0
	engine, engineErr := "build-1", error(nil)
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &fingerprintedScanner{
			mockScanner: &mockScanner{
				getInfoFunc: func() scanner.Info { return scanner.Info{Name: opengrep.ScannerName, Version: "1"} },
				scanFunc: func(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
					calls++
					// What the engine sees: its build and every variable it reads.
					seen := map[string]string{"assetType": "algorithm", "algorithmFamily": "SHA", "engine": engine}
					for _, name := range names {
						if value, ok := os.LookupEnv(name); ok {
							seen[name] = value
						}
					}
					return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{FilePath: filepath.Join(target, "dep.go"), CryptographicAssets: []entities.CryptographicAsset{{Metadata: seen}}}}}, nil
				},
			},
			fingerprint: func() (string, error) { return engine, engineErr },
		}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	depDir := filepath.Join(dir, "sources", "dep", "1")
	if err := os.MkdirAll(depDir, 0o750); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: []dependency.Dependency{{Module: "dep", Version: "1", Dir: depDir}}}, nil
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
	session := func(which int) {
		for name, values := range sessionNoise {
			if name == "PATH" {
				// Keep the toolchain reachable; only the order changes.
				parts := filepath.SplitList(os.Getenv("PATH"))
				if which == 1 {
					slices.Reverse(parts)
				}
				t.Setenv(name, strings.Join(parts, string(os.PathListSeparator)))
				continue
			}
			t.Setenv(name, values[which])
		}
	}
	// expectMiss checks that the current state is scanned once, matches the
	// cache-disabled output, and is then served from the cache.
	expectMiss := func(what string) string {
		t.Helper()
		uncached := run(nil)
		count := calls
		if got := run(cache); got != uncached || calls != count+1 {
			t.Fatalf("%s: must rescan once and match the cache-disabled output (rescans=%d identical=%v)", what, calls-count, got == uncached)
		}
		count = calls
		if got := run(cache); got != uncached || calls != count {
			t.Fatalf("%s: second run must be served from the cache", what)
		}
		return uncached
	}

	for _, name := range names {
		t.Setenv(name, "") // Restores the original value after the test.
		os.Unsetenv(name)
	}
	session(0)
	cold := expectMiss("cold")
	session(1)
	count := calls
	if warm := run(cache); warm != cold || calls != count {
		t.Fatalf("another machine or session must not split the cache: rescans=%d identical=%v", calls-count, warm == cold)
	}

	for _, name := range names {
		t.Setenv(name, "fixture-"+name)
		if expectMiss(name) == cold {
			t.Fatalf("%s must change the fixture engine's output", name)
		}
		os.Unsetenv(name)
	}
	count = calls
	if got := run(cache); got != cold || calls != count {
		t.Fatal("restoring the variables must reuse the first entry")
	}

	engine = "build-2"
	if expectMiss("engine build") == cold {
		t.Fatal("the engine build must change the fixture engine's output")
	}
	engine, engineErr = "build-1", errors.New("unreadable engine")
	count = calls
	if got := run(cache); got != cold || calls != count+1 {
		t.Fatal("an engine that cannot be fingerprinted must bypass the cache")
	}
	engineErr = nil

	// The same package extracted under another root (another HOME's source
	// cache): its findings name other paths.
	depDir = filepath.Join(dir, "other-home", "sources", "dep", "1")
	if err := os.MkdirAll(depDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if moved := expectMiss("dependency root"); moved == cold || !strings.Contains(moved, depDir) {
		t.Fatal("findings under another root must name that root")
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
