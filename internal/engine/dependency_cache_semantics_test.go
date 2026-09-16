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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/skip"
	"github.com/scanoss/crypto-finder/internal/version"
)

func TestDependencyCachePartitionsEffectiveArguments(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rules:\n- id: fixture\n  languages: [go]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewDiskFindingsCacheWithDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	reportedVersion := "1"
	var selected scanner.Config
	selectedName := "fixture"
	selectedModule := "dep"
	runtimeToken := ""
	var initializationErr error
	scanContext := t.Context()
	var lastDetails map[string]any
	registry := scanner.NewRegistry()
	factory := func() scanner.Scanner {
		var config scanner.Config
		return &mockScanner{
			getInfoFunc:    func() scanner.Info { return scanner.Info{Name: selectedName, Version: reportedVersion} },
			initializeFunc: func(_ context.Context, cfg scanner.Config) error { config = cfg; return initializationErr },
			scanFunc: func(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
				calls++
				env := config.Env["TOKEN"]
				if env == "" {
					env = os.Getenv("DEPENDENCY_SCAN_TOKEN")
				}
				cwd := config.WorkDir
				if cwd == "" {
					cwd, _ = os.Getwd()
				}
				return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{FilePath: filepath.Join(target, "dep.go"), CryptographicAssets: []entities.CryptographicAsset{{Metadata: map[string]string{"assetType": "algorithm", "primitive": "hash", "algorithmFamily": "SHA", "argument": config.ExtraArgs[0], "implementation": selectedName, "toolVersion": info.Version, "scannerVersion": reportedVersion, "environment": env, "workdir": cwd, "interfile": strconv.FormatBool(config.Interfile), "dedup": strconv.FormatBool(config.DisableDedup), "tests": strings.Join(config.SkipPatterns, "|")}}}}}}, nil
			},
		}
	}
	registry.RegisterFactory("fixture", factory)
	registry.RegisterFactory("other", factory)
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "go", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: []dependency.Dependency{{Module: selectedModule, Version: "1", Dir: dir}}}, nil
	}}
	run := func(argument string, backend FindingsCache) string {
		t.Helper()
		cfg := selected
		cfg.ExtraArgs = []string{argument}
		consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), backend)
		result, scanErr := consumer.ScanWithDependencies(scanContext, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: selectedName, ScannerConfig: cfg, JavaRuntimeCacheToken: runtimeToken}})
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		lastDetails = result.ProgressDetails()
		data, marshalErr := json.Marshal(struct {
			Report *entities.InterimReport
			Graph  *callgraph.CallGraph
		}{result.Report, result.CallGraph})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return string(data)
	}
	before := run("before", nil)
	after := run("after", nil)
	if before == after {
		t.Fatal("changed arguments must change uncached findings")
	}
	if got := run("before", cache); got != before {
		t.Fatal("cold cache differs from disabled")
	}
	count := calls
	if got := run("before", cache); got != before || calls != count {
		t.Fatal("same semantics must reuse complete cached output")
	}
	if got := run("after", cache); got != after {
		t.Fatal("changed arguments reused stale findings instead of cache-disabled output")
	}
	reportedVersion = "2"
	newVersion := run("after", nil)
	if newVersion == after {
		t.Fatal("changed scanner version must change uncached output")
	}
	if got := run("after", cache); got != newVersion {
		t.Fatal("changed scanner version reused stale findings")
	}

	t.Setenv("DEPENDENCY_SCAN_TOKEN", "changed")
	newEnvironment := run("after", nil)
	if newEnvironment == newVersion {
		t.Fatal("ambient environment must change uncached output")
	}
	if got := run("after", cache); got != newEnvironment {
		t.Fatal("ambient environment reused stale findings")
	}

	for _, change := range []string{"environment", "workdir", "interfile", "dedup", "tests", "scanner"} {
		t.Run(change, func(t *testing.T) {
			selected = scanner.Config{}
			selectedName = "fixture"
			baseline := run("after", cache)
			switch change {
			case "environment":
				selected.Env = map[string]string{"TOKEN": "configured"}
			case "workdir":
				selected.WorkDir = t.TempDir()
			case "interfile":
				selected.Interfile = true
			case "dedup":
				selected.DisableDedup = true
			case "tests":
				selected.SkipPatterns = skip.WithDefaultTestPatterns([]string{"primary-only"})
			case "scanner":
				selectedName = "other"
			}
			expected := run("after", nil)
			if baseline == expected {
				t.Fatal("option must change observable uncached output")
			}
			if got := run("after", cache); got != expected {
				t.Fatal("changed option differs from cache-disabled output")
			}
			count := calls
			if got := run("after", cache); got != expected || count != calls {
				t.Fatal("same effective option must reuse complete cached output")
			}
			if change == "tests" {
				selected.SkipPatterns = skip.WithDefaultTestPatterns([]string{"different-primary-only"})
				if got := run("after", cache); got != expected || count != calls {
					t.Fatal("irrelevant primary exclusions must not invalidate dependency cache")
				}
			}
		})
	}
	selected, selectedName = scanner.Config{}, "fixture"
	previousFinderVersion := version.Version
	t.Cleanup(func() { version.Version = previousFinderVersion })
	baselineFinder := run("after", cache)
	version.Version = "fixture-next"
	nextFinder := run("after", nil)
	if nextFinder == baselineFinder {
		t.Fatal("finder version must change observable tool metadata")
	}
	if got := run("after", cache); got != nextFinder {
		t.Fatal("finder version reused stale tool metadata")
	}
	count = calls
	initializationErr = errors.New("fixture unavailable")
	if got := run("after", cache); got == nextFinder || count != calls || lastDetails["deps_failed"] != 1 {
		t.Fatal("failed discovery must not trust warm findings or execute scanner")
	}
	initializationErr = nil
	if got := run("after", cache); got != nextFinder || count != calls {
		t.Fatal("transient discovery failure must preserve reusable warm entry")
	}
	expired, expire := context.WithTimeout(t.Context(), -time.Second)
	defer expire()
	scanContext = expired
	if got := run("after", cache); got != nextFinder || count != calls {
		t.Fatal("expired parent deadline must retain independent dependency scan budget")
	}
	scanContext = t.Context()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), cache)
	_, cancelErr := consumer.ScanWithDependencies(canceled, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: dir, ScannerName: "fixture", ScannerConfig: scanner.Config{ExtraArgs: []string{"after"}}}})
	if !errors.Is(cancelErr, context.Canceled) || count != calls {
		t.Fatalf("warm canceled scan: %v, actual scans=%d", cancelErr, calls)
	}
	selectedModule = "example.com/" + strings.Repeat("segment/", 20) + "dep"
	longExpected := run("after", nil)
	if got := run("after", cache); got != longExpected {
		t.Fatal("long package cold cache differs")
	}
	count = calls
	if got := run("after", cache); got != longExpected || count != calls {
		t.Fatal("long package identity must fit disk cache filename and reuse findings")
	}

	runtimeToken = "jdk-21"
	if got := run("after", cache); got != longExpected || calls != count+1 {
		t.Fatal("Java runtime token must partition cached findings")
	}
	count = calls
	if got := run("after", cache); got != longExpected || count != calls {
		t.Fatal("same runtime token must reuse findings")
	}
	for _, missingVersion := range []string{"", "unknown"} {
		reportedVersion = missingVersion
		expected := run("after", nil)
		if got := run("after", cache); got != expected {
			t.Fatal("unknown identity must preserve normal scan output")
		}
		count = calls
		if got := run("after", cache); got != expected || calls != count+1 {
			t.Fatal("unavailable version identity must bypass cache rather than trust warm entries")
		}
	}
}
