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
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// The rule prefilter changes the rules a dependency is scanned with, so its
// findings cache key must change with it; core mode is keyed too. The
// default modes add nothing to the key, so caches written before these
// options existed stay valid.
func TestDependencyCacheKeySplitsByOpengrepModeAndPrefilter(t *testing.T) {
	reg := scanner.NewRegistry()
	reg.Register("fixture", &mockScanner{getInfoFunc: func() scanner.Info { return scanner.Info{Name: "fixture", Version: "1.0.0"} }})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{}), reg)
	dep := dependency.Dependency{Module: "library", Version: "1", Dir: t.TempDir()}
	keyFor := func(config scanner.Config) string {
		t.Helper()
		cache := &fakeFindingsCache{}
		ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}, findingsCache: cache, orchestrator: orchestrator}
		res := ds.scanSingleDep(context.Background(), dep, "library@1", []string{"fixture.yaml"}, DepScanOptions{ScanOptions: ScanOptions{ScannerName: "fixture", ScannerConfig: config}})
		if res.err != nil {
			t.Fatal(res.err)
		}
		if !strings.HasPrefix(cache.putLastKey, "dependency-findings-v2:") {
			t.Fatalf("no cache key written: %q", cache.putLastKey)
		}
		return cache.putLastKey
	}
	off := keyFor(scanner.Config{})
	prefiltered := keyFor(scanner.Config{RulePrefilter: scanner.RulePrefilterImports})
	core := keyFor(scanner.Config{OpengrepMode: scanner.OpengrepModeCore})
	if prefiltered == off || core == off || core == prefiltered {
		t.Errorf("cache keys must differ per mode: off %s, imports %s, core %s", off, prefiltered, core)
	}
	if keyFor(scanner.Config{RulePrefilter: scanner.RulePrefilterImports}) != prefiltered {
		t.Error("the prefiltered cache key must be stable")
	}
	encoded, err := json.Marshal(scanner.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "OpengrepMode") || strings.Contains(string(encoded), "RulePrefilter") {
		t.Errorf("default modes must not change the encoded configuration: %s", encoded)
	}
}
