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

package scan

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// entryRuleCase is one planted crypto call in an entry_rules fixture and the
// verdict it must get. rootKind and first describe one of its chains: the
// root kind of its first frame and a substring of that frame's name. An empty
// rootKind asks for no chain check.
type entryRuleCase struct {
	id, file, needle string
	reachability     string
	rootKind         callgraph.RootKind
	first            string
}

// entryRulesFixture builds testdata/entry_rules/<dir> with parser and plants
// one finding per case.
func entryRulesFixture(t *testing.T, dir, ecosystem, language string, parser callgraph.Parser, cases []entryRuleCase) entryRootsFixture {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(testFile), "testdata", "entry_rules", dir)
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for _, c := range cases {
		line := lineContaining(t, filepath.Join(root, c.file), c.needle)
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: c.file,
			Language: language,
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: c.id,
				StartLine: line,
				EndLine:   line,
				Match:     c.needle,
				Rules:     []entities.RuleInfo{{ID: language + ".crypto." + c.id}},
				Metadata:  map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	return entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		Ecosystem:   ecosystem,
		ProjectRoot: root,
	}}
}

// checkEntryRules exports the fixture and checks every case.
func checkEntryRules(t *testing.T, fixture entryRootsFixture, cases []entryRuleCase) {
	t.Helper()
	graphs := exportEntryRoots(t, fixture, 0)
	for _, c := range cases {
		fg, ok := graphs[c.id]
		if !ok {
			t.Errorf("%s: no finding graph", c.id)
			continue
		}
		if fg.Reachability != c.reachability {
			t.Errorf("%s: reachability = %q, want %q (chains %+v)", c.id, fg.Reachability, c.reachability, shortChains(fg))
			continue
		}
		if c.rootKind == "" {
			continue
		}
		found := false
		for _, chain := range fg.CallChains {
			if chain[0].RootKind == string(c.rootKind) && strings.Contains(chain[0].FunctionName, c.first) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: chains = %+v, want one starting at %q as %s", c.id, shortChains(fg), c.first, c.rootKind)
		}
	}
}

// TestExportCallGraph_JavaContainerEntryPoints: methods a Java container calls
// by reflection or lifecycle are entry points, so crypto written directly in
// them is reachable. An annotation counts through a single-type or on-demand
// import or its qualified spelling, and one of the same simple name from
// another package does not. A method nothing calls that no rule recognizes
// stays unreachable.
func TestExportCallGraph_JavaContainerEntryPoints(t *testing.T) {
	t.Parallel()
	cases := []entryRuleCase{
		{
			id: "postconstruct", file: "src/main/java/com/app/boot/KeyWarmup.java", needle: `getInstance("SHA-256")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "KeyWarmup.warmUp",
		},
		{
			id: "bean", file: "src/main/java/com/app/boot/CryptoConfig.java", needle: `getInstance("AES")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "CryptoConfig.sessionKeys",
		},
		{
			id: "servlet", file: "src/main/java/com/app/web/LegacyExportServlet.java", needle: `getInstance("DES`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "LegacyExportServlet.doPost",
		},
		{
			id: "websocket", file: "src/main/java/com/app/ws/ChatEndpoint.java", needle: `getInstance("MD5")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "ChatEndpoint.onMessage",
		},
		{
			id: "helper", file: "src/main/java/com/app/ws/AuditFeed.java", needle: `getInstance("SHA-1")`,
			reachability: graphfrag.ReachabilityUnreachable,
		},
		{
			id: "on-demand-import", file: "src/main/java/com/app/jobs/Rotation.java", needle: `getInstance("SHA-384")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "Rotation.rotate",
		},
		{
			id: "qualified-annotation", file: "src/main/java/com/app/jobs/Rotation.java", needle: `getInstance("SHA-224")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "Rotation.onKey",
		},
		// @PostConstruct imported from org.acme.lifecycle, not jakarta.annotation.
		{
			id: "unrelated-annotation", file: "src/main/java/com/app/boot/LocalHooks.java", needle: `getInstance("SHA-512")`,
			reachability: graphfrag.ReachabilityUnreachable,
		},
	}
	checkEntryRules(t, entryRulesFixture(t, "java", "java", "java", callgraph.NewJavaParser(), cases), cases)
}
