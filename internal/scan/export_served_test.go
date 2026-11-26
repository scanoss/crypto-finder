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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// A dependency asset whose verdict the API served is exported with that
// verdict, its reason and its chains, through the OID preparation every scan
// export goes through, and keeps its dependency route.
func TestExportCallGraph_WritesServedVerdicts(t *testing.T) {
	info := &entities.DependencyInfo{Module: "org.a:a", Version: "1.0", PURL: "pkg:maven/org.a/a@1.0"}
	served := func(id string, line int, verdict, reason, chains string) entities.CryptographicAsset {
		asset := entities.CryptographicAsset{
			FindingID: id, StartLine: line, EndLine: line, Match: "MessageDigest.getInstance(\"MD5\")", Source: "dependency",
			DependencyInfo: info, Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "MD5"},
			Served: &entities.ServedReachability{Reachability: verdict, Reason: reason},
		}
		if chains != "" {
			asset.Served.CallChains = json.RawMessage(chains)
			asset.Served.Analysis = json.RawMessage(`{"call_chains":"complete","route_evidence":"direct"}`)
		}
		return asset
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "org/a/X.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			served("reached", 10, "reachable", "", `[[{"function_key":"app.(A).run#0","function_name":"app.A.run"},{"function_key":"org.a.(X).digest#0"}]]`),
			served("unknown", 20, "unknown", "ambiguous_dispatch", ""),
			served("unreached", 30, "unreachable", "", ""),
		},
	}}}
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{
		CallGraph:       &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:       "java",
		Dependencies:    []dependency.Dependency{{Module: "org.a:a", Version: "1.0"}},
		DependencyPaths: map[string]dependency.Path{"org.a:a": {Steps: []dependency.PathStep{{Module: "org.a:a"}}}},
	}
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := ExportResolvedCallGraph(path, "json", result, prepared.ReportClone(), CallGraphExportOptions{InternedFrames: true}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var export struct {
		FindingGraphs []struct {
			FindingID        string  `json:"finding_id"`
			Reachability     string  `json:"reachability"`
			Reachable        *bool   `json:"reachable"`
			UnresolvedReason string  `json:"unresolved_reason"`
			CallChainIndexes [][]int `json:"call_chain_indexes"`
			Analysis         *struct {
				RouteEvidence string `json:"route_evidence"`
			} `json:"analysis"`
			Dependency *struct {
				Relationship string `json:"relationship"`
			} `json:"dependency"`
		} `json:"finding_graphs"`
		Functions []struct {
			FunctionKey string `json:"function_key"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	if len(export.FindingGraphs) != 3 {
		t.Fatalf("finding graphs = %d", len(export.FindingGraphs))
	}
	byID := map[string]int{}
	for i, fg := range export.FindingGraphs {
		byID[fg.FindingID] = i
		if fg.Dependency == nil || fg.Dependency.Relationship != "direct" {
			t.Errorf("%s: dependency = %+v", fg.FindingID, fg.Dependency)
		}
	}
	reached := export.FindingGraphs[byID["reached"]]
	if reached.Reachability != "reachable" || reached.Reachable == nil || !*reached.Reachable {
		t.Errorf("reached: %q %v", reached.Reachability, reached.Reachable)
	}
	if len(reached.CallChainIndexes) != 1 || len(reached.CallChainIndexes[0]) != 2 || len(export.Functions) != 2 ||
		export.Functions[reached.CallChainIndexes[0][0]].FunctionKey != "app.(A).run#0" {
		t.Errorf("reached chains = %v over functions %+v", reached.CallChainIndexes, export.Functions)
	}
	if reached.Analysis == nil || reached.Analysis.RouteEvidence != "direct" {
		t.Errorf("reached analysis = %+v", reached.Analysis)
	}
	unknown := export.FindingGraphs[byID["unknown"]]
	if unknown.Reachability != "unknown" || unknown.Reachable != nil || unknown.UnresolvedReason != "ambiguous_dispatch" {
		t.Errorf("unknown: %q %v %q", unknown.Reachability, unknown.Reachable, unknown.UnresolvedReason)
	}
	unreached := export.FindingGraphs[byID["unreached"]]
	if unreached.Reachability != "unreachable" || unreached.Reachable == nil || *unreached.Reachable || unreached.UnresolvedReason != "" {
		t.Errorf("unreached: %q %v %q", unreached.Reachability, unreached.Reachable, unreached.UnresolvedReason)
	}
}
