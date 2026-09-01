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

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestExportCallGraphWithOptions_CryptoEntryPoints(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                string
		options             CallGraphExportOptions
		wantCryptoEntryKeys bool
	}{
		{
			name:                "zero value preserves the reverse reachability index",
			wantCryptoEntryKeys: true,
		},
		{
			name: "explicit omission removes the reverse reachability index",
			options: CallGraphExportOptions{
				OmitCryptoEntryPoints: true,
			},
			wantCryptoEntryKeys: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph, projectRoot := buildSupportingGraph(t)
			report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
			outputPath := filepath.Join(t.TempDir(), "callgraph.json")
			if err := ExportCallGraphWithOptions(outputPath, "json", &engine.DepScanResult{
				Report:      report,
				CallGraph:   graph,
				Ecosystem:   "java",
				ProjectRoot: projectRoot,
				RootModule:  "com.app:app",
			}, tc.options); err != nil {
				t.Fatalf("ExportCallGraphWithOptions: %v", err)
			}

			assertJSONMatchesSchema(t, filepath.Join("..", "..", "schemas", "callgraph-schema.json"), outputPath)

			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("read callgraph export: %v", err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("decode callgraph export: %v", err)
			}
			_, hasCryptoEntryPoints := document["crypto_entry_points"]
			if hasCryptoEntryPoints != tc.wantCryptoEntryKeys {
				t.Fatalf("crypto_entry_points present = %v, want %v", hasCryptoEntryPoints, tc.wantCryptoEntryKeys)
			}
			for _, key := range []string{"schema_version", "scan_metadata", "finding_graphs", "functions", "supporting_calls"} {
				if _, ok := document[key]; !ok {
					t.Errorf("callgraph export missing %q when crypto_entry_points presence is %v", key, hasCryptoEntryPoints)
				}
			}
		})
	}
}

func TestExportCallGraphWithOptions_InternedFrames(t *testing.T) {
	t.Parallel()

	graph, projectRoot := buildSupportingGraph(t)
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	for _, tc := range []struct {
		name          string
		interned      bool
		wantVersion   string
		wantFrameName bool
	}{
		{
			name:          "default inlined 6.14",
			wantVersion:   graphfrag.CallgraphSchemaVersion,
			wantFrameName: true,
		},
		{
			name:          "opt-in interned 6.15",
			interned:      true,
			wantVersion:   graphfrag.CallgraphInternedSchemaVersion,
			wantFrameName: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outputPath := filepath.Join(t.TempDir(), "callgraph.json")
			if err := ExportCallGraphWithOptions(outputPath, "json", &engine.DepScanResult{
				Report:      report,
				CallGraph:   graph,
				Ecosystem:   "java",
				ProjectRoot: projectRoot,
				RootModule:  "com.app:app",
			}, CallGraphExportOptions{InternedFrames: tc.interned}); err != nil {
				t.Fatalf("ExportCallGraphWithOptions: %v", err)
			}

			if !tc.interned {
				assertJSONMatchesSchema(t, filepath.Join("..", "..", "schemas", "callgraph-schema.json"), outputPath)
			}

			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("read callgraph export: %v", err)
			}
			var payload callGraphExportV2
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatalf("decode callgraph export: %v", err)
			}
			if payload.SchemaVersion != tc.wantVersion {
				t.Fatalf("schema_version = %q, want %q", payload.SchemaVersion, tc.wantVersion)
			}
			if len(payload.FindingGraphs) == 0 || len(payload.FindingGraphs[0].CallChains) == 0 {
				t.Fatal("expected at least one call chain")
			}
			frame := payload.FindingGraphs[0].CallChains[0][0]
			if (frame.FunctionName != "") != tc.wantFrameName {
				t.Fatalf("frame function_name present = %v, want %v (%q)", frame.FunctionName != "", tc.wantFrameName, frame.FunctionName)
			}
			if len(payload.Functions) == 0 {
				t.Fatal("functions catalog empty")
			}
			rebuilt, ok := graphfrag.ReconstructChainIdentities(payload.Functions, payload.FindingGraphs[0].CallChainIndexes)
			if !ok || len(rebuilt) == 0 || rebuilt[0][0].FunctionName == "" {
				t.Fatalf("catalog reconstruction failed: ok=%v rebuilt=%#v", ok, rebuilt)
			}
		})
	}
}

func TestExportCallGraphWithOptions_InternedAndInlinedDescribeSameRoutes(t *testing.T) {
	t.Parallel()

	graph, projectRoot := buildSupportingGraph(t)
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
	result := &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		Ecosystem:   "java",
		ProjectRoot: projectRoot,
		RootModule:  "com.app:app",
	}

	internedPath := filepath.Join(t.TempDir(), "interned.json")
	inlinedPath := filepath.Join(t.TempDir(), "inlined.json")
	if err := ExportCallGraphWithOptions(inlinedPath, "json", result, CallGraphExportOptions{}); err != nil {
		t.Fatalf("inlined export: %v", err)
	}
	if err := ExportCallGraphWithOptions(internedPath, "json", result, CallGraphExportOptions{InternedFrames: true}); err != nil {
		t.Fatalf("interned export: %v", err)
	}

	interned := mustDecodeCallGraphExport(t, internedPath)
	inlined := mustDecodeCallGraphExport(t, inlinedPath)
	if interned.SchemaVersion != graphfrag.CallgraphInternedSchemaVersion {
		t.Fatalf("interned schema_version = %q, want %q", interned.SchemaVersion, graphfrag.CallgraphInternedSchemaVersion)
	}
	if inlined.SchemaVersion != graphfrag.CallgraphSchemaVersion {
		t.Fatalf("inlined schema_version = %q, want %q", inlined.SchemaVersion, graphfrag.CallgraphSchemaVersion)
	}
	if len(interned.FindingGraphs) != len(inlined.FindingGraphs) {
		t.Fatalf("finding_graphs interned=%d inlined=%d", len(interned.FindingGraphs), len(inlined.FindingGraphs))
	}
	internedIDs := findingIDs(interned.FindingGraphs)
	inlinedIDs := findingIDs(inlined.FindingGraphs)
	for id := range internedIDs {
		if !inlinedIDs[id] {
			t.Fatalf("inlined render missing finding %q", id)
		}
	}
	if len(interned.CryptoEntryPoints) != len(inlined.CryptoEntryPoints) {
		t.Fatalf("crypto_entry_points interned=%d inlined=%d", len(interned.CryptoEntryPoints), len(inlined.CryptoEntryPoints))
	}
	internedEPs := liveEntryPointIDs(interned.CryptoEntryPoints)
	inlinedEPs := liveEntryPointIDs(inlined.CryptoEntryPoints)
	for id := range internedEPs {
		if !inlinedEPs[id] {
			t.Fatalf("inlined render missing entry point %q", id)
		}
	}

	for i := range interned.FindingGraphs {
		internedFG := interned.FindingGraphs[i]
		inlinedFG := inlined.FindingGraphs[i]
		if internedFG.FindingID != inlinedFG.FindingID {
			t.Fatalf("finding %d interned=%q inlined=%q", i, internedFG.FindingID, inlinedFG.FindingID)
		}
		internedRoutes, ok := graphfrag.ReconstructChainIdentities(interned.Functions, internedFG.CallChainIndexes)
		if !ok {
			t.Fatalf("finding %q interned indexes out of catalog", internedFG.FindingID)
		}
		inlinedRoutes, ok := graphfrag.ReconstructChainIdentities(inlined.Functions, inlinedFG.CallChainIndexes)
		if !ok {
			t.Fatalf("finding %q inlined indexes out of catalog", inlinedFG.FindingID)
		}
		if len(internedRoutes) != len(inlinedRoutes) || len(internedRoutes) != len(inlinedFG.CallChains) {
			t.Fatalf("finding %q routes interned=%d inlined-catalog=%d inlined-frames=%d", internedFG.FindingID, len(internedRoutes), len(inlinedRoutes), len(inlinedFG.CallChains))
		}
		for r := range inlinedFG.CallChains {
			chain := inlinedFG.CallChains[r]
			if len(internedRoutes[r]) != len(chain) || len(inlinedRoutes[r]) != len(chain) {
				t.Fatalf("finding %q route %d lens interned=%d inlined-catalog=%d inlined-frames=%d", internedFG.FindingID, r, len(internedRoutes[r]), len(inlinedRoutes[r]), len(chain))
			}
			for f := range chain {
				frame := &chain[f]
				got := internedRoutes[r][f]
				if got.FunctionName != frame.FunctionName || got.FilePath != frame.FilePath || got.CanonicalSignature != frame.CanonicalSignature {
					t.Fatalf("finding %q route %d frame %d interned catalog %+v does not match inlined frame identity", internedFG.FindingID, r, f, got)
				}
				if inlinedRoutes[r][f].FunctionName != frame.FunctionName {
					t.Fatalf("finding %q route %d frame %d inlined catalog name %q does not match frame %q", internedFG.FindingID, r, f, inlinedRoutes[r][f].FunctionName, frame.FunctionName)
				}
			}
		}
	}
}

func mustDecodeCallGraphExport(t *testing.T, path string) callGraphExportV2 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var payload callGraphExportV2
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return payload
}

func findingIDs(graphs []callGraphExportFinding) map[string]bool {
	out := make(map[string]bool, len(graphs))
	for i := range graphs {
		out[graphs[i].FindingID] = true
	}
	return out
}

func liveEntryPointIDs(points []callGraphCryptoEntryPoint) map[string]bool {
	out := make(map[string]bool, len(points))
	for i := range points {
		id := points[i].CanonicalSignature
		if id == "" {
			id = points[i].FunctionKey
		}
		out[id] = true
	}
	return out
}
