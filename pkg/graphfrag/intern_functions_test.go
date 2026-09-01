// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

func TestFunctionInterner_ReusesFirstSeenIdentity(t *testing.T) {
	t.Parallel()

	var intern FunctionInterner
	a := intern.Intern(FrameIdentity{FunctionKey: "alpha#0", FunctionName: "App.alpha", FilePath: "App.java", StartLine: 1})
	b := intern.Intern(FrameIdentity{FunctionKey: "mid#0", FunctionName: "App.mid", FilePath: "App.java", StartLine: 11})
	aAgain := intern.Intern(FrameIdentity{FunctionKey: "alpha#0", FunctionName: "App.alpha", FilePath: "App.java", StartLine: 1})
	if a != 0 || b != 1 || aAgain != 0 {
		t.Fatalf("indexes a=%d b=%d aAgain=%d, want 0, 1, 0", a, b, aAgain)
	}
	if got := intern.Functions(); len(got) != 2 {
		t.Fatalf("catalog len = %d, want 2", len(got))
	}
}

func TestFunctionInterner_KeepsSameSignatureAcrossDependencies(t *testing.T) {
	t.Parallel()

	var intern FunctionInterner
	left := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:left", Version: "1.0.0", PURL: "pkg:maven/com.lib/left@1.0.0"},
	})
	right := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:right", Version: "2.0.0", PURL: "pkg:maven/com.lib/right@2.0.0"},
	})
	leftAgain := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:left", Version: "1.0.0", PURL: "pkg:maven/com.lib/left@1.0.0"},
	})
	if left == right {
		t.Fatalf("same function_key interned as one catalog row across two dependencies")
	}
	if leftAgain != left {
		t.Fatalf("left interned twice: first=%d again=%d", left, leftAgain)
	}
	got := intern.Functions()
	if len(got) != 2 {
		t.Fatalf("catalog len = %d, want 2", len(got))
	}
	if got[left].DependencyInfo == nil || got[left].DependencyInfo.Module != "com.lib:left" {
		t.Fatalf("left catalog row = %+v, want module com.lib:left", got[left].DependencyInfo)
	}
	if got[right].DependencyInfo == nil || got[right].DependencyInfo.Module != "com.lib:right" {
		t.Fatalf("right catalog row = %+v, want module com.lib:right", got[right].DependencyInfo)
	}
}

func TestToCallgraphExport_ContractsFrameIdentityIntoCatalog(t *testing.T) {
	t.Parallel()

	root, deps, frags := chainEntryFixture()
	res, err := Stitch(root, deps, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	out := res.ToCallgraphExport(root, ScanMeta{RootModule: "com.acme:app", Ecosystem: "java", InternedFrames: true})
	if out.SchemaVersion != CallgraphInternedSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", out.SchemaVersion, CallgraphInternedSchemaVersion)
	}
	if CallgraphInternedSchemaVersion != "6.15" {
		t.Fatalf("CallgraphInternedSchemaVersion = %q, want 6.15", CallgraphInternedSchemaVersion)
	}
	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]
	if len(fg.CallChains) == 0 {
		t.Fatal("call_chains empty, want the N-sample of routes")
	}
	if len(fg.CallChainIndexes) != len(fg.CallChains) {
		t.Fatalf("call_chain_indexes len = %d, want %d matching routes", len(fg.CallChainIndexes), len(fg.CallChains))
	}
	if len(out.Functions) == 0 {
		t.Fatal("functions catalog empty")
	}

	for i, chain := range fg.CallChains {
		for j, frame := range chain {
			if !chainNodeIdentityEmpty(frame) {
				t.Fatalf("route %d frame %d still carries interned identity: %+v", i, j, IdentityFromChainNode(frame))
			}
		}
	}

	rebuilt, ok := ReconstructChainIdentities(out.Functions, fg.CallChainIndexes)
	if !ok {
		t.Fatal("call_chain_indexes pointed outside functions[]")
	}
	if len(rebuilt) != len(fg.CallChains) {
		t.Fatalf("reconstructed routes = %d, want %d", len(rebuilt), len(fg.CallChains))
	}
	for i, chain := range fg.CallChains {
		if len(rebuilt[i]) != len(chain) {
			t.Fatalf("route %d rebuilt len = %d, contracted len = %d", i, len(rebuilt[i]), len(chain))
		}
		for j, got := range rebuilt[i] {
			if got.FunctionName == "" || got.FilePath == "" {
				t.Fatalf("route %d frame %d catalog identity empty: %+v", i, j, got)
			}
		}
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	assertJSONFramesOmitIdentity(t, document)
	assertJSONCatalogHasIdentity(t, document)

	entryCount := len(out.CryptoEntryPoints)
	if entryCount < 2 {
		t.Fatalf("crypto_entry_points len = %d, want the full reverse-reach set (at least alpha and beta)", entryCount)
	}
	var sawCanonical bool
	for _, ep := range out.CryptoEntryPoints {
		if ep.CanonicalSignature != "" {
			sawCanonical = true
			break
		}
	}
	if !sawCanonical {
		t.Fatal("crypto_entry_points missing canonical_signature; join with functions[] would fail")
	}

	hydrated := out
	if !hydrated.HydrateChainIdentities() {
		t.Fatal("HydrateChainIdentities failed on interned export")
	}
	for i, chain := range hydrated.FindingGraphs[0].CallChains {
		for j, frame := range chain {
			if frame.FunctionName == "" || frame.FilePath == "" {
				t.Fatalf("hydrated route %d frame %d still empty: %+v", i, j, IdentityFromChainNode(frame))
			}
		}
	}
}

func TestToCallgraphExport_DefaultKeepsInlinedIdentity(t *testing.T) {
	t.Parallel()

	root, deps, frags := chainEntryFixture()
	res, err := Stitch(root, deps, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	inlined := res.ToCallgraphExport(root, ScanMeta{RootModule: "com.acme:app", Ecosystem: "java"})
	contracted := res.ToCallgraphExport(root, ScanMeta{RootModule: "com.acme:app", Ecosystem: "java", InternedFrames: true})
	if inlined.SchemaVersion != CallgraphSchemaVersion {
		t.Fatalf("default schema_version = %q, want %q", inlined.SchemaVersion, CallgraphSchemaVersion)
	}
	if CallgraphSchemaVersion != "6.14" {
		t.Fatalf("CallgraphSchemaVersion = %q, want 6.14", CallgraphSchemaVersion)
	}
	if contracted.SchemaVersion != CallgraphInternedSchemaVersion {
		t.Fatalf("interned schema_version = %q, want %q", contracted.SchemaVersion, CallgraphInternedSchemaVersion)
	}
	if len(inlined.FindingGraphs) != 1 || len(contracted.FindingGraphs) != 1 {
		t.Fatalf("finding graphs inlined=%d contracted=%d, want 1 each", len(inlined.FindingGraphs), len(contracted.FindingGraphs))
	}
	inlinedFG := inlined.FindingGraphs[0]
	if len(inlinedFG.CallChains) == 0 {
		t.Fatal("inlined call_chains empty")
	}
	for i, chain := range inlinedFG.CallChains {
		for j, frame := range chain {
			if frame.FunctionName == "" || frame.FilePath == "" {
				t.Fatalf("inlined route %d frame %d missing identity: %+v", i, j, IdentityFromChainNode(frame))
			}
		}
	}

	assertEquivalentRenders(t, inlined, contracted)
}

func chainNodeIdentityEmpty(n ExportChainNode) bool {
	return n.FunctionKey == "" && n.FunctionName == "" && n.CanonicalSignature == "" &&
		n.ReturnType == "" && len(n.ParameterTypes) == 0 && n.Visibility == "" &&
		n.OwnerVisibility == "" && n.DisplaySymbol == "" && len(n.Aliases) == 0 &&
		n.FilePath == "" && n.StartLine == 0 && n.DependencyInfo == nil
}

func assertEquivalentRenders(t *testing.T, inlined, contracted CallgraphExport) {
	t.Helper()
	if inlined.FindingGraphs[0].FindingID != contracted.FindingGraphs[0].FindingID {
		t.Fatalf("finding_id inlined=%q contracted=%q", inlined.FindingGraphs[0].FindingID, contracted.FindingGraphs[0].FindingID)
	}
	if len(inlined.CryptoEntryPoints) != len(contracted.CryptoEntryPoints) {
		t.Fatalf("crypto_entry_points len inlined=%d contracted=%d", len(inlined.CryptoEntryPoints), len(contracted.CryptoEntryPoints))
	}
	inlinedIDs := internedEntryPointIDs(inlined.CryptoEntryPoints)
	contractedIDs := internedEntryPointIDs(contracted.CryptoEntryPoints)
	for id := range inlinedIDs {
		if !contractedIDs[id] {
			t.Fatalf("contracted render missing entry point %q", id)
		}
	}

	inlinedRebuilt, ok := ReconstructChainIdentities(inlined.Functions, inlined.FindingGraphs[0].CallChainIndexes)
	if !ok {
		t.Fatal("inlined call_chain_indexes pointed outside functions[]")
	}
	contractedRebuilt, ok := ReconstructChainIdentities(contracted.Functions, contracted.FindingGraphs[0].CallChainIndexes)
	if !ok {
		t.Fatal("contracted call_chain_indexes pointed outside functions[]")
	}
	if len(inlinedRebuilt) != len(contractedRebuilt) {
		t.Fatalf("routes inlined=%d contracted=%d", len(inlinedRebuilt), len(contractedRebuilt))
	}
	for i, chain := range inlined.FindingGraphs[0].CallChains {
		if len(inlinedRebuilt[i]) != len(chain) || len(contractedRebuilt[i]) != len(chain) {
			t.Fatalf("route %d lens inlined-rebuilt=%d contracted-rebuilt=%d inlined-frames=%d", i, len(inlinedRebuilt[i]), len(contractedRebuilt[i]), len(chain))
		}
		for j := range chain {
			frame := &chain[j]
			gotInlined := inlinedRebuilt[i][j]
			gotContracted := contractedRebuilt[i][j]
			if gotInlined.FunctionKey != frame.FunctionKey || gotInlined.FunctionName != frame.FunctionName || gotInlined.FilePath != frame.FilePath || gotInlined.StartLine != frame.StartLine {
				t.Fatalf("inlined catalog route %d frame %d %+v does not match inlined frame %+v", i, j, gotInlined, IdentityFromChainNode(*frame))
			}
			if gotContracted.FunctionKey != frame.FunctionKey || gotContracted.FunctionName != frame.FunctionName || gotContracted.FilePath != frame.FilePath || gotContracted.CanonicalSignature != frame.CanonicalSignature {
				t.Fatalf("contracted catalog route %d frame %d %+v does not match inlined frame %+v", i, j, gotContracted, IdentityFromChainNode(*frame))
			}
			if (gotContracted.DependencyInfo == nil) != (frame.DependencyInfo == nil) {
				t.Fatalf("route %d frame %d dependency_info presence contracted=%v inlined=%v", i, j, gotContracted.DependencyInfo, frame.DependencyInfo)
			}
			if gotContracted.DependencyInfo != nil && *gotContracted.DependencyInfo != *frame.DependencyInfo {
				t.Fatalf("route %d frame %d dependency_info contracted=%+v inlined=%+v", i, j, *gotContracted.DependencyInfo, *frame.DependencyInfo)
			}
		}
	}
}

func internedEntryPointIDs(points []ExportCryptoEntryPoint) map[string]bool {
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

func mustRebuiltChains(t *testing.T, functions []ExportInternedFunction, indexes [][]int) [][]ExportInternedFunction {
	t.Helper()
	rebuilt, ok := ReconstructChainIdentities(functions, indexes)
	if !ok {
		t.Fatal("call_chain_indexes pointed outside functions[]")
	}
	return rebuilt
}

func assertJSONFramesOmitIdentity(t *testing.T, document map[string]any) {
	t.Helper()
	graphs, _ := document["finding_graphs"].([]any)
	if len(graphs) == 0 {
		t.Fatal("finding_graphs missing from JSON")
	}
	fg, _ := graphs[0].(map[string]any)
	chains, _ := fg["call_chains"].([]any)
	if len(chains) == 0 {
		t.Fatal("call_chains missing from JSON")
	}
	identityKeys := []string{"function_key", "function_name", "canonical_signature", "file_path", "dependency_info", "start_line"}
	for i, chainAny := range chains {
		chain, _ := chainAny.([]any)
		for j, frameAny := range chain {
			frame, _ := frameAny.(map[string]any)
			for _, key := range identityKeys {
				if _, ok := frame[key]; ok {
					t.Fatalf("JSON route %d frame %d still has %s", i, j, key)
				}
			}
		}
	}
}

func assertJSONCatalogHasIdentity(t *testing.T, document map[string]any) {
	t.Helper()
	funcs, _ := document["functions"].([]any)
	if len(funcs) == 0 {
		t.Fatal("functions catalog missing from JSON")
	}
	first, _ := funcs[0].(map[string]any)
	if first["function_name"] == nil || first["file_path"] == nil {
		t.Fatalf("catalog row missing identity: %#v", first)
	}
}
