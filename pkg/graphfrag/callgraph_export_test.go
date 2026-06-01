// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

// hand-built 3-component closure used in Phase 6 tests:
//
//	compRoot: rootEntry() --[exact external, entryCall line=10]--> compDep1: bridge()
//	compDep1: bridge()   --[exact internal, entryCall line=20]--> compDep1: encrypt()
//	               encrypt() has a crypto op with CryptoCall + MatchedOperation
//
// compRoot is the root (no dependency_info on root frames).
// compDep1 is the dependency (dependency_info.module = "net.crypto:lib").

var (
	phase6Root = ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	phase6Dep1 = ComponentKey{Purl: "pkg:maven/net.crypto/lib", Version: "2.0.0"}
)

func buildPhase6Fragments() map[ComponentKey]Fragment {
	entryCall10 := &CallSite{
		Line: 10,
		Parameters: []Parameter{
			{ParameterIndex: 0, Type: "byte[]", VariableName: "key"},
		},
	}
	entryCall20 := &CallSite{
		Line: 20,
		Parameters: []Parameter{
			{ParameterIndex: 0, Type: "byte[]", VariableName: "data"},
		},
	}

	return map[ComponentKey]Fragment{
		phase6Root: {
			Component: phase6Root,
			Module:    "com.acme:app",
			Functions: []Function{
				{
					Signature:          "com.acme.App.entry#0",
					FunctionName:       "com.acme.App.entry",
					CanonicalSignature: "com.acme.App.entry(): void",
					ReturnType:         "void",
					Visibility:         "public",
					OwnerVisibility:    "public",
					FilePath:           "App.java",
					StartLine:          5,
				},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.App.entry#0",
					TargetSignature: "net.crypto.Lib.bridge#0",
					Resolution:      ResolutionExact,
					EntryCall:       entryCall10,
				},
			},
		},
		phase6Dep1: {
			Component: phase6Dep1,
			Module:    "net.crypto:lib",
			Functions: []Function{
				{
					Signature:          "net.crypto.Lib.bridge#0",
					FunctionName:       "net.crypto.Lib.bridge",
					CanonicalSignature: "net.crypto.Lib.bridge(): void",
					ReturnType:         "void",
					Visibility:         "public",
					OwnerVisibility:    "public",
					FilePath:           "Lib.java",
					StartLine:          10,
				},
				{
					Signature:          "net.crypto.Lib.encrypt#0",
					FunctionName:       "net.crypto.Lib.encrypt",
					CanonicalSignature: "net.crypto.Lib.encrypt(): void",
					ReturnType:         "void",
					Visibility:         "public",
					OwnerVisibility:    "public",
					FilePath:           "Lib.java",
					StartLine:          25,
				},
			},
			InternalEdges: []InternalEdge{
				{
					Caller:     "net.crypto.Lib.bridge#0",
					Callee:     "net.crypto.Lib.encrypt#0",
					Resolution: ResolutionExact,
					EntryCall:  entryCall20,
				},
			},
			CryptoOperations: []CryptoOperation{
				{
					Function:  "net.crypto.Lib.encrypt#0",
					FindingID: "find-phase6",
					RuleID:    "java.crypto.cipher.getinstance",
					Symbol:    "javax.crypto.Cipher.getInstance",
					CryptoCall: &CryptoCall{
						FunctionName:       "javax.crypto.Cipher.getInstance",
						CanonicalSignature: "javax.crypto.Cipher.getInstance(String): Cipher",
						ReturnType:         "Cipher",
						ParameterTypes:     []string{"String"},
						Line:               30,
					},
					MatchedOperation: &MatchedOp{
						Kind:   "call",
						Symbol: "javax.crypto.Cipher.getInstance",
					},
				},
			},
		},
	}
}

// buildPhase6Result produces a stitched Result for the phase 6 test closure.
func buildPhase6Result(t *testing.T) *Result {
	t.Helper()
	fragments := buildPhase6Fragments()
	deps := DependencyGraph{
		phase6Root: {phase6Dep1},
	}
	res, err := Stitch(phase6Root, deps, fragments)
	if err != nil {
		t.Fatalf("buildPhase6Result Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("buildPhase6Result: chains = %d, want 1", len(res.Chains))
	}
	return res
}

// TestToCallgraphExport_SchemaVersion asserts that the exported struct carries a
// non-empty schema_version field.
func TestToCallgraphExport_SchemaVersion(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{
		SchemaVersion: "5.3",
		RootModule:    "com.acme:app",
		Ecosystem:     "java",
	}
	out := res.ToCallgraphExport(phase6Root, meta)
	if out.SchemaVersion == "" {
		t.Fatal("SchemaVersion is empty, want non-empty (e.g. 5.3)")
	}
}

// TestToCallgraphExport_NodeCountAndDependencyInfo asserts that:
//   - finding_graphs[0].call_chains[0] has the correct node count (3)
//   - the first node (root frame) has no dependency_info
//   - the second node (dep frame) has dependency_info.module == "net.crypto:lib"
func TestToCallgraphExport_NodeCountAndDependencyInfo(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "5.3", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]
	if len(fg.CallChains) != 1 {
		t.Fatalf("CallChains len = %d, want 1", len(fg.CallChains))
	}
	chain := fg.CallChains[0]
	if len(chain) != 3 {
		t.Fatalf("chain node count = %d, want 3", len(chain))
	}

	// Root frame: no dependency_info.
	node0 := chain[0]
	if node0.DependencyInfo != nil {
		t.Errorf("node[0] (root) DependencyInfo = %#v, want nil", node0.DependencyInfo)
	}

	// Dep frame: dependency_info.module == the dep fragment's module.
	node1 := chain[1]
	if node1.DependencyInfo == nil {
		t.Fatal("node[1] (dep) DependencyInfo is nil, want non-nil")
	}
	if node1.DependencyInfo.Module != "net.crypto:lib" {
		t.Errorf("node[1].DependencyInfo.Module = %q, want net.crypto:lib", node1.DependencyInfo.Module)
	}
}

// TestToCallgraphExport_EntryCallOnFrame1 asserts that the entry_call on node[1]
// structurally matches the CallSite from frame[1].
func TestToCallgraphExport_EntryCallOnFrame1(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "5.3", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	chain := out.FindingGraphs[0].CallChains[0]
	node1 := chain[1]
	if node1.EntryCall == nil {
		t.Fatal("node[1].EntryCall is nil, want non-nil")
	}
	if node1.EntryCall.Line != 10 {
		t.Errorf("node[1].EntryCall.Line = %d, want 10", node1.EntryCall.Line)
	}
	if len(node1.EntryCall.Parameters) != 1 {
		t.Fatalf("node[1].EntryCall.Parameters len = %d, want 1", len(node1.EntryCall.Parameters))
	}
	if node1.EntryCall.Parameters[0].VariableName != "key" {
		t.Errorf("node[1].EntryCall.Parameters[0].VariableName = %q, want key", node1.EntryCall.Parameters[0].VariableName)
	}
}

// TestToCallgraphExport_CryptoCallOnLastNode asserts that the crypto_call on
// the terminal node equals the CryptoOperation's CryptoCall.
func TestToCallgraphExport_CryptoCallOnLastNode(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "5.3", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	chain := out.FindingGraphs[0].CallChains[0]
	last := chain[len(chain)-1]
	if last.CryptoCall == nil {
		t.Fatal("last node CryptoCall is nil, want non-nil")
	}
	if last.CryptoCall.FunctionName != "javax.crypto.Cipher.getInstance" {
		t.Errorf("CryptoCall.FunctionName = %q", last.CryptoCall.FunctionName)
	}
}

// TestToCallgraphExport_EntryPointIndex asserts that entry_point_index has one
// entry for this 3-frame chain with chain_depth=3 (len(chain) - pos=0 = 3).
func TestToCallgraphExport_EntryPointIndex(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "5.3", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	if len(out.EntryPointIndex) == 0 {
		t.Fatal("EntryPointIndex is empty, want at least one entry")
	}
	// Find the entry for the root entry function.
	var found *ExportEntryPoint
	for i := range out.EntryPointIndex {
		if out.EntryPointIndex[i].Function == "com.acme.App.entry" {
			found = &out.EntryPointIndex[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no entry_point_index entry for com.acme.App.entry; got %#v", out.EntryPointIndex)
	}
	if len(found.ReachableFindings) == 0 {
		t.Fatal("ReachableFindings is empty, want 1 finding")
	}
	// chain_depth for the root frame (pos=0) is len(chain)-0 = 3.
	wantDepth := 3
	if found.ReachableFindings[0].ChainDepth != wantDepth {
		t.Errorf("ReachableFindings[0].ChainDepth = %d, want %d", found.ReachableFindings[0].ChainDepth, wantDepth)
	}
}

// TestToCallgraphExport_NilEntryCallEmitsNoField asserts that a frame with no
// EntryCall produces a node without the entry_call JSON field.
func TestToCallgraphExport_NilEntryCallEmitsNoField(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "5.3", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	// node[0] is the root frame and has no EntryCall.
	chain := out.FindingGraphs[0].CallChains[0]
	node0 := chain[0]
	if node0.EntryCall != nil {
		t.Errorf("node[0].EntryCall = %#v, want nil", node0.EntryCall)
	}

	// Marshal and verify no "entry_call" key in the first node's JSON.
	b, err := json.Marshal(node0)
	if err != nil {
		t.Fatalf("marshal node[0]: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal node[0] json: %v", err)
	}
	if _, ok := raw["entry_call"]; ok {
		t.Error("node[0] JSON contains entry_call field, want omitted")
	}
}
