// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
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
		SchemaVersion: "6.0",
		RootModule:    "com.acme:app",
		Ecosystem:     "java",
	}
	out := res.ToCallgraphExport(phase6Root, meta)
	if out.SchemaVersion == "" {
		t.Fatal("SchemaVersion is empty, want non-empty (e.g. 6.0)")
	}
}

// TestToCallgraphExport_NodeCountAndDependencyInfo asserts that:
//   - finding_graphs[0].call_chains[0] has the correct node count (3)
//   - the first node (root frame) has no dependency_info
//   - the second node (dep frame) has dependency_info.module == "net.crypto:lib"
func TestToCallgraphExport_NodeCountAndDependencyInfo(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
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
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
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

func TestToCallgraphExport_EntryCallIncludesCalleeSignatureTypes(t *testing.T) {
	res := &Result{
		Chains: []FindingChain{{
			FindingID: "find-entry-types",
			Symbol:    "javax.crypto.SecretKeyFactory.getInstance",
			Frames: []CallFrame{
				{
					Component: phase6Root,
					Signature: "com.acme.App.entry#0",
					Function: Function{
						Signature:          "com.acme.App.entry#0",
						FunctionName:       "com.acme.App.entry",
						CanonicalSignature: "com.acme.App.entry(): void",
						FilePath:           "App.java",
					},
				},
				{
					Component: phase6Dep1,
					Signature: "net.crypto.Lib.makeKey#1",
					Function: Function{
						Signature:          "net.crypto.Lib.makeKey#1",
						FunctionName:       "net.crypto.Lib.makeKey",
						CanonicalSignature: "net.crypto.Lib.makeKey(String): SecretKey",
						ReturnType:         "SecretKey",
						ParameterTypes:     []string{"String"},
						FilePath:           "Lib.java",
					},
					EntryCall: &CallSite{Line: 42},
				},
			},
		}},
	}

	out := res.ToCallgraphExport(phase6Root, ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"})
	entryCall := out.FindingGraphs[0].CallChains[0][1].EntryCall
	if entryCall == nil {
		t.Fatal("EntryCall is nil, want non-nil")
	}
	if entryCall.ReturnType != "SecretKey" {
		t.Fatalf("EntryCall.ReturnType = %q, want SecretKey", entryCall.ReturnType)
	}
	if len(entryCall.ParameterTypes) != 1 || entryCall.ParameterTypes[0] != "String" {
		t.Fatalf("EntryCall.ParameterTypes = %#v, want [String]", entryCall.ParameterTypes)
	}
}

// TestToCallgraphExport_CryptoCallOnLastNode asserts that the crypto_call on
// the terminal node equals the CryptoOperation's CryptoCall.
func TestToCallgraphExport_CryptoCallOnLastNode(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
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

func TestToCallgraphExport_PreservesStoredMatchedOperation(t *testing.T) {
	res := &Result{
		Chains: []FindingChain{{
			FindingID: "find-type-usage",
			Symbol:    "fallback.symbol",
			Frames: []CallFrame{{
				Component: phase6Root,
				Signature: "com.acme.App.entry#0",
				Function: Function{
					Signature:    "com.acme.App.entry#0",
					FunctionName: "com.acme.App.entry",
					FilePath:     "App.java",
				},
			}},
			CryptoOp: &CryptoOperation{
				MatchedOperation: &MatchedOp{
					Kind:       "type_usage",
					Symbol:     "java.security.cert.X509Certificate",
					Expression: "X509Certificate cert",
					Line:       17,
				},
			},
		}},
	}

	out := res.ToCallgraphExport(phase6Root, ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"})
	got := out.FindingGraphs[0].MatchedOperation
	if got == nil {
		t.Fatal("MatchedOperation is nil, want preserved operation")
	}
	if got.Kind != "type_usage" || got.Symbol != "java.security.cert.X509Certificate" ||
		got.Expression != "X509Certificate cert" || got.Line != 17 {
		t.Fatalf("MatchedOperation = %#v, want stored non-call operation", got)
	}
}

// TestToCallgraphExport_EmitsSupportingCallIDsFromCryptoOp asserts the served
// finding_graph carries the per-finding supporting->finding foreign key (6.1),
// sourced from the terminal CryptoOperation the stitcher populated. This is the
// value the mining service surfaces as the per-asset supporting_call_ids
// breadcrumb — it must ride through stitch, not be re-derived at serve time.
func TestToCallgraphExport_EmitsSupportingCallIDsFromCryptoOp(t *testing.T) {
	res := &Result{
		Chains: []FindingChain{{
			FindingID: "find-1",
			Symbol:    "javax.crypto.Cipher.doFinal",
			Frames: []CallFrame{{
				Component: phase6Root,
				Signature: "com.acme.App.entry#0",
				Function: Function{
					Signature:    "com.acme.App.entry#0",
					FunctionName: "com.acme.App.entry",
					FilePath:     "App.java",
				},
			}},
			CryptoOp: &CryptoOperation{
				SupportingCallIDs: []string{"sup_aaaa", "sup_bbbb"},
			},
		}},
	}

	out := res.ToCallgraphExport(phase6Root, ScanMeta{SchemaVersion: "6.1", RootModule: "com.acme:app", Ecosystem: "java"})
	if len(out.FindingGraphs) != 1 {
		t.Fatalf("want 1 finding graph, got %d", len(out.FindingGraphs))
	}
	got := out.FindingGraphs[0].SupportingCallIDs
	want := []string{"sup_aaaa", "sup_bbbb"}
	if len(got) != len(want) {
		t.Fatalf("supporting_call_ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("supporting_call_ids[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestToCallgraphExport_CryptoEntryPoints asserts that crypto_entry_points has one
// entry for this 3-frame chain with chain_depth=3 (len(chain) - pos=0 = 3).
func TestToCallgraphExport_CryptoEntryPoints(t *testing.T) {
	res := buildPhase6Result(t)
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	if len(out.CryptoEntryPoints) == 0 {
		t.Fatal("CryptoEntryPoints is empty, want at least one entry")
	}
	// Find the entry for the root entry function.
	var found *ExportEntryPoint
	for i := range out.CryptoEntryPoints {
		if out.CryptoEntryPoints[i].FunctionName == "com.acme.App.entry" {
			found = &out.CryptoEntryPoints[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no crypto_entry_points entry for com.acme.App.entry; got %#v", out.CryptoEntryPoints)
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
	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
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

func TestBuildCallgraphCryptoEntryPointsPropagatesSupportingCallsThroughChains(t *testing.T) {
	entry := ExportChainNode{FunctionKey: "com.acme.Api.entry#0", FunctionName: "com.acme.Api.entry"}
	terminal := ExportChainNode{FunctionKey: "com.acme.Service.hash#1", FunctionName: "com.acme.Service.hash"}
	points := buildCallgraphCryptoEntryPoints(
		[]ExportFindingGraph{{
			FindingID: "finding-1",
			MatchedOperation: &ExportMatchedOperation{
				Kind:   "call",
				Symbol: "com.password4j.Hash.withBcrypt",
				Line:   42,
			},
			SupportingCallIDs: []string{"support-1"},
			CallChains:        [][]ExportChainNode{{entry, terminal}},
		}},
		[]ExportSupportingCall{{
			SupportingID: "support-1",
			FunctionKey:  terminal.FunctionKey,
			FunctionName: terminal.FunctionName,
		}},
	)

	entryPoint := findExportEntryPointByFunctionKey(points, entry.FunctionKey)
	if entryPoint == nil {
		t.Fatalf("missing entry point %q: %#v", entry.FunctionKey, points)
	}
	if len(entryPoint.ReachableSupportingCalls) != 1 {
		t.Fatalf("entry reachable_supporting_calls = %#v, want support-1", entryPoint.ReachableSupportingCalls)
	}
	if got := entryPoint.ReachableSupportingCalls[0]; got.SupportingID != "support-1" || got.ChainDepth != 2 {
		t.Fatalf("entry reachable_supporting_calls[0] = %#v, want support-1 at depth 2", got)
	}
}

func findExportEntryPointByFunctionKey(points []ExportCryptoEntryPoint, key string) *ExportCryptoEntryPoint {
	for i := range points {
		if points[i].FunctionKey == key {
			return &points[i]
		}
	}
	return nil
}

// testFindingID mirrors the canonical finding_id formula exactly:
//
//	sha256(path + ":" + startLine + ":" + ruleID)[:8]
//
// where path = module@version/filePath when module+version are non-empty.
// This helper is duplicated (not imported) so the test pins equality to
// the live formula independently of production code.
func testFindingID(filePath string, startLine int, ruleID, module, version string) string {
	path := filePath
	if module != "" && version != "" {
		path = module + "@" + version + "/" + filePath
	}
	h := sha256.Sum256([]byte(path + ":" + strconv.Itoa(startLine) + ":" + ruleID))
	return hex.EncodeToString(h[:])[:8]
}

// buildPhase6FragmentsWithFilePath is like buildPhase6Fragments but adds
// FilePath and StartLine to the CryptoOperation so the finding_id recompute
// test has deterministic inputs.
func buildPhase6FragmentsWithFilePath() map[ComponentKey]Fragment {
	frags := buildPhase6Fragments()
	dep := frags[phase6Dep1]
	dep.CryptoOperations[0].FilePath = "Lib.java"
	dep.CryptoOperations[0].StartLine = 30
	frags[phase6Dep1] = dep
	return frags
}

// TestToCallgraphExport_DepFindingIDPrefixed asserts that for a dep-component
// crypto op, the emitted finding_id equals sha256(M@V/path:line:rule)[:8] and
// the terminal node's file_path equals M@V/path (the prefixed form). This
// mirrors the live `crypto-finder scan --scan-dependencies` behavior
// the canonical finding_id formula.
func TestToCallgraphExport_DepFindingIDPrefixed(t *testing.T) {
	frags := buildPhase6FragmentsWithFilePath()
	deps := DependencyGraph{phase6Root: {phase6Dep1}}
	res, err := Stitch(phase6Root, deps, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains = %d, want 1", len(res.Chains))
	}

	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]

	// The crypto op belongs to phase6Dep1 (module "net.crypto:lib", version "2.0.0").
	// Expected finding_id: sha256("net.crypto:lib@2.0.0/Lib.java:30:java.crypto.cipher.getinstance")[:8]
	wantFindingID := testFindingID("Lib.java", 30, "java.crypto.cipher.getinstance", "net.crypto:lib", "2.0.0")
	if fg.FindingID != wantFindingID {
		t.Errorf("FindingGraph.FindingID = %q, want %q (dep-prefixed)", fg.FindingID, wantFindingID)
	}

	// The terminal node's file_path must be prefixed.
	chain := fg.CallChains[0]
	last := chain[len(chain)-1]
	wantFilePath := "net.crypto:lib@2.0.0/Lib.java"
	if last.FilePath != wantFilePath {
		t.Errorf("terminal node FilePath = %q, want %q", last.FilePath, wantFilePath)
	}
}

// TestToCallgraphExport_RootFindingIDUnprefixed asserts that for a root-component
// crypto op (direct finding), the finding_id and file_path are NOT prefixed.
func TestToCallgraphExport_RootFindingIDUnprefixed(t *testing.T) {
	// Build a single-component closure: root has a crypto op on its own function.
	rootFilePath := "App.java"
	rootStartLine := 5
	rootRuleID := "java.crypto.cipher.getinstance"

	rootFrag := Fragment{
		Component: phase6Root,
		Module:    "com.acme:app",
		Functions: []Function{
			{
				Signature:          "com.acme.App.doEncrypt#0",
				FunctionName:       "com.acme.App.doEncrypt",
				CanonicalSignature: "com.acme.App.doEncrypt(): void",
				FilePath:           rootFilePath,
				StartLine:          rootStartLine,
			},
		},
		CryptoOperations: []CryptoOperation{
			{
				Function:  "com.acme.App.doEncrypt#0",
				FindingID: "rootfid1",
				RuleID:    rootRuleID,
				Symbol:    "javax.crypto.Cipher.getInstance",
				FilePath:  rootFilePath,
				StartLine: rootStartLine,
				CryptoCall: &CryptoCall{
					FunctionName: "javax.crypto.Cipher.getInstance",
					Line:         rootStartLine,
				},
				MatchedOperation: &MatchedOp{Kind: "call", Symbol: "javax.crypto.Cipher.getInstance"},
			},
		},
	}

	res, err := Stitch(phase6Root, DependencyGraph{}, map[ComponentKey]Fragment{phase6Root: rootFrag})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains = %d, want 1", len(res.Chains))
	}

	meta := ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"}
	out := res.ToCallgraphExport(phase6Root, meta)

	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]

	// Root component: no prefix, so finding_id = sha256(filePath:line:rule)[:8]
	wantFindingID := testFindingID(rootFilePath, rootStartLine, rootRuleID, "", "")
	if fg.FindingID != wantFindingID {
		t.Errorf("FindingGraph.FindingID = %q, want %q (unprefixed root)", fg.FindingID, wantFindingID)
	}

	// Terminal node's file_path must NOT be prefixed.
	chain := fg.CallChains[0]
	last := chain[len(chain)-1]
	if last.FilePath != rootFilePath {
		t.Errorf("terminal node FilePath = %q, want %q (unprefixed)", last.FilePath, rootFilePath)
	}
}

// TestCallgraphSchemaVersion_Is66 pins the canonical callgraph schema version
// at 6.6 — the contract change that serializes ambiguous forward dispatch. The bump
// is unconditional: it advances regardless of whether any given export
// actually emits the new fields (see package doc on CallgraphSchemaVersion).
func TestCallgraphSchemaVersion_Is66(t *testing.T) {
	t.Parallel()

	if CallgraphSchemaVersion != "6.6" {
		t.Fatalf("CallgraphSchemaVersion = %q, want %q", CallgraphSchemaVersion, "6.6")
	}
}
