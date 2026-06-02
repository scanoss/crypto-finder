// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package equiv provides a semantic diff tool for schema-5.x callgraph exports.
// Tests verify all five table-driven scenarios from the SDD spec:
//
//	(a) identical A,B -> no divergences
//	(b) A has chain through a suppressed edge, absent from B -> no divergence (expected suppression)
//	(c) B has an extra chain not in A -> ExtraInB divergence
//	(d) a node field differs (non-ignored) -> NodeFieldMismatch
//	(e) an ignored field differs -> KnownDivergences, not failure
package equiv

import (
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// ---------------------------------------------------------------------------
// Helpers to build minimal CallgraphExportJSON fixtures
// ---------------------------------------------------------------------------

func node(fnName, canonicalSig string) ExportChainNodeJSON {
	return ExportChainNodeJSON{
		FunctionName:       fnName,
		CanonicalSignature: canonicalSig,
		ReturnType:         "void",
		FilePath:           "src/Foo.java",
	}
}

func appNodeWith(returnType, filePath string) ExportChainNodeJSON {
	return ExportChainNodeJSON{
		FunctionName:       "com.acme.App.entry",
		CanonicalSignature: "com.acme.App.entry(): void",
		ReturnType:         returnType,
		FilePath:           filePath,
	}
}

func chain(nodes ...ExportChainNodeJSON) []ExportChainNodeJSON {
	return nodes
}

func findingGraph(findingID string, chains ...[]ExportChainNodeJSON) ExportFindingGraphJSON {
	return ExportFindingGraphJSON{
		FindingID:  findingID,
		CallChains: chains,
	}
}

func export(graphs ...ExportFindingGraphJSON) CallgraphExportJSON {
	return CallgraphExportJSON{
		SchemaVersion: "5.3",
		FindingGraphs: graphs,
	}
}

// ---------------------------------------------------------------------------
// Suppression helpers
// ---------------------------------------------------------------------------

// suppressedEdge builds a SuppressedEdge that matches callerSig->method (arity
// is used by the oracle).
func suppressedEdge(callerSig, method string, arity int) graphfrag.SuppressedEdge {
	return graphfrag.SuppressedEdge{
		Caller: graphfrag.CallFrame{
			Signature: callerSig,
		},
		MethodName: method,
		Arity:      arity,
		Reason:     graphfrag.SuppressReasonNameOnly,
	}
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// TestCompare_Identical verifies that identical A and B produce no divergences.
func TestCompare_Identical(t *testing.T) {
	nodeA := node("com.acme.App.entry", "com.acme.App.entry(): void")
	nodeB := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-001",
		chain(nodeA, nodeB),
	))
	b := export(findingGraph("find-001",
		chain(nodeA, nodeB),
	))

	report := Compare(a, b, nil, Options{})

	if len(report.MissingInB) != 0 {
		t.Errorf("MissingInB = %v, want empty", report.MissingInB)
	}
	if len(report.ExtraInB) != 0 {
		t.Errorf("ExtraInB = %v, want empty", report.ExtraInB)
	}
	if len(report.NodeFieldMismatches) != 0 {
		t.Errorf("NodeFieldMismatches = %v, want empty", report.NodeFieldMismatches)
	}
	if len(report.EntryPointDivergences) != 0 {
		t.Errorf("EntryPointDivergences = %v, want empty", report.EntryPointDivergences)
	}
}

// TestCompare_SuppressedChainAbsentFromB verifies that a chain in A which
// traverses a suppressed edge is not reported as MissingInB. Since the chain is
// expected to be absent from B (it was suppressed), no regression is raised.
func TestCompare_SuppressedChainAbsentFromB(t *testing.T) {
	// A has a chain: caller -> nameOnly -> crypto
	caller := node("com.acme.App.call", "com.acme.App.call(): void")
	nameOnly := node("com.acme.Legacy.dispatch", "com.acme.Legacy.dispatch(): void")
	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-002",
		chain(caller, nameOnly, crypto),
	))
	// B does NOT have this chain (the suppressed edge was not traversed).
	b := export(findingGraph("find-002"))

	// The suppressed edge goes from "App.call" to method "dispatch" (arity 0).
	suppressed := []graphfrag.SuppressedEdge{
		suppressedEdge("com.acme.App.call", "dispatch", 0),
	}

	report := Compare(a, b, suppressed, Options{})

	// No regression: the absent chain was expected to be suppressed.
	if len(report.MissingInB) != 0 {
		t.Errorf("MissingInB = %v, want empty (chain was suppressed)", report.MissingInB)
	}
}

func TestCompare_SuppressedChainPresentInBIsExtra(t *testing.T) {
	caller := node("com.acme.App.call", "com.acme.App.call(): void")
	nameOnly := node("com.acme.Legacy.dispatch", "com.acme.Legacy.dispatch(): void")
	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-suppressed-extra",
		chain(caller, nameOnly, crypto),
	))
	b := export(findingGraph("find-suppressed-extra",
		chain(caller, nameOnly, crypto),
	))
	suppressed := []graphfrag.SuppressedEdge{
		suppressedEdge("com.acme.App.call", "dispatch", 0),
	}

	report := Compare(a, b, suppressed, Options{})

	if len(report.ExtraInB) != 1 {
		t.Fatalf("ExtraInB = %v, want the suppressed chain that persisted in B", report.ExtraInB)
	}
	if len(report.NodeFieldMismatches) != 0 {
		t.Fatalf("NodeFieldMismatches = %v, want no comparison for suppressed chain", report.NodeFieldMismatches)
	}
}

func TestCompare_SuppressedArityIgnoredWhenParameterTypesOmitted(t *testing.T) {
	caller := node("com.acme.App.call", "com.acme.App.call(): void")
	callee := node("com.acme.Legacy.dispatch", "com.acme.Legacy.dispatch(): void")
	callee.ParameterTypes = nil
	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-suppressed-omitted-arity",
		chain(caller, callee, crypto),
	))
	b := export(findingGraph("find-suppressed-omitted-arity"))
	suppressed := []graphfrag.SuppressedEdge{
		suppressedEdge("com.acme.App.call", "dispatch", 1),
	}

	report := Compare(a, b, suppressed, Options{})

	if len(report.MissingInB) != 0 {
		t.Fatalf("MissingInB = %v, want omitted parameter_types to allow arity suppression", report.MissingInB)
	}
}

// TestCompare_SuppressedChainAbsentFromB_Triangulation verifies that a chain
// NOT covered by any suppressed edge IS reported as MissingInB when absent from
// B. This forces the suppression oracle to actually discriminate.
func TestCompare_SuppressedChainAbsentFromB_Triangulation(t *testing.T) {
	entry := node("com.acme.App.entry", "com.acme.App.entry(): void")
	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-003",
		chain(entry, crypto),
	))
	// B is empty (chain not suppressed -> this is a real regression).
	b := export(findingGraph("find-003"))

	// No suppressed edges.
	report := Compare(a, b, nil, Options{})

	if len(report.MissingInB) == 0 {
		t.Error("MissingInB is empty, want the unsuppressed chain to be reported as missing")
	}
}

// TestCompare_ExtraInB verifies that a chain in B that does not exist in A is
// reported as ExtraInB.
func TestCompare_ExtraInB(t *testing.T) {
	// A has one chain.
	nodeA1 := node("com.acme.App.entry", "com.acme.App.entry(): void")
	nodeA2 := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	// B has that chain plus a phantom extra chain.
	nodeB1 := node("com.acme.App.extra", "com.acme.App.extra(): void")
	nodeB2 := node("com.acme.Crypto.hash", "com.acme.Crypto.hash(): void")

	a := export(findingGraph("find-004",
		chain(nodeA1, nodeA2),
	))
	b := export(findingGraph("find-004",
		chain(nodeA1, nodeA2), // exists in A
		chain(nodeB1, nodeB2), // extra — not in A
	))

	report := Compare(a, b, nil, Options{})

	if len(report.ExtraInB) == 0 {
		t.Error("ExtraInB is empty, want the phantom chain to be reported")
	}
	if len(report.MissingInB) != 0 {
		t.Errorf("MissingInB = %v, want empty", report.MissingInB)
	}
}

// TestCompare_NodeFieldMismatch verifies that a non-ignored node field
// difference is reported as a NodeFieldMismatch.
func TestCompare_NodeFieldMismatch(t *testing.T) {
	// Both A and B have the same chain key (by canonical_signature) but a different
	// return_type on the first node.
	nodeInA := appNodeWith("void", "App.java")
	nodeInB := appNodeWith("int", "App.java") // return_type differs

	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-005",
		chain(nodeInA, crypto),
	))
	b := export(findingGraph("find-005",
		chain(nodeInB, crypto),
	))

	report := Compare(a, b, nil, Options{})

	if len(report.NodeFieldMismatches) == 0 {
		t.Error("NodeFieldMismatches is empty, want a mismatch for return_type")
	}
	// Verify the mismatch describes the right field.
	found := false
	for _, m := range report.NodeFieldMismatches {
		if m.Field == "return_type" {
			found = true
			if m.AValue != "void" {
				t.Errorf("NodeFieldMismatch.AValue = %q, want void", m.AValue)
			}
			if m.BValue != "int" {
				t.Errorf("NodeFieldMismatch.BValue = %q, want int", m.BValue)
			}
		}
	}
	if !found {
		t.Errorf("no NodeFieldMismatch for field return_type; got %v", report.NodeFieldMismatches)
	}
}

// TestCompare_IgnoredFieldDifference verifies that a difference in an ignored
// field (e.g. file_path, which is in the default IgnoreFields list) goes into
// KnownDivergences, not NodeFieldMismatches.
func TestCompare_IgnoredFieldDifference(t *testing.T) {
	// file_path differs between A and B. Since file_path is in the default
	// IgnoreFields list (live vs stitched paths diverge), this should not be a
	// hard failure.
	nodeInA := appNodeWith("void", "src/main/App.java")
	nodeInB := appNodeWith("void", "/different/App.java")

	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-006",
		chain(nodeInA, crypto),
	))
	b := export(findingGraph("find-006",
		chain(nodeInB, crypto),
	))

	// Use default Options (file_path is ignored by default).
	report := Compare(a, b, nil, Options{})

	// No hard mismatch.
	if len(report.NodeFieldMismatches) != 0 {
		t.Errorf("NodeFieldMismatches = %v, want empty (file_path is ignored)", report.NodeFieldMismatches)
	}
	// But the divergence is recorded.
	if len(report.KnownDivergences) == 0 {
		t.Error("KnownDivergences is empty, want file_path difference to be recorded")
	}
}

// TestCompare_ExplicitIgnoreFields verifies that a caller-specified IgnoreFields
// entry suppresses mismatches for that field.
func TestCompare_ExplicitIgnoreFields(t *testing.T) {
	nodeInA := appNodeWith("void", "App.java")
	// return_type differs, but we will explicitly ignore it.
	nodeInB := appNodeWith("int", "App.java")

	crypto := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	a := export(findingGraph("find-007",
		chain(nodeInA, crypto),
	))
	b := export(findingGraph("find-007",
		chain(nodeInB, crypto),
	))

	report := Compare(a, b, nil, Options{IgnoreFields: []string{"return_type"}})

	if len(report.NodeFieldMismatches) != 0 {
		t.Errorf("NodeFieldMismatches = %v, want empty (return_type is ignored)", report.NodeFieldMismatches)
	}
	if len(report.KnownDivergences) == 0 {
		t.Error("KnownDivergences is empty, want return_type divergence to be recorded")
	}
}

// TestCompare_EntryPointIndexConsistency verifies that B's entry_point_index is
// checked against B's surviving chains.
func TestCompare_EntryPointIndexConsistency(t *testing.T) {
	nodeA := node("com.acme.App.entry", "com.acme.App.entry(): void")
	nodeB := node("com.acme.Crypto.encrypt", "com.acme.Crypto.encrypt(): void")

	// B has an entry_point_index that references a finding not present in any chain.
	phantom := ExportEntryPointJSON{
		Function:           "com.acme.App.phantom",
		CanonicalSignature: "com.acme.App.phantom(): void",
		ReachableFindings: []ExportReachableFindingJSON{
			{FindingID: "find-ghost", ChainDepth: 1},
		},
	}

	a := export(findingGraph("find-008", chain(nodeA, nodeB)))
	b := CallgraphExportJSON{
		SchemaVersion: "5.3",
		FindingGraphs: []ExportFindingGraphJSON{
			findingGraph("find-008", chain(nodeA, nodeB)),
		},
		EntryPointIndex: []ExportEntryPointJSON{phantom},
	}

	report := Compare(a, b, nil, Options{})

	if len(report.EntryPointDivergences) == 0 {
		t.Error("EntryPointDivergences is empty, want phantom entry point to be flagged")
	}
}
