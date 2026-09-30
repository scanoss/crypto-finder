// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"strings"
	"testing"
)

const evidenceSink = "net.crypto.CryptoSink.encrypt(): void"

// evidenceFixture is a root reaching a dependency's crypto function through
// an interface dispatch from AppEntry.alpha and, when direct is set, also
// through three exact calls from AppEntry.zeta.
func evidenceFixture(direct bool) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "com.acme.app.AppEntry.alpha(): void"}},
		ExternalCalls: []ExternalCall{{
			Caller: "com.acme.app.AppEntry.alpha(): void", TargetSignature: evidenceSink,
			Resolution: ResolutionInterfaceDispatch, DeclaredType: "net.crypto.Sink", MethodName: "encrypt", CallSite: 10,
		}},
	}
	sink := Fragment{
		Component: componentC,
		Functions: []Function{{Signature: evidenceSink}},
		CryptoOperations: []CryptoOperation{
			{Function: evidenceSink, FindingID: "f-sink", RuleID: "rule.aes"},
		},
	}
	if direct {
		root.Functions = append(root.Functions, Function{Signature: "com.acme.app.AppEntry.zeta(): void"})
		root.ExternalCalls = append(root.ExternalCalls, ExternalCall{
			Caller: "com.acme.app.AppEntry.zeta(): void", TargetSignature: "net.crypto.Codec.encode(): void",
			Resolution: ResolutionExact, MethodName: "encode", CallSite: 20,
		})
		sink.Functions = append(sink.Functions,
			Function{Signature: "net.crypto.Codec.encode(): void"},
			Function{Signature: "net.crypto.Codec.write(): void"})
		sink.InternalEdges = append(sink.InternalEdges,
			InternalEdge{
				Caller: "net.crypto.Codec.encode(): void", Callee: "net.crypto.Codec.write(): void",
				Resolution: ResolutionExact, MethodName: "write", CallSite: 30,
			},
			InternalEdge{
				Caller: "net.crypto.Codec.write(): void", Callee: evidenceSink,
				Resolution: ResolutionExact, MethodName: "encrypt", CallSite: 40,
			})
	}
	return componentA, DependencyGraph{componentA: {componentC}},
		map[ComponentKey]Fragment{componentA: root, componentC: sink}
}

func stitchedFindingWithBudget(t *testing.T, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, maxChains int) ExportFindingGraph {
	t.Helper()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true, MaxChains: maxChains})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1: %+v", len(cg.FindingGraphs), cg.FindingGraphs)
	}
	return cg.FindingGraphs[0]
}

// A budget of one chain goes to the route whose every call resolved
// statically, not to the shorter one through a dispatch, and the analysis
// says the best route is direct.
func TestStitch_KeepsTheDirectRouteFirst(t *testing.T) {
	t.Parallel()
	root, deps, fragments := evidenceFixture(true)
	fg := stitchedFindingWithBudget(t, root, deps, fragments, 1)
	if fg.Reachability != ReachabilityReachable {
		t.Fatalf("reachability = %q, want reachable", fg.Reachability)
	}
	if len(fg.CallChains) != 1 || !strings.Contains(fg.CallChains[0][0].FunctionName+fg.CallChains[0][0].FunctionKey, "zeta") {
		t.Fatalf("kept chain = %+v, want the direct route from AppEntry.zeta", fg.CallChains)
	}
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != RouteEvidenceDirect {
		t.Fatalf("analysis = %+v, want route_evidence direct", fg.Analysis)
	}
}

// With the dispatch route alone the finding stays reachable, rated dispatch.
func TestStitch_DispatchRouteReadsDispatchEvidence(t *testing.T) {
	t.Parallel()
	root, deps, fragments := evidenceFixture(false)
	fg := stitchedFindingWithBudget(t, root, deps, fragments, 4)
	if fg.Reachability != ReachabilityReachable {
		t.Fatalf("reachability = %q, want reachable through the dispatch", fg.Reachability)
	}
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != RouteEvidenceDispatch {
		t.Fatalf("analysis = %+v, want route_evidence dispatch", fg.Analysis)
	}
}

// A finding the root reaches only over a name_only edge reads name_only.
func TestStitch_NameOnlyRouteReadsNameOnlyEvidence(t *testing.T) {
	t.Parallel()
	root, deps, fragments := nameOnlySinkFixture(false)
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != RouteEvidenceNameOnly {
		t.Fatalf("analysis = %+v, want route_evidence name_only", fg.Analysis)
	}
}
