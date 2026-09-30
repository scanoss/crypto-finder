// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// nameOnlySinkFixture is the root calling a dependency's crypto function
// through a name_only edge, and, when typed is set, also through an exact one
// from a second function.
func nameOnlySinkFixture(typed bool) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{
			{Signature: "com.acme.app.AppEntry.entry(): void"},
			{Signature: "com.acme.app.AppEntry.other(): void"},
		},
		ExternalCalls: []ExternalCall{{
			Caller: "com.acme.app.AppEntry.entry(): void", TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
			Resolution: ResolutionNameOnly, MethodName: "encrypt", CallSite: 10,
		}},
	}
	if typed {
		root.ExternalCalls = append(root.ExternalCalls, ExternalCall{
			Caller: "com.acme.app.AppEntry.other(): void", TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
			Resolution: ResolutionExact, MethodName: "encrypt", CallSite: 20,
		})
	}
	sink := Fragment{
		Component: componentC,
		Functions: []Function{{Signature: "net.crypto.CryptoSink.encrypt(): void"}},
		CryptoOperations: []CryptoOperation{
			{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "f-sink", RuleID: "rule.aes"},
		},
	}
	return componentA, DependencyGraph{componentA: {componentC}},
		map[ComponentKey]Fragment{componentA: root, componentC: sink}
}

// onlyStitchedFinding stitches on the serving path and returns the one
// finding graph the fixture holds.
func onlyStitchedFinding(t *testing.T, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) ExportFindingGraph {
	t.Helper()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1: %+v", len(cg.FindingGraphs), cg.FindingGraphs)
	}
	return cg.FindingGraphs[0]
}

// A finding the root reaches only through a name_only edge says why it is
// unknown, the way the live export does.
func TestStitch_NameOnlyRouteReadsUnresolvedDispatch(t *testing.T) {
	t.Parallel()
	root, deps, fragments := nameOnlySinkFixture(false)
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("reachability = %q, reason = %q; want %q, %q",
			fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// One typed route keeps the finding reachable and gives it no reason.
func TestStitch_TypedRouteBesideNameOnlyStaysReachable(t *testing.T) {
	t.Parallel()
	root, deps, fragments := nameOnlySinkFixture(true)
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Reachability != ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("reachability = %q, reason = %q; want %q and none",
			fg.Reachability, fg.UnresolvedReason, ReachabilityReachable)
	}
}

// A finding unknown for another cause keeps no reason: an unknown-resolution
// edge is not a name_only guess.
func TestStitch_UnknownEdgeGivesNoDispatchReason(t *testing.T) {
	t.Parallel()
	root, deps, fragments := nameOnlySinkFixture(false)
	f := fragments[root]
	f.ExternalCalls[0].Resolution = ResolutionUnknown
	fragments[root] = f
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != "" {
		t.Fatalf("reachability = %q, reason = %q; want %q and none",
			fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown)
	}
}

// composeFixtureWithLeg gives composeFixture's dependency the internal edge
// from its entry point to the crypto function, with the given resolution. The
// mine-time index records the finding either way.
func composeFixtureWithLeg(resolution ResolutionKind) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root, deps, fragments := composeFixture()
	dep := deps[root][0]
	f := fragments[dep]
	f.Functions = append(f.Functions, Function{
		Signature: "org.example.client.(Ssl).init#0", FunctionName: "org.example.client.Ssl.init",
	})
	f.InternalEdges = append(f.InternalEdges, InternalEdge{
		Caller: "org.example.client.(Client).<init>#1$Map", Callee: "org.example.client.(Ssl).init#0",
		Resolution: resolution, MethodName: "init", CallSite: 12,
	})
	fragments[dep] = f
	return root, deps, fragments
}

// The dependency's mine-time index counts routes over name_only edges too. A
// finding it reaches only through one must not be upgraded to reachable.
func TestStitch_ComposedIndexOverNameOnlyLegReadsUnresolvedDispatch(t *testing.T) {
	t.Parallel()
	root, deps, fragments := composeFixtureWithLeg(ResolutionNameOnly)
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("reachability = %q, reason = %q; want %q, %q",
			fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// With the same leg typed, the finding stays reachable.
func TestStitch_ComposedIndexOverTypedLegStaysReachable(t *testing.T) {
	t.Parallel()
	root, deps, fragments := composeFixtureWithLeg(ResolutionExact)
	fg := onlyStitchedFinding(t, root, deps, fragments)
	if fg.Reachability != ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("reachability = %q, reason = %q; want %q and none",
			fg.Reachability, fg.UnresolvedReason, ReachabilityReachable)
	}
}
