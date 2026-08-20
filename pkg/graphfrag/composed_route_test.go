// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"testing"
)

// routeFixture is composeFixture with both legs of the cross-component route
// named: the root's stitched frames reach the dependency's entry point, and the
// dependency's fragment records how that entry point gets to the crypto.
//
//	Factory.create -> Factory.Extended.<init> -> Client.<init>   (stitched)
//	Client.<init> -> Client.handshake -> Ssl.init                (mine-time route)
//
// The two legs share Client.<init>, which is what the join has to reconcile.
func routeFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root, deps, fragments := composeFixture()

	dep := ComponentKey{Purl: "pkg:maven/org.example/client", Version: "2.0.0"}
	depFragment := fragments[dep]
	depFragment.Functions = append(depFragment.Functions,
		Function{
			Signature: "org.example.client.(Client).handshake#0", FunctionName: "org.example.client.Client.handshake",
			CanonicalSignature: "org.example.client.Client.handshake(): void", Visibility: "private", OwnerVisibility: "public",
		},
		Function{
			Signature: "org.example.client.(Ssl).init#0", FunctionName: "org.example.client.Ssl.init",
			CanonicalSignature: "org.example.client.Ssl.init(): void", Visibility: "private", OwnerVisibility: "public",
		},
	)
	depFragment.CryptoEntryPoints[0].ReachableFindings[0].Route = []string{
		"org.example.client.(Client).<init>#1$Map",
		"org.example.client.(Client).handshake#0",
		"org.example.client.(Ssl).init#0",
	}
	depFragment.CryptoEntryPoints[0].ReachableFindings[0].ChainDepth = 3
	fragments[dep] = depFragment

	return root, deps, fragments
}

func stitchRouteFixture(t *testing.T, sig string) CallgraphExport {
	t.Helper()
	root, deps, fragments := routeFixture()
	var sigs []string
	if sig != "" {
		sigs = []string{sig}
	}
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: sigs,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	return res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java", RootModule: "org.example.wrapper"})
}

// TestComposedRouteSpansTheBoundary is the point of the whole change: a chain
// filtered by the consumer's own call reaches the crypto instead of stopping at
// the frame that holds it.
func TestComposedRouteSpansTheBoundary(t *testing.T) {
	t.Parallel()

	cg := stitchRouteFixture(t, "org.example.wrapper.Factory.create(): Client")
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	fg := cg.FindingGraphs[0]
	if len(fg.CallChains) != 1 {
		t.Fatalf("call chains = %d, want 1", len(fg.CallChains))
	}
	chain := fg.CallChains[0]

	want := []string{
		"org.example.wrapper.(Factory).create#0",
		"org.example.wrapper.(Factory.Extended).<init>#1",
		"org.example.client.(Client).<init>#1$Map",
		"org.example.client.(Client).handshake#0",
		"org.example.client.(Ssl).init#0",
	}
	if len(chain) != len(want) {
		var got []string
		for _, n := range chain {
			got = append(got, n.FunctionKey)
		}
		t.Fatalf("chain = %v, want %v", got, want)
	}
	for i, key := range want {
		if chain[i].FunctionKey != key {
			t.Errorf("frame %d = %q, want %q", i, chain[i].FunctionKey, key)
		}
	}

	// The shared frame appears once. Both legs name it, and a chain that
	// repeated it would claim a call from a function to itself.
	seen := map[string]int{}
	for _, n := range chain {
		seen[n.FunctionKey]++
	}
	for key, n := range seen {
		if n > 1 {
			t.Errorf("frame %q appears %d times, want once", key, n)
		}
	}

	if fg.Reachability != ReachabilityReachable {
		t.Errorf("reachability = %q, want %q", fg.Reachability, ReachabilityReachable)
	}
	// Partial however whole the route reads: its dependency leg was recorded
	// under that dependency's own chain cap.
	if fg.Analysis == nil || fg.Analysis.CallChains != AnalysisPartial {
		t.Errorf("analysis = %+v, want call_chains %q", fg.Analysis, AnalysisPartial)
	}
}

// TestComposedRouteFallsBackWithoutADependencyLeg pins the degradation: a
// fragment that named no route still answers, with the single frame holding the
// crypto. Half a route would place the crypto somewhere it is not.
func TestComposedRouteFallsBackWithoutADependencyLeg(t *testing.T) {
	t.Parallel()

	// composeFixture is routeFixture without the mine-time route.
	root, deps, fragments := composeFixture()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"org.example.wrapper.Factory.create(): Client"},
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java", RootModule: "org.example.wrapper"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	if got := len(cg.FindingGraphs[0].CallChains[0]); got != 1 {
		t.Errorf("chain has %d frames, want the single crypto-holding frame", got)
	}
	if cg.FindingGraphs[0].Reachability != ReachabilityReachable {
		t.Errorf("reachability = %q, want the verdict regardless", cg.FindingGraphs[0].Reachability)
	}
}

// TestComposedRouteRejectsAMismatchedJoin: the two legs must actually meet. A
// dependency route starting somewhere else describes a different journey, and
// splicing the two would invent a call.
func TestComposedRouteRejectsAMismatchedJoin(t *testing.T) {
	t.Parallel()

	root, deps, fragments := routeFixture()
	dep := ComponentKey{Purl: "pkg:maven/org.example/client", Version: "2.0.0"}
	depFragment := fragments[dep]
	route := depFragment.CryptoEntryPoints[0].ReachableFindings[0].Route
	// Head no longer the entry point the stitched leg arrives at.
	depFragment.CryptoEntryPoints[0].ReachableFindings[0].Route =
		append([]string{"org.example.client.(Client).handshake#0"}, route[1:]...)
	fragments[dep] = depFragment

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"org.example.wrapper.Factory.create(): Client"},
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java", RootModule: "org.example.wrapper"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	if got := len(cg.FindingGraphs[0].CallChains[0]); got != 1 {
		t.Errorf("chain has %d frames, want the fallback: the legs do not meet", got)
	}
}

// TestComposedRouteAnnotatesEachFrame: a route is only evidence if a reader can
// tell a certain hop from an inferred one. The head carries none, since no call
// arrives at it.
func TestComposedRouteAnnotatesEachFrame(t *testing.T) {
	t.Parallel()

	cg := stitchRouteFixture(t, "org.example.wrapper.Factory.create(): Client")
	chain := cg.FindingGraphs[0].CallChains[0]

	if chain[0].EntryResolution != "" {
		t.Errorf("head frame resolution = %q, want empty: no call arrives at it", chain[0].EntryResolution)
	}
	// The stitched leg is exact in this fixture; the dependency leg's own hops
	// are not in the stitched adjacency and report nothing rather than borrowing
	// a resolution they were not given.
	if got := chain[1].EntryResolution; got != string(ResolutionExact) {
		t.Errorf("frame 1 resolution = %q, want %q", got, ResolutionExact)
	}
	if got := chain[2].EntryResolution; got != string(ResolutionExact) {
		t.Errorf("frame 2 resolution = %q, want %q", got, ResolutionExact)
	}
}

// TestUnfilteredRouteUnchanged: the default path must not move. The composed
// route only ever supplies a chain a restricted enumeration could not produce.
func TestUnfilteredRouteUnchanged(t *testing.T) {
	t.Parallel()

	withRoute := stitchRouteFixture(t, "")

	root, deps, fragments := composeFixture()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	withoutRoute := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java", RootModule: "org.example.wrapper"})

	if len(withRoute.FindingGraphs) != len(withoutRoute.FindingGraphs) {
		t.Fatalf("finding graphs = %d with a route, %d without",
			len(withRoute.FindingGraphs), len(withoutRoute.FindingGraphs))
	}
	for i := range withRoute.FindingGraphs {
		a, b := withRoute.FindingGraphs[i], withoutRoute.FindingGraphs[i]
		if len(a.CallChains) != len(b.CallChains) {
			t.Errorf("finding %s: chains = %d with a route, %d without",
				a.FindingID, len(a.CallChains), len(b.CallChains))
		}
		if a.Reachability != b.Reachability {
			t.Errorf("finding %s: reachability %q vs %q", a.FindingID, a.Reachability, b.Reachability)
		}
	}
}
