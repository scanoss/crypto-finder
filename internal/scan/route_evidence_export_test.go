// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// evidenceGraph builds call graphs whose routes to one library crypto
// function org.lib.(Sink).hash differ in how their calls were resolved.
type evidenceGraph struct {
	graph  *callgraph.CallGraph
	target *callgraph.FunctionDecl
}

func newEvidenceGraph() *evidenceGraph {
	g := &evidenceGraph{graph: &callgraph.CallGraph{
		Functions:       map[string]*callgraph.FunctionDecl{},
		Callers:         map[string][]string{},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}}
	g.target = g.add("org.lib", "Sink", "hash#0", 1000)
	return g
}

func (g *evidenceGraph) add(pkg, typ, name string, line int) *callgraph.FunctionDecl {
	id := callgraph.FunctionID{Package: pkg, Type: typ, Name: name}
	decl := &callgraph.FunctionDecl{ID: id, FilePath: typ + ".java", StartLine: line, EndLine: line + 50}
	g.graph.Functions[id.String()] = decl
	return decl
}

// link records a call from caller to callee at line, classified as kind.
func (g *evidenceGraph) link(caller, callee *callgraph.FunctionDecl, line int, kind callgraph.EdgeKind) {
	caller.Calls = append(caller.Calls, callgraph.FunctionCall{Callee: callee.ID, Line: line})
	key := callee.ID.String()
	seen := false
	for _, existing := range g.graph.Callers[key] {
		seen = seen || existing == caller.ID.String()
	}
	if !seen {
		g.graph.Callers[key] = append(g.graph.Callers[key], caller.ID.String())
	}
	res := callgraph.EdgeResolution{Kind: kind, CallSite: line, DeclaredType: "org.lib.Parser"}
	g.graph.EdgeResolutions[callgraph.EdgeResolutionKey(caller.ID.String(), callee.ID.String(), res)] = res
}

// guessedRoute adds com.app.(Alpha).run -> Sink.hash through a name_only
// call: the shortest route, and the first root in name order.
func (g *evidenceGraph) guessedRoute() *callgraph.FunctionDecl {
	alpha := g.add("com.app", "Alpha", "run#0", 10)
	g.link(alpha, g.target, 11, callgraph.EdgeKindNameOnly)
	return alpha
}

// dispatchRoute adds com.app.(Beta).run -> org.lib.(Pool).submit ->
// org.lib.(Worker).run -> Sink.hash, the second call an interface dispatch.
func (g *evidenceGraph) dispatchRoute() *callgraph.FunctionDecl {
	beta := g.add("com.app", "Beta", "run#0", 20)
	pool := g.add("org.lib", "Pool", "submit#0", 200)
	worker := g.add("org.lib", "Worker", "run#0", 300)
	g.link(beta, pool, 21, callgraph.EdgeKindExact)
	g.link(pool, worker, 201, callgraph.EdgeKindInterfaceDispatch)
	g.link(worker, g.target, 301, callgraph.EdgeKindExact)
	return beta
}

// directRoute adds com.app.(Gamma).run -> three exact library frames ->
// Sink.hash: the longest route, and the last root in name order.
func (g *evidenceGraph) directRoute() {
	gamma := g.add("com.app", "Gamma", "run#0", 30)
	a := g.add("org.lib", "Codec", "encode#0", 400)
	b := g.add("org.lib", "Codec", "write#0", 500)
	c := g.add("org.lib", "Codec", "flush#0", 600)
	g.link(gamma, a, 31, callgraph.EdgeKindExact)
	g.link(a, b, 401, callgraph.EdgeKindExact)
	g.link(b, c, 501, callgraph.EdgeKindExact)
	g.link(c, g.target, 601, callgraph.EdgeKindExact)
}

func (g *evidenceGraph) context(maxChains int) *exportBuildContext {
	ctx := &exportBuildContext{
		graph:                   g.graph,
		packageSeparator:        ".",
		userPackages:            map[string]bool{"com.app": true},
		fragmentEdgeResolutions: indexFragmentEdgeResolutions(g.graph),
		maxChainsBudget:         maxChains,
	}
	ensureCallChainCaches(ctx)
	ctx.callChainRemainingUses[g.target.ID.String()] = 1
	return ctx
}

func chainRoots(chains [][]callGraphChainNode) []string {
	roots := make([]string, 0, len(chains))
	for _, chain := range chains {
		roots = append(roots, chain[0].FunctionName)
	}
	return roots
}

func chainHasResolution(chain []callGraphChainNode, resolution string) bool {
	for i := range chain {
		if chain[i].EntryResolution == resolution {
			return true
		}
	}
	return false
}

// TestBuildFindingGraph_KeepsTheStrongestRouteFirst: three routes reach the
// crypto, a name_only guess (shortest), a dispatch route and a direct route
// (longest). A budget of one chain used to go to the shortest route, so the
// finding read reachable with its only chain resting on a guess. The direct
// route now comes first, then the dispatch route, then the guess.
func TestBuildFindingGraph_KeepsTheStrongestRouteFirst(t *testing.T) {
	t.Parallel()
	g := newEvidenceGraph()
	g.guessedRoute()
	g.dispatchRoute()
	g.directRoute()

	one := buildDepthFindingGraph(g.context(1), g.target)
	if one.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable", one.Reachability)
	}
	if got := chainRoots(one.CallChains); len(got) != 1 || got[0] != "com.app.Gamma.run" {
		t.Fatalf("kept roots with a budget of 1 = %v, want the direct route from com.app.Gamma.run", got)
	}
	if one.Analysis == nil || one.Analysis.RouteEvidence != graphfrag.RouteEvidenceDirect {
		t.Fatalf("Analysis = %+v, want route_evidence direct", one.Analysis)
	}

	all := buildDepthFindingGraph(g.context(3), g.target)
	want := []string{"com.app.Gamma.run", "com.app.Beta.run", "com.app.Alpha.run"}
	got := chainRoots(all.CallChains)
	if len(got) != len(want) {
		t.Fatalf("kept roots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("kept roots = %v, want %v: strongest evidence first", got, want)
		}
	}
}

// TestBuildFindingGraph_DispatchOnlyRouteReadsReachableWithDispatchEvidence:
// the only route free of a name_only guess needs an interface dispatch. The
// finding stays reachable, says its best route is dispatch, and keeps that
// route ahead of the shorter guess, with the dispatch hop named on its frame.
func TestBuildFindingGraph_DispatchOnlyRouteReadsReachableWithDispatchEvidence(t *testing.T) {
	t.Parallel()
	g := newEvidenceGraph()
	g.guessedRoute()
	g.dispatchRoute()

	fg := buildDepthFindingGraph(g.context(1), g.target)

	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable through the dispatch route", fg.Reachability)
	}
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != graphfrag.RouteEvidenceDispatch {
		t.Fatalf("Analysis = %+v, want route_evidence dispatch", fg.Analysis)
	}
	if len(fg.CallChains) != 1 || fg.CallChains[0][0].FunctionName != "com.app.Beta.run" {
		t.Fatalf("kept chains = %v, want the dispatch route from com.app.Beta.run", chainRoots(fg.CallChains))
	}
	chain := fg.CallChains[0]
	if chainHasResolution(chain, string(callgraph.EdgeKindNameOnly)) {
		t.Fatalf("kept chain has a name_only frame: %+v", chain)
	}
	if !chainHasResolution(chain, string(callgraph.EdgeKindInterfaceDispatch)) {
		t.Fatalf("kept chain does not name its dispatch hop: %+v", chain)
	}
}

// TestBuildFindingGraph_GuessOnlyRouteReadsNameOnlyEvidence: with the guess
// as the only route the verdict is unknown (unresolved_dispatch), and the
// analysis says why in the same vocabulary.
func TestBuildFindingGraph_GuessOnlyRouteReadsNameOnlyEvidence(t *testing.T) {
	t.Parallel()
	g := newEvidenceGraph()
	g.guessedRoute()

	fg := buildDepthFindingGraph(g.context(4), g.target)

	if fg.Reachability != graphfrag.ReachabilityUnknown || fg.UnresolvedReason != unresolvedDispatch {
		t.Fatalf("Reachability = %q (%q), want unknown / unresolved_dispatch", fg.Reachability, fg.UnresolvedReason)
	}
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != graphfrag.RouteEvidenceNameOnly {
		t.Fatalf("Analysis = %+v, want route_evidence name_only", fg.Analysis)
	}
}

// TestBuildFindingGraph_NoCallersOnly: every root of the routes that support
// the verdict is an application function nothing calls, so the finding is
// flagged. A recognized entry on a supporting route clears the flag; one that
// reaches the crypto only through a name_only guess does not.
func TestBuildFindingGraph_NoCallersOnly(t *testing.T) {
	t.Parallel()

	t.Run("every supporting root has no callers", func(t *testing.T) {
		t.Parallel()
		g := newEvidenceGraph()
		g.dispatchRoute()
		g.directRoute()
		fg := buildDepthFindingGraph(g.context(4), g.target)
		if fg.Analysis == nil || !fg.Analysis.NoCallersOnly {
			t.Fatalf("Analysis = %+v, want no_callers_only", fg.Analysis)
		}
	})

	t.Run("a scheduled job on a dispatch route clears it", func(t *testing.T) {
		t.Parallel()
		g := newEvidenceGraph()
		g.dispatchRoute().EntryKind = callgraph.RootKindFrameworkEntry // an imported @Scheduled
		g.directRoute()
		fg := buildDepthFindingGraph(g.context(4), g.target)
		if fg.Analysis == nil || fg.Analysis.NoCallersOnly {
			t.Fatalf("Analysis = %+v, want no_callers_only unset: a scheduled job reaches the crypto", fg.Analysis)
		}
	})

	t.Run("an entry reaching it only by a guess does not count", func(t *testing.T) {
		t.Parallel()
		g := newEvidenceGraph()
		g.guessedRoute().EntryKind = callgraph.RootKindFrameworkEntry // an imported @Scheduled
		g.directRoute()
		fg := buildDepthFindingGraph(g.context(4), g.target)
		if fg.Analysis == nil || !fg.Analysis.NoCallersOnly {
			t.Fatalf("Analysis = %+v, want no_callers_only: the scheduled job's route rests on a name_only guess", fg.Analysis)
		}
	})
}

// TestBuildFindingGraph_FirstVariantNamesTheStrongestCallSite: the caller
// calls the library twice, first through a name_only guess, then exactly.
// The route holds without a guess, so the chain the budget keeps must show
// the exact call site, not the first one in source order.
func TestBuildFindingGraph_FirstVariantNamesTheStrongestCallSite(t *testing.T) {
	t.Parallel()
	g := newEvidenceGraph()
	gamma := g.add("com.app", "Gamma", "run#0", 30)
	g.link(gamma, g.target, 31, callgraph.EdgeKindNameOnly)
	g.link(gamma, g.target, 35, callgraph.EdgeKindExact)

	fg := buildDepthFindingGraph(g.context(1), g.target)

	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable", fg.Reachability)
	}
	if len(fg.CallChains) != 1 {
		t.Fatalf("CallChains = %d, want 1", len(fg.CallChains))
	}
	sink := fg.CallChains[0][len(fg.CallChains[0])-1]
	if sink.EntryResolution != string(callgraph.EdgeKindExact) || sink.EntryCall == nil || sink.EntryCall.Line != 35 {
		t.Fatalf("sink frame = resolution %q, entry_call %+v; want the exact call at line 35", sink.EntryResolution, sink.EntryCall)
	}
}

// TestBuildFindingGraph_DispatchFrameNamesItsDispatchCallSite: the library
// calls Worker.run through its interface at line 201, which dispatch links,
// and at line 205 through a receiver only a name_only guess links. The
// frame's call names neither callee exactly, so the chain step's line decides
// which classification it reads: it must be the dispatch site the route was
// chosen by, not a site the frame would read as a guess.
func TestBuildFindingGraph_DispatchFrameNamesItsDispatchCallSite(t *testing.T) {
	t.Parallel()
	g := newEvidenceGraph()
	beta := g.add("com.app", "Beta", "run#0", 20)
	pool := g.add("org.lib", "Pool", "submit#0", 200)
	worker := g.add("org.lib", "Worker", "run#0", 300)
	g.link(beta, pool, 21, callgraph.EdgeKindExact)
	g.link(worker, g.target, 301, callgraph.EdgeKindExact)
	pool.Calls = append(pool.Calls,
		callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "org.lib", Type: "Task", Name: "run#0"}, Line: 201},
		callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "org.other", Type: "Job", Name: "run#0"}, Line: 205})
	g.graph.Callers[worker.ID.String()] = []string{pool.ID.String()}
	for _, res := range []callgraph.EdgeResolution{
		{Kind: callgraph.EdgeKindInterfaceDispatch, CallSite: 201, DeclaredType: "org.lib.Task", MethodName: "run"},
		{Kind: callgraph.EdgeKindNameOnly, CallSite: 205, DeclaredType: "org.other.Job", MethodName: "run"},
	} {
		g.graph.EdgeResolutions[callgraph.EdgeResolutionKey(pool.ID.String(), worker.ID.String(), res)] = res
	}

	fg := buildDepthFindingGraph(g.context(4), g.target)

	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable through the dispatch", fg.Reachability)
	}
	if fg.Analysis == nil || fg.Analysis.RouteEvidence != graphfrag.RouteEvidenceDispatch {
		t.Fatalf("Analysis = %+v, want route_evidence dispatch", fg.Analysis)
	}
	var frame *callGraphChainNode
	for i := range fg.CallChains[0] {
		if fg.CallChains[0][i].FunctionName == "org.lib.Worker.run" {
			frame = &fg.CallChains[0][i]
		}
	}
	if frame == nil {
		t.Fatalf("no Worker.run frame in %+v", fg.CallChains[0])
	}
	if frame.EntryResolution != string(callgraph.EdgeKindInterfaceDispatch) {
		t.Fatalf("Worker.run entry_resolution = %q, want interface_dispatch", frame.EntryResolution)
	}
}
