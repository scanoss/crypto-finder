// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// dispatchChainContext builds app.(Main).run -> org.lib.(Facade).parse ->
// org.lib.(Guess).hash, where the second edge is a name_only dispatch guess,
// and, when typedRoute is set, a second exact route app.(Batch).run ->
// org.lib.(Guess).hash.
func dispatchChainContext(typedRoute bool) (*exportBuildContext, *callgraph.FunctionDecl) {
	graph := &callgraph.CallGraph{
		Functions:       map[string]*callgraph.FunctionDecl{},
		Callers:         map[string][]string{},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	add := func(id callgraph.FunctionID, file string, line int) *callgraph.FunctionDecl {
		decl := &callgraph.FunctionDecl{ID: id, FilePath: file, StartLine: line, EndLine: line + 5}
		graph.Functions[id.String()] = decl
		return decl
	}
	link := func(caller, callee *callgraph.FunctionDecl, kind callgraph.EdgeKind) {
		line := caller.StartLine + 1
		caller.Calls = append(caller.Calls, callgraph.FunctionCall{Callee: callee.ID, Line: line})
		graph.Callers[callee.ID.String()] = append(graph.Callers[callee.ID.String()], caller.ID.String())
		res := callgraph.EdgeResolution{Kind: kind, CallSite: line, DeclaredType: "org.lib.Parser"}
		graph.EdgeResolutions[callgraph.EdgeResolutionKey(caller.ID.String(), callee.ID.String(), res)] = res
	}
	main := add(callgraph.FunctionID{Package: "com.app", Type: "Main", Name: "run#0"}, "app/Main.java", 1)
	facade := add(callgraph.FunctionID{Package: "org.lib", Type: "Facade", Name: "parse#0"}, "lib/Facade.java", 10)
	target := add(callgraph.FunctionID{Package: "org.lib", Type: "Guess", Name: "hash#0"}, "lib/Guess.java", 20)
	link(main, facade, callgraph.EdgeKindExact)
	link(facade, target, callgraph.EdgeKindNameOnly)
	if typedRoute {
		batch := add(callgraph.FunctionID{Package: "com.app", Type: "Batch", Name: "run#0"}, "app/Batch.java", 30)
		link(batch, target, callgraph.EdgeKindExact)
	}
	ctx := &exportBuildContext{
		graph:                   graph,
		packageSeparator:        ".",
		userPackages:            map[string]bool{"com.app": true},
		fragmentEdgeResolutions: indexFragmentEdgeResolutions(graph),
	}
	ensureCallChainCaches(ctx)
	ctx.callChainRemainingUses[target.ID.String()] = 1
	return ctx, target
}

// TestBuildFindingGraph_OnlyNameOnlyRoutesReadUnknown: the application
// reaches the crypto only through a call linked by name to a class not proven
// to be a subtype of the receiver's type. That is a guess, not proof: the
// finding reads unknown with reason unresolved_dispatch, keeps the chain as
// evidence, and each step still says how it was resolved.
func TestBuildFindingGraph_OnlyNameOnlyRoutesReadUnknown(t *testing.T) {
	t.Parallel()
	ctx, target := dispatchChainContext(false)

	fg := buildDepthFindingGraph(ctx, target)

	if fg.Reachability != graphfrag.ReachabilityUnknown {
		t.Fatalf("Reachability = %q, want unknown when every route crosses a name_only edge", fg.Reachability)
	}
	if fg.UnresolvedReason != unresolvedDispatch {
		t.Fatalf("UnresolvedReason = %q, want %q", fg.UnresolvedReason, unresolvedDispatch)
	}
	if fg.Reachable != nil {
		t.Fatalf("Reachable = %v, want unset", *fg.Reachable)
	}
	if fg.FindingLocation != nil {
		t.Fatalf("FindingLocation = %+v, want none: the finding is attributed", fg.FindingLocation)
	}
	if len(fg.CallChains) != 1 || len(fg.CallChains[0]) != 3 {
		t.Fatalf("CallChains = %#v, want the one 3-frame chain kept as evidence", fg.CallChains)
	}
	if got := fg.CallChains[0][2].EntryResolution; got != string(callgraph.EdgeKindNameOnly) {
		t.Fatalf("entry_resolution of the guessed frame = %q, want name_only", got)
	}
}

// TestBuildFindingGraph_TypedRouteKeepsReachable: one route without a guess
// is enough for reachable, whatever the other routes cross.
func TestBuildFindingGraph_TypedRouteKeepsReachable(t *testing.T) {
	t.Parallel()
	ctx, target := dispatchChainContext(true)

	fg := buildDepthFindingGraph(ctx, target)

	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable through the exact route", fg.Reachability)
	}
	if fg.UnresolvedReason != "" {
		t.Fatalf("UnresolvedReason = %q, want none", fg.UnresolvedReason)
	}
	if len(fg.CallChains) != 2 {
		t.Fatalf("CallChains = %d, want both routes", len(fg.CallChains))
	}
}
