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

package callgraph

import (
	"slices"
	"testing"
)

// edgeGraph builds a graph from caller -> callee pairs over Go-style keys
// ("pkg.Name"), so tests read as the call structure they describe.
func edgeGraph(edges ...[2]FunctionID) *CallGraph {
	graph := &CallGraph{Functions: map[string]*FunctionDecl{}, Callers: map[string][]string{}}
	add := func(id FunctionID) *FunctionDecl {
		if decl, ok := graph.Functions[id.String()]; ok {
			return decl
		}
		decl := &FunctionDecl{ID: id, FilePath: "/" + id.Package + ".go", StartLine: 1, EndLine: 9}
		graph.Functions[id.String()] = decl
		return decl
	}
	for i := range edges {
		caller, callee := add(edges[i][0]), add(edges[i][1])
		caller.Calls = append(caller.Calls, FunctionCall{Callee: callee.ID, Line: i + 2})
		graph.Callers[callee.ID.String()] = append(graph.Callers[callee.ID.String()], caller.ID.String())
	}
	return graph
}

func fn(pkg, name string) FunctionID { return FunctionID{Package: pkg, Name: name} }

func chainNames(chain CallChain) []string {
	names := make([]string, len(chain.Steps))
	for i, step := range chain.Steps {
		names[i] = step.Function.Name
	}
	return names
}

var appPackages = map[string]bool{"app": true}

// TestTraceBackCondensed_WalksBackToTheApplicationRoot: the chain no longer
// stops at the first application frame.
func TestTraceBackCondensed_WalksBackToTheApplicationRoot(t *testing.T) {
	t.Parallel()
	crypto := fn("lib", "Sum")
	graph := edgeGraph(
		[2]FunctionID{fn("app", "main"), fn("app", "serve")},
		[2]FunctionID{fn("app", "serve"), fn("app", "hash")},
		[2]FunctionID{fn("app", "hash"), crypto},
	)

	trace := NewTracer(graph, ".").TraceBackCondensed(crypto, appPackages, 0, 0)

	if len(trace.Chains) != 1 {
		t.Fatalf("chains = %d, want 1", len(trace.Chains))
	}
	if got := chainNames(trace.Chains[0]); !slices.Equal(got, []string{"main", "serve", "hash", "Sum"}) {
		t.Fatalf("chain = %v, want main -> serve -> hash -> Sum", got)
	}
	if trace.Chains[0].RootKind != RootKindMain {
		t.Fatalf("root kind = %q, want main", trace.Chains[0].RootKind)
	}
}

// TestTraceBackCondensed_ApplicationCallbackReachedThroughLibrary: crypto in
// an application callback that only a library calls is still reached from the
// application code that calls the library.
func TestTraceBackCondensed_ApplicationCallbackReachedThroughLibrary(t *testing.T) {
	t.Parallel()
	callback := fn("app", "onEvent")
	graph := edgeGraph(
		[2]FunctionID{fn("app", "main"), fn("lib", "Run")},
		[2]FunctionID{fn("lib", "Run"), callback},
	)

	trace := NewTracer(graph, ".").TraceBackCondensed(callback, appPackages, 0, 0)

	if len(trace.Chains) != 1 || !slices.Equal(chainNames(trace.Chains[0]), []string{"main", "Run", "onEvent"}) {
		t.Fatalf("chains = %+v, want main -> Run -> onEvent", trace.Chains)
	}
}

// TestTraceBackCondensed_UncalledApplicationCycleHasARoot: mutual recursion
// that nothing outside it calls has no member without callers, but the
// application still reaches the crypto from it.
func TestTraceBackCondensed_UncalledApplicationCycleHasARoot(t *testing.T) {
	t.Parallel()
	crypto := fn("lib", "Sum")
	graph := edgeGraph(
		[2]FunctionID{fn("app", "ping"), fn("app", "pong")},
		[2]FunctionID{fn("app", "pong"), fn("app", "ping")},
		[2]FunctionID{fn("app", "pong"), crypto},
	)

	trace := NewTracer(graph, ".").TraceBackCondensed(crypto, appPackages, 0, 0)

	if len(trace.Chains) != 1 || trace.Chains[0].RootKind != RootKindNoCallers {
		t.Fatalf("chains = %+v, want one chain rooted in the cycle", trace.Chains)
	}
}

// TestTraceBackCondensed_SelfRecursionDoesNotHideTheRoot: a function that
// calls itself is still one nothing else calls.
func TestTraceBackCondensed_SelfRecursionDoesNotHideTheRoot(t *testing.T) {
	t.Parallel()
	crypto := fn("lib", "Sum")
	graph := edgeGraph(
		[2]FunctionID{fn("app", "retry"), fn("app", "retry")},
		[2]FunctionID{fn("app", "retry"), crypto},
	)

	trace := NewTracer(graph, ".").TraceBackCondensed(crypto, appPackages, 0, 0)

	if len(trace.Chains) != 1 || !slices.Equal(chainNames(trace.Chains[0]), []string{"retry", "Sum"}) {
		t.Fatalf("chains = %+v, want retry -> Sum", trace.Chains)
	}
}

// TestTraceBackCondensed_DepthLimitIsReported: a limit that stops the walk
// inside the library leaves the question open; one that stops it inside the
// application makes that frame a depth_limit root.
func TestTraceBackCondensed_DepthLimitIsReported(t *testing.T) {
	t.Parallel()
	crypto := fn("lib", "Sum")
	libCut := edgeGraph(
		[2]FunctionID{fn("app", "main"), fn("lib", "A")},
		[2]FunctionID{fn("lib", "A"), fn("lib", "B")},
		[2]FunctionID{fn("lib", "B"), crypto},
	)
	trace := NewTracer(libCut, ".").TraceBackCondensed(crypto, appPackages, 2, 0)
	if len(trace.Chains) != 0 || !trace.DepthLimited || !trace.Truncated {
		t.Fatalf("library cut: chains=%d depthLimited=%v truncated=%v, want 0/true/true",
			len(trace.Chains), trace.DepthLimited, trace.Truncated)
	}

	appCut := edgeGraph(
		[2]FunctionID{fn("app", "main"), fn("app", "A")},
		[2]FunctionID{fn("app", "A"), fn("app", "B")},
		[2]FunctionID{fn("app", "B"), crypto},
	)
	trace = NewTracer(appCut, ".").TraceBackCondensed(crypto, appPackages, 2, 0)
	if len(trace.Chains) != 1 || trace.Chains[0].RootKind != RootKindDepthLimit || trace.DepthLimited || !trace.Truncated {
		t.Fatalf("application cut: %+v, want one depth_limit chain, truncated but not depth-limited", trace)
	}
}

// TestTraceBackCondensed_BudgetPrefersEntryPoints: with room for one chain it
// comes from the recognized entry point, even when another root sorts first
// and is closer.
func TestTraceBackCondensed_BudgetPrefersEntryPoints(t *testing.T) {
	t.Parallel()
	crypto := fn("lib", "Sum")
	graph := edgeGraph(
		[2]FunctionID{fn("app", "main"), fn("app", "serve")},
		[2]FunctionID{fn("app", "serve"), crypto},
		[2]FunctionID{fn("app", "aaTool"), crypto},
	)

	trace := NewTracer(graph, ".").TraceBackCondensed(crypto, appPackages, 0, 1)

	if len(trace.Chains) != 1 || trace.Chains[0].RootKind != RootKindMain || trace.Total != 2 || !trace.Truncated {
		t.Fatalf("trace = %+v, want the main chain of 2", trace)
	}
}
