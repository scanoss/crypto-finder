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
	"fmt"
	"testing"
	"time"
)

// buildHighFanInGraph builds a layered call graph where every node in layer i
// is called by every node in layer i+1. The number of distinct caller paths
// from the roots down to the target therefore grows as width^depth. A tracer
// that enumerates paths (rather than nodes) explodes combinatorially on such a
// graph — the shape mirrors a large crypto library (e.g. BouncyCastle) whose
// utility functions have very high fan-in.
func buildHighFanInGraph(width, depth int) (*CallGraph, FunctionID) {
	functions := make(map[string]*FunctionDecl)
	callers := make(map[string][]string)

	target := FunctionID{Package: "dep/crypto", Name: "Cipher"}
	functions[target.String()] = &FunctionDecl{ID: target, FilePath: "/dep/crypto.go", StartLine: 1, EndLine: 2}

	prevLayer := []FunctionID{target}
	for d := 1; d <= depth; d++ {
		layer := make([]FunctionID, 0, width)
		for w := range width {
			id := FunctionID{Package: "dep/lib", Name: fmt.Sprintf("L%dN%d", d, w)}
			functions[id.String()] = &FunctionDecl{
				ID: id, FilePath: "/dep/lib.go", StartLine: d*1000 + w, EndLine: d*1000 + w + 1,
			}
			layer = append(layer, id)
		}
		// Every node in the previous layer is called by every node in this layer.
		callerKeys := make([]string, 0, width)
		for _, caller := range layer {
			callerKeys = append(callerKeys, caller.String())
		}
		for _, callee := range prevLayer {
			callers[callee.String()] = callerKeys
		}
		prevLayer = layer
	}
	return &CallGraph{Functions: functions, Callers: callers}, target
}

// TestTraceBackLimited_HighFanInTerminatesBounded guards against the call-chain
// explosion that hung the callgraph export on large dependency trees. With a
// per-path visited set, TraceBackLimited must expand width^depth partial paths
// before any chain completes at a root, so it never returns in bounded time.
// A graph-global frontier keeps the work O(V+E) and the result bounded.
//
// userPackages is nil here to mirror scanning a dependency artifact directly
// (--scan-dependencies), which disables the user-boundary short-circuit and is
// exactly the configuration that hung in the field.
func TestTraceBackLimited_HighFanInTerminatesBounded(t *testing.T) {
	graph, target := buildHighFanInGraph(6, 8)
	tracer := NewTracer(graph, "/")

	const maxChains = 128
	const budget = 400 * time.Millisecond

	type result struct {
		chains    []CallChain
		truncated bool
	}
	done := make(chan result, 1)
	go func() {
		chains, truncated := tracer.TraceBackLimited(target, nil, 0, maxChains)
		done <- result{chains: chains, truncated: truncated}
	}()

	select {
	case r := <-done:
		if len(r.chains) == 0 {
			t.Fatal("expected at least one call chain, got none")
		}
		if len(r.chains) > maxChains {
			t.Fatalf("chains = %d, exceeds maxChains = %d", len(r.chains), maxChains)
		}
	case <-time.After(budget):
		t.Fatalf("TraceBackLimited did not terminate within %s on a high-fan-in graph "+
			"(combinatorial path explosion — frontier must be node-bounded, not path-bounded)", budget)
	}
}

// TestTraceBackLimited_DistinctEntriesPreserved guards the reachability contract
// behind the graph-global frontier optimization: collapsing re-convergent paths
// must NOT drop any user entry point that actually reaches the target. Here two
// distinct user entries (app.E1, app.E2) both reach the crypto target through a
// shared intermediate (dep.M); both must still be reported even though M is
// enqueued only once.
func TestTraceBackLimited_DistinctEntriesPreserved(t *testing.T) {
	target := FunctionID{Package: "dep", Name: "Cipher"}
	middle := FunctionID{Package: "dep", Name: "Helper"}
	e1 := FunctionID{Package: "app", Name: "E1"}
	e2 := FunctionID{Package: "app", Name: "E2"}

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			target.String(): {ID: target, FilePath: "/dep/c.go", StartLine: 1, EndLine: 2},
			middle.String(): {ID: middle, FilePath: "/dep/h.go", StartLine: 1, EndLine: 2},
			e1.String():     {ID: e1, FilePath: "/app/a.go", StartLine: 1, EndLine: 2},
			e2.String():     {ID: e2, FilePath: "/app/b.go", StartLine: 1, EndLine: 2},
		},
		Callers: map[string][]string{
			target.String(): {middle.String()},
			middle.String(): {e1.String(), e2.String()},
		},
	}

	tracer := NewTracer(graph, "/")
	chains, truncated := tracer.TraceBackLimited(target, map[string]bool{"app": true}, 0, 0)
	if truncated {
		t.Fatal("unexpected truncation")
	}

	entries := make(map[string]bool)
	for _, chain := range chains {
		entries[chain.Steps[0].Function.String()] = true
	}
	if !entries[e1.String()] || !entries[e2.String()] {
		t.Fatalf("expected both user entries reachable, got chains from %v", entries)
	}
}
