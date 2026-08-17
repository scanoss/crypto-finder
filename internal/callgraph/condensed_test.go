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
	"strings"
	"testing"
	"time"
)

// buildJedisShapeGraph reproduces the structure behind issue #249, taken from
// the IBM redis-demo: one user function makes two calls into a library, both
// land on the same dispatch function, and that function sits in a retry cycle
// before reaching the crypto call.
//
//	user.run ──→ Jedis.set ──┐
//	         └──→ Jedis.get ──┴──→ [executeCommand ⇄ handleConnectionProblem ⇄ retry]
//	                                        └──→ connect ──→ createSocket   (target)
func buildJedisShapeGraph() (*CallGraph, FunctionID, map[string]bool) {
	mk := func(pkg, typ, name string, line int) *FunctionDecl {
		id := FunctionID{Package: pkg, Type: typ, Name: name}
		return &FunctionDecl{ID: id, FilePath: "/" + typ + ".java", StartLine: line, EndLine: line + 5}
	}

	user := mk("com.example", "App", "run", 80)
	set := mk("redis.clients.jedis", "Jedis", "set", 100)
	get := mk("redis.clients.jedis", "Jedis", "get", 200)
	exec := mk("redis.clients.jedis", "Connection", "executeCommand", 300)
	handle := mk("redis.clients.jedis", "Connection", "handleConnectionProblem", 400)
	retry := mk("redis.clients.jedis", "Connection", "retry", 500)
	connect := mk("redis.clients.jedis", "Connection", "connect", 600)
	socket := mk("redis.clients.jedis", "DefaultJedisSocketFactory", "createSocket", 700)

	all := []*FunctionDecl{user, set, get, exec, handle, retry, connect, socket}
	functions := make(map[string]*FunctionDecl, len(all))
	for _, fn := range all {
		functions[fn.ID.String()] = fn
	}

	// The two user call sites are on distinct lines, which is what a reader
	// needs in order to remediate both.
	user.Calls = []FunctionCall{
		{Callee: set.ID, Line: 83},
		{Callee: get.ID, Line: 84},
	}
	set.Calls = []FunctionCall{{Callee: exec.ID, Line: 101}}
	get.Calls = []FunctionCall{{Callee: exec.ID, Line: 201}}
	exec.Calls = []FunctionCall{{Callee: handle.ID, Line: 301}, {Callee: connect.ID, Line: 302}}
	handle.Calls = []FunctionCall{{Callee: retry.ID, Line: 401}}
	retry.Calls = []FunctionCall{{Callee: exec.ID, Line: 501}}
	connect.Calls = []FunctionCall{{Callee: socket.ID, Line: 601}}

	callers := map[string][]string{
		set.ID.String():     {user.ID.String()},
		get.ID.String():     {user.ID.String()},
		exec.ID.String():    {set.ID.String(), get.ID.String(), retry.ID.String()},
		handle.ID.String():  {exec.ID.String()},
		retry.ID.String():   {handle.ID.String()},
		connect.ID.String(): {exec.ID.String()},
		socket.ID.String():  {connect.ID.String()},
	}

	graph := &CallGraph{Functions: functions, Callers: callers}
	return graph, socket.ID, map[string]bool{"com.example": true}
}

func chainSignature(chain CallChain) string {
	parts := make([]string, 0, len(chain.Steps))
	for _, step := range chain.Steps {
		parts = append(parts, step.Function.Type+"."+step.Function.Name)
	}
	return strings.Join(parts, " -> ")
}

// TestTraceBackLimited_DropsReconvergentUserCall pins the defect: the existing
// tracer collects one chain because both library APIs converge on the same user
// function, and whichever caller sorts first claims it.
func TestTraceBackLimited_DropsReconvergentUserCall(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()

	chains, _ := NewTracer(graph, ".").TraceBackLimited(target, userPackages, 32, 128)

	if len(chains) != 1 {
		t.Fatalf("TraceBackLimited chains = %d, want 1 (the documented collapse)", len(chains))
	}
	sig := chainSignature(chains[0])
	if !strings.Contains(sig, "Jedis.get") {
		t.Fatalf("surviving chain = %q, want the alphabetically first caller (Jedis.get)", sig)
	}
	if strings.Contains(sig, "Jedis.set") {
		t.Fatalf("chain %q unexpectedly contains Jedis.set", sig)
	}
}

// TestTraceBackCondensed_KeepsBothUserCalls is the fix: condensing the retry
// cycle leaves the two library APIs in separate components, so both user calls
// are reported.
func TestTraceBackCondensed_KeepsBothUserCalls(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()

	chains, total, truncated := NewTracer(graph, ".").TraceBackCondensed(target, userPackages, 32, 128)

	if total != 2 {
		t.Fatalf("total condensed paths = %d, want 2", total)
	}
	if truncated {
		t.Fatal("truncated = true, want false: 2 paths fit in a budget of 128")
	}
	if len(chains) != 2 {
		t.Fatalf("chains = %d, want 2", len(chains))
	}

	want := map[string]bool{
		"App.run -> Jedis.get -> Connection.executeCommand -> Connection.connect -> DefaultJedisSocketFactory.createSocket": false,
		"App.run -> Jedis.set -> Connection.executeCommand -> Connection.connect -> DefaultJedisSocketFactory.createSocket": false,
	}
	for _, chain := range chains {
		sig := chainSignature(chain)
		if _, ok := want[sig]; !ok {
			t.Fatalf("unexpected chain %q", sig)
		}
		want[sig] = true
	}
	for sig, seen := range want {
		if !seen {
			t.Errorf("missing chain %q", sig)
		}
	}
}

// TestTraceBackCondensed_ReportsUserCallLines checks that each chain carries the
// call site of the user call it describes — line 83 for set, line 84 for get.
// Without this a report can name the API but not the line to change, which is
// the remediation gap issue #249 describes.
func TestTraceBackCondensed_ReportsUserCallLines(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()

	chains, _, _ := NewTracer(graph, ".").TraceBackCondensed(target, userPackages, 32, 128)

	lines := map[string]int{}
	for _, chain := range chains {
		if len(chain.Steps) < 2 {
			t.Fatalf("chain too short: %q", chainSignature(chain))
		}
		entry := chain.Steps[0]
		api := chain.Steps[1].Function.Name
		if entry.Function.Package != "com.example" {
			t.Fatalf("chain entry = %s, want a com.example function", entry.Function.String())
		}
		lines[api] = entry.Line
	}
	if lines["set"] != 83 {
		t.Errorf("user call line for Jedis.set = %d, want 83", lines["set"])
	}
	if lines["get"] != 84 {
		t.Errorf("user call line for Jedis.get = %d, want 84", lines["get"])
	}
}

// TestTraceBackCondensed_CollapsesCycleInsteadOfEnumeratingIt verifies the
// cycle contributes one representative traversal rather than one chain per
// internal ordering.
func TestTraceBackCondensed_CollapsesCycleInsteadOfEnumeratingIt(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()

	chains, total, _ := NewTracer(graph, ".").TraceBackCondensed(target, userPackages, 32, 128)

	if total != 2 {
		t.Fatalf("total = %d, want 2: the retry cycle must not multiply routes", total)
	}
	for _, chain := range chains {
		seen := map[string]bool{}
		for _, step := range chain.Steps {
			key := step.Function.String()
			if seen[key] {
				t.Fatalf("chain revisits %s: %q", key, chainSignature(chain))
			}
			seen[key] = true
		}
	}
}

// TestTraceBackCondensed_HighFanInStaysBounded runs the shape that motivated the
// O(V+E) frontier — a dense library with very high fan-in — and asserts the
// budget is respected, the exact total is still reported, and it finishes fast.
func TestTraceBackCondensed_HighFanInStaysBounded(t *testing.T) {
	t.Parallel()
	graph, target := buildHighFanInGraph(8, 8)

	start := time.Now()
	chains, total, truncated := NewTracer(graph, "/").TraceBackCondensed(target, nil, 32, 128)
	elapsed := time.Since(start)

	if len(chains) > 128 {
		t.Fatalf("chains = %d, want at most the 128 budget", len(chains))
	}
	if !truncated {
		t.Fatalf("truncated = false with total %d and budget 128, want true", total)
	}
	if total <= 128 {
		t.Fatalf("total = %d, want more than the budget on a high-fan-in graph", total)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("condensed traceback took %s, want well under 10s", elapsed)
	}
	t.Logf("high fan-in: emitted=%d total=%d elapsed=%s", len(chains), total, elapsed)
}

// TestTraceBackCondensed_MinePathUsesGraphRoots covers the mine path, where
// there is no user code and a graph root is the library's public API.
//
// The count is routes x terminals, not one per terminal: a single root that
// reaches the crypto through two different APIs still yields two chains, which
// is the distinction the report needs.
func TestTraceBackCondensed_MinePathUsesGraphRoots(t *testing.T) {
	t.Parallel()
	graph, target, _ := buildJedisShapeGraph()

	chains, total, _ := NewTracer(graph, ".").TraceBackCondensed(target, nil, 32, 128)

	if total != 2 {
		t.Fatalf("total = %d, want 2: one route per API from the single graph root", total)
	}
	if len(chains) != 2 {
		t.Fatalf("chains = %d, want 2", len(chains))
	}
	apis := map[string]bool{}
	for _, chain := range chains {
		if got := chain.Steps[0].Function.Name; got != "run" {
			t.Fatalf("chain starts at %q, want the graph root run", got)
		}
		apis[chain.Steps[1].Function.Name] = true
	}
	if !apis["set"] || !apis["get"] {
		t.Fatalf("chains cover APIs %v, want both set and get", apis)
	}
}

// TestTraceBackCondensed_UnreachableFindingHasNoChains keeps the #244 behavior:
// crypto no user code reaches contributes nothing.
func TestTraceBackCondensed_UnreachableFindingHasNoChains(t *testing.T) {
	t.Parallel()
	graph, target, _ := buildJedisShapeGraph()

	// No user package matches the graph, so nothing reaches the crypto.
	chains, total, truncated := NewTracer(graph, ".").TraceBackCondensed(
		target, map[string]bool{"com.other": true}, 32, 128)

	if len(chains) != 0 || total != 0 || truncated {
		t.Fatalf("chains=%d total=%d truncated=%v, want 0/0/false", len(chains), total, truncated)
	}
}
