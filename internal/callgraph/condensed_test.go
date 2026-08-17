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

// buildPostgresShapeGraph reproduces the second acceptance case: two library
// functions that converge on the same caller, taken from the pgjdbc driver.
//
//	Driver.connect ──→ PgConnection.<init>     ──┐
//	               └─→ PgConnection.setReadOnly ─┴──→ QueryExecutor.sendQueryCancel
//	                                                        └──→ PGStream.getSocketFactory
//
// It matters because everything here sits FAR below both bounds — one chain
// against a budget of 128, four frames against a depth cap of 32 — so a fix
// that merely raised the cap cannot make this case pass. The loss is purely the
// shared-caller collapse.
func buildPostgresShapeGraph() (*CallGraph, FunctionID) {
	mk := func(typ, name string, line int) *FunctionDecl {
		id := FunctionID{Package: "org.postgresql", Type: typ, Name: name}
		return &FunctionDecl{ID: id, FilePath: "/" + typ + ".java", StartLine: line, EndLine: line + 5}
	}

	connect := mk("Driver", "connect", 100)
	ctor := mk("PgConnection", "<init>", 200)
	readOnly := mk("PgConnection", "setReadOnly", 300)
	cancel := mk("QueryExecutor", "sendQueryCancel", 400)
	stream := mk("PGStream", "getSocketFactory", 500)

	all := []*FunctionDecl{connect, ctor, readOnly, cancel, stream}
	functions := make(map[string]*FunctionDecl, len(all))
	for _, fn := range all {
		functions[fn.ID.String()] = fn
	}

	connect.Calls = []FunctionCall{{Callee: ctor.ID, Line: 101}, {Callee: readOnly.ID, Line: 102}}
	ctor.Calls = []FunctionCall{{Callee: cancel.ID, Line: 201}}
	readOnly.Calls = []FunctionCall{{Callee: cancel.ID, Line: 301}}
	cancel.Calls = []FunctionCall{{Callee: stream.ID, Line: 401}}

	callers := map[string][]string{
		ctor.ID.String():     {connect.ID.String()},
		readOnly.ID.String(): {connect.ID.String()},
		cancel.ID.String():   {ctor.ID.String(), readOnly.ID.String()},
		stream.ID.String():   {cancel.ID.String()},
	}

	return &CallGraph{Functions: functions, Callers: callers}, stream.ID
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

// TestReachingFunctions_IncludesCycleMembersChainsSkip is the premise behind
// deriving crypto_entry_points from the set rather than from the chains: a
// condensed chain takes the shortest way through a cycle, so members the long
// way visits appear in no chain — but they do reach the crypto and the set says
// so. Measured on the IBM postgres-demo, three functions were lost this way.
func TestReachingFunctions_IncludesCycleMembersChainsSkip(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()
	tracer := NewTracer(graph, ".")

	chains, _, _ := tracer.TraceBackCondensed(target, userPackages, 32, 128)
	inChains := map[string]bool{}
	for _, chain := range chains {
		for _, step := range chain.Steps {
			inChains[step.Function.Name] = true
		}
	}

	depths, _ := tracer.ReachingFunctions(target, userPackages, 32)
	inSet := map[string]bool{}
	for key := range depths {
		if id, err := ParseFunctionID(key); err == nil {
			inSet[id.Name] = true
		}
	}

	// The retry cycle's other members are skipped by the shortest traversal...
	for _, skipped := range []string{"handleConnectionProblem", "retry"} {
		if inChains[skipped] {
			t.Fatalf("%s unexpectedly present in a chain; the fixture no longer exercises the gap", skipped)
		}
		// ...and are still reported as reaching the crypto.
		if !inSet[skipped] {
			t.Errorf("%s missing from the reaching set", skipped)
		}
	}

	for _, expected := range []string{"run", "set", "get", "executeCommand", "connect", "createSocket"} {
		if !inSet[expected] {
			t.Errorf("%s missing from the reaching set", expected)
		}
	}
}

// TestReachingFunctions_DepthIsTrueMinimum checks the hop counts the index
// publishes as chain_depth: the target is 0 and every caller adds one, measured
// on the graph rather than on whichever chain got exported.
func TestReachingFunctions_DepthIsTrueMinimum(t *testing.T) {
	t.Parallel()
	graph, target, userPackages := buildJedisShapeGraph()

	depths, terminals := NewTracer(graph, ".").ReachingFunctions(target, userPackages, 32)

	byName := map[string]int{}
	for key, d := range depths {
		if id, err := ParseFunctionID(key); err == nil {
			byName[id.Name] = d
		}
	}
	want := map[string]int{
		"createSocket":   0,
		"connect":        1,
		"executeCommand": 2,
		"set":            3,
		"get":            3,
		"run":            4,
	}
	for name, expected := range want {
		if got, ok := byName[name]; !ok || got != expected {
			t.Errorf("depth of %s = %d (present=%v), want %d", name, got, ok, expected)
		}
	}

	// Only the user function terminates a chain.
	termNames := map[string]bool{}
	for key := range terminals {
		if id, err := ParseFunctionID(key); err == nil {
			termNames[id.Name] = true
		}
	}
	if !termNames["run"] || len(termNames) != 1 {
		t.Errorf("terminals = %v, want only run", termNames)
	}
}

// TestPostgresShape_LossIsNotTheChainCap is the guard that keeps this fix from
// being mistaken for a cap raise: with one chain against a budget of 128 and
// four frames against a depth cap of 32, RAISING THE CAP CHANGES NOTHING — and
// the set still reports both converging functions.
func TestPostgresShape_LossIsNotTheChainCap(t *testing.T) {
	t.Parallel()
	graph, target := buildPostgresShapeGraph()
	tracer := NewTracer(graph, ".")

	covered := func(chains []CallChain) map[string]bool {
		out := map[string]bool{}
		for _, chain := range chains {
			for _, step := range chain.Steps {
				out[step.Function.Type+"."+step.Function.Name] = true
			}
		}
		return out
	}

	// Neither bound is anywhere near being hit...
	chains, truncated := tracer.TraceBackLimited(target, nil, 32, 128)
	if len(chains) != 1 || truncated {
		t.Fatalf("chains=%d truncated=%v, want 1 chain and no truncation", len(chains), truncated)
	}
	if got := len(chains[0].Steps); got != 4 {
		t.Fatalf("chain length = %d, want 4 (far below the depth cap of 32)", got)
	}

	// ...and raising the cap by three orders of magnitude recovers nothing.
	raised, _ := tracer.TraceBackLimited(target, nil, 32, 100000)
	if len(raised) != 1 {
		t.Fatalf("chains at cap=100000 = %d, want still 1: the cap is not what loses the function", len(raised))
	}
	both := covered(raised)
	if both["PgConnection.<init>"] && both["PgConnection.setReadOnly"] {
		t.Fatal("both converging functions covered; the fixture no longer exercises the collapse")
	}

	// The set has both, at their true distances.
	depths, terminals := tracer.ReachingFunctions(target, nil, 32)
	byName := map[string]int{}
	for key, d := range depths {
		if id, err := ParseFunctionID(key); err == nil {
			byName[id.Type+"."+id.Name] = d
		}
	}
	for _, want := range []string{"PgConnection.<init>", "PgConnection.setReadOnly"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("%s missing from the reaching set", want)
		} else if byName[want] != 2 {
			t.Errorf("depth of %s = %d, want 2", want, byName[want])
		}
	}

	// And the condensed traceback emits a chain for each route.
	condensed, total, _ := tracer.TraceBackCondensed(target, nil, 32, 128)
	if total != 2 {
		t.Fatalf("total condensed routes = %d, want 2", total)
	}
	got := covered(condensed)
	if !got["PgConnection.<init>"] || !got["PgConnection.setReadOnly"] {
		t.Errorf("condensed chains cover %v, want both converging functions", got)
	}
	if len(terminals) != 1 {
		t.Errorf("terminals = %d, want only the graph root Driver.connect", len(terminals))
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
