// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A dispatch edge's call names the interface method, not the implementation
// the edge leads to, so the caller holds no call to the implementation to
// take a line from. The chain step names the call site where the strongest
// resolution of the pair was recorded: that is the call the route was chosen
// by, and the site that reads interface_dispatch on the exported frame rather
// than the function's first line, which matches no recorded site.
func TestTraceBackCondensed_StepNamesTheStrongestCallSite(t *testing.T) {
	t.Parallel()
	mk := func(pkg, typ, name string, line int) *FunctionDecl {
		return &FunctionDecl{ID: FunctionID{Package: pkg, Type: typ, Name: name}, FilePath: typ + ".java", StartLine: line, EndLine: line + 20}
	}
	app := mk("com.app", "Main", "run#0", 10)
	pool := mk("org.lib", "Pool", "submit#0", 200)
	worker := mk("org.lib", "Worker", "run#0", 300)
	app.Calls = []FunctionCall{{Callee: pool.ID, Line: 11}}
	pool.Calls = []FunctionCall{
		{Callee: FunctionID{Package: "org.other", Type: "Job", Name: "run#0"}, Line: 203},
		{Callee: FunctionID{Package: "org.lib", Type: "Task", Name: "run#0"}, Line: 207},
	}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			app.ID.String(): app, pool.ID.String(): pool, worker.ID.String(): worker,
		},
		Callers: map[string][]string{
			pool.ID.String():   {app.ID.String()},
			worker.ID.String(): {pool.ID.String()},
		},
		EdgeResolutions: map[string]EdgeResolution{},
	}
	for _, res := range []EdgeResolution{
		{Kind: EdgeKindNameOnly, CallSite: 203, StartCol: 5, EndCol: 14, DeclaredType: "org.other.Job", MethodName: "run"},
		{Kind: EdgeKindInterfaceDispatch, CallSite: 207, StartCol: 9, EndCol: 19, DeclaredType: "org.lib.Task", MethodName: "run"},
	} {
		graph.EdgeResolutions[EdgeResolutionKey(pool.ID.String(), worker.ID.String(), res)] = res
	}

	trace := NewTracer(graph, ".").TraceBackCondensed(worker.ID, map[string]bool{"com.app": true}, 0, 4)

	if trace.Evidence != RouteEvidenceDispatch {
		t.Fatalf("Evidence = %q, want dispatch", trace.Evidence)
	}
	if len(trace.Chains) != 1 || len(trace.Chains[0].Steps) != 3 {
		t.Fatalf("Chains = %+v, want one 3-step chain", trace.Chains)
	}
	step := trace.Chains[0].Steps[1]
	if step.Line != 207 || step.StartCol != 9 || step.EndCol != 19 {
		t.Fatalf("Pool.submit step = line %d cols %d-%d, want the dispatch site 207, cols 9-19", step.Line, step.StartCol, step.EndCol)
	}
}
