// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// moduleGraph: one application entry point reaches the target through three
// methods of library x by plain calls, and through library y only over an
// interface dispatch edge, a weaker evidence tier.
func moduleGraph() (*CallGraph, FunctionID) {
	mk := func(pkg, typ, name string, line int) *FunctionDecl {
		return &FunctionDecl{ID: FunctionID{Package: pkg, Type: typ, Name: name}, FilePath: pkg + "/" + typ + ".java", StartLine: line, EndLine: line + 20}
	}
	app := mk("com.app", "Main", "main#0", 10)
	sink := mk("org.sink", "Digest", "use#0", 500)
	graph := &CallGraph{
		Functions:       map[string]*FunctionDecl{app.ID.String(): app, sink.ID.String(): sink},
		Callers:         map[string][]string{},
		EdgeResolutions: map[string]EdgeResolution{},
	}
	link := func(caller, callee *FunctionDecl, line int) {
		graph.Callers[callee.ID.String()] = append(graph.Callers[callee.ID.String()], caller.ID.String())
		caller.Calls = append(caller.Calls, FunctionCall{Callee: callee.ID, Line: line})
	}
	for i, name := range []string{"a#0", "b#0", "c#0"} {
		x := mk("org.x", "X", name, 100+50*i)
		graph.Functions[x.ID.String()] = x
		link(app, x, 11+i)
		link(x, sink, 101+50*i)
	}
	y := mk("org.y", "Impl", "run#0", 300)
	graph.Functions[y.ID.String()] = y
	link(y, sink, 301)
	graph.Callers[y.ID.String()] = append(graph.Callers[y.ID.String()], app.ID.String())
	app.Calls = append(app.Calls, FunctionCall{Callee: FunctionID{Package: "org.y", Type: "Task", Name: "run#0"}, Line: 20})
	res := EdgeResolution{Kind: EdgeKindInterfaceDispatch, CallSite: 20, StartCol: 3, EndCol: 12, DeclaredType: "org.y.Task", MethodName: "run"}
	graph.EdgeResolutions[EdgeResolutionKey(app.ID.String(), y.ID.String(), res)] = res
	return graph, sink.ID
}

func throughY(trace CondensedTrace) bool {
	for _, chain := range trace.Chains {
		for _, step := range chain.Steps {
			if step.Function.Package == "org.y" {
				return true
			}
		}
	}
	return false
}

// With a budget of two the strongest tier's variants fill the plain
// selection; with a module function the library only the dispatch tier
// reaches is shown, and the first chain is still a plain-call route.
func TestSelectTiered_ModuleFunctionShowsALibraryOfAWeakerTier(t *testing.T) {
	t.Parallel()
	user := map[string]bool{"com.app": true}

	graph, sink := moduleGraph()
	plain := NewTracer(graph, ".").TraceBackCondensed(sink, user, 0, 2)
	if len(plain.Chains) != 2 || throughY(plain) {
		t.Fatalf("plain chains = %+v, want 2 chains through org.x only", plain.Chains)
	}

	graph, sink = moduleGraph()
	tracer := NewTracer(graph, ".")
	tracer.SetModuleFunc(func(key string) string {
		switch {
		case strings.HasPrefix(key, "org.x"):
			return "x"
		case strings.HasPrefix(key, "org.y"):
			return "y"
		case strings.HasPrefix(key, "org.sink"):
			return "sink"
		}
		return ""
	})
	diverse := tracer.TraceBackCondensed(sink, user, 0, 2)
	if len(diverse.Chains) != 2 || !throughY(diverse) {
		t.Fatalf("diverse chains = %+v, want 2 chains, one through org.y", diverse.Chains)
	}
	for _, step := range diverse.Chains[0].Steps {
		if step.Function.Package == "org.y" {
			t.Fatalf("first chain %+v crosses the dispatch edge; the strongest route must stay first", diverse.Chains[0])
		}
	}
}
