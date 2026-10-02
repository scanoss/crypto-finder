// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// One application entry point reaches the target through three methods of one
// library and one method of another. With a budget of two, the plain fill keeps
// two routes through the first library; with a module function the second
// library's route is kept instead.
func TestSelectTiered_UsesTheModuleFunction(t *testing.T) {
	t.Parallel()
	mk := func(pkg, name string) *FunctionDecl {
		return &FunctionDecl{ID: FunctionID{Package: pkg, Type: "C", Name: name}, FilePath: pkg + ".java", StartLine: 1, EndLine: 9}
	}
	app := mk("com.app", "main#0")
	sink := mk("org.sink", "use#0")
	mids := []*FunctionDecl{mk("org.x", "a#0"), mk("org.x", "b#0"), mk("org.x", "c#0"), mk("org.y", "z#0")}
	graph := &CallGraph{
		Functions:       map[string]*FunctionDecl{app.ID.String(): app, sink.ID.String(): sink},
		Callers:         map[string][]string{},
		EdgeResolutions: map[string]EdgeResolution{},
	}
	for i, m := range mids {
		graph.Functions[m.ID.String()] = m
		graph.Callers[sink.ID.String()] = append(graph.Callers[sink.ID.String()], m.ID.String())
		graph.Callers[m.ID.String()] = []string{app.ID.String()}
		m.Calls = []FunctionCall{{Callee: sink.ID, Line: 2 + i}}
		app.Calls = append(app.Calls, FunctionCall{Callee: m.ID, Line: 2 + i})
	}
	user := map[string]bool{"com.app": true}
	modules := func(trace CondensedTrace) map[string]bool {
		seen := map[string]bool{}
		for _, chain := range trace.Chains {
			for _, step := range chain.Steps {
				if strings.HasPrefix(step.Function.Package, "org.y") {
					seen["y"] = true
				}
			}
		}
		return seen
	}

	plain := NewTracer(graph, ".").TraceBackCondensed(sink.ID, user, 0, 2)
	if len(plain.Chains) != 2 || modules(plain)["y"] {
		t.Fatalf("plain chains = %+v, want 2 chains none through org.y", plain.Chains)
	}

	tracer := NewTracer(graph, ".")
	tracer.SetModuleFunc(func(key string) string {
		switch {
		case strings.HasPrefix(key, "org.x"):
			return "x"
		case strings.HasPrefix(key, "org.y"):
			return "y"
		}
		return ""
	})
	diverse := tracer.TraceBackCondensed(sink.ID, user, 0, 2)
	if len(diverse.Chains) != 2 || !modules(diverse)["y"] {
		t.Fatalf("diverse chains = %+v, want 2 chains, one through org.y", diverse.Chains)
	}
}
