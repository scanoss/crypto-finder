// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/reach/callgraph"
)

// Inlining a callee's returns marks the inlined copies, never the callee's own
// return sources: those belong to the graph, which later exports (and the
// parallel edge build) read.
func TestResolveCalleeReturnSourcesLeavesTheCalleeAlone(t *testing.T) {
	target := callgraph.FunctionID{Package: "p", Type: "T", Name: "algorithm#0"}
	guarded := &callgraph.SourceFlow{Guard: &callgraph.SourceGuard{Default: true}}
	callee := &callgraph.FunctionDecl{ID: target, ReturnSources: []callgraph.SourceNode{
		{Type: "STRING_LITERAL", Value: "AES", Flow: guarded},
		{Type: "STRING_LITERAL", Value: "DES"},
	}}
	ctx := &exportBuildContext{graph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{target.String(): callee}}}
	node := &callgraph.SourceNode{Type: sourceNodeTypeCallResult, CallTarget: &target}

	got := resolveCalleeReturnSources(ctx, node, 0)
	if len(got) != 2 || got[0].Flow == nil || !got[0].Flow.ReturnValue || got[1].Flow == nil || !got[1].Flow.ReturnValue {
		t.Fatalf("inlined returns %+v: want both marked as return values", got)
	}
	if got[0].Flow.Guard == nil || !got[0].Flow.Guard.Default {
		t.Errorf("the inlined copy lost its guard: %+v", got[0].Flow)
	}
	if guarded.ReturnValue || callee.ReturnSources[0].Flow != guarded || callee.ReturnSources[1].Flow != nil {
		t.Errorf("the callee's return sources changed: %+v %+v", callee.ReturnSources[0].Flow, callee.ReturnSources[1].Flow)
	}
}
