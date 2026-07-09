// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"strings"
	"testing"
)

// fwdEdgeSpec is one directed internal edge in a forward-closure test fixture.
// line, when non-zero, attaches an EntryCall{Line: line} to the edge so tests
// can assert entry_call propagation. resolution defaults to ResolutionExact
// when zero.
type fwdEdgeSpec struct {
	from, to   string
	line       int
	resolution ResolutionKind
	params     []Parameter
}

// buildForwardFixture assembles a single-component Fragment from a flat
// function-name list, a set of directed edges, crypto operations (finding
// anchors), and supporting calls (annotation source). Every test in this file
// builds its graph through this helper so fixtures stay small and declarative.
func buildForwardFixture(
	functions []string,
	edges []fwdEdgeSpec,
	ops []CryptoOperation,
	supporting []SupportingCall,
) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := ComponentKey{Purl: "pkg:maven/com.acme/fwd", Version: "1.0.0"}

	fns := make([]Function, len(functions))
	for i, f := range functions {
		fns[i] = Function{
			Signature:    f,
			FunctionName: "com.acme.Fwd." + f,
			FilePath:     "Fwd.java",
		}
	}

	internal := make([]InternalEdge, 0, len(edges))
	for _, e := range edges {
		resolution := e.resolution
		if resolution == "" {
			resolution = ResolutionExact
		}
		ie := InternalEdge{Caller: e.from, Callee: e.to, Resolution: resolution}
		if e.line != 0 || len(e.params) > 0 {
			ie.EntryCall = &CallSite{Line: e.line, Parameters: e.params}
		}
		internal = append(internal, ie)
	}

	frag := Fragment{
		Component:        root,
		Module:           "com.acme:fwd",
		Functions:        fns,
		InternalEdges:    internal,
		CryptoOperations: ops,
		SupportingCalls:  supporting,
	}
	return root, DependencyGraph{}, map[ComponentKey]Fragment{root: frag}
}

// TestForwardClosure_OffIsByteIdentical is the load-bearing parity gate: with
// StitchOptions.ForwardClosure unset (zero value), the served output MUST
// carry no forward_calls key anywhere, regardless of how many other stitch
// options are set. This test must stay green through every later phase.
func TestForwardClosure_OffIsByteIdentical(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"entry", "a", "sink"},
		[]fwdEdgeSpec{
			{from: "entry", to: "a", line: 10},
			{from: "a", to: "sink", line: 20},
		},
		[]CryptoOperation{
			{Function: "sink", FindingID: "f-sink", RuleID: "r", Symbol: "Crypto.sink"},
		},
		nil,
	)

	for _, opts := range []StitchOptions{
		{},
		{EntryRootedOnly: true},
	} {
		res, err := StitchWithOptions(root, deps, fragments, opts)
		if err != nil {
			t.Fatalf("StitchWithOptions(%+v): %v", opts, err)
		}
		if res.forwardClosures != nil {
			t.Fatalf("opts=%+v: forwardClosures = %v, want nil (ForwardClosure off)", opts, res.forwardClosures)
		}

		out := res.ToCallgraphExport(root, ScanMeta{})
		if out.SchemaVersion != CallgraphSchemaVersion {
			t.Fatalf("opts=%+v: SchemaVersion = %q, want %q", opts, out.SchemaVersion, CallgraphSchemaVersion)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("opts=%+v: marshal: %v", opts, err)
		}
		if strings.Contains(string(raw), "forward_calls") {
			t.Fatalf("opts=%+v: forward_calls present with ForwardClosure off: %s", opts, raw)
		}
	}
}

// forwardNodeDepths collects each forward node's depth keyed by function
// signature — the order-independent assertion shape used by the model-level
// tests in this file (BFS discovery order is deterministic by construction,
// but tests assert on content, not incidental slice order).
func forwardNodeDepths(fc *forwardClosure) map[string]int {
	out := make(map[string]int, len(fc.nodes))
	for _, n := range fc.nodes {
		out[n.node.Function] = n.depth
	}
	return out
}

func findForwardEdge(fc *forwardClosure, from, to string) *forwardEdge {
	for i := range fc.edges {
		if fc.edges[i].from.Function == from && fc.edges[i].to.Function == to {
			return &fc.edges[i]
		}
	}
	return nil
}

// TestForwardClosure_LinearChain exercises the simplest shape: anchor -> a ->
// b -> sink, all exact-resolution edges. Asserts shortest-path depths, that
// every edge carries its entryCall (call-site data-flow), and truncated=false
// well within the default caps.
func TestForwardClosure_LinearChain(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"entry", "a", "b", "sink"},
		[]fwdEdgeSpec{
			{from: "entry", to: "a", line: 10, params: []Parameter{{ParameterIndex: 0, ResolvedValue: "X"}}},
			{from: "a", to: "b", line: 20},
			{from: "b", to: "sink", line: 30},
		},
		[]CryptoOperation{
			{Function: "entry", FindingID: "f1", RuleID: "r", Symbol: "Crypto.entry"},
		},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}

	anchor := graphNode{Component: root, Function: "entry"}
	fc := res.forwardClosures[anchor]
	if fc == nil {
		t.Fatalf("forwardClosures[%v] = nil, want a closure", anchor)
	}
	if fc.truncated {
		t.Fatalf("truncated = true, want false")
	}
	if fc.maxDepth != defaultMaxForwardDepth {
		t.Fatalf("maxDepth = %d, want %d", fc.maxDepth, defaultMaxForwardDepth)
	}
	if fc.anchor.Signature != "entry" {
		t.Fatalf("anchor.Signature = %q, want %q", fc.anchor.Signature, "entry")
	}

	depths := forwardNodeDepths(fc)
	want := map[string]int{"a": 1, "b": 2, "sink": 3}
	if len(depths) != len(want) {
		t.Fatalf("nodes = %v, want depths %v", depths, want)
	}
	for fn, d := range want {
		if depths[fn] != d {
			t.Errorf("depth[%q] = %d, want %d", fn, depths[fn], d)
		}
	}

	edge := findForwardEdge(fc, "entry", "a")
	if edge == nil || edge.entryCall == nil {
		t.Fatalf("entry->a edge/entryCall missing: %+v", edge)
	}
	if edge.entryCall.Line != 10 {
		t.Errorf("entry->a entryCall.Line = %d, want 10", edge.entryCall.Line)
	}
	if len(edge.entryCall.Parameters) != 1 || edge.entryCall.Parameters[0].ResolvedValue != "X" {
		t.Errorf("entry->a entryCall.Parameters = %+v, want resolved_value X", edge.entryCall.Parameters)
	}

	if e := findForwardEdge(fc, "a", "b"); e == nil || e.entryCall == nil || e.entryCall.Line != 20 {
		t.Errorf("a->b edge = %+v, want entryCall.Line=20", e)
	}
	if e := findForwardEdge(fc, "b", "sink"); e == nil || e.entryCall == nil || e.entryCall.Line != 30 {
		t.Errorf("b->sink edge = %+v, want entryCall.Line=30", e)
	}
}
