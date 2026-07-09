// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"strings"
	"testing"
)

// stitchForExport runs StitchWithOptions with ForwardClosure on and returns
// the CallgraphExport, failing the test on any stitch error.
func stitchForExport(t *testing.T, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) CallgraphExport {
	t.Helper()
	result, err := StitchWithOptions(root, deps, fragments, opts)
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	return result.ToCallgraphExport(root, ScanMeta{})
}

// TestToCallgraphExportForwardCallsEmitted asserts the forward closure is
// projected onto each finding graph: anchor identity, depth-annotated nodes
// sorted by function_key, and edges carrying entry_call with resolved values.
func TestToCallgraphExportForwardCallsEmitted(t *testing.T) {
	t.Parallel()

	// Mirrors the proposal's password4j example: the anchor (withPBKDF2)
	// forward-reaches a config getter and a factory whose call site carries
	// the resolved defaults.
	root, deps, fragments := buildForwardFixture(
		[]string{"withPBKDF2", "getPBKDF2Instance", "getInstance", "saltGen"},
		[]fwdEdgeSpec{
			{from: "withPBKDF2", to: "getPBKDF2Instance", line: 11},
			{from: "getPBKDF2Instance", to: "getInstance", line: 22, params: []Parameter{
				{ParameterIndex: 0, Type: "String", ArgumentExpression: "params.algorithm", ResolvedValue: "PBKDF2WithHmacSHA256"},
				{ParameterIndex: 1, Type: "int", ArgumentExpression: "params.iterations", ResolvedValue: "310000"},
				{ParameterIndex: 2, Type: "int", ArgumentExpression: "params.length", ResolvedValue: "256"},
			}},
			{from: "getInstance", to: "saltGen", line: 33},
		},
		[]CryptoOperation{
			{Function: "withPBKDF2", FindingID: "f-pbkdf2", RuleID: "r", Symbol: "HashBuilder.withPBKDF2"},
		},
		[]SupportingCall{
			{Function: "saltGen", Category: "config"},
		},
	)

	export := stitchForExport(t, root, deps, fragments, StitchOptions{ForwardClosure: true})

	if len(export.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs = %d, want 1", len(export.FindingGraphs))
	}
	fg := export.FindingGraphs[0]
	if fg.ForwardCalls == nil {
		t.Fatalf("forward_calls missing on finding graph %s", fg.FindingID)
	}
	fc := fg.ForwardCalls

	if fc.Anchor.FunctionKey != "withPBKDF2" {
		t.Errorf("anchor.function_key = %q, want withPBKDF2", fc.Anchor.FunctionKey)
	}
	if fc.MaxDepth != defaultMaxForwardDepth {
		t.Errorf("max_depth = %d, want %d", fc.MaxDepth, defaultMaxForwardDepth)
	}
	if fc.Truncated {
		t.Error("truncated = true, want false")
	}

	if len(fc.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(fc.Nodes))
	}
	for i := 1; i < len(fc.Nodes); i++ {
		if fc.Nodes[i-1].FunctionKey > fc.Nodes[i].FunctionKey {
			t.Errorf("nodes not sorted by function_key: %q > %q", fc.Nodes[i-1].FunctionKey, fc.Nodes[i].FunctionKey)
		}
	}
	byKey := map[string]ExportForwardNode{}
	for _, n := range fc.Nodes {
		byKey[n.FunctionKey] = n
	}
	if n := byKey["getPBKDF2Instance"]; n.Depth != 1 {
		t.Errorf("getPBKDF2Instance depth = %d, want 1", n.Depth)
	}
	if n := byKey["saltGen"]; n.Depth != 3 || !n.CryptoRelevant || n.SupportingCategory != "config" {
		t.Errorf("saltGen = %+v, want depth 3, crypto_relevant, supporting_category config", n)
	}

	if len(fc.Edges) != 3 {
		t.Fatalf("edges = %d, want 3", len(fc.Edges))
	}
	var factoryEdge *ExportForwardEdge
	for i := range fc.Edges {
		if fc.Edges[i].From == "getPBKDF2Instance" && fc.Edges[i].To == "getInstance" {
			factoryEdge = &fc.Edges[i]
		}
	}
	if factoryEdge == nil || factoryEdge.EntryCall == nil {
		t.Fatalf("getPBKDF2Instance->getInstance edge with entry_call missing: %+v", fc.Edges)
	}
	if got := len(factoryEdge.EntryCall.Parameters); got != 3 {
		t.Fatalf("factory edge parameters = %d, want 3", got)
	}
	if v := factoryEdge.EntryCall.Parameters[1].ResolvedValue; v != "310000" {
		t.Errorf("iterations resolved_value = %q, want 310000", v)
	}
}

// TestToCallgraphExportForwardCallsSharedAnchor asserts findings sharing one
// anchor inline the same projected forward_calls content.
func TestToCallgraphExportForwardCallsSharedAnchor(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "helper"},
		[]fwdEdgeSpec{{from: "anchor", to: "helper", line: 7}},
		[]CryptoOperation{
			{Function: "anchor", FindingID: "f-one", RuleID: "r1", Symbol: "S.one"},
			{Function: "anchor", FindingID: "f-two", RuleID: "r2", Symbol: "S.two"},
		},
		nil,
	)

	export := stitchForExport(t, root, deps, fragments, StitchOptions{ForwardClosure: true})

	if len(export.FindingGraphs) != 2 {
		t.Fatalf("finding_graphs = %d, want 2", len(export.FindingGraphs))
	}
	a, err := json.Marshal(export.FindingGraphs[0].ForwardCalls)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(export.FindingGraphs[1].ForwardCalls)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) == "null" || string(a) != string(b) {
		t.Errorf("shared-anchor findings differ or are empty:\n%s\n%s", a, b)
	}
}

// TestToCallgraphExportForwardCallsAbsentWhenOff asserts the export never
// contains the forward_calls key when the option is off (the projection-side
// half of the byte-identical gate).
func TestToCallgraphExportForwardCallsAbsentWhenOff(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "helper"},
		[]fwdEdgeSpec{{from: "anchor", to: "helper", line: 7}},
		[]CryptoOperation{
			{Function: "anchor", FindingID: "f-one", RuleID: "r1", Symbol: "S.one"},
		},
		nil,
	)

	export := stitchForExport(t, root, deps, fragments, StitchOptions{})
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "forward_calls") {
		t.Errorf("forward_calls present with option off:\n%s", raw)
	}
}
