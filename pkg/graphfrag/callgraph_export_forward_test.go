// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"bytes"
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

func TestToCallgraphExportForwardCallsExposeAmbiguousDispatch(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	entryCall := &CallSite{Line: 23, Parameters: []Parameter{{
		ParameterIndex:     0,
		ArgumentExpression: "payload",
		SourceNodes:        []SourceNode{{Type: "PARAMETER", Name: "payload"}},
	}}}
	fragment := Fragment{
		Component: root,
		Module:    "com.acme:app",
		Functions: []Function{
			{Signature: "anchor", FunctionName: "com.acme.App.anchor", DeclaringType: "App", CanonicalSignature: "com.acme.App.anchor(byte[]): void", ReturnType: "void", ParameterTypes: []string{"byte[]"}, FilePath: "App.java"},
			{Signature: "dispatch", FunctionName: "com.acme.App.dispatch", DeclaringType: "App", CanonicalSignature: "com.acme.App.dispatch(Processor, byte[]): byte[]", ReturnType: "byte[]", ParameterTypes: []string{"Processor", "byte[]"}, FilePath: "App.java"},
			{Signature: "impl-a", FunctionName: "com.acme.FirstProcessor.apply", DeclaringType: "FirstProcessor", CanonicalSignature: "com.acme.FirstProcessor.apply(byte[]): byte[]", ReturnType: "byte[]", ParameterTypes: []string{"byte[]"}, FilePath: "App.java"},
			{Signature: "impl-b", FunctionName: "com.acme.SecondProcessor.apply", DeclaringType: "SecondProcessor", CanonicalSignature: "com.acme.SecondProcessor.apply(byte[]): byte[]", ReturnType: "byte[]", ParameterTypes: []string{"byte[]"}, FilePath: "App.java"},
		},
		InternalEdges: []InternalEdge{
			{Caller: "anchor", Callee: "dispatch", Resolution: ResolutionExact, EntryCall: &CallSite{Line: 11}},
			{Caller: "dispatch", Callee: "impl-b", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 1, CallSite: 23, StartCol: 9, EndCol: 33, EntryCall: entryCall},
			{Caller: "dispatch", Callee: "impl-a", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 1, CallSite: 23, StartCol: 9, EndCol: 33, EntryCall: entryCall},
			{Caller: "dispatch", Callee: "impl-b", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 1, CallSite: 23, StartCol: 38, EndCol: 62, EntryCall: entryCall},
			{Caller: "dispatch", Callee: "impl-a", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 1, CallSite: 23, StartCol: 38, EndCol: 62, EntryCall: entryCall},
		},
		CryptoOperations: []CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r1", Symbol: "Cipher.run"}},
	}

	export := stitchForExport(t, root, DependencyGraph{}, map[ComponentKey]Fragment{root: fragment}, StitchOptions{
		ForwardClosure:  true,
		MaxForwardDepth: 2,
	})
	forward := export.FindingGraphs[0].ForwardCalls
	if forward == nil {
		t.Fatal("forward_calls missing")
	}
	if forward.Truncated {
		t.Fatal("truncated = true, ambiguity must remain distinct from budget truncation")
	}
	for _, node := range forward.Nodes {
		if node.FunctionKey == "impl-a" || node.FunctionKey == "impl-b" {
			t.Fatalf("ambiguous candidate leaked into forward nodes: %#v", forward.Nodes)
		}
	}
	if len(forward.AmbiguousCalls) != 2 {
		t.Fatalf("ambiguous_calls = %#v, want two same-line groups", forward.AmbiguousCalls)
	}
	group := forward.AmbiguousCalls[0]
	if group.GroupID == forward.AmbiguousCalls[1].GroupID {
		t.Fatalf("same-line call sites share group_id %q", group.GroupID)
	}
	if group.GroupID == "" || group.Reason != SuppressReasonAmbiguousDispatch || group.Completeness != AmbiguityComplete {
		t.Fatalf("ambiguous group = %#v", group)
	}
	if group.CallSite.CallerFunctionKey != "dispatch" || group.CallSite.Line != 23 || group.CallSite.StartCol != 9 || group.CallSite.EndCol != 33 || group.CallSite.MethodName != "apply" || group.CallSite.Arity != 1 {
		t.Errorf("call_site = %#v", group.CallSite)
	}
	if len(group.Candidates) != 2 {
		t.Fatalf("candidates = %#v, want two", group.Candidates)
	}
	if group.Candidates[0].CanonicalSignature != "com.acme.FirstProcessor.apply(byte[]): byte[]" ||
		group.Candidates[1].CanonicalSignature != "com.acme.SecondProcessor.apply(byte[]): byte[]" {
		t.Errorf("candidate order/identity = %#v", group.Candidates)
	}
	for _, candidate := range group.Candidates {
		if candidate.CandidateID == "" || candidate.DeclaringType == "" || candidate.ReturnType != "byte[]" || len(candidate.ParameterTypes) != 1 {
			t.Errorf("incomplete candidate = %#v", candidate)
		}
		if candidate.EntryCall == nil || len(candidate.EntryCall.Parameters) != 1 || len(candidate.EntryCall.Parameters[0].SourceNodes) != 1 {
			t.Errorf("candidate evidence missing = %#v", candidate)
		}
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"ambiguous_calls"`)) {
		t.Fatalf("serialized export lacks ambiguous_calls: %s", raw)
	}
}

func TestToCallgraphExportForwardCallsMarksLegacyAmbiguityPartial(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:generic/app", Version: "1"}
	fragment := Fragment{
		Component: root,
		Functions: []Function{
			{Signature: "anchor", FunctionName: "app.anchor"},
			{Signature: "impl-a", FunctionName: "app.First.apply"},
			{Signature: "impl-b", FunctionName: "app.Second.apply"},
		},
		InternalEdges: []InternalEdge{
			{Caller: "anchor", Callee: "impl-a", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 0, CallSite: 7},
			{Caller: "anchor", Callee: "impl-b", Resolution: ResolutionInterfaceDispatch, MethodName: "apply", Arity: 0, CallSite: 7},
		},
		CryptoOperations: []CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r1"}},
	}

	export := stitchForExport(t, root, DependencyGraph{}, map[ComponentKey]Fragment{root: fragment}, StitchOptions{ForwardClosure: true})
	group := export.FindingGraphs[0].ForwardCalls.AmbiguousCalls[0]
	if group.Completeness != AmbiguityPartial {
		t.Fatalf("completeness = %q, want %q", group.Completeness, AmbiguityPartial)
	}
	for _, candidate := range group.Candidates {
		if candidate.CandidateID == "" || candidate.ParameterTypes == nil {
			t.Errorf("legacy candidate does not degrade explicitly: %#v", candidate)
		}
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
	if bytes.Equal(a, []byte("null")) || !bytes.Equal(a, b) {
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
