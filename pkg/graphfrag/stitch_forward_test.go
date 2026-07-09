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
