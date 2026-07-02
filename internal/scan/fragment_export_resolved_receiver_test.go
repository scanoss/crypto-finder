// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// TestBuildGraphFragmentExport_CarriesResolvedReceiverType proves that an
// interface-dispatch call site whose receiver the callgraph builder resolved
// to a concrete type (EdgeResolution.ResolvedReceiverType, e.g. stamped by
// resolveParameterPassthroughDispatch for a password4j-shaped pass-through
// call) produces a fragment edge carrying resolved_receiver_type — the field
// pkg/graphfrag's stitcher reads to disambiguate an otherwise-ambiguous
// dispatch group (see pkg/graphfrag/stitch_receiver_provenance_test.go).
func TestBuildGraphFragmentExport_CarriesResolvedReceiverType(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "com.acme", Type: "Builder", Name: "withPBKDF2#0"}
	ifaceID := callgraph.FunctionID{Package: "com.acme", Type: "AbstractHashingFunction", Name: "hash#3"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			callerID.String(): {
				ID:        callerID,
				FilePath:  "Builder.java",
				StartLine: 1,
				EndLine:   5,
				Calls: []callgraph.FunctionCall{
					{Callee: ifaceID, FilePath: "Builder.java", Line: 3, Raw: "hasher.hash(...)"},
				},
			},
			ifaceID.String(): {ID: ifaceID, FilePath: "AbstractHashingFunction.java", StartLine: 1, EndLine: 4},
		},
		Callers: map[string][]string{
			ifaceID.String(): {callerID.String()},
		},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	res := callgraph.EdgeResolution{
		Kind:                 callgraph.EdgeKindExact,
		MethodName:           "hash",
		Arity:                3,
		CallSite:             3,
		ResolvedReceiverType: "PBKDF2Function",
	}
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(callerID.String(), ifaceID.String(), res)] = res

	payload := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	edge := findInternalEdge(&payload, callerID.String(), ifaceID.String())
	if edge == nil {
		t.Fatalf("internal edge %s -> %s not found in export", callerID.String(), ifaceID.String())
	}
	if edge.ResolvedReceiverType != "PBKDF2Function" {
		t.Fatalf("ResolvedReceiverType = %q, want %q", edge.ResolvedReceiverType, "PBKDF2Function")
	}
}

// TestBuildGraphFragmentExport_OmitsResolvedReceiverTypeWhenUnresolved proves
// the field is empty (and therefore omitted on the wire via omitempty) for the
// common case: an edge inference did not resolve a concrete receiver for.
// This is the backward-compatibility contract — a v0.12.0 stitcher parsing a
// v1.6 fragment sees the SAME shape it always has for these edges.
func TestBuildGraphFragmentExport_OmitsResolvedReceiverTypeWhenUnresolved(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "com.acme", Type: "Builder", Name: "with#0"}
	ifaceID := callgraph.FunctionID{Package: "com.acme", Type: "HashingFunction", Name: "hash#3"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			callerID.String(): {
				ID:        callerID,
				FilePath:  "Builder.java",
				StartLine: 1,
				EndLine:   5,
				Calls: []callgraph.FunctionCall{
					{Callee: ifaceID, FilePath: "Builder.java", Line: 3, Raw: "hasher.hash(...)"},
				},
			},
			ifaceID.String(): {ID: ifaceID, FilePath: "HashingFunction.java", StartLine: 1, EndLine: 4},
		},
		Callers: map[string][]string{
			ifaceID.String(): {callerID.String()},
		},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	res := callgraph.EdgeResolution{
		Kind:         callgraph.EdgeKindInterfaceDispatch,
		DeclaredType: "com.acme.HashingFunction",
		MethodName:   "hash",
		Arity:        3,
		CallSite:     3,
		// ResolvedReceiverType intentionally left empty: inference did not resolve it.
	}
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(callerID.String(), ifaceID.String(), res)] = res

	payload := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	edge := findInternalEdge(&payload, callerID.String(), ifaceID.String())
	if edge == nil {
		t.Fatalf("internal edge %s -> %s not found in export", callerID.String(), ifaceID.String())
	}
	if edge.ResolvedReceiverType != "" {
		t.Fatalf("ResolvedReceiverType = %q, want empty for an unresolved dispatch edge", edge.ResolvedReceiverType)
	}
}
