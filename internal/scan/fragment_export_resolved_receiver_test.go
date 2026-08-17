// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
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

func TestBuildGraphFragmentExport_DirectNewFieldReceiverStitchesOneImplementation(t *testing.T) {
	t.Parallel()

	src := `package com.example;
interface Operation { void run(); }
class ClosureA implements Operation { public void run() {} }
class ClosureB implements Operation { public void run() {} }
class Wrapper {
    private Operation operation;
    Wrapper() { this.operation = new ClosureA(); }
    void invoke() { operation.run(); }
}
`
	component := graphfrag.ComponentKey{Purl: "pkg:maven/com.example/direct-new", Version: "1.0.0"}
	fragment := buildModuleFragment(t, component, "com.example", "Wrapper.java", src, &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: "Wrapper.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "closure-a-run",
				StartLine: 3,
				EndLine:   3,
				Match:     "run()",
				Rules:     []entities.RuleInfo{{ID: "java.test.closure-a-run"}},
			}},
		}},
	})
	caller := "com.example.(Wrapper).invoke#0"
	for _, target := range []string{
		"com.example.(ClosureA).run#0",
		"com.example.(ClosureB).run#0",
	} {
		var edge *graphfrag.InternalEdge
		for i := range fragment.InternalEdges {
			candidate := &fragment.InternalEdges[i]
			if candidate.Caller == caller && candidate.Callee == target {
				edge = candidate
				break
			}
		}
		if edge == nil {
			t.Fatalf("internal edge %s -> %s not found", caller, target)
		}
		if edge.ResolvedReceiverType != "ClosureA" {
			t.Fatalf("%s exported receiver provenance = %q, want ClosureA", target, edge.ResolvedReceiverType)
		}
	}

	result, err := graphfrag.StitchWithOptions(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment}, graphfrag.StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	if len(result.Chains) != 1 {
		t.Fatalf("chains = %#v, want one ClosureA survivor", result.Chains)
	}
	if result.Chains[0].FindingID != "closure-a-run" {
		t.Fatalf("FindingID = %q, want closure-a-run", result.Chains[0].FindingID)
	}
	if len(result.Suppressed) != 0 {
		t.Fatalf("suppressed = %#v, want no dispatch fan-out suppression", result.Suppressed)
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
