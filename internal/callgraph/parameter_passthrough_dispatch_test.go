// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"path/filepath"
	"testing"
)

// TestResolveParameterPassthroughDispatch_ConstructorArgumentDisambiguates is
// the minimal reproduction of the password4j withPBKDF2 shape: a factory
// method (viaImplA) constructs a concrete SinkImplA and passes it, in one
// statement, to with(Sink), whose ENTIRE body immediately dispatches on that
// parameter (s.run()) — an interface call site that is genuinely ambiguous
// judged in isolation (2 concrete Sink implementors in the graph), but
// resolvable for viaImplA's specific call because it supplies a
// constructor-known concrete type.
//
// Asserts: a new direct edge viaImplA -> SinkImplA.run is recorded as exact
// and carries ResolvedReceiverType "SinkImplA" — the fragment exporter reads
// this to stamp graph-fragment resolved_receiver_type (see
// internal/scan/fragment_export_resolved_receiver_test.go), which the
// stitcher then uses to disambiguate (see
// pkg/graphfrag/stitch_receiver_provenance_test.go).
func TestResolveParameterPassthroughDispatch_ConstructorArgumentDisambiguates(t *testing.T) {
	root := t.TempDir()

	sinkID := FunctionID{Package: "com.acme", Type: "Sink", Name: "run#0"}
	implAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	implBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}
	withID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	viaAID := FunctionID{Package: "com.acme", Type: "Builder", Name: "viaImplA#0"}

	sinkIface := FunctionDecl{
		ID: sinkID, FilePath: filepath.Join(root, "Sink.java"), StartLine: 1, EndLine: 2,
		OwnerType: ownerTypeInterface, OwnerName: "Sink", Parameters: []FunctionParameter{},
	}
	implA := FunctionDecl{
		ID: implAID, FilePath: filepath.Join(root, "SinkImplA.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplA", Parameters: []FunctionParameter{},
	}
	implB := FunctionDecl{
		ID: implBID, FilePath: filepath.Join(root, "SinkImplB.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplB", Parameters: []FunctionParameter{},
	}
	// with(Sink s) { s.run(); } — the pass-through candidate: a single call
	// whose ReceiverVar ("s") names its own only parameter.
	withFn := FunctionDecl{
		ID: withID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 10, EndLine: 12,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "s"}},
		Calls: []FunctionCall{
			{Callee: sinkID, ReceiverVar: "s", FilePath: filepath.Join(root, "Builder.java"), Line: 11, Raw: "s.run()"},
		},
	}
	// viaImplA() { with(new SinkImplA()); } — passes a constructor-known
	// concrete type as the ambiguous call's ultimate receiver.
	viaA := FunctionDecl{
		ID: viaAID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 20, EndLine: 22,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Calls: []FunctionCall{
			{
				Callee:    withID,
				Arguments: []string{"new SinkImplA()"},
				ArgumentSources: [][]SourceNode{
					{
						{
							Type:         sourceNodeCallResult,
							CallTarget:   &FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "<init>#0"},
							DeclaredType: "SinkImplA",
						},
					},
				},
				FilePath: filepath.Join(root, "Builder.java"),
				Line:     21,
				Raw:      "with(new SinkImplA())",
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{sinkIface, implA, implB, withFn, viaA}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.acme"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Precondition: the with() call site is genuinely ambiguous in isolation —
	// both SinkImplA.run and SinkImplB.run are candidates.
	ambiguousKey := dispatchGroupKeyForTest(withID.String(), 11, "run", 0)
	implARes, ok := graph.EdgeResolutions[EdgeResolutionKey(withID.String(), implAID.String(), EdgeResolution{
		Kind: EdgeKindInterfaceDispatch, DeclaredType: "com.acme.Sink", MethodName: "run", Arity: 0, CallSite: 11,
	})]
	if !ok || implARes.Kind != EdgeKindInterfaceDispatch {
		t.Fatalf("precondition failed: expected interface_dispatch edge with#1 -> SinkImplA.run, got %#v (key=%v)", implARes, ambiguousKey)
	}

	// The disambiguated bypass edge: viaImplA -> SinkImplA.run, exact, carrying
	// ResolvedReceiverType "SinkImplA".
	bypassKey := EdgeResolutionKey(viaAID.String(), implAID.String(), EdgeResolution{
		Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 21,
	})
	bypass, ok := graph.EdgeResolutions[bypassKey]
	if !ok {
		t.Fatalf("expected a resolved pass-through bypass edge viaImplA -> SinkImplA.run; EdgeResolutions=%#v", graph.EdgeResolutions)
	}
	if bypass.Kind != EdgeKindExact {
		t.Fatalf("bypass edge kind = %q, want %q", bypass.Kind, EdgeKindExact)
	}
	if bypass.ResolvedReceiverType != "SinkImplA" {
		t.Fatalf("bypass edge ResolvedReceiverType = %q, want %q", bypass.ResolvedReceiverType, "SinkImplA")
	}

	// No bypass edge should exist to the OTHER implementor — the pass must not
	// guess when it has resolved the type.
	wrongKey := EdgeResolutionKey(viaAID.String(), implBID.String(), EdgeResolution{
		Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 21,
	})
	if _, ok := graph.EdgeResolutions[wrongKey]; ok {
		t.Fatalf("unexpected bypass edge viaImplA -> SinkImplB.run; the resolved type must only ever match SinkImplA")
	}
}

// dispatchGroupKeyForTest is a tiny readability helper for failure messages;
// it has no behavior of its own.
func dispatchGroupKeyForTest(caller string, callSite int, method string, arity int) dispatchAmbiguousGroupKey {
	return dispatchAmbiguousGroupKey{Caller: caller, CallSite: callSite, MethodName: method, Arity: arity}
}

// TestResolveParameterPassthroughDispatch_NoBypassWithoutConcreteArgument is
// the regression guard: when NO caller of the pass-through candidate supplies
// a staticaly concrete argument (e.g. the argument is itself another
// interface-typed value with no constructor/declared-return-type anchor), no
// bypass edge is added and the original ambiguous group is left exactly as
// the pre-existing fail-closed policy would judge it.
func TestResolveParameterPassthroughDispatch_NoBypassWithoutConcreteArgument(t *testing.T) {
	root := t.TempDir()

	sinkID := FunctionID{Package: "com.acme", Type: "Sink", Name: "run#0"}
	implAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	implBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}
	withID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	viaUnknownID := FunctionID{Package: "com.acme", Type: "Builder", Name: "viaUnknown#1"}

	sinkIface := FunctionDecl{
		ID: sinkID, FilePath: filepath.Join(root, "Sink.java"), StartLine: 1, EndLine: 2,
		OwnerType: ownerTypeInterface, OwnerName: "Sink", Parameters: []FunctionParameter{},
	}
	implA := FunctionDecl{
		ID: implAID, FilePath: filepath.Join(root, "SinkImplA.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplA", Parameters: []FunctionParameter{},
	}
	implB := FunctionDecl{
		ID: implBID, FilePath: filepath.Join(root, "SinkImplB.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplB", Parameters: []FunctionParameter{},
	}
	withFn := FunctionDecl{
		ID: withID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 10, EndLine: 12,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "s"}},
		Calls: []FunctionCall{
			{Callee: sinkID, ReceiverVar: "s", FilePath: filepath.Join(root, "Builder.java"), Line: 11, Raw: "s.run()"},
		},
	}
	// viaUnknown(Sink passthroughParam) { with(passthroughParam); } — the
	// argument is itself just a parameter with no constructor/return-type
	// anchor, so no concrete type can be resolved.
	viaUnknown := FunctionDecl{
		ID: viaUnknownID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 30, EndLine: 32,
		OwnerType:  ownerTypeClass,
		OwnerName:  "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "passthroughParam"}},
		Calls: []FunctionCall{
			{
				Callee:    withID,
				Arguments: []string{"passthroughParam"},
				FilePath:  filepath.Join(root, "Builder.java"),
				Line:      31,
				Raw:       "with(passthroughParam)",
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{sinkIface, implA, implB, withFn, viaUnknown}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.acme"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	for _, implKey := range []string{implAID.String(), implBID.String()} {
		key := EdgeResolutionKey(viaUnknownID.String(), implKey, EdgeResolution{
			Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 31,
		})
		if _, ok := graph.EdgeResolutions[key]; ok {
			t.Fatalf("unexpected bypass edge viaUnknown -> %s; no concrete argument type was available to resolve", implKey)
		}
	}
}
