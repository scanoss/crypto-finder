// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// componentE is a second concrete implementation host used to model ambiguous
// interface dispatch (two impls of the same interface method live in closure).
var componentE = ComponentKey{Purl: "pkg:maven/net.crypto/e-benign", Version: "1.0.0"}

// TestStitch_NameOnlyDispatchDoesNotReach proves the core false-positive guard:
// an edge the producer could only resolve by method name + arity (no receiver
// type anchor) must NOT extend a reachability chain, even when a name-matching
// crypto sink exists in the closure. This is the `inputDecryptorProvider.get(...)`
// over-broad dispatch case that produced the bogus BCrypt chain.
func TestStitch_NameOnlyDispatchDoesNotReach(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					Resolution:      ResolutionNameOnly,
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "should-not-appear"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (name-only dispatch must fail closed): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 {
		t.Fatalf("suppressed len = %d, want 1", len(res.Suppressed))
	}
	if res.Suppressed[0].Reason != SuppressReasonNameOnly {
		t.Fatalf("suppressed reason = %q, want %q", res.Suppressed[0].Reason, SuppressReasonNameOnly)
	}
}

// TestStitch_UnknownResolutionFailsClosed proves the schema default is safe:
// an unclassified edge (zero-value resolution) is treated as untrusted and is
// never traversed. This protects against a producer that forgets to classify.
func TestStitch_UnknownResolutionFailsClosed(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					// Resolution intentionally left zero-value.
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "should-not-appear"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (unknown resolution must fail closed)", len(res.Chains))
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonUnknown {
		t.Fatalf("suppressed = %#v, want one unknown-resolution entry", res.Suppressed)
	}
}

// TestStitch_InterfaceDispatchUniqueImplReaches proves that interface dispatch
// is trusted when exactly one concrete implementation is present in the current
// component's direct dependencies — the legitimate single-impl case we must NOT
// lose.
func TestStitch_InterfaceDispatchUniqueImplReaches(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "net.crypto.Sink",
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "iface-unique"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1 (unique interface impl must reach)", len(res.Chains))
	}
	if res.Chains[0].FindingID != "iface-unique" {
		t.Fatalf("FindingID = %q, want iface-unique", res.Chains[0].FindingID)
	}
	if res.Chains[0].Confidence != ConfidenceHigh {
		t.Fatalf("Confidence = %q, want %q", res.Chains[0].Confidence, ConfidenceHigh)
	}
}

// TestStitch_InterfaceDispatchAmbiguousDropsClosed proves that when more than
// one concrete implementation of the dispatched interface method is present in
// the closure, the stitcher refuses to guess: it drops the whole call site and
// records it. Name+arity dispatch would otherwise fabricate a crypto chain
// through the wrong implementation.
func TestStitch_InterfaceDispatchAmbiguousDropsClosed(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "net.crypto.Sink",
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.BenignSink.encrypt(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "net.crypto.Sink",
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "should-not-appear"},
			},
		},
		componentE: {
			Component: componentE,
			Functions: []Function{
				{Signature: "net.crypto.BenignSink.encrypt(): void"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC, componentE}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (ambiguous interface dispatch must fail closed): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 {
		t.Fatalf("suppressed len = %d, want 1 grouped ambiguous call site", len(res.Suppressed))
	}
	if res.Suppressed[0].Reason != SuppressReasonAmbiguousDispatch {
		t.Fatalf("suppressed reason = %q, want %q", res.Suppressed[0].Reason, SuppressReasonAmbiguousDispatch)
	}
}

// TestStitch_InterfaceDispatchUniqueInDirectDependenciesReaches proves "unique"
// is judged against direct dependencies, not the universe of fragments: a
// sibling implementation that exists in storage but is NOT a direct dependency
// does not make the call site ambiguous.
func TestStitch_InterfaceDispatchUniqueInDirectDependenciesReaches(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "net.crypto.Sink",
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "net.crypto.BenignSink.encrypt(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "net.crypto.Sink",
					MethodName:      "encrypt",
					Arity:           0,
					CallSite:        10,
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "iface-unique-closure"},
			},
		},
		// componentE provides BenignSink but is NOT in the closure below.
		componentE: {
			Component: componentE,
			Functions: []Function{
				{Signature: "net.crypto.BenignSink.encrypt(): void"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC}} // only C in closure

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1 (only one impl in closure)", len(res.Chains))
	}
	if res.Chains[0].FindingID != "iface-unique-closure" {
		t.Fatalf("FindingID = %q, want iface-unique-closure", res.Chains[0].FindingID)
	}
}

// TestStitch_InternalNameOnlyEdgeDoesNotReach proves the policy applies to
// intra-component (internal) edges too. The internal edge lives in the bridge
// component B (not the root), so reachability depends on the edge being
// traversed — not on the sink happening to be a root entry point.
func TestStitch_InternalNameOnlyEdgeDoesNotReach(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "org.bridge.Bridge.bridge(): void",
					Resolution:      ResolutionExact,
				},
			},
		},
		componentB: {
			Component: componentB,
			Functions: []Function{
				{Signature: "org.bridge.Bridge.bridge(): void"},
				{Signature: "org.bridge.LocalSink.run(): void"},
			},
			InternalEdges: []InternalEdge{
				{
					Caller:     "org.bridge.Bridge.bridge(): void",
					Callee:     "org.bridge.LocalSink.run(): void",
					Resolution: ResolutionNameOnly,
					MethodName: "run",
					Arity:      0,
					CallSite:   20,
				},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "org.bridge.LocalSink.run(): void", FindingID: "should-not-appear"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentB}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (internal name-only must fail closed): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonNameOnly {
		t.Fatalf("suppressed = %#v, want one name_only entry", res.Suppressed)
	}
}

// TestStitch_InternalInterfaceUniqueImplReaches proves a unique-impl internal
// interface dispatch is trusted (the legitimate single-impl intra-component case).
func TestStitch_InternalInterfaceUniqueImplReaches(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "org.bridge.Bridge.bridge(): void",
					Resolution:      ResolutionExact,
				},
			},
		},
		componentB: {
			Component: componentB,
			Functions: []Function{
				{Signature: "org.bridge.Bridge.bridge(): void"},
				{Signature: "org.bridge.LocalSink.run(): void"},
			},
			InternalEdges: []InternalEdge{
				{
					Caller:       "org.bridge.Bridge.bridge(): void",
					Callee:       "org.bridge.LocalSink.run(): void",
					Resolution:   ResolutionInterfaceDispatch,
					DeclaredType: "org.bridge.Sink",
					MethodName:   "run",
					Arity:        0,
					CallSite:     20,
				},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "org.bridge.LocalSink.run(): void", FindingID: "internal-iface-unique"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentB}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 || res.Chains[0].FindingID != "internal-iface-unique" {
		t.Fatalf("chains = %#v, want one internal-iface-unique chain", res.Chains)
	}
}

// TestStitch_CrossBoundaryDispatchSiblingsAreAmbiguous is the key correctness
// case for "gate both": one interface call site in the bridge component expands
// to a co-located impl (internal edge) AND a dependency impl (external call).
// Judged separately each looks unique; judged together (same call site) they are
// ambiguous and MUST fail closed. This guards against fabricated reachability
// through the wrong implementation when impls straddle the component boundary.
func TestStitch_CrossBoundaryDispatchSiblingsAreAmbiguous(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.app.AppEntry.entry(): void",
					TargetSignature: "org.bridge.Bridge.bridge(): void",
					Resolution:      ResolutionExact,
				},
			},
		},
		componentB: {
			Component: componentB,
			Functions: []Function{
				{Signature: "org.bridge.Bridge.bridge(): void"},
				{Signature: "org.bridge.LocalSink.run(): void"},
			},
			InternalEdges: []InternalEdge{
				{
					Caller:       "org.bridge.Bridge.bridge(): void",
					Callee:       "org.bridge.LocalSink.run(): void",
					Resolution:   ResolutionInterfaceDispatch,
					DeclaredType: "org.bridge.Sink",
					MethodName:   "run",
					Arity:        0,
					CallSite:     20,
				},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "org.bridge.Bridge.bridge(): void",
					TargetSignature: "net.crypto.RemoteSink.run(): void",
					Resolution:      ResolutionInterfaceDispatch,
					DeclaredType:    "org.bridge.Sink",
					MethodName:      "run",
					Arity:           0,
					CallSite:        20,
				},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "org.bridge.LocalSink.run(): void", FindingID: "local-should-not-appear"},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.RemoteSink.run(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.RemoteSink.run(): void", FindingID: "remote-should-not-appear"},
			},
		},
	}
	deps := DependencyGraph{
		componentA: {componentB},
		componentB: {componentC},
	}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (cross-boundary dispatch siblings are ambiguous): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonAmbiguousDispatch {
		t.Fatalf("suppressed = %#v, want one ambiguous-dispatch entry grouped across the boundary", res.Suppressed)
	}
}
