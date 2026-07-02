// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestStitch_AmbiguousDispatchWithProvenanceResolvesToMatch proves the core
// disambiguation contract: a dispatch group with more than one candidate
// target in closure, where the call site carries ResolvedReceiverType
// provenance matching EXACTLY ONE candidate's declaring type, keeps that one
// edge and drops the rest — WITHOUT recording SuppressReasonAmbiguousDispatch.
// This is the mine-time KB-contract/return-type inference (see
// internal/callgraph.resolveParameterPassthroughDispatch) paying off at
// stitch time.
func TestStitch_AmbiguousDispatchWithProvenanceResolvesToMatch(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:               "com.acme.app.AppEntry.entry(): void",
					TargetSignature:      "net.crypto.CryptoSink.encrypt(): void",
					Resolution:           ResolutionInterfaceDispatch,
					DeclaredType:         "net.crypto.Sink",
					MethodName:           "encrypt",
					Arity:                0,
					CallSite:             10,
					ResolvedReceiverType: "CryptoSink",
				},
				{
					Caller:               "com.acme.app.AppEntry.entry(): void",
					TargetSignature:      "net.crypto.BenignSink.encrypt(): void",
					Resolution:           ResolutionInterfaceDispatch,
					DeclaredType:         "net.crypto.Sink",
					MethodName:           "encrypt",
					Arity:                0,
					CallSite:             10,
					ResolvedReceiverType: "CryptoSink",
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void", FunctionName: "net.crypto.CryptoSink.encrypt"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "resolved-by-provenance"},
			},
		},
		componentE: {
			Component: componentE,
			Functions: []Function{
				{Signature: "net.crypto.BenignSink.encrypt(): void", FunctionName: "net.crypto.BenignSink.encrypt"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC, componentE}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1 (provenance must disambiguate): %#v", len(res.Chains), res.Chains)
	}
	if res.Chains[0].FindingID != "resolved-by-provenance" {
		t.Fatalf("FindingID = %q, want resolved-by-provenance", res.Chains[0].FindingID)
	}
	if len(res.Suppressed) != 0 {
		t.Fatalf("suppressed = %#v, want none — a resolved-by-provenance group must not be recorded as ambiguous", res.Suppressed)
	}
}

// TestStitch_AmbiguousDispatchWithoutProvenanceStillFailsClosed is the
// regression guard: a dispatch group with no ResolvedReceiverType on any
// sibling behaves EXACTLY as before this change — fail closed, suppressed,
// zero chains. Proves the disambiguation is strictly additive and never
// changes the default policy for call sites inference did not resolve.
func TestStitch_AmbiguousDispatchWithoutProvenanceStillFailsClosed(t *testing.T) {
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
					// ResolvedReceiverType intentionally left empty.
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
				{Signature: "net.crypto.CryptoSink.encrypt(): void", FunctionName: "net.crypto.CryptoSink.encrypt"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "should-not-appear"},
			},
		},
		componentE: {
			Component: componentE,
			Functions: []Function{
				{Signature: "net.crypto.BenignSink.encrypt(): void", FunctionName: "net.crypto.BenignSink.encrypt"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC, componentE}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (no provenance -> fail closed, regression): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonAmbiguousDispatch {
		t.Fatalf("suppressed = %#v, want one ambiguous-dispatch entry", res.Suppressed)
	}
}

// TestStitch_AmbiguousDispatchWithProvenanceMatchingNothingFailsClosed proves
// a resolved receiver type that matches NEITHER candidate (stale/foreign type,
// e.g. a producer bug or a type outside this dispatch group's candidate set)
// is treated exactly like no provenance at all — fail closed, never a guess.
func TestStitch_AmbiguousDispatchWithProvenanceMatchingNothingFailsClosed(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:               "com.acme.app.AppEntry.entry(): void",
					TargetSignature:      "net.crypto.CryptoSink.encrypt(): void",
					Resolution:           ResolutionInterfaceDispatch,
					DeclaredType:         "net.crypto.Sink",
					MethodName:           "encrypt",
					Arity:                0,
					CallSite:             10,
					ResolvedReceiverType: "SomeUnrelatedType",
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
				{Signature: "net.crypto.CryptoSink.encrypt(): void", FunctionName: "net.crypto.CryptoSink.encrypt"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "should-not-appear"},
			},
		},
		componentE: {
			Component: componentE,
			Functions: []Function{
				{Signature: "net.crypto.BenignSink.encrypt(): void", FunctionName: "net.crypto.BenignSink.encrypt"},
			},
		},
	}
	deps := DependencyGraph{componentA: {componentC, componentE}}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Fatalf("chains len = %d, want 0 (provenance matching nothing -> fail closed): %#v", len(res.Chains), res.Chains)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonAmbiguousDispatch {
		t.Fatalf("suppressed = %#v, want one ambiguous-dispatch entry", res.Suppressed)
	}
}
