// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"errors"
	"testing"
)

var (
	componentA = ComponentKey{Purl: "pkg:maven/com.acme/a-app", Version: "1.0.0"}
	componentB = ComponentKey{Purl: "pkg:maven/org.bridge/b-bridge", Version: "1.0.0"}
	componentC = ComponentKey{Purl: "pkg:maven/net.crypto/c-crypto", Version: "1.0.0"}
	componentD = ComponentKey{Purl: "pkg:maven/net.crypto/c-crypto", Version: "2.0.0"}
)

func TestStitch_ZeroFindingBridgeConnectsRootToTransitiveCrypto(t *testing.T) {
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Module:    "com.acme:a-app",
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void", FilePath: "AppEntry.java"},
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
			Module:    "org.bridge:b-bridge",
			Functions: []Function{
				{Signature: "org.bridge.Bridge.bridge(): void", FilePath: "Bridge.java"},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "org.bridge.Bridge.bridge(): void",
					TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
					Resolution:      ResolutionExact,
				},
			},
			// This is the point of the test: B has no crypto operations, but
			// it is still required as the bridge between A and C.
			CryptoOperations: nil,
		},
		componentC: {
			Component: componentC,
			Module:    "net.crypto:c-crypto",
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void", FilePath: "CryptoSink.java"},
			},
			CryptoOperations: []CryptoOperation{
				{
					Function:  "net.crypto.CryptoSink.encrypt(): void",
					FindingID: "beaecdb7",
					RuleID:    "java.crypto.cipher.getinstance",
					Symbol:    "javax.crypto.Cipher.getInstance",
				},
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
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1", len(res.Chains))
	}
	assertChain(t, res.Chains[0], []string{
		"com.acme.app.AppEntry.entry(): void",
		"org.bridge.Bridge.bridge(): void",
		"net.crypto.CryptoSink.encrypt(): void",
	})
	if res.Chains[0].FindingID != "beaecdb7" {
		t.Fatalf("FindingID = %q, want beaecdb7", res.Chains[0].FindingID)
	}
}

func TestStitch_MissingBridgeFragmentFailsClosed(t *testing.T) {
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
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "beaecdb7"},
			},
		},
	}
	deps := DependencyGraph{
		componentA: {componentB},
		componentB: {componentC},
	}

	_, err := Stitch(componentA, deps, fragments)
	var missing *ErrMissingFragment
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *ErrMissingFragment", err)
	}
	if len(missing.Components) != 1 || missing.Components[0] != componentB {
		t.Fatalf("missing components = %#v, want only B", missing.Components)
	}
}

func TestStitch_UsesDependencyGraphVersionsForExternalCalls(t *testing.T) {
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
					Resolution:      ResolutionExact,
				},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "v1-finding"},
			},
		},
		componentD: {
			Component: componentD,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "v2-finding"},
			},
		},
	}
	deps := DependencyGraph{
		componentA: {componentC},
	}

	res, err := Stitch(componentA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1", len(res.Chains))
	}
	if res.Chains[0].FindingID != "v1-finding" {
		t.Fatalf("FindingID = %q, want v1-finding from dependency graph version", res.Chains[0].FindingID)
	}
	assertChain(t, res.Chains[0], []string{
		"com.acme.app.AppEntry.entry(): void",
		"net.crypto.CryptoSink.encrypt(): void",
	})
}

func TestStitch_DoesNotResolveExternalCallsThroughTransitiveDependencies(t *testing.T) {
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
					Resolution:      ResolutionExact,
				},
			},
		},
		componentB: {
			Component: componentB,
			Functions: []Function{
				{Signature: "org.bridge.Bridge.bridge(): void"},
			},
		},
		componentC: {
			Component: componentC,
			Functions: []Function{
				{Signature: "net.crypto.CryptoSink.encrypt(): void"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "transitive-only"},
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
		t.Fatalf("chains len = %d, want 0 because C is not a direct dependency of A: %#v", len(res.Chains), res.Chains)
	}
}

// TestStitch_CallFrameEnrichedWith1_2Data asserts that after a Stitch() of a
// 3-node, 2-component closure built from graph-fragment-1.2 data:
//   - frame[1].EntryCall equals the EntryCall on the traversed InternalEdge
//   - the last frame's Function.CanonicalSignature is non-empty
//   - the terminal CryptoOperation.CryptoCall is non-nil on the single chain
//
// This is the Phase 5 acceptance test.
func TestStitch_CallFrameEnrichedWith1_2Data(t *testing.T) {
	// Three nodes in two components:
	//   compA: entry() --[exact external, entryCall line=10]--> compB: bridge()
	//   compB: bridge() --[exact internal, entryCall line=20]--> compB: encrypt()
	//          encrypt() has a crypto op with CryptoCall populated
	entryCall10 := &CallSite{
		Line: 10,
		Parameters: []Parameter{
			{ParameterIndex: 0, Type: "byte[]", VariableName: "key"},
		},
	}
	entryCall20 := &CallSite{
		Line: 20,
		Parameters: []Parameter{
			{ParameterIndex: 0, Type: "byte[]", VariableName: "data"},
		},
	}

	compA := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	compB := ComponentKey{Purl: "pkg:maven/net.crypto/lib", Version: "2.0.0"}

	fragments := map[ComponentKey]Fragment{
		compA: {
			Component: compA,
			Module:    "com.acme:app",
			Functions: []Function{
				{
					Signature:          "com.acme.App.entry#0",
					FunctionName:       "com.acme.App.entry",
					CanonicalSignature: "com.acme.App.entry(): void",
				},
			},
			ExternalCalls: []ExternalCall{
				{
					Caller:          "com.acme.App.entry#0",
					TargetSignature: "net.crypto.Lib.bridge#0",
					Resolution:      ResolutionExact,
					EntryCall:       entryCall10,
				},
			},
		},
		compB: {
			Component: compB,
			Module:    "net.crypto:lib",
			Functions: []Function{
				{
					Signature:          "net.crypto.Lib.bridge#0",
					FunctionName:       "net.crypto.Lib.bridge",
					CanonicalSignature: "net.crypto.Lib.bridge(): void",
				},
				{
					Signature:          "net.crypto.Lib.encrypt#0",
					FunctionName:       "net.crypto.Lib.encrypt",
					CanonicalSignature: "net.crypto.Lib.encrypt(): void",
				},
			},
			InternalEdges: []InternalEdge{
				{
					Caller:     "net.crypto.Lib.bridge#0",
					Callee:     "net.crypto.Lib.encrypt#0",
					Resolution: ResolutionExact,
					EntryCall:  entryCall20,
				},
			},
			CryptoOperations: []CryptoOperation{
				{
					Function:  "net.crypto.Lib.encrypt#0",
					FindingID: "find-1",
					RuleID:    "java.crypto.cipher.getinstance",
					Symbol:    "javax.crypto.Cipher.getInstance",
					CryptoCall: &CryptoCall{
						FunctionName:       "javax.crypto.Cipher.getInstance",
						CanonicalSignature: "javax.crypto.Cipher.getInstance(String): Cipher",
					},
				},
			},
		},
	}

	deps := DependencyGraph{
		compA: {compB},
	}

	res, err := Stitch(compA, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if len(res.Chains) != 1 {
		t.Fatalf("chains len = %d, want 1", len(res.Chains))
	}

	chain := res.Chains[0]
	if len(chain.Frames) != 3 {
		t.Fatalf("frames len = %d, want 3", len(chain.Frames))
	}

	// frame[0] = root entry: no EntryCall (it's the root frame).
	frame0 := chain.Frames[0]
	if frame0.Signature != "com.acme.App.entry#0" {
		t.Errorf("frame[0].Signature = %q", frame0.Signature)
	}
	if frame0.EntryCall != nil {
		t.Errorf("frame[0].EntryCall = %#v, want nil (root frame)", frame0.EntryCall)
	}

	// frame[1] = bridge: EntryCall from the external edge (line=10, key param)
	frame1 := chain.Frames[1]
	if frame1.Signature != "net.crypto.Lib.bridge#0" {
		t.Errorf("frame[1].Signature = %q", frame1.Signature)
	}
	if frame1.EntryCall == nil {
		t.Fatal("frame[1].EntryCall is nil, want non-nil")
	}
	if frame1.EntryCall.Line != 10 {
		t.Errorf("frame[1].EntryCall.Line = %d, want 10", frame1.EntryCall.Line)
	}
	if len(frame1.EntryCall.Parameters) != 1 || frame1.EntryCall.Parameters[0].VariableName != "key" {
		t.Errorf("frame[1].EntryCall.Parameters = %#v", frame1.EntryCall.Parameters)
	}

	// frame[2] = encrypt: last frame; Function.CanonicalSignature non-empty.
	frame2 := chain.Frames[2]
	if frame2.Signature != "net.crypto.Lib.encrypt#0" {
		t.Errorf("frame[2].Signature = %q", frame2.Signature)
	}
	if frame2.Function.CanonicalSignature == "" {
		t.Errorf("frame[2].Function.CanonicalSignature is empty, want non-empty")
	}

	// Terminal CryptoOperation must carry CryptoCall.
	if len(res.Chains[0].Frames) > 0 {
		// The CryptoOperation is on the last node; check via CryptoOperations from the fragment.
		op := fragments[compB].CryptoOperations[0]
		if op.CryptoCall == nil {
			t.Error("terminal CryptoOperation.CryptoCall is nil, want non-nil")
		}
		if op.CryptoCall.FunctionName != "javax.crypto.Cipher.getInstance" {
			t.Errorf("CryptoCall.FunctionName = %q", op.CryptoCall.FunctionName)
		}
	}
}

func assertChain(t *testing.T, got FindingChain, wantSignatures []string) {
	t.Helper()
	if len(got.Frames) != len(wantSignatures) {
		t.Fatalf("frames len = %d, want %d: %#v", len(got.Frames), len(wantSignatures), got.Frames)
	}
	for i, sig := range wantSignatures {
		if got.Frames[i].Signature != sig {
			t.Fatalf("frame[%d] Signature = %q, want %q", i, got.Frames[i].Signature, sig)
		}
	}
}
