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
	assertChain(t, res.Chains[0], []CallFrame{
		{Component: componentA, Function: "com.acme.app.AppEntry.entry(): void"},
		{Component: componentB, Function: "org.bridge.Bridge.bridge(): void"},
		{Component: componentC, Function: "net.crypto.CryptoSink.encrypt(): void"},
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
	assertChain(t, res.Chains[0], []CallFrame{
		{Component: componentA, Function: "com.acme.app.AppEntry.entry(): void"},
		{Component: componentC, Function: "net.crypto.CryptoSink.encrypt(): void"},
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

func assertChain(t *testing.T, got FindingChain, want []CallFrame) {
	t.Helper()
	if len(got.Frames) != len(want) {
		t.Fatalf("frames len = %d, want %d: %#v", len(got.Frames), len(want), got.Frames)
	}
	for i := range want {
		if got.Frames[i] != want[i] {
			t.Fatalf("frame[%d] = %#v, want %#v", i, got.Frames[i], want[i])
		}
	}
}
