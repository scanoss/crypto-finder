// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"reflect"
	"testing"
)

// TestToCallgraphExport_DependencyFindingCarriesItsProvenance: the stitched
// finding of a transitive dependency names its component, package URL and
// route from the root in the dependency graph, as the live export does; the
// root's own finding carries none.
func TestToCallgraphExport_DependencyFindingCarriesItsProvenance(t *testing.T) {
	t.Parallel()
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Module:    "com.acme:a-app",
			Functions: []Function{
				{Signature: "com.acme.app.AppEntry.entry(): void", FilePath: "AppEntry.java"},
				{Signature: "com.acme.app.AppEntry.local(): void", FilePath: "AppEntry.java"},
			},
			InternalEdges: []InternalEdge{{Caller: "com.acme.app.AppEntry.entry(): void", Callee: "com.acme.app.AppEntry.local(): void", Resolution: ResolutionExact}},
			ExternalCalls: []ExternalCall{{
				Caller:          "com.acme.app.AppEntry.entry(): void",
				TargetSignature: "org.bridge.Bridge.bridge(): void",
				Resolution:      ResolutionExact,
			}},
			CryptoOperations: []CryptoOperation{{Function: "com.acme.app.AppEntry.local(): void", FindingID: "app00001", RuleID: "java.crypto.digest"}},
		},
		componentB: {
			Component: componentB,
			Module:    "org.bridge:b-bridge",
			Functions: []Function{{Signature: "org.bridge.Bridge.bridge(): void", FilePath: "Bridge.java"}},
			ExternalCalls: []ExternalCall{{
				Caller:          "org.bridge.Bridge.bridge(): void",
				TargetSignature: "net.crypto.CryptoSink.encrypt(): void",
				Resolution:      ResolutionExact,
			}},
		},
		componentC: {
			Component: componentC,
			Module:    "net.crypto:c-crypto",
			Functions: []Function{{Signature: "net.crypto.CryptoSink.encrypt(): void", FilePath: "CryptoSink.java", StartLine: 3}},
			CryptoOperations: []CryptoOperation{{
				Function: "net.crypto.CryptoSink.encrypt(): void", FindingID: "beaecdb7",
				RuleID: "java.crypto.cipher.getinstance", Symbol: "javax.crypto.Cipher.getInstance",
				FilePath: "CryptoSink.java", StartLine: 5,
			}},
		},
	}
	deps := DependencyGraph{componentA: {componentB}, componentB: {componentC}}
	res, err := StitchWithOptions(componentA, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	export := res.ToCallgraphExport(componentA, ScanMeta{Ecosystem: "java", RootModule: "com.acme:a-app"})

	want := &ExportFindingDependency{
		Module: "net.crypto:c-crypto", Version: "1.0.0", PURL: "pkg:maven/net.crypto/c-crypto@1.0.0",
		Relationship: DependencyTransitive,
		Path: []ExportDependencyPathStep{
			{Module: "org.bridge:b-bridge", Version: "1.0.0", PURL: "pkg:maven/org.bridge/b-bridge@1.0.0"},
			{Module: "net.crypto:c-crypto", Version: "1.0.0", PURL: "pkg:maven/net.crypto/c-crypto@1.0.0"},
		},
	}
	var sawDependency, sawRoot bool
	for _, fg := range export.FindingGraphs {
		// Served finding ids are recomputed; the terminal frame says whose it is.
		chain := fg.CallChains[0]
		if chain[len(chain)-1].FunctionKey == "com.acme.app.AppEntry.local(): void" {
			sawRoot = true
			if fg.Dependency != nil {
				t.Errorf("root finding carries dependency %+v", fg.Dependency)
			}
			continue
		}
		sawDependency = true
		if !reflect.DeepEqual(fg.Dependency, want) {
			t.Errorf("%s: dependency = %+v, want %+v", fg.FindingID, fg.Dependency, want)
		}
	}
	if !sawDependency || !sawRoot {
		t.Fatalf("%d finding graphs, want the root's and the dependency's finding", len(export.FindingGraphs))
	}
}
