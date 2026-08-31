// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"testing"
)

func TestFunctionInterner_ReusesFirstSeenIdentity(t *testing.T) {
	t.Parallel()

	var intern FunctionInterner
	a := intern.Intern(FrameIdentity{FunctionKey: "alpha#0", FunctionName: "App.alpha", FilePath: "App.java", StartLine: 1})
	b := intern.Intern(FrameIdentity{FunctionKey: "mid#0", FunctionName: "App.mid", FilePath: "App.java", StartLine: 11})
	aAgain := intern.Intern(FrameIdentity{FunctionKey: "alpha#0", FunctionName: "App.alpha", FilePath: "App.java", StartLine: 1})
	if a != 0 || b != 1 || aAgain != 0 {
		t.Fatalf("indexes a=%d b=%d aAgain=%d, want 0, 1, 0", a, b, aAgain)
	}
	if got := intern.Functions(); len(got) != 2 {
		t.Fatalf("catalog len = %d, want 2", len(got))
	}
}

func TestToCallgraphExport_InternsCallChainsBesideInlinedFrames(t *testing.T) {
	t.Parallel()

	root, deps, frags := chainEntryFixture()
	res, err := Stitch(root, deps, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	out := res.ToCallgraphExport(root, ScanMeta{RootModule: "com.acme:app", Ecosystem: "java"})
	if out.SchemaVersion != CallgraphSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", out.SchemaVersion, CallgraphSchemaVersion)
	}
	if CallgraphSchemaVersion != "6.14" {
		t.Fatalf("CallgraphSchemaVersion = %q, want 6.14", CallgraphSchemaVersion)
	}
	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]
	if len(fg.CallChains) == 0 {
		t.Fatal("inlined call_chains empty, want the 6.x sample preserved")
	}
	if len(fg.CallChainIndexes) != len(fg.CallChains) {
		t.Fatalf("call_chain_indexes len = %d, want %d matching inlined chains", len(fg.CallChainIndexes), len(fg.CallChains))
	}
	if len(out.Functions) == 0 {
		t.Fatal("functions catalog empty")
	}

	rebuilt, ok := ReconstructChainIdentities(out.Functions, fg.CallChainIndexes)
	if !ok {
		t.Fatal("call_chain_indexes pointed outside functions[]")
	}
	if len(rebuilt) != len(fg.CallChains) {
		t.Fatalf("reconstructed routes = %d, want %d", len(rebuilt), len(fg.CallChains))
	}
	for i, chain := range fg.CallChains {
		if len(rebuilt[i]) != len(chain) {
			t.Fatalf("route %d rebuilt len = %d, inlined len = %d", i, len(rebuilt[i]), len(chain))
		}
		for j, frame := range chain {
			got := rebuilt[i][j]
			if got.FunctionKey != frame.FunctionKey || got.FunctionName != frame.FunctionName || got.FilePath != frame.FilePath || got.StartLine != frame.StartLine {
				t.Fatalf("route %d frame %d identity %+v does not match inlined %+v", i, j, got, IdentityFromChainNode(frame))
			}
			if got.CanonicalSignature != frame.CanonicalSignature {
				t.Fatalf("route %d frame %d canonical_signature = %q, want %q", i, j, got.CanonicalSignature, frame.CanonicalSignature)
			}
		}
	}

	entryCount := len(out.CryptoEntryPoints)
	if entryCount < 2 {
		t.Fatalf("crypto_entry_points len = %d, want the full reverse-reach set (at least alpha and beta)", entryCount)
	}
}
