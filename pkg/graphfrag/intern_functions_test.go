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

func TestFunctionInterner_KeepsSameSignatureAcrossDependencies(t *testing.T) {
	t.Parallel()

	var intern FunctionInterner
	left := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:left", Version: "1.0.0", PURL: "pkg:maven/com.lib/left@1.0.0"},
	})
	right := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:right", Version: "2.0.0", PURL: "pkg:maven/com.lib/right@2.0.0"},
	})
	leftAgain := intern.Intern(FrameIdentity{
		FunctionKey:    "sink#0",
		FunctionName:   "com.lib.Sink.run",
		FilePath:       "Sink.java",
		StartLine:      10,
		DependencyInfo: &ExportDependencyInfo{Module: "com.lib:left", Version: "1.0.0", PURL: "pkg:maven/com.lib/left@1.0.0"},
	})
	if left == right {
		t.Fatalf("same function_key interned as one catalog row across two dependencies")
	}
	if leftAgain != left {
		t.Fatalf("left interned twice: first=%d again=%d", left, leftAgain)
	}
	got := intern.Functions()
	if len(got) != 2 {
		t.Fatalf("catalog len = %d, want 2", len(got))
	}
	if got[left].DependencyInfo == nil || got[left].DependencyInfo.Module != "com.lib:left" {
		t.Fatalf("left catalog row = %+v, want module com.lib:left", got[left].DependencyInfo)
	}
	if got[right].DependencyInfo == nil || got[right].DependencyInfo.Module != "com.lib:right" {
		t.Fatalf("right catalog row = %+v, want module com.lib:right", got[right].DependencyInfo)
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
			if (got.DependencyInfo == nil) != (frame.DependencyInfo == nil) {
				t.Fatalf("route %d frame %d dependency_info presence interned=%v inlined=%v", i, j, got.DependencyInfo, frame.DependencyInfo)
			}
			if got.DependencyInfo != nil && *got.DependencyInfo != *frame.DependencyInfo {
				t.Fatalf("route %d frame %d dependency_info interned=%+v inlined=%+v", i, j, *got.DependencyInfo, *frame.DependencyInfo)
			}
		}
	}

	entryCount := len(out.CryptoEntryPoints)
	if entryCount < 2 {
		t.Fatalf("crypto_entry_points len = %d, want the full reverse-reach set (at least alpha and beta)", entryCount)
	}
}
