// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/graphfrag/equiv"
)

// diamondFixtureSrc has a re-convergent ("diamond") call graph: the crypto-bearing
// function common() is reachable from the single entry entry() via TWO distinct
// paths — entry->left->common and entry->right->common.
//
// An unbounded all-simple-paths traversal emits BOTH chains. The bounded
// global-frontier traversal used by live `--export-callgraph` (TraceBackLimited)
// enqueues each function at most once, so re-convergent paths collapse to the
// single shortest chain. For the served stitch to match live output (the parity
// contract), pkg/graphfrag's trace() must collapse the same way — otherwise the
// stitched export carries an extra chain (ExtraInB) the live scan never produced.
const diamondFixtureSrc = `package com.app;

class Svc {
    void entryA() {
        mid();
    }
    void entryB() {
        mid();
    }
    void mid() {
        left();
        right();
    }
    void left() {
        common();
    }
    void right() {
        common();
    }
    void common() {
        javax.crypto.Cipher.getInstance("AES");
    }
}
`

// TestEquivalence_Diamond_ReconvergentPathsCollapse asserts the served stitch
// reproduces the live `--export-callgraph` output on a re-convergent graph:
// re-convergent paths must collapse to a single chain, exactly as the bounded
// live tracer does. Pre-fix (unbounded all-simple-paths stitch DFS) this fails
// with ExtraInB — the stitch emits both diamond paths while live emits one.
func TestEquivalence_Diamond_ReconvergentPathsCollapse(t *testing.T) {
	t.Parallel()
	key := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0"}
	report := reportForTerminal(t, 21, `javax.crypto.Cipher.getInstance("AES")`, "javax.crypto.Cipher.getInstance")

	// A — live export of the component scanned directly (bounded backward tracer).
	live := liveCallgraphExport(t, "com.app:app", "Svc.java", diamondFixtureSrc, report)

	// B — stitched export from the component's cached fragment. Mirror the serving
	// path, which uses EntryRootedOnly=true (trace only from in-degree-0 entries).
	frag := buildModuleFragment(t, key, "com.app:app", "Svc.java", diamondFixtureSrc, report)
	res, err := graphfrag.StitchWithOptions(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag}, graphfrag.StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

	if len(live.FindingGraphs) == 0 || len(stitched.FindingGraphs) == 0 {
		t.Fatalf("no finding_graphs to compare (live=%d stitched=%d)", len(live.FindingGraphs), len(stitched.FindingGraphs))
	}

	liveEq := decodeEquiv(t, live)
	stitchedEq := decodeEquiv(t, stitched)

	// Diagnostic: chain shapes each side emits, to read the exact target semantics.
	t.Logf("live chains=%d stitched chains=%d", countChains(liveEq), countChains(stitchedEq))
	t.Logf("LIVE shapes:\n  %s", strings.Join(sortedKeys(chainShapes(liveEq)), "\n  "))
	t.Logf("STITCHED shapes:\n  %s", strings.Join(sortedKeys(chainShapes(stitchedEq)), "\n  "))

	rep := equiv.Compare(liveEq, stitchedEq, res.Suppressed, equiv.Options{})
	assertEquivClean(t, rep)
}

func countChains(cg equiv.CallgraphExportJSON) int {
	n := 0
	for _, fg := range cg.FindingGraphs {
		n += len(fg.CallChains)
	}
	return n
}

// TestEquivalence_EntryRooted_SupportingCallsMatchLive runs the supporting-call
// lifecycle fixture through the SERVING path (EntryRootedOnly=true, the bounded
// backward BFS) and asserts it still matches live `--export-callgraph`. The
// headline TestEquivalence_SingleComponent_StitchMatchesLive exercises only the
// EntryRootedOnly=false forward traversal; this guards that the backward rewrite
// the serving layer actually uses reproduces supporting_calls + the
// supporting_call_ids foreign key, not just bare chains.
func TestEquivalence_EntryRooted_SupportingCallsMatchLive(t *testing.T) {
	t.Parallel()
	key := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0"}
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	live := liveCallgraphExport(t, "com.app:app", "Svc.java", supportingFixtureSrc, report)

	frag := buildModuleFragment(t, key, "com.app:app", "Svc.java", supportingFixtureSrc, report)
	res, err := graphfrag.StitchWithOptions(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag}, graphfrag.StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

	if len(live.FindingGraphs) == 0 || len(stitched.FindingGraphs) == 0 {
		t.Fatalf("no finding_graphs to compare (live=%d stitched=%d)", len(live.FindingGraphs), len(stitched.FindingGraphs))
	}
	if len(stitched.SupportingCalls) == 0 {
		t.Fatal("fixture produced no supporting_calls; cannot validate the supporting_call_ids FK on the backward path")
	}

	rep := equiv.Compare(decodeEquiv(t, live), decodeEquiv(t, stitched), res.Suppressed, equiv.Options{})
	assertEquivClean(t, rep)
}
