// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"sort"
	"testing"
)

// reachableFindingIDs collects the distinct terminal-crypto finding IDs present
// in a stitch result. It is the set the serving layer cares about: which crypto
// operations are reachable from a traced root, regardless of how many distinct
// paths reach them.
func reachableFindingIDs(res *Result) []string {
	seen := map[string]bool{}
	for _, chain := range res.Chains {
		seen[chain.FindingID] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// rootFrameSignatures collects the distinct root-frame (chain head) signatures
// in a stitch result — i.e. the functions traces actually started from.
func rootFrameSignatures(res *Result) []string {
	seen := map[string]bool{}
	for _, chain := range res.Chains {
		if len(chain.Frames) == 0 {
			continue
		}
		seen[chain.Frames[0].Signature] = true
	}
	out := make([]string, 0, len(seen))
	for sig := range seen {
		out = append(out, sig)
	}
	sort.Strings(out)
	return out
}

// entryRootedFixture builds a single-component graph where one entry function
// (entry#0) calls a mid function (mid#0) that reaches the crypto sink (sink#0).
// mid#0 also directly reaches the sink, so the finding is reachable from BOTH
// entry#0 and mid#0. Only entry#0 has in-degree 0.
func entryRootedFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "com.acme:app",
		Functions: []Function{
			{Signature: "entry#0", FilePath: "App.java"},
			{Signature: "mid#0", FilePath: "App.java"},
			{Signature: "sink#0", FilePath: "App.java"},
		},
		InternalEdges: []InternalEdge{
			{Caller: "entry#0", Callee: "mid#0", Resolution: ResolutionExact},
			{Caller: "mid#0", Callee: "sink#0", Resolution: ResolutionExact},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "sink#0", FindingID: "f-sink", RuleID: "r", Symbol: "Crypto.sink"},
		},
	}
	return root, DependencyGraph{}, map[ComponentKey]Fragment{root: frag}
}

// TestStitchEntryRooted_PreservesReachableFindingSet asserts the entry-rooted
// trace reaches the SAME set of terminal findings as full-rooting (a finding
// reachable from a non-entry function is still reachable from the entry that
// calls it), while rooting at strictly fewer functions.
func TestStitchEntryRooted_PreservesReachableFindingSet(t *testing.T) {
	t.Parallel()

	root, deps, fragments := entryRootedFixture()

	full, err := Stitch(root, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch (full): %v", err)
	}
	entry, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions (entry-rooted): %v", err)
	}

	fullFindings := reachableFindingIDs(full)
	entryFindings := reachableFindingIDs(entry)
	if len(fullFindings) != len(entryFindings) {
		t.Fatalf("reachable findings differ: full=%v entry=%v", fullFindings, entryFindings)
	}
	for i := range fullFindings {
		if fullFindings[i] != entryFindings[i] {
			t.Fatalf("reachable findings differ: full=%v entry=%v", fullFindings, entryFindings)
		}
	}

	fullRoots := rootFrameSignatures(full)
	entryRoots := rootFrameSignatures(entry)
	if len(entryRoots) >= len(fullRoots) {
		t.Fatalf("entry-rooted should root at fewer functions: full roots=%v entry roots=%v", fullRoots, entryRoots)
	}
	// The only entry (in-degree 0) function is entry#0.
	if len(entryRoots) != 1 || entryRoots[0] != "entry#0" {
		t.Fatalf("entry roots = %v, want exactly [entry#0]", entryRoots)
	}
}

// TestStitch_DefaultUnchanged is a guard that the default Stitch still roots at
// every root-fragment function (here it produces chains rooted at entry#0,
// mid#0, and sink#0 itself).
func TestStitch_DefaultRootsEveryFunction(t *testing.T) {
	t.Parallel()

	root, deps, fragments := entryRootedFixture()
	full, err := Stitch(root, deps, fragments)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	roots := rootFrameSignatures(full)
	if len(roots) != 3 {
		t.Fatalf("default Stitch root frames = %v, want 3 (entry#0, mid#0, sink#0)", roots)
	}
}
