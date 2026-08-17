// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"sort"
	"testing"
)

// chainEntryFixture builds a diamond: two entries (alpha, beta) both reach the
// crypto sink through the same mid function. Both have in-degree 0, so both are
// entries, and the finding is reachable from either — the shape where a chain
// budget has to choose which entry's routes to emit.
func chainEntryFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "com.acme:app",
		Functions: []Function{
			{Signature: "alpha#0", FunctionName: "com.acme.App.alpha", CanonicalSignature: "com.acme.App.alpha(): void", FilePath: "App.java"},
			{Signature: "beta#0", FunctionName: "com.acme.App.beta", CanonicalSignature: "com.acme.App.beta(): void", FilePath: "App.java"},
			{Signature: "mid#0", FunctionName: "com.acme.App.mid", CanonicalSignature: "com.acme.App.mid(): void", FilePath: "App.java"},
			{Signature: "sink#0", FunctionName: "com.acme.App.sink", CanonicalSignature: "com.acme.App.sink(): void", FilePath: "App.java"},
		},
		InternalEdges: []InternalEdge{
			{Caller: "alpha#0", Callee: "mid#0", Resolution: ResolutionExact},
			{Caller: "beta#0", Callee: "mid#0", Resolution: ResolutionExact},
			{Caller: "mid#0", Callee: "sink#0", Resolution: ResolutionExact},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "sink#0", FindingID: "f-sink", RuleID: "r", Symbol: "Crypto.sink"},
		},
	}
	return root, DependencyGraph{}, map[ComponentKey]Fragment{root: frag}
}

// entryPointSignatures collects the published entry-point index, sorted.
func entryPointSignatures(t *testing.T, res *Result, root ComponentKey, module string) []string {
	t.Helper()
	export := res.ToCallgraphExport(root, ScanMeta{RootModule: module, Ecosystem: "java"})
	out := make([]string, 0, len(export.CryptoEntryPoints))
	for _, ep := range export.CryptoEntryPoints {
		out = append(out, ep.CanonicalSignature)
	}
	sort.Strings(out)
	return out
}

// TestStitchChainEntrySignatures_RestrictsChainsNotTheIndex is the point of the
// option: the caller narrows which routes are worth emitting without narrowing
// the answer to "which functions reach this crypto". Deriving the index from the
// chains is the bug #249 fixed, so this asserts the index is byte-identical
// whether or not the restriction is applied.
func TestStitchChainEntrySignatures_RestrictsChainsNotTheIndex(t *testing.T) {
	t.Parallel()

	root, deps, fragments := chainEntryFixture()
	module := fragments[root].Module

	all, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions (unrestricted): %v", err)
	}
	only, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"com.acme.App.alpha(): void"},
	})
	if err != nil {
		t.Fatalf("StitchWithOptions (restricted): %v", err)
	}

	if got := rootFrameSignatures(all); len(got) != 2 {
		t.Fatalf("unrestricted chain heads = %v, want both entries", got)
	}
	gotHeads := rootFrameSignatures(only)
	if len(gotHeads) != 1 || gotHeads[0] != "alpha#0" {
		t.Errorf("restricted chain heads = %v, want only alpha#0", gotHeads)
	}

	// The finding is still reported — restricting the routes must not hide it.
	if got := reachableFindingIDs(only); len(got) != 1 || got[0] != "f-sink" {
		t.Errorf("restricted findings = %v, want f-sink", got)
	}

	allIndex := entryPointSignatures(t, all, root, module)
	onlyIndex := entryPointSignatures(t, only, root, module)
	if len(allIndex) != len(onlyIndex) {
		t.Fatalf("index changed with the restriction:\n unrestricted %v\n restricted   %v", allIndex, onlyIndex)
	}
	for i := range allIndex {
		if allIndex[i] != onlyIndex[i] {
			t.Fatalf("index changed with the restriction:\n unrestricted %v\n restricted   %v", allIndex, onlyIndex)
		}
	}
	// beta reaches the crypto and is published even though no route was emitted
	// for it — the property a signature filter must not break.
	var sawBeta bool
	for _, sig := range onlyIndex {
		if sig == "com.acme.App.beta(): void" {
			sawBeta = true
		}
	}
	if !sawBeta {
		t.Errorf("index = %v, want beta listed: it reaches the crypto", onlyIndex)
	}
}

// TestStitchChainEntrySignatures_UnknownSignatureEmitsNoChain guards the
// fail-quiet direction: a signature naming nothing must yield no routes, and must
// NOT fall through to the self-chain fallback, which would report the operation
// as reachable from an entry that does not reach it.
func TestStitchChainEntrySignatures_UnknownSignatureEmitsNoChain(t *testing.T) {
	t.Parallel()

	root, deps, fragments := chainEntryFixture()

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"com.acme.App.absent(): void"},
	})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	if len(res.Chains) != 0 {
		t.Errorf("chains = %d, want none: the signature names no entry", len(res.Chains))
	}

	// The index empties out with them, and deliberately so: it is published per
	// emitted finding graph, and with no route emitted there is no finding graph
	// to anchor it to. That is the honest answer to "show me what my entry
	// reaches" when the entry reaches nothing — and it is what lets a served
	// request report the signature back as unmatched instead of pruning the
	// findings against an index that would contradict it.
	if index := entryPointSignatures(t, res, root, fragments[root].Module); len(index) != 0 {
		t.Errorf("index = %v, want empty: nothing the caller named reaches a crypto operation", index)
	}
}

// TestStitchChainEntrySignatures_NilKeepsEveryEntry pins the default: no
// signatures means no restriction, so the serving path is unchanged.
func TestStitchChainEntrySignatures_NilKeepsEveryEntry(t *testing.T) {
	t.Parallel()

	root, deps, fragments := chainEntryFixture()

	base, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions (base): %v", err)
	}
	empty, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{},
	})
	if err != nil {
		t.Fatalf("StitchWithOptions (empty slice): %v", err)
	}

	if len(base.Chains) != len(empty.Chains) {
		t.Errorf("chains = %d with an empty slice, want %d (no restriction)", len(empty.Chains), len(base.Chains))
	}
}
