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
	for i := range export.CryptoEntryPoints {
		out = append(out, export.CryptoEntryPoints[i].CanonicalSignature)
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

// TestStitchMaxChains_KeepsFullEntryIndex is issue #334: N=1 samples one route
// but crypto_entry_points still lists every function that reaches the finding.
func TestStitchMaxChains_KeepsFullEntryIndex(t *testing.T) {
	t.Parallel()

	root, deps, fragments := chainEntryFixture()
	module := fragments[root].Module

	full, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions (default): %v", err)
	}
	one, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true, MaxChains: 1})
	if err != nil {
		t.Fatalf("StitchWithOptions (N=1): %v", err)
	}

	if got := rootFrameSignatures(full); len(got) != 2 {
		t.Fatalf("default chain heads = %v, want both entries", got)
	}
	if got := rootFrameSignatures(one); len(got) != 1 {
		t.Fatalf("N=1 chain heads = %v, want one sampled route", got)
	}

	oneExport := one.ToCallgraphExport(root, ScanMeta{RootModule: module, Ecosystem: "java"})
	if len(oneExport.FindingGraphs) != 1 {
		t.Fatalf("N=1 FindingGraphs len = %d, want 1", len(oneExport.FindingGraphs))
	}
	fg := oneExport.FindingGraphs[0]
	if len(fg.CallChains) != 1 {
		t.Fatalf("N=1 CallChains len = %d, want 1", len(fg.CallChains))
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != AnalysisPartial {
		t.Fatalf("N=1 Analysis = %+v, want call_chains partial", fg.Analysis)
	}
	if fg.Reachability == ReachabilityUnreachable {
		t.Fatal("N=1 reachability is unreachable; budget truncation must not claim that")
	}

	fullIndex := entryPointSignatures(t, full, root, module)
	oneIndex := entryPointSignatures(t, one, root, module)
	if len(fullIndex) != len(oneIndex) {
		t.Fatalf("index shrunk at N=1:\n default %v\n N=1     %v", fullIndex, oneIndex)
	}
	for i := range fullIndex {
		if fullIndex[i] != oneIndex[i] {
			t.Fatalf("index shrunk at N=1:\n default %v\n N=1     %v", fullIndex, oneIndex)
		}
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

// twoOpChainEntryFixture is chainEntryFixture plus an unrelated root (gamma)
// reaching a second operation, so a restriction to one entry leaves an
// operation it does not reach.
func twoOpChainEntryFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root, deps, fragments := chainEntryFixture()
	frag := fragments[root]
	frag.Functions = append(frag.Functions,
		Function{Signature: "gamma#0", FunctionName: "com.acme.App.gamma", CanonicalSignature: "com.acme.App.gamma(): void", FilePath: "App.java"},
		Function{Signature: "other#0", FunctionName: "com.acme.App.other", CanonicalSignature: "com.acme.App.other(): void", ErasedSignature: "com.acme.App.other()", FilePath: "Other.java"},
	)
	frag.InternalEdges = append(frag.InternalEdges, InternalEdge{Caller: "gamma#0", Callee: "other#0", Resolution: ResolutionExact})
	frag.CryptoOperations = append(frag.CryptoOperations, CryptoOperation{Function: "other#0", FindingID: "f-other", RuleID: "r", Symbol: "Crypto.other", FilePath: "Other.java", StartLine: 9})
	fragments[root] = frag
	return root, deps, fragments
}

// TestStitchChainEntrySignatures_NonRootEntryResolves pins that every published
// entry point is a usable filter value, not only the roots: mid is published
// (it reaches the crypto) but has callers, so it is no root.
func TestStitchChainEntrySignatures_NonRootEntryResolves(t *testing.T) {
	t.Parallel()

	root, deps, fragments := chainEntryFixture()
	module := fragments[root].Module
	frag := fragments[root]
	frag.EntryKinds = map[string]string{} // recorded: the roots read no_callers
	fragments[root] = frag

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"com.acme.App.mid(): void"},
	})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	if got := rootFrameSignatures(res); len(got) != 1 || got[0] != "mid#0" {
		t.Errorf("chain heads = %v, want only mid#0", got)
	}
	export := res.ToCallgraphExport(root, ScanMeta{RootModule: module, Ecosystem: "java"})
	if got := exportFindingFiles(&export); len(got) != 1 || got["App.java"] != ReachabilityReachable {
		t.Fatalf("findings = %v, want f-sink reachable", got)
	}
	// mid has callers, so it is no root and its chain claims no root_kind.
	for _, chain := range export.FindingGraphs[0].CallChains {
		if chain[0].RootKind != "" {
			t.Errorf("head %s root_kind = %q, want none", chain[0].FunctionKey, chain[0].RootKind)
		}
	}
	var midListsSink bool
	for i := range export.CryptoEntryPoints {
		ep := &export.CryptoEntryPoints[i]
		if ep.CanonicalSignature != "com.acme.App.mid(): void" {
			continue
		}
		for _, rf := range ep.ReachableFindings {
			midListsSink = midListsSink || rf.FindingID == export.FindingGraphs[0].FindingID
		}
	}
	if !midListsSink {
		t.Errorf("index = %+v, want mid listing f-sink", export.CryptoEntryPoints)
	}
}

// TestStitchChainEntrySignatures_ErasedSignatureResolves accepts the erased
// spelling the index also publishes.
func TestStitchChainEntrySignatures_ErasedSignatureResolves(t *testing.T) {
	t.Parallel()

	root, deps, fragments := twoOpChainEntryFixture()

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly:      true,
		ChainEntrySignatures: []string{"com.acme.App.other()"},
	})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	if got := reachableFindingIDs(res); len(got) != 1 || got[0] != "f-other" {
		t.Errorf("findings = %v, want f-other", got)
	}
}

// TestStitchChainEntrySignatures_IndexStaysCompleteForUnreachedOps pins that an
// operation the requested entry does not reach still has its entry points
// published, although it gets no finding graph.
func TestStitchChainEntrySignatures_IndexStaysCompleteForUnreachedOps(t *testing.T) {
	t.Parallel()

	root, deps, fragments := twoOpChainEntryFixture()
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

	export := only.ToCallgraphExport(root, ScanMeta{RootModule: module, Ecosystem: "java"})
	if got := exportFindingFiles(&export); len(got) != 1 || got["App.java"] == "" {
		t.Errorf("finding graphs = %v, want only f-sink", got)
	}
	if len(only.SupportingCalls) != len(all.SupportingCalls) {
		t.Errorf("supporting calls = %d, want %d", len(only.SupportingCalls), len(all.SupportingCalls))
	}

	allExport := all.ToCallgraphExport(root, ScanMeta{RootModule: module, Ecosystem: "java"})
	if len(allExport.CryptoEntryPoints) != len(export.CryptoEntryPoints) {
		t.Fatalf("index changed with the restriction:\n unrestricted %+v\n restricted   %+v",
			allExport.CryptoEntryPoints, export.CryptoEntryPoints)
	}
	for i := range allExport.CryptoEntryPoints {
		want, got := allExport.CryptoEntryPoints[i], export.CryptoEntryPoints[i]
		if want.FunctionKey != got.FunctionKey || len(want.ReachableFindings) != len(got.ReachableFindings) || want.Root != got.Root {
			t.Errorf("entry %d = %+v, want %+v", i, got, want)
		}
	}
}
