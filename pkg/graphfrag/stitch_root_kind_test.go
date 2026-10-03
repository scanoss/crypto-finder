// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	rootKindMainFn      = "com.acme.app.App.main(): void"
	rootKindHandlerFn   = "com.acme.app.Handler.handle(): void"
	rootKindUncalledFn  = "com.acme.app.Job.run(): void"
	rootKindHelperFn    = "com.acme.app.Helper.help(): void"
	rootKindCryptoFn    = "com.acme.app.Crypto.encrypt(): void"
	rootKindCryptoFinID = "f-root-kind"
)

// rootKindFragment is a root component whose entry points all reach one crypto
// function through Helper.help. entries maps a function to its recorded entry
// kind; recorded says whether the producer recorded entry kinds at all.
func rootKindFragment(recorded bool, entries map[string]string, callers ...string) Fragment {
	frag := Fragment{
		Component: componentA,
		Functions: []Function{
			{Signature: rootKindHelperFn},
			{Signature: rootKindCryptoFn},
		},
		InternalEdges: []InternalEdge{{
			Caller: rootKindHelperFn, Callee: rootKindCryptoFn,
			Resolution: ResolutionExact, MethodName: "encrypt", CallSite: 5,
		}},
		CryptoOperations: []CryptoOperation{{
			Function: rootKindCryptoFn, FindingID: rootKindCryptoFinID, RuleID: "rule.aes",
			FilePath: "Crypto.java", StartLine: 9,
		}},
	}
	if recorded {
		frag.EntryKinds = map[string]string{}
	}
	for i, caller := range callers {
		frag.Functions = append(frag.Functions, Function{Signature: caller})
		if kind := entries[caller]; recorded && kind != "" {
			frag.EntryKinds[caller] = kind
		}
		frag.InternalEdges = append(frag.InternalEdges, InternalEdge{
			Caller: caller, Callee: rootKindHelperFn,
			Resolution: ResolutionExact, MethodName: "help", CallSite: 10 + i,
		})
	}
	return frag
}

func stitchRootKindFinding(t *testing.T, frag Fragment) ExportFindingGraph {
	t.Helper()
	return onlyStitchedFinding(t, componentA, DependencyGraph{}, map[ComponentKey]Fragment{componentA: frag})
}

func chainRootKinds(fg ExportFindingGraph) map[string]string {
	kinds := map[string]string{}
	for _, chain := range fg.CallChains {
		kinds[chain[0].FunctionKey] = chain[0].RootKind
	}
	return kinds
}

// A chain rooted at a recorded entry reads its kind; one rooted at a function
// nothing calls reads no_callers; the finding is not no_callers_only while an
// entry reaches it.
func TestStitch_RootKindFromRecordedEntryKinds(t *testing.T) {
	t.Parallel()
	frag := rootKindFragment(true, map[string]string{
		rootKindMainFn:    RootKindMain,
		rootKindHandlerFn: RootKindFrameworkEntry,
	}, rootKindMainFn, rootKindHandlerFn, rootKindUncalledFn)
	fg := stitchRootKindFinding(t, frag)

	want := map[string]string{
		rootKindMainFn:     RootKindMain,
		rootKindHandlerFn:  RootKindFrameworkEntry,
		rootKindUncalledFn: RootKindNoCallers,
	}
	got := chainRootKinds(fg)
	for fn, kind := range want {
		if got[fn] != kind {
			t.Errorf("root_kind of %s = %q, want %q (all: %v)", fn, got[fn], kind, got)
		}
	}
	if fg.Analysis == nil || fg.Analysis.NoCallersOnly {
		t.Fatalf("analysis = %+v, want no_callers_only false while an entry reaches the finding", fg.Analysis)
	}
}

// Every root a no_callers root: no_callers_only. One recorded entry among them
// turns it off.
func TestStitch_NoCallersOnlyNeedsEveryRootToBeNoCallers(t *testing.T) {
	t.Parallel()
	only := stitchRootKindFinding(t, rootKindFragment(true, nil, rootKindUncalledFn, rootKindHandlerFn))
	if only.Analysis == nil || !only.Analysis.NoCallersOnly {
		t.Fatalf("analysis = %+v, want no_callers_only with every root no_callers", only.Analysis)
	}
	for fn, kind := range chainRootKinds(only) {
		if kind != RootKindNoCallers {
			t.Errorf("root_kind of %s = %q, want no_callers", fn, kind)
		}
	}

	mixed := stitchRootKindFinding(t, rootKindFragment(true,
		map[string]string{rootKindHandlerFn: RootKindFrameworkEntry}, rootKindUncalledFn, rootKindHandlerFn))
	if mixed.Analysis == nil || mixed.Analysis.NoCallersOnly {
		t.Fatalf("analysis = %+v, want no_callers_only false with a framework entry among the roots", mixed.Analysis)
	}
}

// A fragment that recorded no entry kinds (graph-fragment-1.13 and older) could
// be hiding a framework entry among its uncalled functions, so the stitched
// export claims neither a root_kind nor no_callers_only for it.
func TestStitch_FragmentWithoutEntryKindsClaimsNothing(t *testing.T) {
	t.Parallel()
	fg := stitchRootKindFinding(t, rootKindFragment(false, nil, rootKindUncalledFn))
	for fn, kind := range chainRootKinds(fg) {
		if kind != "" {
			t.Errorf("root_kind of %s = %q, want none without entry-kind data", fn, kind)
		}
	}
	if fg.Analysis == nil || fg.Analysis.NoCallersOnly {
		t.Fatalf("analysis = %+v, want no_callers_only false without entry-kind data", fg.Analysis)
	}
	if fg.Reachability != ReachabilityReachable {
		t.Fatalf("reachability = %q, want reachable (the verdict is unchanged)", fg.Reachability)
	}
}

// A crypto function nothing calls that is no entry point is dead code, not a
// route: it reads unreachable and never no_callers_only.
func TestStitch_UncalledCryptoFunctionIsNotNoCallersOnly(t *testing.T) {
	t.Parallel()
	frag := rootKindFragment(true, nil)
	frag.InternalEdges = nil
	fg := stitchRootKindFinding(t, frag)
	if fg.Reachability == ReachabilityReachable {
		t.Fatalf("reachability = %q, want the uncalled crypto function not reachable", fg.Reachability)
	}
	if fg.Analysis != nil && fg.Analysis.NoCallersOnly {
		t.Fatalf("analysis = %+v, want no_callers_only false for dead code", fg.Analysis)
	}
}

// The serialized export carries root_kind on the first frame only, and
// no_callers_only on the analysis.
func TestStitch_RootKindSerializes(t *testing.T) {
	t.Parallel()
	frag := rootKindFragment(true, nil, rootKindUncalledFn)
	res, err := StitchWithOptions(componentA, DependencyGraph{}, map[ComponentKey]Fragment{componentA: frag}, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	data, err := json.Marshal(res.ToCallgraphExport(componentA, ScanMeta{Ecosystem: "java"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), `"root_kind":"no_callers"`); got != 1 {
		t.Errorf(`"root_kind":"no_callers" appears %d times, want 1 (first frame only): %s`, got, data)
	}
	if !strings.Contains(string(data), `"no_callers_only":true`) {
		t.Errorf("no_callers_only missing: %s", data)
	}
}

// entry_kind and scan_metadata.entry_kinds survive a fragment round trip, and a
// pre-1.14 fragment still decodes, with no entry-kind data.
func TestFragment_EntryKindsRoundTripAndOldFragment(t *testing.T) {
	t.Parallel()
	in := rootKindFragment(true, map[string]string{rootKindMainFn: RootKindMain}, rootKindMainFn)
	data, err := EncodeFragment(in)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	got, err := DecodeFragment(componentA, data)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if len(got.EntryKinds) != 1 || got.EntryKinds[rootKindMainFn] != RootKindMain {
		t.Errorf("entry kinds after round trip = %v, want only %s = main", got.EntryKinds, rootKindMainFn)
	}

	none, err := EncodeFragment(rootKindFragment(true, nil, rootKindUncalledFn))
	if err != nil {
		t.Fatal(err)
	}
	recordedNone, err := DecodeFragment(componentA, none)
	if err != nil {
		t.Fatal(err)
	}
	if recordedNone.EntryKinds == nil || len(recordedNone.EntryKinds) != 0 {
		t.Errorf("a fragment that recorded no entry point must stay recorded: %#v", recordedNone.EntryKinds)
	}

	old := `{"schema_version":"graph-fragment-1.13","scan_metadata":{"exported_at":"x"},` +
		`"functions":[{"key":"a.A.run","function_name":"a.A.run"}]}`
	oldFrag, err := DecodeFragment(componentA, []byte(old))
	if err != nil {
		t.Fatalf("a graph-fragment-1.13 fragment must still decode: %v", err)
	}
	if oldFrag.EntryKinds != nil || len(oldFrag.Functions) != 1 {
		t.Errorf("old fragment = %+v, want no entry-kind data", oldFrag)
	}
}
