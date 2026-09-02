// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestStitch_UnattributedCryptoOpEmitsNoFabricatedFrame pins the contract for a
// crypto operation the parser could not attribute to any containing function
// (CryptoOperation.Function == ""): a match inside a `#[cfg(test)] mod`, a macro
// body or a static initializer.
//
// Such an op used to take the self-chain fallback, which fabricated a frame with
// NO identity at all. The interned form cannot express that frame — its catalog
// entry carries nothing to hydrate from — so a consumer that requires hydrated
// frames rejects the WHOLE component over one unattributable op, serving no
// reachability for any of its findings.
//
// The served shape must match what a live scan emits for the same op: the
// finding is still reported, with empty call_chains and reachability
// not_applicable. Everything that does NOT depend on a chain frame must
// survive — the finding's purl, its dependency-prefixed finding_id and the
// supporting calls on the same node — because only the frame's identity is
// unexpressible, not the finding.
func TestStitch_UnattributedCryptoOpEmitsNoFabricatedFrame(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:cargo/lib", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "lib",
		Functions: []Function{{
			Signature:          "lib.(Params).from_str#1",
			FunctionName:       "lib.Params.from_str",
			CanonicalSignature: "lib.Params.from_str(&str)",
			FilePath:           "src/params.rs",
			StartLine:          10,
			EndLine:            20,
		}},
		CryptoOperations: []CryptoOperation{
			{
				// Attributed: line 15 is inside from_str's range.
				Function:  "lib.(Params).from_str#1",
				FindingID: "attributed",
				RuleID:    "rule.suite",
				Symbol:    "lib.Params.from_str",
				PURL:      "pkg:cargo/lib@1.0.0",
				FilePath:  "src/params.rs",
				StartLine: 15,
			},
			{
				// Unattributed: line 90 is inside `#[cfg(test)] mod tests`, which
				// the Rust parser does not emit as a function.
				Function:  "",
				FindingID: "unattributed",
				RuleID:    "rule.suite",
				Symbol:    "lib.Params.from_str",
				PURL:      "pkg:cargo/lib@1.0.0",
				FilePath:  "src/params.rs",
				StartLine: 90,
			},
		},
	}

	// EntryRootedOnly is the serving path — the one under the live parity
	// contract. The historical full-rooting path traces from the root fragment's
	// declared functions, so it never visits an op with no containing function
	// and has always omitted it entirely.
	res, err := StitchWithOptions(root, DependencyGraph{root: nil},
		map[ComponentKey]Fragment{root: frag}, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	out := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "rust", InternedFrames: true})

	// Both ids are recomputed from the terminal frame's file, line and rule.
	// The unattributed carrier keeps its frame for exactly this reason: without
	// it the finding would fall back to the fragment's own id and, for a
	// dependency component, stop joining the findings envelope.
	attributedID := computeFindingID("src/params.rs", 15, "rule.suite")
	unattributedID := computeFindingID("src/params.rs", 90, "rule.suite")

	byID := make(map[string]ExportFindingGraph, len(out.FindingGraphs))
	for _, fg := range out.FindingGraphs {
		byID[fg.FindingID] = fg
	}
	unattributed, ok := byID[unattributedID]
	if !ok {
		t.Fatalf("the unattributable op must still be reported; got %d graphs %v",
			len(out.FindingGraphs), byID)
	}
	if len(unattributed.CallChains) != 0 {
		t.Fatalf("CallChains = %#v, want empty for an op with no containing function",
			unattributed.CallChains)
	}
	if got := unattributed.Reachability; got != ReachabilityNotApplicable {
		t.Fatalf("Reachability = %q, want %q — the question does not apply when there is no containing function",
			got, ReachabilityNotApplicable)
	}
	if unattributed.Analysis != nil {
		t.Fatalf("Analysis = %+v, want nil as live leaves it", unattributed.Analysis)
	}
	if unattributed.PURL != "pkg:cargo/lib@1.0.0" {
		t.Fatalf("PURL = %q, want the finding's own purl kept", unattributed.PURL)
	}
	// Live has no containing function to walk forward from and emits nothing.
	if unattributed.ForwardCalls != nil {
		t.Fatalf("ForwardCalls = %+v, want none — live emits none for this op", unattributed.ForwardCalls)
	}
	attributed, ok := byID[attributedID]
	if !ok {
		t.Fatalf("the attributed op disappeared; got %v", byID)
	}
	if len(attributed.CallChains) != 1 || len(attributed.CallChains[0]) != 1 {
		t.Fatalf("the attributed op must keep its self-chain; got %#v",
			attributed.CallChains)
	}

	// The catalog is the only copy of identity in the interned form, so an entry
	// with none is unhydratable by construction.
	for i, fn := range out.Functions {
		if fn.FunctionName == "" && fn.CanonicalSignature == "" {
			t.Fatalf("functions[%d] interned with no identity: %+v", i, fn)
		}
	}
	if !out.HydrateChainIdentities() {
		t.Fatalf("HydrateChainIdentities returned false")
	}
	for _, fg := range out.FindingGraphs {
		for i, chain := range fg.CallChains {
			for j, frame := range chain {
				if frame.FunctionName == "" && frame.CanonicalSignature == "" {
					t.Fatalf("%s chain %d frame %d has no identity after hydrate",
						fg.FindingID, i, j)
				}
			}
		}
	}
}

// TestStitch_UnattributedFlagDoesNotStampAGroupWithChains pins the collision
// case: an attributed and an unattributed op can collapse into ONE finding
// group — same finding_id and occurrence key, different function keys. Stamping
// the group from the flag alone put not_applicable on a finding that had a
// real, fully identified chain, and dropped its analysis block with it.
func TestStitch_UnattributedFlagDoesNotStampAGroupWithChains(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:cargo/lib", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "lib",
		Functions: []Function{{
			Signature:          "lib.f#0",
			FunctionName:       "lib.f",
			CanonicalSignature: "lib.f()",
			FilePath:           "src/lib.rs",
			StartLine:          1,
			EndLine:            20,
		}},
		CryptoOperations: []CryptoOperation{
			// Same file, same line and same rule, so both resolve to one
			// finding_id — but one has a containing function and one does not.
			{
				Function: "lib.f#0", FindingID: "attributed", RuleID: "r", Symbol: "s",
				PURL: "pkg:cargo/lib@1.0.0", FilePath: "src/lib.rs", StartLine: 10,
			},
			{
				Function: "", FindingID: "unattributed", RuleID: "r", Symbol: "s",
				PURL: "pkg:cargo/lib@1.0.0", FilePath: "src/lib.rs", StartLine: 10,
			},
		},
	}

	res, err := StitchWithOptions(root, DependencyGraph{root: nil},
		map[ComponentKey]Fragment{root: frag}, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	out := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "rust", InternedFrames: true})

	for _, fg := range out.FindingGraphs {
		if len(fg.CallChains) == 0 {
			continue
		}
		if fg.Reachability == ReachabilityNotApplicable {
			t.Fatalf("%s has %d chains and still reads %q",
				fg.FindingID, len(fg.CallChains), fg.Reachability)
		}
		if fg.Analysis == nil {
			t.Fatalf("%s has chains but no analysis block", fg.FindingID)
		}
	}
}
