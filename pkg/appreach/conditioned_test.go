// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"reflect"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"
)

// expansionFixture is a dependency with a stored anchor (verdict set by the
// stitch) and a value its own code passes, already specialized and stored.
func expansionFixture(truncated bool, reachability, reason string) (ComponentKey, *Fragment, []*FindingDTO, map[string][]conditioned.Expansion) {
	key := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}
	op := gf.CryptoOperation{Function: "A.f#1", FindingID: "anchor", CryptoCall: &gf.CryptoCall{FunctionName: "javax.crypto.Mac.getInstance", Line: 3}}
	frag := &Fragment{
		Module: "g:a", CryptoOperations: []CryptoOperation{op},
		ExternalCalls: []ExternalCall{{Caller: "A.f#1", TargetSignature: "javax.crypto.(Mac).getInstance#1", CallSite: 3, StartCol: 5, EndCol: 40}},
	}
	rule := &conditioned.Rule{ID: "r", Symbols: []string{"Mac.getInstance"}}
	stored := []*FindingDTO{{FilePath: "A.java", CryptographicAssets: []*CryptographicAssetDTO{
		{FindingID: "anchor", StartLine: 3, StartCol: 10, EndCol: 30, OccurrenceKey: "v1:k", Rules: []CryptoRuleDTO{{ID: "generic"}}, Metadata: json.RawMessage(`{"api":"Mac.getInstance"}`), Reachability: reachability, ReachabilityReason: reason, Analysis: json.RawMessage(`{"call_chains":"complete"}`)},
		{FindingID: "own", StartLine: 3, StartCol: 10, EndCol: 30, Rules: []CryptoRuleDTO{{ID: "r"}}, Metadata: json.RawMessage(`{"parameterCondition":"param[0]==Own"}`)},
	}}}
	spec := func(value, verdict, why string) conditioned.ClosureSpecialization {
		return conditioned.ClosureSpecialization{
			Specialization: conditioned.Specialization{Rule: rule, Metadata: map[string]string{"parameterCondition": "param[0]==" + value}, ConditionedValue: "param[0]==" + value},
			Reachability:   verdict, UnresolvedReason: why,
		}
	}
	expansion := conditioned.Expansion{
		Anchor:          &conditioned.Anchor{Component: key, Operation: &frag.CryptoOperations[0], Rules: []*conditioned.Rule{rule}},
		Specializations: []conditioned.ClosureSpecialization{spec("Own", VerdictReachable, ""), spec("Up", VerdictReachable, ""), spec("Amb", VerdictUnknown, ReasonAmbiguousDispatch), spec("Far", VerdictUnreachable, "")},
		Truncated:       truncated,
	}
	return key, frag, stored, map[string][]conditioned.Expansion{"anchor": {expansion}}
}

func servedVerdicts(assets []*CryptographicAssetDTO) map[string]string {
	out := map[string]string{}
	for _, a := range assets {
		out[a.ConditionedValue] = a.Reachability + ":" + a.ReachabilityReason
	}
	return out
}

// Each value is served once (the file's own specialization stands), with a
// verdict no stronger than its anchor's.
func TestAddConditionedAssets(t *testing.T) {
	_, frag, stored, byAnchor := expansionFixture(false, VerdictUnknown, ReasonSearchCapped)
	// The same value on another line of the file is another asset.
	stored[0].CryptographicAssets = append(stored[0].CryptographicAssets, &CryptographicAssetDTO{
		FindingID: "elsewhere", StartLine: 9, StartCol: 10, EndCol: 30, Rules: []CryptoRuleDTO{{ID: "r"}}, Metadata: json.RawMessage(`{"parameterCondition":"param[0]==Up"}`),
	})
	served := []*FindingDTO{{FilePath: "g:a@1/A.java", CryptographicAssets: append([]*CryptographicAssetDTO(nil), stored[0].CryptographicAssets...)}}
	added := addConditionedAssets(frag, stored, served, byAnchor)
	want := map[string]string{
		"param[0]==Up":  "unknown:" + ReasonSearchCapped,
		"param[0]==Amb": "unknown:" + ReasonAmbiguousDispatch,
		"param[0]==Far": "unreachable:",
	}
	if got := servedVerdicts(added); !reflect.DeepEqual(got, want) {
		t.Errorf("added %v, want %v", got, want)
	}
	if len(served[0].CryptographicAssets) != 6 || len(stored[0].CryptographicAssets) != 3 {
		t.Errorf("served file holds %d assets (want 6), stored %d (want 3)", len(served[0].CryptographicAssets), len(stored[0].CryptographicAssets))
	}
	if a := added[0]; a.FindingID != conditioned.FindingID("A.java", 3, "r", "param[0]==Up") || a.TerminalStartCol != 5 || a.TerminalEndCol != 40 {
		t.Errorf("asset id %s, terminal %d-%d", a.FindingID, a.TerminalStartCol, a.TerminalEndCol)
	}
	if string(served[0].CryptographicAssets[0].Analysis) != `{"call_chains":"complete"}` {
		t.Errorf("anchor analysis changed without a cut: %s", served[0].CryptographicAssets[0].Analysis)
	}
}

// A cut value walk reads call_chains partial on the anchor and on what it
// yields: a value, and its asset, may be missing.
func TestAddConditionedAssetsTruncated(t *testing.T) {
	_, frag, stored, byAnchor := expansionFixture(true, VerdictReachable, "")
	served := []*FindingDTO{{FilePath: "g:a@1/A.java", CryptographicAssets: append([]*CryptographicAssetDTO(nil), stored[0].CryptographicAssets...)}}
	added := addConditionedAssets(frag, stored, served, byAnchor)
	if got := string(served[0].CryptographicAssets[0].Analysis); got != `{"call_chains":"partial"}` {
		t.Errorf("anchor analysis %s, want call_chains partial", got)
	}
	if got := string(added[0].Analysis); got != `{"call_chains":"partial","parameters":"complete"}` {
		t.Errorf("asset analysis %s", got)
	}
	if got := servedVerdicts(added)["param[0]==Up"]; got != "reachable:" {
		t.Errorf("verdict under a reachable anchor %s, want reachable", got)
	}
}

// Behind a dependency without a graph, a value no route passes is unknown, as
// every finding there is, and each asset counts in the summaries.
func TestApplicationResponseConditionedAssets(t *testing.T) {
	key, frag, stored, byAnchor := expansionFixture(false, "", "")
	frag.CryptoOperations[0].FilePath, frag.CryptoOperations[0].StartLine, frag.CryptoOperations[0].RuleID = "A.java", 3, "generic"
	pins := Pins{Order: []string{key.Purl}, Dep: map[string]Dependency{key.Purl: {Purl: key.Purl, Version: key.Version, Direct: true}}}
	anchorID := ComputeFindingID("g:a@1/A.java", 3, "generic")
	resp, added := applicationResponse(pins, []ComponentKey{key},
		map[ComponentKey]Component{key: {Fragment: frag, Stored: &StoredFindings{Findings: stored}}},
		&ComponentDataDTO{}, map[ComponentKey]Fragment{key: *frag},
		map[string]verdict{anchorID: {reachability: VerdictReachable}}, map[ComponentKey]bool{key: true},
		conditionedExpansions{key: byAnchor})
	dep := resp.Dependencies[0]
	if added != 3 || dep.FindingCount != 5 || dep.Summary != (Summary{Reachable: 2, Unknown: 3}) || resp.Summary != dep.Summary {
		t.Fatalf("added %d, finding_count %d, summary %+v / %+v", added, dep.FindingCount, dep.Summary, resp.Summary)
	}
	if got := servedVerdicts(dep.Findings[0].CryptographicAssets)["param[0]==Far"]; got != "unknown:"+ReasonDependencyWithoutGraph {
		t.Errorf("Far: %s, want unknown:%s", got, ReasonDependencyWithoutGraph)
	}
}
