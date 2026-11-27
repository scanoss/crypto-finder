// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"reflect"
	"testing"

	core "github.com/scanoss/reach/appreach"
)

// A stored asset that no annotation operation names was never seen by the
// stitch: it is unknown, not unreachable.
func TestApplicationResponseStoredAssetNotAnnotated(t *testing.T) {
	key := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}
	frag := Fragment{Module: "g:a", CryptoOperations: []CryptoOperation{{FindingID: "seen", FilePath: "A.java", StartLine: 3, RuleID: "r"}}}
	stored := &StoredFindings{Findings: []*FindingDTO{{FilePath: "A.java", CryptographicAssets: []*CryptographicAssetDTO{
		{FindingID: "seen", StartLine: 3, Source: "direct"}, {FindingID: "unseen", StartLine: 9, Source: "direct"},
	}}}}
	pins := Pins{Order: []string{key.Purl}, Dep: map[string]Dependency{key.Purl: {Purl: key.Purl, Version: key.Version, Direct: true}}}
	seen := ComputeFindingID("g:a@1/A.java", 3, "r")
	resp, _ := applicationResponse(pins, []ComponentKey{key},
		map[ComponentKey]Component{key: {Fragment: &frag, Stored: stored}},
		&ComponentDataDTO{}, map[ComponentKey]Fragment{key: frag},
		map[string]core.Verdict{seen: {Reachability: VerdictReachable}}, nil, nil)
	got := verdictsByID(resp.Dependencies[0])
	want := map[string]string{"seen": "reachable:", "unseen": "unknown:" + ReasonNotAnnotated}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v, want %v", got, want)
	}
	if f := resp.Dependencies[0].Findings[0]; f.FilePath != "g:a@1/A.java" || stored.Findings[0].CryptographicAssets[0].Reachability != "" {
		t.Errorf("served path %q; stored asset written: %+v", f.FilePath, stored.Findings[0].CryptographicAssets[0])
	}
}

// An annotation whose operations carry no finding ids cannot be joined to the
// report: the findings rendered from it are served.
func TestApplicationResponseAnnotationWithoutFindingIDs(t *testing.T) {
	key := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}
	frag := Fragment{Module: "g:a", CryptoOperations: []CryptoOperation{{FilePath: "A.java", StartLine: 3, RuleID: "r"}}}
	stored := &StoredFindings{Findings: []*FindingDTO{{FilePath: "A.java", CryptographicAssets: []*CryptographicAssetDTO{{FindingID: "stored", StartLine: 3}}}}}
	pins := Pins{Order: []string{key.Purl}, Dep: map[string]Dependency{key.Purl: {Purl: key.Purl, Version: key.Version, Direct: true}}}
	seen := ComputeFindingID("g:a@1/A.java", 3, "r")
	block := &ComponentDataDTO{Findings: []*FindingDTO{{FilePath: "g:a@1/A.java", CryptographicAssets: []*CryptographicAssetDTO{{FindingID: seen, StartLine: 3}}}}}
	resp, _ := applicationResponse(pins, []ComponentKey{key},
		map[ComponentKey]Component{key: {Fragment: &frag, Stored: stored}},
		block, map[ComponentKey]Fragment{key: frag},
		map[string]core.Verdict{seen: {Reachability: VerdictReachable}}, nil, nil)
	if got := verdictsByID(resp.Dependencies[0]); !reflect.DeepEqual(got, map[string]string{seen: "reachable:"}) {
		t.Errorf("verdicts %v, want the rendered finding %s reachable", got, seen)
	}
}

func verdictsByID(d *DependencyDTO) map[string]string {
	out := map[string]string{}
	for _, f := range d.Findings {
		for _, a := range f.CryptographicAssets {
			out[a.FindingID] = a.Reachability + ":" + a.ReachabilityReason
		}
	}
	return out
}
