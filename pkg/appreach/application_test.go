// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"reflect"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"
)

func TestFindingVerdicts(t *testing.T) {
	partial := &gf.ExportFindingAnalysis{CallChains: "partial"}
	complete := &gf.ExportFindingAnalysis{CallChains: "complete"}
	got := findingVerdicts([]ExportFindingGraph{
		{FindingID: "reach", Reachability: "reachable", CallChains: [][]gf.ExportChainNode{{{}, {}}}},
		{FindingID: "reach-interned", Reachability: "reachable", CallChainIndexes: [][]int{{0}, {1, 2}}},
		// Reachable only by the dependency's entry-point index: no call reaches the finding.
		{FindingID: "index", Reachability: "reachable", CallChains: [][]gf.ExportChainNode{{{}}}},
		{FindingID: "ambiguous", Reachability: "unknown", UnresolvedReason: gf.UnresolvedReasonAmbiguousDispatch},
		{FindingID: "nameonly", Reachability: "unknown", UnresolvedReason: gf.UnresolvedReasonDispatch},
		{FindingID: "capped", Reachability: "unknown", Analysis: partial},
		// The stitched export's closure-wide unknown: no route, nothing unresolved on the way.
		{FindingID: "global", Reachability: "unknown", Analysis: complete},
		{FindingID: "none", Reachability: "unreachable"},
		{FindingID: "field", Reachability: gf.ReachabilityNotApplicable},
	})
	want := map[string]verdict{
		"reach":          {VerdictReachable, ""},
		"reach-interned": {VerdictReachable, ""},
		"index":          {VerdictUnknown, ReasonDependencyEntryPointOnly},
		"ambiguous":      {VerdictUnknown, ReasonAmbiguousDispatch},
		"nameonly":       {VerdictUnknown, ReasonUnresolvedDispatch},
		"capped":         {VerdictUnknown, ReasonSearchCapped},
		"global":         {VerdictUnreachable, ""},
		"none":           {VerdictUnreachable, ""},
		"field":          {VerdictUnknown, ReasonNoContainingFunction},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v, want %v", got, want)
	}
}

func TestApplicationDependencyGraph(t *testing.T) {
	key := func(name string) ComponentKey { return ComponentKey{Purl: "pkg:maven/g/" + name, Version: "1"} }
	a, b, c, d, gone := key("a"), key("b"), key("c"), key("d"), key("gone")
	present := map[ComponentKey]Fragment{a: {}, b: {}, c: {}, d: {}}
	// project -> a -> gone -> b; project -> c; d is pinned but no edge names it.
	edges := map[ComponentKey][]ComponentKey{a: {gone}, gone: {b}}
	deps, via := dependencyGraph(Root, []ComponentKey{a, gone, b, c, d}, []string{a.Purl, c.Purl}, edges, present)
	want := DependencyGraph{Root: {a, c, d}, a: {b}, b: nil, c: nil, d: nil}
	if !reflect.DeepEqual(deps, want) {
		t.Errorf("graph %v, want %v (gone spliced out, d on the classpath)", deps, want)
	}
	if !reflect.DeepEqual(via, map[ComponentKey]bool{b: true}) {
		t.Errorf("reached only through a missing graph: %v, want only b", via)
	}
}

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
		map[string]verdict{seen: {reachability: VerdictReachable}}, nil, nil)
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
		map[string]verdict{seen: {reachability: VerdictReachable}}, nil, nil)
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

// A PyPI purl's module id is its PEP 503 distribution name, the name the
// Python dependency resolver gives the dependency (not its import name).
func TestPurlToModule(t *testing.T) {
	t.Parallel()
	for purl, want := range map[string]string{
		"pkg:maven/commons-codec/commons-codec": "commons-codec:commons-codec",
		"pkg:pypi/pyjwt":                        "pyjwt",
		"pkg:pypi/Matrix_Synapse@1.165.0":       "matrix-synapse",
		"pkg:pypi/zope.interface?extra=x":       "zope-interface",
		"pkg:pypi/":                             "pkg:pypi/",
		"pkg:golang/filippo.io/age@v1.3.2":      "filippo.io/age",
		"pkg:npm/left-pad":                      "pkg:npm/left-pad",
		"pkg:nuget/Acme.Crypto":                 "Acme.Crypto",
		"pkg:nuget/Acme.Mail@5.0.0":             "Acme.Mail",
		"pkg:nuget/":                            "pkg:nuget/",
	} {
		if got := PurlToModule(purl); got != want {
			t.Errorf("PurlToModule(%q) = %q, want %q", purl, got, want)
		}
	}
}
