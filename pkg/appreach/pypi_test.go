// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"reflect"
	"testing"

	core "github.com/scanoss/reach/appreach"

	gf "github.com/scanoss/reach/graphfrag"
)

// A PyPI dependency is pinned under its PEP 503 name and PEP 440 version; two
// spellings of one release are one dependency, two releases conflict. Maven
// purls and versions are read as before.
func TestNewPlanPyPISpelling(t *testing.T) {
	t.Parallel()
	sites := &gf.GraphFragmentExport{SchemaVersion: SchemaVersion}
	plan, rejected := NewPlan(Request{SchemaVersion: RequestSchemaVersion, CallSites: sites, Dependencies: []Dependency{
		{Purl: "pkg:pypi/Zope.Interface", Version: "7.0-RC1", Direct: true},
		{Purl: "pkg:pypi/zope_interface", Version: "7.0.0rc1"},
		{Purl: "pkg:pypi/PyJWT@2.10.1"},
		{Purl: "pkg:maven/Org.Example/Lib", Version: "1.0-RC1"},
	}}, DefaultLimits)
	if rejected != nil {
		t.Fatalf("rejected: %s", rejected.InfoMessage)
	}
	want := []ComponentKey{{Purl: "pkg:pypi/zope-interface", Version: "7.0rc1"}, {Purl: "pkg:pypi/pyjwt", Version: "2.10.1"}, {Purl: "pkg:maven/Org.Example/Lib", Version: "1.0-RC1"}}
	if !reflect.DeepEqual(plan.Keys, want) {
		t.Errorf("keys = %v, want %v", plan.Keys, want)
	}
	_, rejected = NewPlan(Request{SchemaVersion: RequestSchemaVersion, CallSites: sites, Dependencies: []Dependency{
		{Purl: "pkg:pypi/pyjwt", Version: "2.10.1", Direct: true}, {Purl: "pkg:pypi/PyJWT", Version: "2.10.2"},
	}}, DefaultLimits)
	if rejected == nil || rejected.InfoCode != InfoInvalidRequest {
		t.Errorf("two releases of one distribution: %+v, want rejected", rejected)
	}
}

// A Python dependency's findings get the stitch's verdict like any other
// ecosystem's: a Python and a Maven dependency in one response are both served
// reachable, and the Python stored report is served as it is.
func TestApplicationResponsePythonVerdicts(t *testing.T) {
	t.Parallel()
	py := ComponentKey{Purl: "pkg:pypi/pyjwt", Version: "2.10.1"}
	mvn := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}
	pyFrag := Fragment{Module: "pyjwt", CryptoOperations: []CryptoOperation{{FindingID: "py", FilePath: "jwt/api_jws.py", StartLine: 3, RuleID: "r"}}}
	mvnFrag := Fragment{Module: "g:a", CryptoOperations: []CryptoOperation{{FindingID: "mvn", FilePath: "A.java", StartLine: 3, RuleID: "r"}}}
	stored := func(id, path string) *StoredFindings {
		return &StoredFindings{Findings: []*FindingDTO{{FilePath: path, CryptographicAssets: []*CryptographicAssetDTO{
			{FindingID: id, StartLine: 3, Match: "sign(...)", Metadata: json.RawMessage(`{"assetType":"algorithm","algorithmName":"RS256"}`)},
		}}}}
	}
	pins := Pins{Order: []string{py.Purl, mvn.Purl}, Dep: map[string]Dependency{
		py.Purl: {Purl: py.Purl, Version: py.Version, Direct: true}, mvn.Purl: {Purl: mvn.Purl, Version: mvn.Version, Direct: true},
	}}
	pyID, mvnID := ComputeFindingID("pyjwt@2.10.1/jwt/api_jws.py", 3, "r"), ComputeFindingID("g:a@1/A.java", 3, "r")
	chains := json.RawMessage(`[[{"function_name":"app.main"}]]`)
	block := &ComponentDataDTO{Findings: []*FindingDTO{
		{FilePath: "pyjwt@2.10.1/jwt/api_jws.py", CryptographicAssets: []*CryptographicAssetDTO{{FindingID: pyID, CallChains: chains, Analysis: json.RawMessage(`{"call_chains":"complete"}`)}}},
		{FilePath: "g:a@1/A.java", CryptographicAssets: []*CryptographicAssetDTO{{FindingID: mvnID, CallChains: chains}}},
	}}
	resp, _ := applicationResponse(pins, []ComponentKey{py, mvn},
		map[ComponentKey]Component{py: {Fragment: &pyFrag, Stored: stored("py", "jwt/api_jws.py")}, mvn: {Fragment: &mvnFrag, Stored: stored("mvn", "A.java")}},
		block, map[ComponentKey]Fragment{py: pyFrag, mvn: mvnFrag},
		map[string]core.Verdict{pyID: {Reachability: VerdictReachable}, mvnID: {Reachability: VerdictReachable}}, nil, nil)
	if got := verdictsByID(resp.Dependencies[0]); !reflect.DeepEqual(got, map[string]string{"py": "reachable:"}) {
		t.Errorf("python: %v", got)
	}
	if a := resp.Dependencies[0].Findings[0].CryptographicAssets[0]; a.Match != "sign(...)" || string(a.Metadata) != `{"assetType":"algorithm","algorithmName":"RS256"}` {
		t.Errorf("python asset: %+v", a)
	}
	if got := verdictsByID(resp.Dependencies[1]); !reflect.DeepEqual(got, map[string]string{"mvn": "reachable:"}) {
		t.Errorf("maven: %v", got)
	}
	if resp.Summary != (Summary{Reachable: 2}) {
		t.Errorf("summary %+v", resp.Summary)
	}
}
