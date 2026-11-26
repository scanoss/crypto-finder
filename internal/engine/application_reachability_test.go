// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/graphfrag"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// applicationClosureFixture is app -> a -> {b, c}, app -> d, with c resolved at a
// second version through a multi-module root.
func applicationClosureFixture() *ApplicationClosure {
	resolved := &dependency.ResolveResult{
		RootModule: "com.example:app",
		Dependencies: []dependency.Dependency{
			{Module: "org.a:a", Version: "1.0", CompiledArtifactPath: "/m2/a-1.0.jar"},
			{Module: "org.b:b", Version: "2.0", CompiledArtifactPath: "/m2/b-2.0.jar"},
			{Module: "org.c:c", Version: "3.0", CompiledArtifactPath: "/m2/c-3.0.jar"},
			{Module: "org.c:c", Version: "3.1"},
			{Module: "org.d:d", Version: "4.0", CompiledArtifactPath: "/m2/d-4.0.jar"},
		},
		VersionedGraph: map[string][]dependency.Ref{
			"com.example:app@1": {{Module: "org.a:a", Version: "1.0"}, {Module: "org.d:d", Version: "4.0"}},
			"org.a:a@1.0":       {{Module: "org.b:b", Version: "2.0"}, {Module: "org.c:c", Version: "3.0"}, {Module: "org.x:unpinned", Version: "9"}},
		},
	}
	return &ApplicationClosure{
		Ecosystem: "java",
		Target:    "/src/app",
		Resolved:  resolved,
		Paths: map[string]dependency.Path{
			"org.a:a": {Steps: []dependency.PathStep{{Module: "org.a:a"}}},
			"org.b:b": {Steps: []dependency.PathStep{{Module: "org.a:a"}, {Module: "org.b:b"}}},
			"org.c:c": {Steps: []dependency.PathStep{{Module: "org.a:a"}, {Module: "org.c:c"}}},
			"org.d:d": {Steps: []dependency.PathStep{{Module: "org.d:d"}}},
		},
	}
}

func TestApplicationClosureRequest_PinsTheClosure(t *testing.T) {
	request, err := applicationClosureFixture().Request(&graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion}, nil, 2)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	want := []apiclient.ApplicationDependency{
		{Purl: "pkg:maven/org.a/a", Version: "1.0", Direct: true, Requires: []string{"pkg:maven/org.b/b", "pkg:maven/org.c/c"}},
		{Purl: "pkg:maven/org.b/b", Version: "2.0"},
		{Purl: "pkg:maven/org.c/c", Version: "3.0"},
		{Purl: "pkg:maven/org.d/d", Version: "4.0", Direct: true},
	}
	if !reflect.DeepEqual(request.Dependencies, want) {
		t.Errorf("dependencies =\n%+v\nwant\n%+v", request.Dependencies, want)
	}
	if request.SchemaVersion != "1" || !request.IncludeCallChains || request.MaxChainsPerFinding != 2 {
		t.Errorf("request = schema %q, chains %v/%d", request.SchemaVersion, request.IncludeCallChains, request.MaxChainsPerFinding)
	}
}

// TestApplicationClosureRequest_RequiresOmittedEdges: a child Maven printed only
// as omitted under a parent (bcutil -> bcprov when the project pins bcprov
// itself) is still one the parent requires; without it the stitch resolves
// none of the parent's calls into the child.
func TestApplicationClosureRequest_RequiresOmittedEdges(t *testing.T) {
	closure := applicationClosureFixture()
	closure.Resolved.OmittedEdges = map[string][]dependency.Ref{
		"org.b:b@2.0": {{Module: "org.d:d", Version: "4.0"}},
		"org.a:a@1.0": {{Module: "org.b:b", Version: "2.0"}},
	}
	request, err := closure.Request(nil, nil, 0)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	want := map[string][]string{
		"pkg:maven/org.a/a": {"pkg:maven/org.b/b", "pkg:maven/org.c/c"},
		"pkg:maven/org.b/b": {"pkg:maven/org.d/d"},
		"pkg:maven/org.c/c": nil,
		"pkg:maven/org.d/d": nil,
	}
	for _, dep := range request.Dependencies {
		if !reflect.DeepEqual(dep.Requires, want[dep.Purl]) {
			t.Errorf("%s requires %v, want %v", dep.Purl, dep.Requires, want[dep.Purl])
		}
	}
}

func TestApplicationClosureRequest_WithoutTreeEveryDependencyIsDirect(t *testing.T) {
	closure := applicationClosureFixture()
	closure.Paths, closure.Resolved.VersionedGraph = nil, nil
	request, err := closure.Request(nil, nil, 0)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	for _, dep := range request.Dependencies {
		if !dep.Direct || dep.Requires != nil {
			t.Errorf("%s: direct %v, requires %v", dep.Purl, dep.Direct, dep.Requires)
		}
	}
	if request.IncludeCallChains || request.MaxChainsPerFinding != 0 {
		t.Errorf("chains requested with max 0")
	}
}

func TestCallSites_KeepsCallersOfDependencies(t *testing.T) {
	project := &graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		ScanMetadata:  graphfrag.GraphFragmentScanMetadata{Ecosystem: "java", RootModule: "com.example:app", GraphAlgoVersion: "graph-algo-34", ToolName: "crypto-finder"},
		Functions:     []graphfrag.GraphFragmentFunction{{Key: "app.(A).calls#0"}, {Key: "app.(B).internal#0"}},
		InternalEdges: []graphfrag.GraphFragmentEdge{{}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{{CallerKey: "app.(A).calls#0", TargetKey: "org.a.(X).run#0"}},
		Supertypes:    map[string][]string{"app.A": {"org.a.Base"}},
		SourceLines:   map[string]map[int]string{"A.java": {1: "x"}},
	}
	got := CallSites(project, nil)
	if len(got.Functions) != 1 || got.Functions[0].Key != "app.(A).calls#0" {
		t.Errorf("functions = %+v", got.Functions)
	}
	if len(got.ExternalCalls) != 1 || !reflect.DeepEqual(got.Supertypes, project.Supertypes) {
		t.Errorf("external calls %d, supertypes %v", len(got.ExternalCalls), got.Supertypes)
	}
	if got.InternalEdges != nil || got.SourceLines != nil || got.ScanMetadata.ToolName != "" {
		t.Errorf("call sites carry more than the API reads: edges %v, source lines %v, tool %q", got.InternalEdges, got.SourceLines, got.ScanMetadata.ToolName)
	}
	if got.ScanMetadata.RootModule != "com.example:app" || got.ScanMetadata.GraphAlgoVersion != "graph-algo-34" || got.SchemaVersion != graphfrag.SchemaVersion {
		t.Errorf("metadata = %+v", got.ScanMetadata)
	}
}

// The API roots its walk at every function it is sent, so the calls of an
// unreachable function are not sent.
func TestCallSites_LeavesOutCallsOfUnreachableFunctions(t *testing.T) {
	project := &graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		Functions:     []graphfrag.GraphFragmentFunction{{Key: "app.live#0"}, {Key: "app.dead#0"}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			{CallerKey: "app.live#0", TargetKey: "org.a.(X).run#0"},
			{CallerKey: "app.dead#0", TargetKey: "org.a.(X).run#0"},
			{CallerKey: "app.dead#0", TargetKey: "org.a.(X).stop#0"},
		},
	}
	got := CallSites(project, map[string]bool{"app.dead#0": true})
	if len(got.Functions) != 1 || got.Functions[0].Key != "app.live#0" {
		t.Errorf("functions = %+v", got.Functions)
	}
	if len(got.ExternalCalls) != 1 || got.ExternalCalls[0].CallerKey != "app.live#0" {
		t.Errorf("external calls = %+v", got.ExternalCalls)
	}
	if got.ScanMetadata.ExternalCalls != 1 || got.ScanMetadata.FunctionCount != 1 {
		t.Errorf("metadata counts = %+v", got.ScanMetadata)
	}
	if len(project.ExternalCalls) != 3 {
		t.Errorf("the project fragment lost calls: %d left", len(project.ExternalCalls))
	}
}

func TestMergeApplicationReachability_ReportsDependencyFindingsWithVerdicts(t *testing.T) {
	closure := applicationClosureFixture()
	report := &entities.InterimReport{Version: entities.InterimFormatVersion, Findings: []entities.Finding{{
		FilePath: "src/main/java/app/A.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 3, Rules: []entities.RuleInfo{{ID: "r.app"}}}},
	}}}
	info := &entities.DependencyInfo{Module: "org.a:a", Version: "1.0", PURL: "pkg:maven/org.a/a@1.0"}
	asset := func(line int, rule, verdict, reason string) apiclient.ApplicationAsset {
		return apiclient.ApplicationAsset{
			Asset:              entities.CryptographicAsset{StartLine: line, EndLine: line, Source: "indirect", FindingID: "served", PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on", Rules: []entities.RuleInfo{{ID: rule}}},
			Reachability:       verdict,
			ReachabilityReason: reason,
			CallChains:         []byte(`[[{"function_key":"app.(A).calls#0"}]]`),
		}
	}
	answer := &apiclient.ApplicationReachability{InfoCode: "READY", Dependencies: []apiclient.ApplicationDependencyAnswer{
		{Purl: "pkg:maven/org.a/a", Version: "1.0", InfoCode: "READY", Findings: []apiclient.ApplicationFinding{{
			FilePath: "org.a:a@1.0/org/a/X.java", Language: "java", DependencyInfo: info,
			CryptographicAssets: []apiclient.ApplicationAsset{asset(10, "r.x", "reachable", ""), asset(20, "r.y", "unknown", "ambiguous_dispatch")},
		}}},
		{Purl: "pkg:maven/org.b/b", Version: "2.0", InfoCode: "NO_INFO"},
	}}
	// The project's graph names its module otherwise than the resolver
	// (a Maven graph says groupId:artifactId, the resolver groupId).
	project := &DepScanResult{RootModule: "com.example:app-graph", ProjectRoot: "/src/app"}

	result, outcome := MergeApplicationReachability(report, project, closure, answer)

	if len(report.Findings) != 1 {
		t.Errorf("the input report changed: %d findings", len(report.Findings))
	}
	findings := result.Report.Findings
	if len(findings) != 2 || findings[0].CryptographicAssets[0].Source != "direct" {
		t.Fatalf("findings = %+v", findings)
	}
	dep := findings[1]
	if dep.FilePath != "org/a/X.java" || len(dep.CryptographicAssets) != 2 {
		t.Fatalf("dependency finding = %q with %d assets", dep.FilePath, len(dep.CryptographicAssets))
	}
	for _, a := range dep.CryptographicAssets {
		if a.Source != "dependency" || a.DependencyInfo == nil || a.DependencyInfo.PURL != "pkg:maven/org.a/a@1.0" {
			t.Errorf("asset %d: source %q, dependency %+v", a.StartLine, a.Source, a.DependencyInfo)
		}
		if a.PURL != "" {
			t.Errorf("asset %d: rule purl %q kept, want it dropped as a dependency scan drops it", a.StartLine, a.PURL)
		}
		if a.FindingID == "" || a.FindingID == "served" {
			t.Errorf("asset %d: finding id %q, want one assigned like a dependency scan's", a.StartLine, a.FindingID)
		}
		if a.Served == nil || len(a.Served.CallChains) == 0 {
			t.Errorf("asset %d: no served verdict", a.StartLine)
		}
	}
	reached, unknown := dep.CryptographicAssets[0].Served, dep.CryptographicAssets[1].Served
	if reached.Reachability != "reachable" || unknown.Reachability != "unknown" || unknown.Reason != "ambiguous_dispatch" {
		t.Errorf("verdicts = %+v, %+v", reached, unknown)
	}
	// The id a dependency scan gives the same finding: module@version/path.
	if want := generateFindingID("org.a:a@1.0/org/a/X.java", 10, []entities.RuleInfo{{ID: "r.x"}}, ""); dep.CryptographicAssets[0].FindingID != want {
		t.Errorf("finding id = %q, want %q", dep.CryptographicAssets[0].FindingID, want)
	}
	if outcome.Findings != 2 || outcome.Reachable != 1 || outcome.Unknown != 1 || len(outcome.DependenciesWithout) != 1 {
		t.Errorf("outcome = %+v", outcome)
	}
	if result.RootModule != "com.example:app" {
		t.Errorf("root module = %q, want the resolver's, as a dependency scan reports it", result.RootModule)
	}
	if len(result.Dependencies) != len(closure.Resolved.Dependencies) || result.DependencyPaths["org.b:b"].Steps == nil || result.Ecosystem != "java" {
		t.Errorf("result dependencies %d, paths %v, ecosystem %q", len(result.Dependencies), result.DependencyPaths, result.Ecosystem)
	}
}

func TestApplicationClosureCompiledArtifacts(t *testing.T) {
	got := applicationClosureFixture().CompiledArtifacts()
	want := []string{"/m2/a-1.0.jar", "/m2/b-2.0.jar", "/m2/c-3.0.jar", "/m2/d-4.0.jar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("compiled artifacts = %v, want %v", got, want)
	}
}

// TestApplicationClosure_NpmPinsTheLoadedVersion: an npm lock with bn.js hoisted
// at 5.2.1 and 4.12.0 nested under elliptic requests 5.2.1 (the version a bare
// require loads, not the text-first 4.12.0) and lists 4.12.0 among the
// dependencies without data, reason other_version_requested.
func TestApplicationClosure_NpmPinsTheLoadedVersion(t *testing.T) {
	target := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"elliptic":"^6.5.0","bn.js":"^5.0.0"}},
"node_modules/bn.js":{"version":"5.2.1"},
"node_modules/elliptic":{"version":"6.5.4","dependencies":{"bn.js":"^4.0.0"}},
"node_modules/elliptic/node_modules/bn.js":{"version":"4.12.0","dependencies":{"inherits":"^2.0.0"}},
"node_modules/inherits":{"version":"2.0.4"}}}`
	if err := os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	closure, err := ResolveApplicationClosure(t.Context(), dependency.NewNpmResolver(), target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := closure.Request(&graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []apiclient.ApplicationDependency{
		{Purl: "pkg:npm/bn.js", Version: "5.2.1", Direct: true},
		{Purl: "pkg:npm/elliptic", Version: "6.5.4", Direct: true, Requires: []string{"pkg:npm/bn.js"}},
	}
	if !reflect.DeepEqual(request.Dependencies, want) {
		t.Errorf("dependencies =\n%+v\nwant\n%+v", request.Dependencies, want)
	}
	var outcome ApplicationReachabilityOutcome
	AddUnpinned(&outcome, closure)
	// inherits is required only by the dropped bn.js 4.12.0: no requested
	// package leads to it, so it is listed rather than served unreachable.
	wantWithout := []DependencyWithout{
		{Module: "bn.js", Version: "4.12.0", PURL: "pkg:npm/bn.js", Reason: DependencyWithoutOtherVersion},
		{Module: "inherits", Version: "2.0.4", PURL: "pkg:npm/inherits", Reason: DependencyWithoutUnderOtherVersion},
	}
	if !reflect.DeepEqual(outcome.DependenciesWithout, wantWithout) {
		t.Errorf("without = %+v, want %+v", outcome.DependenciesWithout, wantWithout)
	}
}
