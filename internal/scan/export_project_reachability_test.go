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

package scan

import (
	"maps"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

type projectReachabilityFixture struct {
	projectRoot string
	depDir      string
	graph       *callgraph.CallGraph
	report      func() *entities.InterimReport
}

// newProjectReachabilityFixture models a Go application: main calls used,
// which hashes; dead hashes but nothing calls it; a dependency function also
// hashes and is called from used.
func newProjectReachabilityFixture(t *testing.T) projectReachabilityFixture {
	t.Helper()
	projectRoot := t.TempDir()
	depDir := t.TempDir()
	appFile := filepath.Join(projectRoot, "main.go")
	libFile := filepath.Join(depDir, "lib.go")

	mainID := callgraph.FunctionID{Package: "example.com/app", Name: "main"}
	usedID := callgraph.FunctionID{Package: "example.com/app", Name: "used"}
	deadID := callgraph.FunctionID{Package: "example.com/app", Name: "dead"}
	libID := callgraph.FunctionID{Package: "example.com/lib", Name: "Digest"}
	sumID := callgraph.FunctionID{Package: "crypto/sha256", Name: "Sum256"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			mainID.String(): {ID: mainID, FilePath: appFile, StartLine: 1, EndLine: 3, Calls: []callgraph.FunctionCall{
				{Callee: usedID, FilePath: appFile, Line: 2, Raw: "used()"},
			}},
			usedID.String(): {ID: usedID, FilePath: appFile, StartLine: 5, EndLine: 8, Calls: []callgraph.FunctionCall{
				{Callee: sumID, FilePath: appFile, Line: 6, Raw: "sha256.Sum256(b)"},
				{Callee: libID, FilePath: appFile, Line: 7, Raw: "lib.Digest(b)"},
			}},
			deadID.String(): {ID: deadID, FilePath: appFile, StartLine: 10, EndLine: 12, Calls: []callgraph.FunctionCall{
				{Callee: sumID, FilePath: appFile, Line: 11, Raw: "sha256.Sum256(b)"},
			}},
			libID.String(): {ID: libID, FilePath: libFile, StartLine: 1, EndLine: 3, Calls: []callgraph.FunctionCall{
				{Callee: sumID, FilePath: libFile, Line: 2, Raw: "sha256.Sum256(b)"},
			}},
		},
		Callers: map[string][]string{
			usedID.String(): {mainID.String()},
			libID.String():  {usedID.String()},
			sumID.String():  {usedID.String(), deadID.String(), libID.String()},
		},
	}
	asset := func(id string, line int) entities.CryptographicAsset {
		return entities.CryptographicAsset{
			FindingID: id,
			StartLine: line,
			EndLine:   line,
			Match:     "sha256.Sum256(b)",
			Rules:     []entities.RuleInfo{{ID: "go.crypto.sha256"}},
			Metadata:  map[string]string{"assetType": "algorithm", "algorithmFamily": "SHA-2"},
		}
	}
	report := func() *entities.InterimReport {
		return &entities.InterimReport{Findings: []entities.Finding{
			{FilePath: appFile, Language: "go", CryptographicAssets: []entities.CryptographicAsset{asset("used", 6), asset("dead", 11)}},
			{FilePath: libFile, Language: "go", CryptographicAssets: []entities.CryptographicAsset{asset("lib", 2)}},
		}}
	}
	return projectReachabilityFixture{projectRoot: projectRoot, depDir: depDir, graph: graph, report: report}
}

func (f projectReachabilityFixture) result(withDependencies bool) *engine.DepScanResult {
	result := &engine.DepScanResult{
		Report:      f.report(),
		CallGraph:   f.graph,
		Ecosystem:   "go",
		ProjectRoot: f.projectRoot,
		RootModule:  "example.com/app",
	}
	if withDependencies {
		result.Dependencies = []dependency.Dependency{{Module: "example.com/lib", Version: "v1.0.0", Dir: f.depDir}}
	}
	return result
}

// exportReachability runs both callgraph export builders (the raw fixture path
// and the resolved path the CLI uses) and requires them to agree.
func exportReachability(t *testing.T, result *engine.DepScanResult, options CallGraphExportOptions) map[string]string {
	t.Helper()
	resolved := prepareOIDFixtureReport(t, result.Report)

	rawPath := filepath.Join(t.TempDir(), "raw.json")
	if err := exportCallGraphWithOptions(rawPath, "json", result, options); err != nil {
		t.Fatalf("exportCallGraphWithOptions: %v", err)
	}
	resolvedPath := filepath.Join(t.TempDir(), "resolved.json")
	if err := ExportResolvedCallGraph(resolvedPath, "json", result, resolved, options); err != nil {
		t.Fatalf("ExportResolvedCallGraph: %v", err)
	}

	raw := reachabilityByFindingID(mustDecodeCallGraphExport(t, rawPath).FindingGraphs)
	viaResolved := reachabilityByFindingID(mustDecodeCallGraphExport(t, resolvedPath).FindingGraphs)
	if !maps.Equal(raw, viaResolved) {
		t.Fatalf("raw export reachability %v differs from resolved export %v", raw, viaResolved)
	}
	return raw
}

func reachabilityByFindingID(graphs []callGraphExportFinding) map[string]string {
	out := make(map[string]string, len(graphs))
	for i := range graphs {
		out[graphs[i].FindingID] = graphs[i].Reachability
	}
	return out
}

func TestExportCallGraph_ProjectReachabilityWithoutDependencies(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)

	got := exportReachability(t, fixture.result(false), CallGraphExportOptions{ProjectReachability: true})

	want := map[string]string{
		"used": graphfrag.ReachabilityReachable,
		"dead": graphfrag.ReachabilityUnreachable,
		"lib":  graphfrag.ReachabilityReachable,
	}
	if !maps.Equal(got, want) {
		t.Fatalf("reachability = %v, want %v", got, want)
	}
}

// The mine path scans a library on its own: without the option a run that
// resolved no dependencies has no user code, so every verdict stays
// not_applicable.
func TestExportCallGraph_WithoutProjectReachabilityKeepsMinePath(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)

	got := exportReachability(t, fixture.result(false), CallGraphExportOptions{})

	for id, verdict := range got {
		if verdict != graphfrag.ReachabilityNotApplicable {
			t.Errorf("finding %s reachability = %q, want %q", id, verdict, graphfrag.ReachabilityNotApplicable)
		}
	}
	if len(got) != 3 {
		t.Fatalf("exported %d finding graphs, want 3", len(got))
	}
}

func TestExportCallGraph_ProjectReachabilityIgnoredWithDependencies(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)

	without := exportReachability(t, fixture.result(true), CallGraphExportOptions{})
	with := exportReachability(t, fixture.result(true), CallGraphExportOptions{ProjectReachability: true})

	if !maps.Equal(without, with) {
		t.Fatalf("with dependencies, reachability changed with the option: without %v, with %v", without, with)
	}
	if with["used"] != graphfrag.ReachabilityReachable || with["dead"] != graphfrag.ReachabilityUnreachable {
		t.Fatalf("reachability = %v, want used reachable and dead unreachable", with)
	}
}

// A resolved run with no root module has no user universe today. The option
// must not supply one, or it would change a result that has dependencies.
func TestExportCallGraph_ProjectReachabilityIgnoredWithDependenciesAndNoRootModule(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)
	withoutRoot := func() *engine.DepScanResult {
		result := fixture.result(true)
		result.RootModule = ""
		return result
	}

	got := exportReachability(t, withoutRoot(), CallGraphExportOptions{ProjectReachability: true})

	want := exportReachability(t, withoutRoot(), CallGraphExportOptions{})
	if !maps.Equal(got, want) {
		t.Fatalf("reachability with the option = %v, want the default %v", got, want)
	}
}

// A full run and a project-reachability run must trace against the same
// first-party universe, or their verdicts could drift apart.
func TestProjectUserPackages_MatchesFirstPartyUniverseOfResolvedRun(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)

	full := exportUserPackages(fixture.result(true))
	project := projectUserPackages(fixture.result(false))

	want := map[string]bool{"example.com/app": true}
	if !maps.Equal(full, want) {
		t.Fatalf("resolved run user packages = %v, want %v", full, want)
	}
	if !maps.Equal(project, want) {
		t.Fatalf("project user packages = %v, want %v", project, want)
	}
}

func TestExportCallGraph_ProjectReachabilityWithNoProjectSourcesStaysNotApplicable(t *testing.T) {
	t.Parallel()
	fixture := newProjectReachabilityFixture(t)
	result := fixture.result(false)
	result.ProjectRoot = ""
	result.RootModule = ""

	got := exportReachability(t, result, CallGraphExportOptions{ProjectReachability: true})

	for id, verdict := range got {
		if verdict != graphfrag.ReachabilityNotApplicable {
			t.Errorf("finding %s reachability = %q, want %q", id, verdict, graphfrag.ReachabilityNotApplicable)
		}
	}
}
