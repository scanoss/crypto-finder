// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// provenanceFixture is an application that reaches crypto in org.b:digest
// through org.a:bridge (app -> A -> B), and depends on org.c:orphan only
// through org.x:types, which joined the graph without source.
type provenanceFixture struct {
	result *engine.DepScanResult
}

func newProvenanceFixture(t *testing.T) provenanceFixture {
	t.Helper()
	projectRoot := t.TempDir()
	depA := filepath.Join(t.TempDir(), "a")
	depB := filepath.Join(t.TempDir(), "b")
	depC := filepath.Join(t.TempDir(), "c")
	digest := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	fn := func(pkg, typ, name, file string, calls ...callgraph.FunctionCall) *callgraph.FunctionDecl {
		return &callgraph.FunctionDecl{
			ID:       callgraph.FunctionID{Package: pkg, Type: typ, Name: name},
			FilePath: file, StartLine: 1, EndLine: 11, Calls: calls,
		}
	}
	call := func(callee callgraph.FunctionID, file string, line int, args ...string) callgraph.FunctionCall {
		return callgraph.FunctionCall{
			Callee: callee, FilePath: file, Line: line, Arguments: args,
			ASTKind: "method_invocation", NamedASTPath: "block[0]/method_invocation[0]",
		}
	}
	appFile := joinTestPath(projectRoot, "com/acme/App.java")
	bridgeFile := joinTestPath(depA, "org/a/Bridge.java")
	hashFile := joinTestPath(depB, "org/b/Hash.java")
	orphanFile := joinTestPath(depC, "org/c/Orphan.java")
	main := fn("com.acme", "App", "main#1", appFile,
		call(callgraph.FunctionID{Package: "org.a", Type: "Bridge", Name: "run#0"}, appFile, 3),
		call(digest, appFile, 4, `"SHA-256"`))
	bridge := fn("org.a", "Bridge", "run#0", bridgeFile,
		call(callgraph.FunctionID{Package: "org.b", Type: "Hash", Name: "md5#0"}, bridgeFile, 3))
	hash := fn("org.b", "Hash", "md5#0", hashFile, call(digest, hashFile, 3, `"MD5"`))
	orphan := fn("org.c", "Orphan", "sha1#0", orphanFile, call(digest, orphanFile, 3, `"SHA-1"`))
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			main.ID.String(): main, bridge.ID.String(): bridge, hash.ID.String(): hash, orphan.ID.String(): orphan,
		},
		Callers: map[string][]string{
			bridge.ID.String(): {main.ID.String()},
			hash.ID.String():   {bridge.ID.String()},
			digest.String():    {main.ID.String(), hash.ID.String(), orphan.ID.String()},
		},
	}
	asset := func(id, file string, dep *entities.DependencyInfo) entities.Finding {
		source := "direct"
		if dep != nil {
			source = "dependency"
		}
		return entities.Finding{FilePath: file, Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
			StartLine: 3, EndLine: 3, Match: "MessageDigest.getInstance(alg)",
			Rules:  []entities.RuleInfo{{ID: "java.hash", Message: "hash", Severity: "INFO"}},
			Status: "pending", Metadata: map[string]string{"api": "MessageDigest.getInstance"},
			FindingID: id, Source: source, DependencyInfo: dep,
		}}}
	}
	report := &entities.InterimReport{
		Version: "1.6",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{
			asset("app", "com/acme/App.java", nil),
			asset("hash", "org/b/Hash.java", &entities.DependencyInfo{Module: "org.b:digest", Version: "2.0"}),
			asset("orphan", "org/c/Orphan.java", &entities.DependencyInfo{Module: "org.c:orphan", Version: "3.0"}),
		},
	}
	report.Findings[0].CryptographicAssets[0].StartLine = 4
	report.Findings[0].CryptographicAssets[0].EndLine = 4
	resolved := &dependency.ResolveResult{
		RootModule: "com.acme:app",
		Graph: map[string][]string{
			"com.acme:app": {"org.a:bridge", "org.x:types"},
			"org.a:bridge": {"org.b:digest"},
			"org.x:types":  {"org.c:orphan"},
		},
	}
	deps := []dependency.Dependency{
		{Module: "org.a:bridge", Version: "1.0", Dir: depA},
		{Module: "org.b:digest", Version: "2.0", Dir: depB},
		{Module: "org.c:orphan", Version: "3.0", Dir: depC},
		{Module: "org.x:types", Version: "4.0"},
	}
	parsed := map[string]bool{"org.a:bridge": true, "org.b:digest": true, "org.c:orphan": true}
	return provenanceFixture{result: &engine.DepScanResult{
		CallGraph: graph, Report: report, RootModule: "com.acme:app", Ecosystem: "java",
		ProjectRoot: projectRoot, Dependencies: deps, DependencyPaths: dependency.Paths(resolved, parsed),
	}}
}

func exportProvenance(t *testing.T, result *engine.DepScanResult) map[string]callGraphExportFinding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := exportCallGraph(path, "json", result); err != nil {
		t.Fatalf("export: %v", err)
	}
	payload := mustDecodeCallGraphExport(t, path)
	out := make(map[string]callGraphExportFinding, len(payload.FindingGraphs))
	for i := range payload.FindingGraphs {
		out[payload.FindingGraphs[i].FindingID] = payload.FindingGraphs[i]
	}
	return out
}

// TestExportCallGraph_DependencyFindingCarriesItsProvenance: a dependency
// finding names its dependency, package URL and route from the application in
// the resolved dependency graph; a first-party finding carries none.
func TestExportCallGraph_DependencyFindingCarriesItsProvenance(t *testing.T) {
	t.Parallel()
	graphs := exportProvenance(t, newProvenanceFixture(t).result)

	if dep := graphs["app"].Dependency; dep != nil {
		t.Errorf("first-party finding carries dependency %+v", dep)
	}
	hash := graphs["hash"]
	want := &graphfrag.ExportFindingDependency{
		Module: "org.b:digest", Version: "2.0", PURL: "pkg:maven/org.b/digest@2.0",
		Relationship: graphfrag.DependencyTransitive,
		Path: []graphfrag.ExportDependencyPathStep{
			{Module: "org.a:bridge", Version: "1.0", PURL: "pkg:maven/org.a/bridge@1.0"},
			{Module: "org.b:digest", Version: "2.0", PURL: "pkg:maven/org.b/digest@2.0"},
		},
	}
	if !reflect.DeepEqual(hash.Dependency, want) {
		t.Errorf("dependency = %+v, want %+v", hash.Dependency, want)
	}
	if hash.Reachability != graphfrag.ReachabilityReachable {
		t.Errorf("reachability = %q, want reachable through the bridge", hash.Reachability)
	}
}

// TestExportCallGraph_DependencyBehindUnparsedSourceIsUnknown: org.c:orphan is
// reached only through org.x:types, which has no source and so no calls in
// the graph. No chain reaches the orphan's crypto, but that proves nothing:
// it reads unknown (dependency_without_source), and its path names the
// dependency the chain would cross.
func TestExportCallGraph_DependencyBehindUnparsedSourceIsUnknown(t *testing.T) {
	t.Parallel()
	orphan := exportProvenance(t, newProvenanceFixture(t).result)["orphan"]

	if orphan.Reachability != graphfrag.ReachabilityUnknown || orphan.UnresolvedReason != graphfrag.UnresolvedReasonDependencyWithoutSource || orphan.Reachable != nil {
		t.Errorf("reachability %q reason %q reachable %v, want unknown %q unset",
			orphan.Reachability, orphan.UnresolvedReason, orphan.Reachable, graphfrag.UnresolvedReasonDependencyWithoutSource)
	}
	if orphan.Analysis == nil || orphan.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Errorf("analysis = %+v, want call_chains partial", orphan.Analysis)
	}
	if orphan.Dependency == nil || len(orphan.Dependency.Path) != 2 || !orphan.Dependency.Path[0].WithoutSource || orphan.Dependency.Path[1].WithoutSource {
		t.Errorf("dependency = %+v, want org.x:types then org.c:orphan, the first without source", orphan.Dependency)
	}
}

// TestExportCallGraph_DependencyProvenanceKeepsOccurrenceKeys: provenance is
// descriptive. With or without a resolved dependency graph, every finding
// keeps its occurrence key, and the reachable finding its verdict.
func TestExportCallGraph_DependencyProvenanceKeepsOccurrenceKeys(t *testing.T) {
	t.Parallel()
	with := exportProvenance(t, newProvenanceFixture(t).result)
	bare := newProvenanceFixture(t).result
	bare.DependencyPaths = nil
	without := exportProvenance(t, bare)
	for id, fg := range with {
		if fg.OccurrenceKey == "" || fg.OccurrenceKey != without[id].OccurrenceKey {
			t.Errorf("%s: occurrence key %q with provenance, %q without", id, fg.OccurrenceKey, without[id].OccurrenceKey)
		}
	}
	if dep := without["hash"].Dependency; dep == nil || dep.PURL != "pkg:maven/org.b/digest@2.0" || dep.Relationship != "" || dep.Path != nil {
		t.Errorf("dependency without a graph = %+v, want the package URL only", dep)
	}
	if without["orphan"].Reachability != graphfrag.ReachabilityUnreachable {
		t.Errorf("orphan without a graph reads %q, want unreachable", without["orphan"].Reachability)
	}
}

// TestExportCallGraph_DependencyProvenanceMatchesSchemas: the dependency block
// is declared by the published schema of each render.
func TestExportCallGraph_DependencyProvenanceMatchesSchemas(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		schema   string
		interned bool
	}{
		{schema: "callgraph-schema.json"},
		{schema: "callgraph-schema-6.17.json", interned: true},
	} {
		path := filepath.Join(t.TempDir(), "callgraph.json")
		if err := exportCallGraphWithOptions(path, "json", newProvenanceFixture(t).result, CallGraphExportOptions{InternedFrames: tc.interned}); err != nil {
			t.Fatalf("export: %v", err)
		}
		schema, err := filepath.Abs(filepath.Join("..", "..", "schemas", tc.schema))
		if err != nil {
			t.Fatal(err)
		}
		assertJSONMatchesSchema(t, schema, path)
	}
}
