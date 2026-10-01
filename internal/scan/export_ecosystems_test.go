package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestExportContextSetRoutesFindingsByLanguage(t *testing.T) {
	t.Parallel()

	nodeGraph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}
	result := &engine.DepScanResult{
		CallGraph:    &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:    ecosystemJava,
		ProjectRoot:  t.TempDir(),
		Dependencies: []dependency.Dependency{{Module: "org.example:lib", Version: "1.0", Dir: t.TempDir()}},
		AdditionalEcosystems: []*engine.DepScanResult{
			{CallGraph: nodeGraph, Ecosystem: ecosystemNode, ProjectRoot: t.TempDir()},
		},
	}
	set := newCallGraphExportContextSet(result, nil, CallGraphExportOptions{})
	if len(set.ordered) != 2 || set.ordered[0] != set.primary {
		t.Fatalf("ordered contexts = %d, want the primary then node", len(set.ordered))
	}

	cases := []struct {
		language     string
		wantPrimary  bool
		wantAnalyzed bool
	}{
		{language: "java", wantPrimary: true, wantAnalyzed: true},
		{language: "typescript", wantPrimary: false, wantAnalyzed: true},
		{language: "javascript", wantPrimary: false, wantAnalyzed: true},
		// enry names .tsx files "TSX" and .jsx files "JSX"; the Node parser
		// reads both.
		{language: "tsx", wantPrimary: false, wantAnalyzed: true},
		{language: "jsx", wantPrimary: false, wantAnalyzed: true},
		// A supported language with no graph in this scan.
		{language: "python", wantPrimary: true, wantAnalyzed: false},
		// A language no call graph parser supports.
		{language: "kotlin", wantPrimary: true, wantAnalyzed: false},
		// Findings the tool synthesizes carry no language and stay primary.
		{language: "", wantPrimary: true, wantAnalyzed: true},
	}
	for _, tc := range cases {
		ctx, analyzed := set.forFinding(entities.Finding{Language: tc.language})
		if (ctx == set.primary) != tc.wantPrimary || analyzed != tc.wantAnalyzed {
			t.Errorf("forFinding(%q) = (primary %v, analyzed %v), want (primary %v, analyzed %v)", tc.language, ctx == set.primary, analyzed, tc.wantPrimary, tc.wantAnalyzed)
		}
	}
	if node := set.additional[ecosystemNode]; node == nil || node.graph != nodeGraph {
		t.Fatal("typescript findings must resolve against the node graph")
	}
}

// With dependencies resolved, an additional ecosystem is classified against
// its own source packages, the way first-party findings of the primary one
// are; without them it follows the project-reachability option.
func TestAdditionalEcosystemReachabilityFollowsThePrimary(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nodeGraph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		"web/app.run": {ID: callgraph.FunctionID{Package: "web/app", Name: "run"}, FilePath: root + "/web/app.ts"},
	}}
	extra := &engine.DepScanResult{CallGraph: nodeGraph, Ecosystem: ecosystemNode, ProjectRoot: root}
	primary := func(deps []dependency.Dependency) *engine.DepScanResult {
		return &engine.DepScanResult{
			CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}, Ecosystem: ecosystemJava,
			ProjectRoot: root, Dependencies: deps, AdditionalEcosystems: []*engine.DepScanResult{extra},
		}
	}
	deps := []dependency.Dependency{{Module: "org.example:lib", Version: "1.0", Dir: t.TempDir()}}

	if got := newCallGraphExportContextSet(primary(deps), nil, CallGraphExportOptions{}).additional[ecosystemNode].userPackages; !got["web/app"] {
		t.Errorf("dependency scan: node user packages = %v, want the node source package", got)
	}
	if got := newCallGraphExportContextSet(primary(nil), nil, CallGraphExportOptions{ProjectReachability: true}).additional[ecosystemNode].userPackages; !got["web/app"] {
		t.Errorf("project reachability: node user packages = %v, want the node source package", got)
	}
	if got := newCallGraphExportContextSet(primary(nil), nil, CallGraphExportOptions{}).additional[ecosystemNode].userPackages; got != nil {
		t.Errorf("library scan: node user packages = %v, want none (not_applicable)", got)
	}
}

func TestAdditionalCallGraphEcosystems(t *testing.T) {
	t.Parallel()

	report := &entities.InterimReport{Findings: []entities.Finding{
		{Language: "java", CryptographicAssets: []entities.CryptographicAsset{{}}},
		{Language: "typescript", CryptographicAssets: []entities.CryptographicAsset{{}}},
		{Language: "javascript", CryptographicAssets: []entities.CryptographicAsset{{}}},
		{Language: "kotlin", CryptographicAssets: []entities.CryptographicAsset{{}}},
		// A dependency finding never asks for a graph of its own.
		{Language: "python", CryptographicAssets: []entities.CryptographicAsset{{DependencyInfo: &entities.DependencyInfo{Module: "m", Version: "1"}}}},
		{Language: "go", CryptographicAssets: []entities.CryptographicAsset{{}}},
	}}
	got := AdditionalCallGraphEcosystems(report, ecosystemJava)
	want := []string{ecosystemGo, ecosystemNode}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("AdditionalCallGraphEcosystems = %v, want %v", got, want)
	}
	cFamily := &entities.InterimReport{Findings: []entities.Finding{{Language: "c++", CryptographicAssets: []entities.CryptographicAsset{{}}}}}
	if got := AdditionalCallGraphEcosystems(cFamily, "c"); len(got) != 0 {
		t.Fatalf("C++ findings of a C scan resolve in its graph, got additional %v", got)
	}
}

func TestExportEcosystemsMetaIsAbsentForOneEcosystem(t *testing.T) {
	t.Parallel()

	result := &engine.DepScanResult{CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}, Ecosystem: ecosystemJava}
	if got := exportEcosystemsMeta(result); got != nil {
		t.Fatalf("single-ecosystem meta = %v, want nil so the export is unchanged", got)
	}
}

// A multi-ecosystem export validates against the schema of the version it
// stamps: the interned render lists the analyzed ecosystems, and the inlined
// compatibility render, still 6.14, leaves the list out.
func TestMultiEcosystemExportMatchesItsSchema(t *testing.T) {
	t.Parallel()

	for _, interned := range []bool{true, false} {
		graph, projectRoot := buildSupportingGraph(t)
		nodeDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(nodeDir, "hash.ts"), []byte("import { createHash } from 'crypto';\nexport function h(s: string) { return createHash('md5').update(s).digest('hex'); }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		nodeGraph, err := callgraph.NewBuilderForEcosystem(ecosystemNode, callgraph.NewNodeParser()).
			BuildFromDirectories([]callgraph.PackageDir{{Dir: nodeDir}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
		report.Findings = append(report.Findings,
			entities.Finding{FilePath: filepath.Join(nodeDir, "hash.ts"), Language: "typescript", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 2, EndLine: 2, Match: "createHash('md5')", Rules: []entities.RuleInfo{{ID: "ts.rule"}}, Metadata: map[string]string{"assetType": "algorithm"}}}},
			entities.Finding{FilePath: "Report.kt", Language: "kotlin", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 3, EndLine: 3, Match: "MessageDigest.getInstance(\"SHA-1\")", Rules: []entities.RuleInfo{{ID: "kt.rule"}}, Metadata: map[string]string{"assetType": "algorithm"}}}},
		)
		engine.EnsureFindingSources(report)
		engine.AssignFindingIDs(report)

		outputPath := filepath.Join(t.TempDir(), "callgraph.json")
		if err := exportCallGraphWithOptions(outputPath, "json", &engine.DepScanResult{
			Report: report, CallGraph: graph, Ecosystem: ecosystemJava, ProjectRoot: projectRoot, RootModule: "com.app:app",
			AdditionalEcosystems: []*engine.DepScanResult{{CallGraph: nodeGraph, Ecosystem: ecosystemNode, ProjectRoot: nodeDir}},
		}, CallGraphExportOptions{InternedFrames: interned, ProjectReachability: true}); err != nil {
			t.Fatalf("export: %v", err)
		}
		schema := "callgraph-schema.json"
		if interned {
			schema = "callgraph-schema-6.17.json"
		}
		assertJSONMatchesSchema(t, filepath.Join("..", "..", "schemas", schema), outputPath)

		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		var payload callGraphExportV2
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if interned != (len(payload.ScanMetadata.Ecosystems) == 2) {
			t.Fatalf("interned=%v: scan_metadata.ecosystems = %v", interned, payload.ScanMetadata.Ecosystems)
		}
		reasons := map[string]string{}
		for _, fg := range payload.FindingGraphs {
			reasons[fg.FindingID] = fg.UnresolvedReason + "/" + fg.Reachability
		}
		want := map[string]string{
			"typescript": "/unreachable",
			"kotlin":     unresolvedLanguageNotAnalyzed + "/not_applicable",
		}
		for i := range report.Findings {
			finding := report.Findings[i]
			got := reasons[finding.CryptographicAssets[0].FindingID]
			if finding.Language == "java" {
				// The Java fixture keeps its own verdict; only its routing matters here.
				if got == want["kotlin"] {
					t.Fatalf("interned=%v: java finding marked not analyzed", interned)
				}
				continue
			}
			if got != want[finding.Language] {
				t.Errorf("interned=%v %s finding: reason/reachability = %q, want %q", interned, finding.Language, got, want[finding.Language])
			}
		}
	}
}
