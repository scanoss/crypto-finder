package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/skip"
)

type fakeResolver struct {
	ecosystem string
	resolveFn func(ctx context.Context, targetDir string) (*dependency.ResolveResult, error)
}

func (f *fakeResolver) Resolve(ctx context.Context, targetDir string) (*dependency.ResolveResult, error) {
	if f.resolveFn != nil {
		return f.resolveFn(ctx, targetDir)
	}
	return &dependency.ResolveResult{}, nil
}

func (f *fakeResolver) Ecosystem() string { return f.ecosystem }

func (f *fakeResolver) CanResolve(string) bool { return true }

type fakeFindingsCache struct {
	getMap     map[string]*entities.InterimReport
	getErr     error
	putErr     error
	putCalls   int
	putLastKey string
}

func (f *fakeFindingsCache) Get(_ context.Context, key string) (*entities.InterimReport, bool, error) {
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	report, ok := f.getMap[key]
	return report, ok, nil
}

func (f *fakeFindingsCache) Put(_ context.Context, key string, _ *entities.InterimReport) error {
	f.putCalls++
	f.putLastKey = key
	return f.putErr
}

type noopCallgraphParser struct{}

func (noopCallgraphParser) ParseDirectory(string, string) ([]*callgraph.FileAnalysis, error) {
	return nil, nil
}

func (noopCallgraphParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "/" + dirName
}

func (noopCallgraphParser) PackageSeparator() string { return "/" }

func TestNewDependencyScanner(t *testing.T) {
	orchestrator := &Orchestrator{}
	resolver := &fakeResolver{ecosystem: "go"}
	builder := callgraph.NewBuilder(noopCallgraphParser{})
	cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}

	ds := NewDependencyScanner(orchestrator, resolver, builder, cache)
	if ds == nil {
		t.Fatal("NewDependencyScanner returned nil")
	}
	if ds.orchestrator != orchestrator || ds.resolver != resolver || ds.cgBuilder != builder || ds.findingsCache != cache {
		t.Fatal("NewDependencyScanner did not wire dependencies correctly")
	}
}

func TestLogDependencyScanSummary_Level(t *testing.T) {
	previous := log.Logger
	t.Cleanup(func() { log.Logger = previous })

	tests := []struct {
		name    string
		summary dependencyScanSummary
		level   string
	}{
		{
			name:    "warns when every dependency lacks source",
			summary: dependencyScanSummary{depsSkippedSource: 3},
			level:   "warn",
		},
		{
			name:    "stays informational when at least one dependency is scanned",
			summary: dependencyScanSummary{depsScanned: 1, depsSkippedSource: 3},
			level:   "info",
		},
		{
			name:    "stays informational when no dependency is skipped",
			summary: dependencyScanSummary{},
			level:   "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			log.Logger = zerolog.New(&output)

			logDependencyScanSummary(tt.summary)

			got := output.String()
			if !strings.Contains(got, `"level":"`+tt.level+`"`) {
				t.Fatalf("expected %s log, got %s", tt.level, got)
			}
			if !strings.Contains(got, `"depsScanned":`) || !strings.Contains(got, `"depsSkippedNoSource":`) {
				t.Fatalf("expected dependency counters in log, got %s", got)
			}
		})
	}
}

func TestDependencyScanner_HelperFunctions(t *testing.T) {
	resolver := &fakeResolver{ecosystem: "go"}
	ds := &DependencyScanner{resolver: resolver}

	dep := &dependency.Dependency{Module: "github.com/org/dep", Version: "v1.0.0", Dir: "/deps/dep"}
	opts := DepScanOptions{ScanOptions: ScanOptions{Target: "/user/project", ScannerConfig: scanner.Config{SkipPatterns: skip.WithDefaultTestPatterns([]string{"vendor"})}}}
	rulePaths := []string{"/rules/go.yaml"}

	depOpts := ds.buildDepScanOptions(dep, rulePaths, opts)
	if depOpts.Target != dep.Dir {
		t.Fatalf("Target = %q, want %q", depOpts.Target, dep.Dir)
	}
	if len(depOpts.RulePaths) != 1 || depOpts.RulePaths[0] != "/rules/go.yaml" {
		t.Fatalf("unexpected RulePaths: %#v", depOpts.RulePaths)
	}
	if len(depOpts.LanguageHint) != 1 || depOpts.LanguageHint[0] != "go" {
		t.Fatalf("unexpected LanguageHint: %#v", depOpts.LanguageHint)
	}
	if len(depOpts.ScannerConfig.SkipPatterns) == 0 {
		t.Fatal("expected test skip patterns to be preserved")
	}
	if containsString(depOpts.ScannerConfig.SkipPatterns, "vendor") {
		t.Fatalf("expected non-test skip patterns to be cleared, got %#v", depOpts.ScannerConfig.SkipPatterns)
	}
	if !containsString(depOpts.ScannerConfig.SkipPatterns, "src/test/") {
		t.Fatalf("expected test skip patterns to be preserved, got %#v", depOpts.ScannerConfig.SkipPatterns)
	}

	if !hasFindings(&entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}) {
		t.Fatal("hasFindings should return true when at least one asset exists")
	}
	if hasFindings(&entities.InterimReport{Findings: []entities.Finding{{}}}) {
		t.Fatal("hasFindings should return false when no assets exist")
	}

	if langs := ecosystemToLanguages("go"); len(langs) != 1 || langs[0] != "go" {
		t.Fatalf("unexpected go languages: %#v", langs)
	}
	if langs := ecosystemToLanguages("unknown"); langs != nil {
		t.Fatalf("expected nil for unknown ecosystem, got %#v", langs)
	}

	resolvedWorkspace := &dependency.ResolveResult{
		WorkspaceMembers: []dependency.WorkspaceMember{{Name: "app", Dir: "/user/app"}, {Name: "lib", Dir: "/user/lib"}},
		RootModule:       "ignored-in-workspace",
	}
	javaDS := &DependencyScanner{resolver: &fakeResolver{ecosystem: "java"}}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "github.com/acme/dep", Version: "v1", Dir: "/deps/dep1"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}},
		},
		{
			dep:    dependency.Dependency{Module: "github.com/acme/dep2", Version: "v2", Dir: "/deps/dep2", CompiledArtifactPath: "/artifacts/dep2.jar"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{}}},
		},
		{
			dep:    dependency.Dependency{Module: "github.com/acme/dep3", Version: "v3", CompiledArtifactPath: "/artifacts/dep3.jar"},
			status: depScanStatusSkippedNoSource,
		},
		{
			dep:    dependency.Dependency{Module: "github.com/acme/dep4", Version: "v4", Dir: "/deps/dep4"},
			status: depScanStatusFailed,
			err:    errors.New("scan failed"),
		},
	}

	sets := javaDS.collectPackageSets("/user/project", resolvedWorkspace, depResults)
	// 2 workspace members + the workspace ROOT + 2 successfully scanned deps with
	// source = 5 graphPackages. dep2 has no crypto findings, but it still needs
	// full source parsing because it can be a bridge in
	// A -> B(no crypto) -> C(crypto) reachability.
	//
	// The root is here because a workspace root carries its own source in some
	// ecosystems: a Cargo virtual manifest has none and this is a no-op there,
	// while an npm workspace root routinely has an index.js of its own, and
	// taking only the members left that file in no package at all.
	if len(sets.graphPackages) != 5 {
		t.Fatalf("graphPackages len = %d, want 5 (2 workspace + root + 2 source deps)", len(sets.graphPackages))
	}
	rootPkg := sets.graphPackages[2]
	if rootPkg.Dir != "/user/project" {
		t.Fatalf("graphPackages[2] should be the workspace root, got %#v", rootPkg)
	}
	// Members live under the root, so the root's walk must skip them or each is
	// parsed twice under a second import path.
	if len(rootPkg.ExcludeDirs) != len(resolvedWorkspace.WorkspaceMembers) {
		t.Fatalf("root ExcludeDirs = %v, want one per workspace member", rootPkg.ExcludeDirs)
	}
	for i, member := range resolvedWorkspace.WorkspaceMembers {
		if rootPkg.ExcludeDirs[i] != member.Dir {
			t.Fatalf("root ExcludeDirs[%d] = %q, want %q", i, rootPkg.ExcludeDirs[i], member.Dir)
		}
	}
	if len(sets.typeOnlyPackages) != 2 {
		t.Fatalf("typeOnlyPackages len = %d, want 2", len(sets.typeOnlyPackages))
	}
	if sets.graphPackages[3].Version != "v1" || sets.graphPackages[4].Version != "v2" {
		t.Fatalf("unexpected graphPackages versions: %#v", sets.graphPackages)
	}
	if sets.graphPackages[4].CompiledArtifactPath != "/artifacts/dep2.jar" {
		t.Fatalf("expected compiled artifact path to propagate for source-parsed dep, got %#v", sets.graphPackages[4])
	}
	if sets.typeOnlyPackages[0].Version != "v3" || sets.typeOnlyPackages[1].Version != "v4" {
		t.Fatalf("unexpected typeOnlyPackages versions: %#v", sets.typeOnlyPackages)
	}
	if sets.typeOnlyPackages[0].CompiledArtifactPath != "/artifacts/dep3.jar" {
		t.Fatalf("expected compiled artifact path to propagate for source-less dep, got %#v", sets.typeOnlyPackages[0])
	}

	workspaceUsers := ds.buildUserPackages(resolvedWorkspace)
	if !workspaceUsers["app"] || !workspaceUsers["lib"] {
		t.Fatalf("unexpected workspace user package set: %#v", workspaceUsers)
	}

	singleResolved := &dependency.ResolveResult{RootModule: "example.com/root"}
	singleUsers := ds.buildUserPackages(singleResolved)
	if !singleUsers["example.com/root"] {
		t.Fatalf("unexpected single-project user package set: %#v", singleUsers)
	}
}

func TestDependencyScanner_MergeReports(t *testing.T) {
	ds := &DependencyScanner{}
	userReport := &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Findings: []entities.Finding{
			{FilePath: "main.go", CryptographicAssets: []entities.CryptographicAsset{{Source: ""}}},
		},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "dep2", Version: "1"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{
				FilePath:            "dep/b.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: "dependency"}},
			}}},
		},
		{
			dep:    dependency.Dependency{Module: "dep1", Version: "1"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{
				FilePath:            "dep/a.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: "dependency"}},
			}}},
		},
	}

	merged := ds.mergeReports(userReport, depResults)
	// All findings included: 1 user + 2 dependency
	if len(merged.Findings) != 3 {
		t.Fatalf("merge findings len = %d, want 3", len(merged.Findings))
	}
	if merged.Findings[0].CryptographicAssets[0].Source != "direct" {
		t.Fatalf("expected user findings to default to direct source")
	}
	if merged.Findings[1].FilePath != "dep/b.go" || merged.Findings[2].FilePath != "dep/a.go" {
		t.Fatalf("unexpected dependency finding order: %#v", merged.Findings)
	}
}

func TestEnsureFindingSources(t *testing.T) {
	report := &entities.InterimReport{
		Findings: []entities.Finding{
			{
				FilePath:            "direct.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: ""}},
			},
			{
				FilePath:            "dep.go",
				CryptographicAssets: []entities.CryptographicAsset{{Source: "dependency"}},
			},
		},
	}

	EnsureFindingSources(report)

	if got := report.Findings[0].CryptographicAssets[0].Source; got != "direct" {
		t.Fatalf("direct source = %q, want direct", got)
	}
	if got := report.Findings[1].CryptographicAssets[0].Source; got != "dependency" {
		t.Fatalf("dependency source = %q, want dependency", got)
	}
}

func TestDependencyScanner_AttributeAndEnrich(t *testing.T) {
	userTarget := t.TempDir()
	depDir := t.TempDir()

	userEntry := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "app", Name: "Entry"},
		FilePath:  filepath.Join(userTarget, "main.go"),
		StartLine: 1,
		EndLine:   20,
		Calls: []callgraph.FunctionCall{{
			Callee:   callgraph.FunctionID{Package: "app", Name: "Helper"},
			FilePath: filepath.Join(userTarget, "main.go"),
			Line:     5,
		}},
	}
	userHelper := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "app", Name: "Helper"},
		FilePath:  filepath.Join(userTarget, "main.go"),
		StartLine: 21,
		EndLine:   60,
		Calls: []callgraph.FunctionCall{{
			Callee:   callgraph.FunctionID{Package: "dep/mod", Name: "Crypto"},
			FilePath: filepath.Join(userTarget, "main.go"),
			Line:     30,
		}},
	}
	depCrypto := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "dep/mod", Name: "Crypto"},
		FilePath:  filepath.Join(depDir, "lib.go"),
		StartLine: 1,
		EndLine:   50,
	}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			userEntry.ID.String():  userEntry,
			userHelper.ID.String(): userHelper,
			depCrypto.ID.String():  depCrypto,
		},
		Callers: map[string][]string{
			userHelper.ID.String(): {userEntry.ID.String()},
			depCrypto.ID.String():  {userHelper.ID.String()},
		},
	}
	tracer := callgraph.NewTracer(graph, "/")

	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}}
	dep := &dependency.Dependency{Module: "dep/mod", Version: "v1.0.0", Dir: depDir}
	depReport := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "lib.go",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 10, PURL: "pkg:golang/dep/mod"}},
	}}}

	ds.attributeFindings(depReport, dep, userTarget, tracer, map[string]bool{"app": true})
	asset := depReport.Findings[0].CryptographicAssets[0]
	if asset.Source != "dependency" {
		t.Fatalf("asset.Source = %q, want dependency", asset.Source)
	}
	if asset.DependencyInfo == nil || asset.DependencyInfo.Module != "dep/mod" || asset.DependencyInfo.Version != "v1.0.0" {
		t.Fatalf("unexpected dependency info: %#v", asset.DependencyInfo)
	}
	if asset.DependencyInfo.PURL != "pkg:golang/dep/mod@v1.0.0" {
		t.Errorf("dependency purl = %q, want pkg:golang/dep/mod@v1.0.0", asset.DependencyInfo.PURL)
	}
	if asset.PURL != "" {
		t.Errorf("top-level dependency PURL = %q, want empty", asset.PURL)
	}
	if depReport.Findings[0].FilePath != "lib.go" {
		t.Fatalf("unexpected dependency file path: %s", depReport.Findings[0].FilePath)
	}
}

func TestEnrichDirectFindingPURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filePath  string
		ecosystem string
		rulePURL  string
		resolved  *dependency.ResolveResult
		want      string
	}{
		{
			name:     "direct dependency",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {{Module: "github.com/acme/lib", Version: "v1.2.3"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib@v1.2.3",
		},
		{
			name:      "maven group root resolves artifact graph",
			filePath:  "Main.java",
			ecosystem: "java",
			rulePURL:  "pkg:maven/org.example/lib",
			resolved: &dependency.ResolveResult{
				RootModule: "com.acme",
				VersionedGraph: map[string][]dependency.Ref{
					"com.acme:app@1.0.0":    {{Module: "org.example:lib", Version: "2.0.0"}},
					"org.example:lib@2.0.0": {{Module: "org.example:transitive", Version: "3.0.0"}},
				},
			},
			want: "pkg:maven/org.example/lib@2.0.0",
		},
		{
			name:     "transitive dependency stays versionless",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {{Module: "github.com/acme/wrapper", Version: "v1.0.0"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib",
		},
		{
			name:     "ambiguous versions stay versionless",
			filePath: "main.go",
			resolved: &dependency.ResolveResult{
				RootModule: "example.com/app",
				VersionedGraph: map[string][]dependency.Ref{
					"example.com/app": {
						{Module: "github.com/acme/lib", Version: "v1.2.3"},
						{Module: "github.com/acme/lib", Version: "v1.2.4"},
					},
				},
			},
			want: "pkg:golang/github.com/acme/lib",
		},
		{
			name:     "workspace member uses its direct graph",
			filePath: "service/main.go",
			resolved: &dependency.ResolveResult{
				RootModule:       "example.com/root",
				WorkspaceMembers: []dependency.WorkspaceMember{{Name: "service", Dir: "/workspace/service"}},
				VersionedGraph: map[string][]dependency.Ref{
					"service": {{Module: "github.com/acme/lib", Version: "v2.0.0"}},
				},
			},
			want: "pkg:golang/github.com/acme/lib@v2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rulePURL := tt.rulePURL
			if rulePURL == "" {
				rulePURL = "pkg:golang/github.com/acme/lib"
			}
			report := &entities.InterimReport{Findings: []entities.Finding{{
				FilePath: tt.filePath,
				CryptographicAssets: []entities.CryptographicAsset{{
					PURL: rulePURL,
				}},
			}}}
			target := "/workspace"
			// The workspace case intentionally exercises owningModule; single-project
			// cases ignore target and use RootModule directly.
			ecosystem := tt.ecosystem
			if ecosystem == "" {
				ecosystem = "go"
			}
			enrichDirectFindingPURLs(report, target, tt.resolved, ecosystem)
			if got := report.Findings[0].CryptographicAssets[0].PURL; got != tt.want {
				t.Fatalf("PURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDependencyScanner_MergeReports_DependencyFindingIDUsesCanonicalPath(t *testing.T) {
	ds := &DependencyScanner{}
	userReport := &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "dep/mod", Version: "v1.0.0", Dir: "/deps/dep"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{
				FilePath: "lib.go",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine:      10,
					Source:         "dependency",
					DependencyInfo: &entities.DependencyInfo{Module: "dep/mod", Version: "v1.0.0"},
					Rules:          []entities.RuleInfo{{ID: "rule.dep"}},
				}},
			}}},
		},
	}

	merged := ds.mergeReports(userReport, depResults)
	got := merged.Findings[0].CryptographicAssets[0].FindingID
	want := generateFindingID("dep/mod@v1.0.0/lib.go", 10, []entities.RuleInfo{{ID: "rule.dep"}})
	if got != want {
		t.Fatalf("dependency finding_id = %q, want %q", got, want)
	}
}

func TestDependencyScanner_LoadFilteredRulesAndScanSingleDep(t *testing.T) {
	ruleDir := t.TempDir()
	goRule := filepath.Join(ruleDir, "go.yaml")
	pyRule := filepath.Join(ruleDir, "python.yaml")
	if err := os.WriteFile(goRule, []byte("rules:\n  - languages: [go]\n"), 0o600); err != nil {
		t.Fatalf("write go rule: %v", err)
	}
	if err := os.WriteFile(pyRule, []byte("rules:\n  - languages: [python]\n"), 0o600); err != nil {
		t.Fatalf("write py rule: %v", err)
	}

	scanCalls := 0
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			scanCalls++
			return &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}, nil
		},
	}
	scannerReg := scanner.NewRegistry()
	scannerReg.Register("test-scanner", mockScan)

	ruleSource := &mockRuleSource{loadFunc: func() ([]string, error) {
		return []string{goRule, pyRule}, nil
	}}
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(ruleSource), scannerReg)

	cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}
	ds := &DependencyScanner{
		orchestrator:  orchestrator,
		resolver:      &fakeResolver{ecosystem: "go"},
		findingsCache: cache,
	}

	filtered, cleanup, err := ds.loadFilteredRules("go")
	if err != nil {
		t.Fatalf("loadFilteredRules: %v", err)
	}
	defer cleanup()
	if len(filtered) != 1 {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}
	if filtered[0] != goRule {
		t.Fatalf("expected go rule path, got %#v", filtered)
	}

	dep := &dependency.Dependency{Module: "github.com/acme/dep", Version: "v1", Dir: t.TempDir()}
	cacheKey := dep.Module + "@" + dep.Version + ":hash"
	cachedReport := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}
	cache.getMap[cacheKey] = cachedReport

	res := ds.scanSingleDep(context.Background(), *dep, dep.Module+"@"+dep.Version, []string{goRule}, "hash", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
	if res.err != nil {
		t.Fatalf("scanSingleDep cache hit error: %v", res.err)
	}
	if res.report != cachedReport {
		t.Fatal("expected cached report to be returned")
	}
	if scanCalls != 0 {
		t.Fatalf("scanner should not be called on cache hit, calls=%d", scanCalls)
	}

	delete(cache.getMap, cacheKey)
	res = ds.scanSingleDep(context.Background(), *dep, dep.Module+"@"+dep.Version, []string{goRule}, "hash", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
	if res.err != nil {
		t.Fatalf("scanSingleDep cache miss error: %v", res.err)
	}
	if res.report == nil {
		t.Fatal("expected non-nil report on cache miss")
	}
	if scanCalls != 1 {
		t.Fatalf("expected scanner to be called once on cache miss, calls=%d", scanCalls)
	}
	if cache.putCalls != 1 || cache.putLastKey == "" {
		t.Fatalf("expected cache put call after successful scan, puts=%d key=%q", cache.putCalls, cache.putLastKey)
	}
}

func TestDependencyScanner_ScanSingleDep_DropsNoFindingReportsFromMemory(t *testing.T) {
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			return &entities.InterimReport{}, nil
		},
	}
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) {
		return []string{"/rules/go.yaml"}, nil
	}}), registry)
	cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}
	ds := &DependencyScanner{
		orchestrator:  orchestrator,
		resolver:      &fakeResolver{ecosystem: "go"},
		findingsCache: cache,
	}

	dep := dependency.Dependency{Module: "github.com/acme/no-crypto", Version: "v1", Dir: t.TempDir()}
	res := ds.scanSingleDep(context.Background(), dep, dep.Module+"@"+dep.Version, []string{"/rules/go.yaml"}, "hash", DepScanOptions{
		ScanOptions: ScanOptions{ScannerName: "test-scanner"},
	})
	if res.err != nil {
		t.Fatalf("scanSingleDep: %v", res.err)
	}
	if res.status != depScanStatusScanned {
		t.Fatalf("status = %v, want scanned", res.status)
	}
	if res.report != nil {
		t.Fatal("expected no-finding dependency report to be dropped from memory")
	}
	if cache.putCalls != 1 {
		t.Fatalf("expected no-finding report to still be cached, puts=%d", cache.putCalls)
	}
}

func TestDependencyScanner_LoadFilteredRules_MalformedParameterConditionAborts(t *testing.T) {
	ruleDir := t.TempDir()
	brokenRule := filepath.Join(ruleDir, "broken.yaml")
	const malformedRule = `
rules:
  - id: java.bouncycastle.algorithm.block-cipher.aes-init-broken
    languages: [java]
    metadata:
      crypto:
        operation: encrypt
        parameterCondition: "param[]==true"
`
	if err := os.WriteFile(brokenRule, []byte(malformedRule), 0o600); err != nil {
		t.Fatalf("write broken rule: %v", err)
	}

	scannerReg := scanner.NewRegistry()
	ruleSource := &mockRuleSource{loadFunc: func() ([]string, error) {
		return []string{brokenRule}, nil
	}}
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(ruleSource), scannerReg)

	ds := &DependencyScanner{
		orchestrator: orchestrator,
		resolver:     &fakeResolver{ecosystem: "java"},
	}

	_, cleanup, err := ds.loadFilteredRules("java")
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Fatal("loadFilteredRules() = nil error, want error")
	}
	if !strings.Contains(err.Error(), "java.bouncycastle.algorithm.block-cipher.aes-init-broken") {
		t.Errorf("error %q does not name the offending rule id", err.Error())
	}
	if !strings.Contains(err.Error(), "param[]==true") {
		t.Errorf("error %q does not contain the raw malformed predicate", err.Error())
	}
}

func TestDependencyScanWorkers_DefaultsAreMemorySafeForJava(t *testing.T) {
	if got := dependencyScanWorkers(0, "java"); got < 1 || got > 2 {
		t.Fatalf("java default workers = %d, want 1..2", got)
	}
	if got := dependencyScanWorkers(6, "java"); got != 6 {
		t.Fatalf("explicit java workers = %d, want 6", got)
	}
	if got := dependencyScanWorkers(0, "go"); got < 1 || got > maxWorkers {
		t.Fatalf("go default workers = %d, want 1..%d", got, maxWorkers)
	}
}

func TestDependencyScanner_ScanDependenciesParallel(t *testing.T) {
	var scanCalls atomic.Int32
	var sawEmptyTarget atomic.Bool
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, target string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			scanCalls.Add(1)
			if target == "" {
				sawEmptyTarget.Store(true)
			}
			if strings.Contains(target, "bad") {
				return nil, errors.New("scan failed")
			}
			return &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}, nil
		},
	}
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{"/rules/go.yaml"}, nil }}), registry)

	ds := &DependencyScanner{orchestrator: orch, resolver: &fakeResolver{ecosystem: "go"}}
	deps := []dependency.Dependency{
		{Module: "c", Version: "1"},
		{Module: "a", Version: "1", Dir: t.TempDir()},
		{Module: "a", Version: "1"}, // duplicate module@version; canonical dep should keep source dir
		{Module: "b", Version: "1", Dir: filepath.Join(t.TempDir(), "bad")},
	}

	outcomes, err := ds.scanDependenciesParallel(context.Background(), deps, []string{"/rules/go.yaml"}, "", DepScanOptions{Workers: 2, ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
	if err != nil {
		t.Fatalf("scanDependenciesParallel: %v", err)
	}

	if len(outcomes) != 3 {
		t.Fatalf("outcomes len = %d, want 3", len(outcomes))
	}
	if outcomes[0].dep.Module != "a" || outcomes[0].status != depScanStatusScanned {
		t.Fatalf("unexpected first outcome: %#v", outcomes[0])
	}
	if outcomes[1].dep.Module != "b" || outcomes[1].status != depScanStatusFailed {
		t.Fatalf("unexpected second outcome: %#v", outcomes[1])
	}
	if outcomes[2].dep.Module != "c" || outcomes[2].status != depScanStatusSkippedNoSource {
		t.Fatalf("unexpected third outcome: %#v", outcomes[2])
	}
	if calls := scanCalls.Load(); calls != 2 {
		t.Fatalf("expected two scan attempts (deduped success + failure), got %d", calls)
	}
	if sawEmptyTarget.Load() {
		t.Fatal("scanner should never be called with an empty dependency target")
	}
}

func TestDependencyScanner_ScanDependenciesParallel_PropagatesCancellation(t *testing.T) {
	cancellation := failure.New(failure.CodeScannerCancelled, failure.StageScan, "scan canceled")
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", &mockScanner{
		scanFunc: func(context.Context, string, []string, entities.ToolInfo) (*entities.InterimReport, error) {
			return nil, cancellation
		},
	})
	orch := NewOrchestrator(
		&mockDetector{},
		rules.NewManager(&mockRuleSource{}),
		registry,
	)
	ds := &DependencyScanner{
		orchestrator: orch,
		resolver:     &fakeResolver{ecosystem: "go"},
	}

	outcomes, err := ds.scanDependenciesParallel(context.Background(), []dependency.Dependency{{
		Module: "example.com/dep", Version: "v1", Dir: t.TempDir(),
	}}, []string{"/rules/go.yaml"}, "", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
	if len(outcomes) != 1 {
		t.Fatalf("outcomes len = %d, want 1", len(outcomes))
	}
	structured, ok := failure.As(err)
	if !ok || structured.Code != failure.CodeScannerCancelled {
		t.Fatalf("error = %v, want scanner_canceled", err)
	}
	if structured != cancellation {
		t.Fatal("dependency cancellation lost its structured error identity")
	}
}

func TestDependencyScanner_ScanSingleDep_JavaRuntimePartitionsCacheKey(t *testing.T) {
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			return &entities.InterimReport{}, nil
		},
	}
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	ruleSource := &mockRuleSource{loadFunc: func() ([]string, error) {
		return []string{"/rules/java.yaml"}, nil
	}}
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(ruleSource), registry)
	cache := &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}}
	ds := &DependencyScanner{
		orchestrator:  orchestrator,
		resolver:      &fakeResolver{ecosystem: "java"},
		findingsCache: cache,
	}

	dep := dependency.Dependency{Module: "org.example:lib", Version: "1.2.3", Dir: t.TempDir()}
	res := ds.scanSingleDep(context.Background(), dep, dep.Module+"@"+dep.Version, []string{"/rules/java.yaml"}, "hash", DepScanOptions{
		ScanOptions: ScanOptions{
			ScannerName:           "test-scanner",
			JavaRuntimeCacheToken: "jdk-21",
		},
	})
	if res.err != nil {
		t.Fatalf("scanSingleDep: %v", res.err)
	}
	if cache.putLastKey != "org.example:lib@1.2.3:hash:jdk-21" {
		t.Fatalf("putLastKey = %q, want org.example:lib@1.2.3:hash:jdk-21", cache.putLastKey)
	}
}

func TestDependencyScanner_CollectPackageSets_NonJavaSkipsTypeOnlyWithoutCompiledFallback(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}}
	resolved := &dependency.ResolveResult{RootModule: "example.com/root"}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "example.com/finding", Version: "v1", Dir: "/deps/finding"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}},
		},
		{
			dep:    dependency.Dependency{Module: "example.com/no-source", Version: "v2"},
			status: depScanStatusSkippedNoSource,
		},
		{
			dep:    dependency.Dependency{Module: "example.com/failed", Version: "v3", Dir: "/deps/failed"},
			status: depScanStatusFailed,
			err:    errors.New("scan failed"),
		},
	}

	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if len(sets.graphPackages) != 2 {
		t.Fatalf("graphPackages len = %d, want 2", len(sets.graphPackages))
	}
	if len(sets.typeOnlyPackages) != 0 {
		t.Fatalf("typeOnlyPackages len = %d, want 0", len(sets.typeOnlyPackages))
	}
}

func TestDependencyScanner_ScanWithDependencies_NoDepsAndErrors(t *testing.T) {
	userReport := &entities.InterimReport{Version: "1.2", Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"}}

	t.Run("no-dependencies", func(t *testing.T) {
		ds := &DependencyScanner{
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string) (*dependency.ResolveResult, error) {
				return &dependency.ResolveResult{RootModule: "example.com/root"}, nil
			}},
		}

		result, err := ds.ScanWithDependencies(context.Background(), userReport, DepScanOptions{ScanOptions: ScanOptions{Target: t.TempDir()}})
		if err != nil {
			t.Fatalf("ScanWithDependencies no-deps: %v", err)
		}
		if result.RootModule != "example.com/root" || result.Ecosystem != "go" {
			t.Fatalf("unexpected result metadata: %#v", result)
		}
		if result.CallGraph != nil {
			t.Fatal("expected nil call graph when no dependencies")
		}
	})

	t.Run("resolver-error", func(t *testing.T) {
		ds := &DependencyScanner{
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string) (*dependency.ResolveResult, error) {
				return nil, errors.New("resolve failed")
			}},
		}

		_, err := ds.ScanWithDependencies(context.Background(), userReport, DepScanOptions{ScanOptions: ScanOptions{Target: t.TempDir()}})
		if err == nil || !strings.Contains(err.Error(), "dependency resolution failed") {
			t.Fatalf("expected wrapped resolver error, got %v", err)
		}
	})

	t.Run("rules-load-error", func(t *testing.T) {
		orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) {
			return nil, errors.New("load failed")
		}}), scanner.NewRegistry())
		ds := &DependencyScanner{
			orchestrator: orch,
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string) (*dependency.ResolveResult, error) {
				return &dependency.ResolveResult{RootModule: "root", Dependencies: []dependency.Dependency{{Module: "a", Version: "1", Dir: t.TempDir()}}}, nil
			}},
		}

		_, err := ds.ScanWithDependencies(context.Background(), userReport, DepScanOptions{ScanOptions: ScanOptions{Target: t.TempDir()}})
		if err == nil || !strings.Contains(err.Error(), "failed to load rules") {
			t.Fatalf("expected rules load error, got %v", err)
		}
	})
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDetachDeadlineKeepCancel(t *testing.T) {
	t.Run("parent deadline expiry does NOT cancel child", func(t *testing.T) {
		// Parent has a 1ms deadline that we let expire.
		parent, parentCancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer parentCancel()

		child, childCancel := detachDeadlineKeepCancel(parent)
		defer childCancel()

		// Wait long enough for the parent to expire.
		<-parent.Done()
		if !errors.Is(parent.Err(), context.DeadlineExceeded) {
			t.Fatalf("parent should have expired with DeadlineExceeded, got %v", parent.Err())
		}

		// Give the watcher goroutine a moment to react (it shouldn't, but
		// race-free assertion needs a small wait).
		time.Sleep(10 * time.Millisecond)

		select {
		case <-child.Done():
			t.Fatalf("child was canceled despite parent only expiring (this is the bug we are fixing)")
		default:
			// expected: child still alive
		}

		// Sanity: child has no deadline.
		if _, ok := child.Deadline(); ok {
			t.Fatalf("child should have no deadline")
		}
	})

	t.Run("parent explicit cancel DOES cancel child", func(t *testing.T) {
		parent, parentCancel := context.WithCancel(context.Background())

		child, childCancel := detachDeadlineKeepCancel(parent)
		defer childCancel()

		parentCancel()

		select {
		case <-child.Done():
			if !errors.Is(child.Err(), context.Canceled) {
				t.Fatalf("child err = %v, want Canceled", child.Err())
			}
		case <-time.After(time.Second):
			t.Fatalf("child was not canceled after parent was explicitly canceled")
		}
	})

	t.Run("explicit cancel of returned func cancels child", func(t *testing.T) {
		parent := context.Background()
		child, cancel := detachDeadlineKeepCancel(parent)

		cancel()

		select {
		case <-child.Done():
			// expected
		case <-time.After(time.Second):
			t.Fatalf("child was not canceled by its own cancel func")
		}
	})
}

func TestDependencyScanner_CollectPackageSets_DropsDepsWhenNoneHaveFindings(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}}
	resolved := &dependency.ResolveResult{
		RootModule: "example.com/root",
		Graph: map[string][]string{
			"example.com/root": {"example.com/no-crypto"},
		},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "example.com/no-crypto", Version: "v1", Dir: "/deps/no-crypto"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
	}

	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if hasPackage(sets.graphPackages, "example.com/no-crypto") {
		t.Fatalf("unexpected no-crypto dependency in graphPackages: %#v", sets.graphPackages)
	}
}

func TestDependencyScanner_CollectPackageSets_PrunesDepsOutsideCryptoPaths(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}}
	resolved := &dependency.ResolveResult{
		RootModule: "example.com/root",
		Graph: map[string][]string{
			"example.com/root":   {"example.com/bridge", "example.com/unused"},
			"example.com/bridge": {"example.com/crypto"},
		},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "example.com/bridge", Version: "v1", Dir: "/deps/bridge"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
		{
			dep:    dependency.Dependency{Module: "example.com/crypto", Version: "v1", Dir: "/deps/crypto"},
			status: depScanStatusScanned,
			report: reportWithCryptoAsset(),
		},
		{
			dep:    dependency.Dependency{Module: "example.com/unused", Version: "v1", Dir: "/deps/unused"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
	}

	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if !hasPackage(sets.graphPackages, "example.com/root") {
		t.Fatalf("expected root package in graphPackages: %#v", sets.graphPackages)
	}
	if !hasPackage(sets.graphPackages, "example.com/bridge") {
		t.Fatalf("expected bridge package in graphPackages: %#v", sets.graphPackages)
	}
	if !hasPackage(sets.graphPackages, "example.com/crypto") {
		t.Fatalf("expected crypto package in graphPackages: %#v", sets.graphPackages)
	}
	if hasPackage(sets.graphPackages, "example.com/unused") {
		t.Fatalf("unexpected unused package in graphPackages: %#v", sets.graphPackages)
	}
}

func TestDependencyScanner_CollectPackageSets_PrunesWithInferredGraphRoots(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "java"}}
	resolved := &dependency.ResolveResult{
		RootModule: "com.acme",
		Graph: map[string][]string{
			"com.acme:app":       {"org.example:bridge", "org.example:unused"},
			"org.example:bridge": {"org.example:crypto"},
		},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "org.example:bridge", Version: "1.0.0", Dir: "/deps/bridge"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
		{
			dep:    dependency.Dependency{Module: "org.example:crypto", Version: "1.0.0", Dir: "/deps/crypto"},
			status: depScanStatusScanned,
			report: reportWithCryptoAsset(),
		},
		{
			dep:    dependency.Dependency{Module: "org.example:unused", Version: "1.0.0", Dir: "/deps/unused"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
	}

	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if !hasPackage(sets.graphPackages, "org.example:bridge") || !hasPackage(sets.graphPackages, "org.example:crypto") {
		t.Fatalf("expected bridge and crypto deps in graphPackages: %#v", sets.graphPackages)
	}
	if hasPackage(sets.graphPackages, "org.example:unused") {
		t.Fatalf("unexpected unused package in graphPackages: %#v", sets.graphPackages)
	}
}

func TestDependencyScanner_CollectPackageSets_FallsBackWhenGraphIncomplete(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "go"}}
	resolved := &dependency.ResolveResult{
		RootModule: "example.com/root",
		Graph: map[string][]string{
			"example.com/root": {"example.com/bridge"},
		},
	}
	depResults := []depScanResult{
		{
			dep:    dependency.Dependency{Module: "example.com/bridge", Version: "v1", Dir: "/deps/bridge"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
		{
			dep:    dependency.Dependency{Module: "example.com/crypto", Version: "v1", Dir: "/deps/crypto"},
			status: depScanStatusScanned,
			report: reportWithCryptoAsset(),
		},
		{
			dep:    dependency.Dependency{Module: "example.com/unused", Version: "v1", Dir: "/deps/unused"},
			status: depScanStatusScanned,
			report: &entities.InterimReport{},
		},
	}

	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if !hasPackage(sets.graphPackages, "example.com/bridge") ||
		!hasPackage(sets.graphPackages, "example.com/crypto") ||
		!hasPackage(sets.graphPackages, "example.com/unused") {
		t.Fatalf("expected conservative fallback to keep all scanned deps: %#v", sets.graphPackages)
	}
}

func reportWithCryptoAsset() *entities.InterimReport {
	return &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}
}

func hasPackage(pkgs []callgraph.PackageDir, importPath string) bool {
	for i := range pkgs {
		if pkgs[i].ImportPath == importPath {
			return true
		}
	}
	return false
}

func TestDependencyScanner_CollectPackageSets_PreservesPythonDistributionAndImportRoot(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "python"}}
	resolved := &dependency.ResolveResult{RootModule: "app"}
	depResults := []depScanResult{{
		dep: dependency.Dependency{
			Module:     "argon2-cffi",
			ImportPath: "argon2",
			Version:    "25.1.0",
			Dir:        "/deps/argon2",
		},
		status: depScanStatusScanned,
		report: reportWithCryptoAsset(),
	}}
	sets := ds.collectPackageSets("/user/project", resolved, depResults)
	if len(sets.graphPackages) != 2 {
		t.Fatalf("graphPackages = %#v, want user root plus dependency", sets.graphPackages)
	}
	dep := sets.graphPackages[1]
	if dep.ImportPath != "argon2" || dep.DistributionName != "argon2-cffi" {
		t.Fatalf("dependency PackageDir = %#v, want ImportPath argon2 and DistributionName argon2-cffi", dep)
	}
}

// writeRepoTree materializes a fixture repository: every key is a path
// relative to the root, every value its contents.
func writeRepoTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// recordingResolver answers per directory and remembers the order it was asked.
type recordingResolver struct {
	ecosystem string
	calls     []string
	answer    func(dir string) (*dependency.ResolveResult, error)
}

func (r *recordingResolver) Resolve(_ context.Context, targetDir string) (*dependency.ResolveResult, error) {
	r.calls = append(r.calls, targetDir)
	return r.answer(targetDir)
}

func (r *recordingResolver) Ecosystem() string { return r.ecosystem }

func TestDependencyScanner_ResolveScanRoot_RootManifestResolvesAtTarget(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"go.mod":            "module example.com/root\n",
		"services/a/go.mod": "module example.com/a\n",
		"services/a/a.go":   "package a",
	})
	resolver := &recordingResolver{ecosystem: "go", answer: func(_ string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "example.com/root"}, nil
	}}
	ds := &DependencyScanner{resolver: resolver}

	resolved, err := ds.resolveScanRoot(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}
	if !reflect.DeepEqual(resolver.calls, []string{root}) {
		t.Fatalf("Resolve calls = %v, want exactly the scan root %q", resolver.calls, root)
	}
	if resolved.RootModule != "example.com/root" {
		t.Errorf("RootModule = %q, want the resolver's own answer untouched", resolved.RootModule)
	}
}

func TestDependencyScanner_ResolveScanRoot_DiscoveredRootsAreResolvedAndMerged(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"services/gateway/pom.xml": "<project/>",
		"services/ledger/pom.xml":  "<project/>",
	})
	resolver := &recordingResolver{ecosystem: "java", answer: func(dir string) (*dependency.ResolveResult, error) {
		name := filepath.Base(dir)
		return &dependency.ResolveResult{
			RootModule:   "com.acme." + name,
			Dependencies: []dependency.Dependency{{Module: "com.acme:" + name + "-dep", Version: "1.0", Dir: dir}},
		}, nil
	}}
	ds := &DependencyScanner{resolver: resolver}

	resolved, err := ds.resolveScanRoot(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("resolveScanRoot: %v", err)
	}

	wantCalls := []string{filepath.Join(root, "services", "gateway"), filepath.Join(root, "services", "ledger")}
	if !reflect.DeepEqual(resolver.calls, wantCalls) {
		t.Fatalf("Resolve calls = %v, want %v", resolver.calls, wantCalls)
	}
	if resolved.RootModule != filepath.Base(root) {
		t.Errorf("RootModule = %q, want %q", resolved.RootModule, filepath.Base(root))
	}
	wantMembers := []dependency.WorkspaceMember{
		{Name: "com.acme.gateway", Dir: wantCalls[0]},
		{Name: "com.acme.ledger", Dir: wantCalls[1]},
	}
	if !reflect.DeepEqual(resolved.WorkspaceMembers, wantMembers) {
		t.Errorf("WorkspaceMembers = %+v, want %+v", resolved.WorkspaceMembers, wantMembers)
	}
	if len(resolved.Dependencies) != 2 {
		t.Errorf("len(Dependencies) = %d, want 2", len(resolved.Dependencies))
	}
}

func TestDependencyScanner_ResolveScanRoot_FailingRootNamesIt(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"services/gateway/pom.xml": "<project/>",
		"services/ledger/pom.xml":  "<project/>",
	})
	resolver := &recordingResolver{ecosystem: "java", answer: func(dir string) (*dependency.ResolveResult, error) {
		if filepath.Base(dir) == "ledger" {
			return nil, failure.New(failure.CodeJavaBuildToolAmbiguous, failure.StageDependency, "both manifests present")
		}
		return &dependency.ResolveResult{RootModule: "com.acme.gateway"}, nil
	}}
	ds := &DependencyScanner{resolver: resolver}

	_, err := ds.resolveScanRoot(context.Background(), root, nil)
	if err == nil {
		t.Fatal("resolveScanRoot: expected an error")
	}
	if !strings.Contains(err.Error(), "services/ledger") {
		t.Errorf("error = %q, want it to name the failing root services/ledger", err.Error())
	}
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("failure.As: %v is not a structured failure", err)
	}
	if structured.Code != failure.CodeJavaBuildToolAmbiguous {
		t.Errorf("Code = %q, want the root's own code %q", structured.Code, failure.CodeJavaBuildToolAmbiguous)
	}
}

// The reproduction from issue #533, driven through the real Java resolver with
// no mvn anywhere on PATH. Maven's fast path returns before any subprocess for
// a pom.xml that declares no dependencies and no modules, so this pins the
// discovery without needing a build tool installed.
func TestDependencyScanner_ScanWithDependencies_NestedPomWithoutMaven(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"services/ledger/pom.xml": `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>ledger</artifactId>
  <version>1.0.0</version>
</project>`,
		"services/ledger/src/main/java/app/Use.java": "package app; class Use {}",
	})
	t.Setenv("PATH", t.TempDir())

	ds := &DependencyScanner{resolver: dependency.NewJavaResolver()}
	userReport := &entities.InterimReport{Version: "1.2", Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"}}

	result, err := ds.ScanWithDependencies(context.Background(), userReport, DepScanOptions{ScanOptions: ScanOptions{Target: root}})
	if err != nil {
		t.Fatalf("ScanWithDependencies: %v, want the nested pom.xml to resolve", err)
	}
	if result.RootModule != filepath.Base(root) {
		t.Errorf("RootModule = %q, want %q: an empty root module zeroes every finding's reachability", result.RootModule, filepath.Base(root))
	}
}

func TestDependencyScanner_ResolveScanRoot_NothingBelowKeepsTheResolverError(t *testing.T) {
	root := writeRepoTree(t, map[string]string{"src/main/java/app/Use.java": "package app; class Use {}"})
	ds := &DependencyScanner{resolver: dependency.NewJavaResolver()}

	_, err := ds.resolveScanRoot(context.Background(), root, nil)
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("failure.As: %v is not a structured failure", err)
	}
	if structured.Code != failure.CodeDependencyBuildToolUnknown {
		t.Errorf("Code = %q, want the unchanged %q", structured.Code, failure.CodeDependencyBuildToolUnknown)
	}
	if structured.Details["target_dir"] != root {
		t.Errorf("target_dir = %v, want the scan root %q", structured.Details["target_dir"], root)
	}
}

// The merge design rests on this: every discovered root becomes its own package
// root, and the scan-root package excludes all of them so no directory is
// parsed under two import paths. The shape fed in is what
// dependency.MergeRootResolutions produces, pinned by
// TestMergeRootResolutions_NamesTheScanRootAndOneMemberPerRoot.
func TestDependencyScanner_CollectPackageSets_MergedRootsEachGetTheirOwnPackage(t *testing.T) {
	ds := &DependencyScanner{resolver: &fakeResolver{ecosystem: "java"}}
	merged := &dependency.ResolveResult{
		RootModule: "monorepo",
		WorkspaceMembers: []dependency.WorkspaceMember{
			{Name: "com.acme.gateway", Dir: "/work/monorepo/services/gateway"},
			{Name: "com.acme.ledger", Dir: "/work/monorepo/services/ledger"},
		},
	}

	sets := ds.collectPackageSets("/work/monorepo", merged, nil)

	want := []callgraph.PackageDir{
		{Dir: "/work/monorepo/services/gateway", ImportPath: "com.acme.gateway"},
		{Dir: "/work/monorepo/services/ledger", ImportPath: "com.acme.ledger"},
		{
			Dir:         "/work/monorepo",
			ImportPath:  "monorepo",
			ExcludeDirs: []string{"/work/monorepo/services/gateway", "/work/monorepo/services/ledger"},
		},
	}
	if !reflect.DeepEqual(sets.graphPackages, want) {
		t.Fatalf("graphPackages = %+v, want %+v", sets.graphPackages, want)
	}
}

// KNOWN LIMITATION, pinned rather than fixed. MavenResolver.parseRootModule
// returns the groupId alone, so two merged roots sharing <groupId>com.acme</groupId>
// become two members with the same name. owningModule then answers "com.acme",
// versionedDirectDependencyRefs and graphDirectDependencyRefs miss because the
// versioned keys are com.acme:<artifactId>@<version>, and mavenRootAliasRefs
// sees two incoming-free candidates and returns nil by design. Every direct
// finding keeps its versionless rule PURL.
//
// The root cause is issue #520, "Maven root-module identifier omits artifactId,
// only returns groupId"; issue #533 is where it surfaces, because merging is
// what puts two same-group roots in one result. When #520 lands this test
// changes with it.
func TestDependencyScanner_EnrichDirectFindingPURLs_MergedMavenRootsSharingAGroupIDStayVersionless(t *testing.T) {
	resolved := &dependency.ResolveResult{
		RootModule: "monorepo",
		WorkspaceMembers: []dependency.WorkspaceMember{
			{Name: "com.acme", Dir: "/workspace/services/gateway"},
			{Name: "com.acme", Dir: "/workspace/services/ledger"},
		},
		VersionedGraph: map[string][]dependency.Ref{
			"com.acme:gateway@1.0.0": {{Module: "org.example:lib", Version: "2.0.0"}},
			"com.acme:ledger@1.0.0":  {{Module: "org.example:lib", Version: "2.0.0"}},
		},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "services/ledger/src/main/java/app/Use.java",
		CryptographicAssets: []entities.CryptographicAsset{{PURL: "pkg:maven/org.example/lib"}},
	}}}

	enrichDirectFindingPURLs(report, "/workspace", resolved, "java")

	if got := report.Findings[0].CryptographicAssets[0].PURL; got != "pkg:maven/org.example/lib" {
		t.Fatalf("PURL = %q, want the versionless rule PURL: see issue #520", got)
	}
}

// Discovery runs mvn, gradle, cargo or go inside every root it qualifies, so
// the scan's own exclusions have to reach it. This drives the whole
// ScanWithDependencies path to pin the plumbing, not just resolveScanRoot.
func TestDependencyScanner_ScanWithDependencies_ExcludedDirIsNeverAResolutionRoot(t *testing.T) {
	root := writeRepoTree(t, map[string]string{
		"third_party/legacy/pom.xml": `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>legacy</artifactId>
  <version>1.0.0</version>
</project>`,
	})
	t.Setenv("PATH", t.TempDir())

	ds := &DependencyScanner{resolver: dependency.NewJavaResolver()}
	userReport := &entities.InterimReport{Version: "1.2", Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"}}
	opts := DepScanOptions{ScanOptions: ScanOptions{
		Target:        root,
		ScannerConfig: scanner.Config{SkipPatterns: []string{"third_party/**"}},
	}}

	_, err := ds.ScanWithDependencies(context.Background(), userReport, opts)
	structured, ok := failure.As(err)
	if !ok {
		t.Fatalf("failure.As: %v is not a structured failure, so the excluded pom.xml was resolved", err)
	}
	if structured.Code != failure.CodeDependencyBuildToolUnknown {
		t.Errorf("Code = %q, want %q: the only manifest sits in an excluded directory", structured.Code, failure.CodeDependencyBuildToolUnknown)
	}
}
