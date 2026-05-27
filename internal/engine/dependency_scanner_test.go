package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
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
func (noopCallgraphParser) SkipDirs() map[string]bool { return nil }
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
	// 2 workspace members + 1 dep with findings = 3 graphPackages; remaining Java deps stay type-only.
	if len(sets.graphPackages) != 3 {
		t.Fatalf("graphPackages len = %d, want 3 (2 workspace + 1 finding dep)", len(sets.graphPackages))
	}
	if len(sets.typeOnlyPackages) != 3 {
		t.Fatalf("typeOnlyPackages len = %d, want 3", len(sets.typeOnlyPackages))
	}
	if sets.graphPackages[2].Version != "v1" {
		t.Fatalf("graphPackages[2].Version = %q, want v1", sets.graphPackages[2].Version)
	}
	if sets.typeOnlyPackages[0].Version != "v2" || sets.typeOnlyPackages[1].Version != "v3" || sets.typeOnlyPackages[2].Version != "v4" {
		t.Fatalf("unexpected typeOnlyPackages versions: %#v", sets.typeOnlyPackages)
	}
	if sets.typeOnlyPackages[0].CompiledArtifactPath != "/artifacts/dep2.jar" {
		t.Fatalf("expected compiled artifact path to propagate, got %#v", sets.typeOnlyPackages[0])
	}
	if sets.typeOnlyPackages[1].CompiledArtifactPath != "/artifacts/dep3.jar" {
		t.Fatalf("expected compiled artifact path to propagate for source-less dep, got %#v", sets.typeOnlyPackages[1])
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

	ds := &DependencyScanner{}
	dep := &dependency.Dependency{Module: "dep/mod", Version: "v1.0.0", Dir: depDir}
	depReport := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "lib.go",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 10}},
	}}}

	ds.attributeFindings(depReport, dep, userTarget, tracer, map[string]bool{"app": true})
	asset := depReport.Findings[0].CryptographicAssets[0]
	if asset.Source != "dependency" {
		t.Fatalf("asset.Source = %q, want dependency", asset.Source)
	}
	if asset.DependencyInfo == nil || asset.DependencyInfo.Module != "dep/mod" || asset.DependencyInfo.Version != "v1.0.0" {
		t.Fatalf("unexpected dependency info: %#v", asset.DependencyInfo)
	}
	if depReport.Findings[0].FilePath != "lib.go" {
		t.Fatalf("unexpected dependency file path: %s", depReport.Findings[0].FilePath)
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

	outcomes := ds.scanDependenciesParallel(context.Background(), deps, []string{"/rules/go.yaml"}, "", DepScanOptions{Workers: 2, ScanOptions: ScanOptions{ScannerName: "test-scanner"}})

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
