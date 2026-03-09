package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

type fakeResolver struct {
	ecosystem string
	resolveFn func(ctx context.Context, targetDir string, maxDepth int) (*dependency.ResolveResult, error)
}

func (f *fakeResolver) Resolve(ctx context.Context, targetDir string, maxDepth int) (*dependency.ResolveResult, error) {
	if f.resolveFn != nil {
		return f.resolveFn(ctx, targetDir, maxDepth)
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
	opts := DepScanOptions{ScanOptions: ScanOptions{Target: "/user/project", ScannerConfig: scanner.Config{SkipPatterns: []string{"vendor"}}}}
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
	if depOpts.ScannerConfig.SkipPatterns != nil {
		t.Fatalf("expected SkipPatterns to be cleared, got %#v", depOpts.ScannerConfig.SkipPatterns)
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
	depReports := map[string]*entities.InterimReport{
		"dep@1": {Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}},
		"dep@2": {Findings: []entities.Finding{{}}},
	}
	depMap := map[string]*dependency.Dependency{
		"dep@1": {Module: "github.com/acme/dep", Version: "v1", Dir: "/deps/dep1"},
		"dep@2": {Module: "github.com/acme/dep2", Version: "v2", Dir: "/deps/dep2"},
	}

	pkgs := ds.collectPackageDirs("/user/project", resolvedWorkspace, depReports, depMap)
	if len(pkgs) != 3 {
		t.Fatalf("collectPackageDirs len = %d, want 3", len(pkgs))
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

func TestDependencyScanner_NormalizeAndMerge(t *testing.T) {
	userTarget := t.TempDir()
	depDir := t.TempDir()

	entries := []callgraph.CallChainEntry{
		{FunctionName: "Entry", Namespace: "app", FilePath: filepath.Join(userTarget, "main.go"), Line: 10},
		{FunctionName: "Crypto", Namespace: "dep", FilePath: filepath.Join(depDir, "lib.go"), Line: 20},
		{FunctionName: "X", Namespace: "other", FilePath: "/outside/path.go", Line: 30},
	}

	normalized := normalizeCallChainPaths(entries, userTarget, &dependency.Dependency{Module: "github.com/acme/dep", Version: "v1", Dir: depDir})
	if normalized[0].FilePath != "main.go" {
		t.Fatalf("expected user path to be normalized, got %q", normalized[0].FilePath)
	}
	if normalized[0].Namespace != "" {
		t.Fatalf("expected user namespace to be cleared, got %q", normalized[0].Namespace)
	}
	if !strings.HasPrefix(normalized[1].FilePath, "github.com/acme/dep@v1/") {
		t.Fatalf("expected dependency path prefix, got %q", normalized[1].FilePath)
	}
	if normalized[1].Namespace != "dep" {
		t.Fatalf("expected dependency namespace to be preserved, got %q", normalized[1].Namespace)
	}
	if normalized[2].FilePath != "/outside/path.go" {
		t.Fatalf("outside path should remain unchanged, got %q", normalized[2].FilePath)
	}

	ds := &DependencyScanner{}
	userReport := &entities.InterimReport{
		Version: "1.2",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Findings: []entities.Finding{
			{FilePath: "main.go", CryptographicAssets: []entities.CryptographicAsset{{Source: ""}}},
		},
	}
	depReports := map[string]*entities.InterimReport{
		"reachable": {
			Findings: []entities.Finding{{
				FilePath:            "dep/a.go",
				CryptographicAssets: []entities.CryptographicAsset{{CallChains: [][]callgraph.CallChainEntry{{{FunctionName: "Entry", Namespace: "app", FilePath: "main.go", Line: 1}}}}},
			}},
		},
		"unreachable": {
			Findings: []entities.Finding{{
				FilePath:            "dep/b.go",
				CryptographicAssets: []entities.CryptographicAsset{{}},
			}},
		},
	}

	mergedReachable := ds.mergeReports(userReport, depReports, false)
	if len(mergedReachable.Findings) != 2 {
		t.Fatalf("reachable-only merge findings len = %d, want 2", len(mergedReachable.Findings))
	}
	if mergedReachable.Findings[0].CryptographicAssets[0].Source != "direct" {
		t.Fatalf("expected user findings to default to direct source")
	}

	mergedAll := ds.mergeReports(userReport, depReports, true)
	if len(mergedAll.Findings) != 3 {
		t.Fatalf("include-unreachable merge findings len = %d, want 3", len(mergedAll.Findings))
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
	if asset.DependencyInfo.Function == "" {
		t.Fatal("expected dependency function attribution to be set")
	}
	if len(asset.CallChains) == 0 {
		t.Fatal("expected dependency call chains to be populated")
	}
	if !strings.HasPrefix(depReport.Findings[0].FilePath, "dep/mod@v1.0.0/") {
		t.Fatalf("unexpected rewritten file path: %s", depReport.Findings[0].FilePath)
	}

	userReport := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "main.go",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 30}},
	}}}
	ds.enrichUserFindings(userReport, userTarget, tracer, map[string]bool{"app": true})
	if len(userReport.Findings[0].CryptographicAssets[0].CallChains) == 0 {
		t.Fatal("expected user finding call chain enrichment")
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

	filtered, err := ds.loadFilteredRules("go")
	if err != nil {
		t.Fatalf("loadFilteredRules: %v", err)
	}
	if len(filtered) != 1 || filtered[0] != goRule {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}

	dep := &dependency.Dependency{Module: "github.com/acme/dep", Version: "v1", Dir: t.TempDir()}
	cacheKey := dep.Module + "@" + dep.Version + ":hash"
	cachedReport := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{}}}}}
	cache.getMap[cacheKey] = cachedReport

	res := ds.scanSingleDep(context.Background(), dep, dep.Module+"@"+dep.Version, []string{goRule}, "hash", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
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
	res = ds.scanSingleDep(context.Background(), dep, dep.Module+"@"+dep.Version, []string{goRule}, "hash", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}})
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
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, target string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			scanCalls.Add(1)
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
		{Module: "a", Version: "1", Dir: t.TempDir()},
		{Module: "a", Version: "1", Dir: t.TempDir()}, // duplicate module@version
		{Module: "b", Version: "1", Dir: filepath.Join(t.TempDir(), "bad")},
	}

	reports, depMap := ds.scanDependenciesParallel(context.Background(), deps, []string{"/rules/go.yaml"}, "", DepScanOptions{Workers: 2, ScanOptions: ScanOptions{ScannerName: "test-scanner"}})

	if len(reports) != 1 {
		t.Fatalf("reports len = %d, want 1", len(reports))
	}
	if len(depMap) != 1 {
		t.Fatalf("depMap len = %d, want 1", len(depMap))
	}
	if calls := scanCalls.Load(); calls < 2 {
		t.Fatalf("expected at least two scan attempts (dedup + failing dep), got %d", calls)
	}
}

func TestDependencyScanner_ScanWithDependencies_NoDepsAndErrors(t *testing.T) {
	userReport := &entities.InterimReport{Version: "1.2", Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"}}

	t.Run("no-dependencies", func(t *testing.T) {
		ds := &DependencyScanner{
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string, _ int) (*dependency.ResolveResult, error) {
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
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string, _ int) (*dependency.ResolveResult, error) {
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
			resolver: &fakeResolver{ecosystem: "go", resolveFn: func(_ context.Context, _ string, _ int) (*dependency.ResolveResult, error) {
				return &dependency.ResolveResult{RootModule: "root", Dependencies: []dependency.Dependency{{Module: "a", Version: "1", Dir: t.TempDir()}}}, nil
			}},
		}

		_, err := ds.ScanWithDependencies(context.Background(), userReport, DepScanOptions{ScanOptions: ScanOptions{Target: t.TempDir()}})
		if err == nil || !strings.Contains(err.Error(), "failed to load rules") {
			t.Fatalf("expected rules load error, got %v", err)
		}
	})
}
