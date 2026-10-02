package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/skip"
)

const goMD5Rule = `rules:
  - id: go.md5
    languages: [go]
    message: MD5
    severity: INFO
    pattern: md5.New()
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
        algorithmFamily: MD5
        algorithmPrimitive: hash
        operation: digest
`

const md5Source = "\n\nimport \"crypto/md5\"\n\nfunc Sum() { md5.New() }\n"

// goPackagesFixture is an application importing two packages of module dep
// and the root package of module other. Every package of both modules uses
// MD5, imported or not.
func goPackagesFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"app/go.mod": "module example.com/app\n\ngo 1.22\n\n" +
			"require (\n\texample.com/dep v1.0.0\n\texample.com/other v1.0.0\n)\n\n" +
			"replace example.com/dep => ../dep\n\nreplace example.com/other => ../other\n",
		"app/main.go":                    "package main\n\nimport (\n\t_ \"example.com/dep/used\"\n\t_ \"example.com/dep/used/deeper/leaf\"\n\t_ \"example.com/other\"\n)\n\nfunc main() {}\n",
		"app/crypto.yaml":                goMD5Rule,
		"dep/go.mod":                     "module example.com/dep\n\ngo 1.22\n",
		"dep/root.go":                    "package dep" + md5Source,
		"dep/used/used.go":               "package used" + md5Source,
		"dep/used/inner/inner.go":        "package inner" + md5Source,
		"dep/used/deeper/leaf/leaf.go":   "package leaf" + md5Source,
		"dep/unused/unused.go":           "package unused" + md5Source,
		"other/go.mod":                   "module example.com/other\n\ngo 1.22\n",
		"other/other.go":                 "package other" + md5Source,
		"other/sub/sub.go":               "package sub" + md5Source,
		"dep/used/used_test.go":          "package used" + md5Source,
		"dep/used/deeper/notes/notes.go": "package notes" + md5Source,
	}
	for rel, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, "app")
}

// scopedOnlyOpengrep is the real adapter without its batch entry point, so
// every dependency takes the single-scan path.
type scopedOnlyOpengrep struct {
	inner interface {
		scanner.Scanner
		scanner.ScopedScanner
	}
}

func (s scopedOnlyOpengrep) Initialize(ctx context.Context, config scanner.Config) error {
	return s.inner.Initialize(ctx, config)
}

func (s scopedOnlyOpengrep) Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	return s.inner.Scan(ctx, target, rulePaths, toolInfo)
}

func (s scopedOnlyOpengrep) ScanScoped(ctx context.Context, target string, scope *scanner.DetectionScope, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	return s.inner.ScanScoped(ctx, target, scope, rulePaths, toolInfo)
}

func (s scopedOnlyOpengrep) GetInfo() scanner.Info { return s.inner.GetInfo() }

func scanGoPackagesFixture(t *testing.T, app string, factory func() scanner.Scanner) *DepScanResult {
	t.Helper()
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture-opengrep", factory)
	rule := filepath.Join(app, "crypto.yaml")
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	ds := NewDependencyScanner(orch, dependency.NewGoResolver(), callgraph.NewBuilder(noopCallgraphParser{}), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := ds.ScanWithDependencies(ctx, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{
		Target: app, ScannerName: "fixture-opengrep",
		ScannerConfig: scanner.Config{SkipPatterns: skip.WithDefaultTestPatterns(nil), Timeout: time.Minute, ExtraArgs: []string{"--jobs", "1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Go links only imported packages, so a dependency scan reads the files
// directly in each imported package's directory: not the module's other
// packages, and not the subdirectories of an imported package, which are
// packages of their own. Both the batched and the single-scan paths.
func TestDependencyScanner_GoScansOnlyImportedPackagesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the go toolchain and real OpenGrep subprocesses")
	}
	for _, tool := range []string{"go", "opengrep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	app := goPackagesFixture(t)

	want := map[string][]string{
		"example.com/dep":   {"used/deeper/leaf/leaf.go", "used/used.go"},
		"example.com/other": {"other.go"},
	}
	paths := map[string]func() scanner.Scanner{
		"batched": func() scanner.Scanner { return opengrep.NewScanner() },
		"single":  func() scanner.Scanner { return scopedOnlyOpengrep{inner: opengrep.NewScanner()} },
	}
	for name, factory := range paths {
		t.Run(name, func(t *testing.T) {
			result := scanGoPackagesFixture(t, app, factory)
			if got := findingsByModule(result.Report); !reflect.DeepEqual(got, want) {
				t.Errorf("findings by dependency = %v, want %v: root.go, unused/, used/inner/ and sub/ are packages nothing imports", got, want)
			}
		})
	}
}

// The findings cache must never answer a package-scoped scan with a whole
// module's findings, or one set of imported packages with another's.
func TestDependencyScanner_CacheKeyFollowsTheScannedPackages(t *testing.T) {
	module := t.TempDir()
	for _, rel := range []string{"a/a.go", "b/b.go"} {
		path := filepath.Join(module, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyFor := func(adapter scanner.Scanner, files ...string) string {
		t.Helper()
		registry := scanner.NewRegistry()
		registry.Register("test-scanner", adapter)
		ds := &DependencyScanner{
			orchestrator:  NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{}), registry),
			resolver:      &fakeResolver{ecosystem: "go"},
			findingsCache: &fakeFindingsCache{getMap: map[string]*entities.InterimReport{}},
		}
		dep := dependency.Dependency{Module: "example.com/mod", Version: "v1.0.0", Dir: module}
		for _, rel := range files {
			dep.Files = append(dep.Files, filepath.Join(module, filepath.FromSlash(rel)))
		}
		item := depWork{key: dependencyKey(dep), dep: dep}
		if _, hit := ds.lookupDependency(context.Background(), &item, []string{"rule.yaml"}, "hash", DepScanOptions{ScanOptions: ScanOptions{ScannerName: "test-scanner"}}); hit {
			t.Fatal("empty cache answered")
		}
		if item.cacheKey == "" {
			t.Fatal("no cache key")
		}
		return item.cacheKey
	}

	whole := keyFor(&scopedMockScanner{})
	onlyA := keyFor(&scopedMockScanner{}, "a/a.go")
	onlyB := keyFor(&scopedMockScanner{}, "b/b.go")
	both := keyFor(&scopedMockScanner{}, "a/a.go", "b/b.go")
	if keys := map[string]bool{whole: true, onlyA: true, onlyB: true, both: true}; len(keys) != 4 {
		t.Fatalf("cache keys collide: whole=%s a=%s b=%s a+b=%s", whole, onlyA, onlyB, both)
	}
	if got := keyFor(&mockScanner{}, "a/a.go"); got != whole {
		t.Errorf("a scanner that cannot limit detection scans the whole module, so its key must be the whole module's: got %s, want %s", got, whole)
	}
}

// Several module roots can resolve one module version with different
// imported packages; the scan covers all of them, once.
func TestCanonicalDependencies_UnionsImportedPackages(t *testing.T) {
	deps := canonicalDependencies([]dependency.Dependency{
		{Module: "example.com/mod", Version: "v1", Dir: "/m", Files: []string{"/m/b/b.go", "/m/a/a.go"}},
		{Module: "example.com/mod", Version: "v1", Dir: "/m", Files: []string{"/m/c/c.go", "/m/a/a.go"}},
		{Module: "example.com/whole", Version: "v1", Dir: "/w", Files: []string{"/w/a/a.go"}},
		{Module: "example.com/whole", Version: "v1", Dir: "/w"},
	})
	want := []dependency.Dependency{
		{Module: "example.com/mod", Version: "v1", Dir: "/m", Files: []string{"/m/a/a.go", "/m/b/b.go", "/m/c/c.go"}},
		{Module: "example.com/whole", Version: "v1", Dir: "/w"},
	}
	if !reflect.DeepEqual(deps, want) {
		t.Errorf("canonicalDependencies = %+v, want %+v: a whole module stays whole", deps, want)
	}
}
