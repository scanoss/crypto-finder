package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
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
)

type recordedBatch struct {
	roots  []string
	config scanner.Config
}

// batchRecorder is shared by every adapter a registry factory hands out. It
// records each scanner invocation the dependency scanner makes and answers
// with one canned report per root.
type batchRecorder struct {
	mu       sync.Mutex
	batches  []recordedBatch
	singles  []string
	batchErr func(roots []string) error
	rootErr  func(root string) error
	slowRoot string
}

type batchAdapter struct {
	*batchRecorder
	config scanner.Config
}

func (a *batchAdapter) Initialize(_ context.Context, config scanner.Config) error {
	a.config = config
	return nil
}

func (a *batchAdapter) GetInfo() scanner.Info {
	return scanner.Info{Name: "batch-scanner", Version: "1"}
}

func (a *batchAdapter) reportFor(root string, info entities.ToolInfo) (*entities.InterimReport, error) {
	if a.rootErr != nil {
		if err := a.rootErr(root); err != nil {
			return nil, err
		}
	}
	report := &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{
		FilePath:            "index.go",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 1, EndLine: 1, Metadata: map[string]string{"assetType": "algorithm", "root": root}}},
	}}}
	if root == a.slowRoot {
		report.IncompleteFiles = []string{filepath.Join(root, "bundle.go")}
	}
	return report, nil
}

func (a *batchAdapter) Scan(_ context.Context, target string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
	a.mu.Lock()
	a.singles = append(a.singles, target)
	a.mu.Unlock()
	return a.reportFor(target, info)
}

func (a *batchAdapter) ScanRoots(_ context.Context, roots, _ []string, info entities.ToolInfo) ([]*entities.InterimReport, error) {
	a.mu.Lock()
	a.batches = append(a.batches, recordedBatch{roots: append([]string(nil), roots...), config: a.config})
	a.mu.Unlock()
	if a.batchErr != nil {
		if err := a.batchErr(roots); err != nil {
			return nil, err
		}
	}
	reports := make([]*entities.InterimReport, len(roots))
	for i, root := range roots {
		report, err := a.reportFor(root, info)
		if err != nil {
			return nil, err
		}
		reports[i] = report
	}
	return reports, nil
}

func (r *batchRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches, r.singles = nil, nil
}

func (r *batchRecorder) batchRoots() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	roots := make([][]string, 0, len(r.batches))
	for i := range r.batches {
		roots = append(roots, r.batches[i].roots)
	}
	return roots
}

type batchFixture struct {
	ds       *DependencyScanner
	recorder *batchRecorder
	cache    *storingFindingsCache
	target   string
	dirs     map[string]string
}

// newBatchFixture resolves one dependency per rel: the module is rel's base
// name and its source directory is rel under the scan target.
func newBatchFixture(t *testing.T, ecosystem string, rels ...string) *batchFixture {
	t.Helper()
	target := t.TempDir()
	rule := filepath.Join(target, "rule.yaml")
	if err := os.WriteFile(rule, []byte("rules:\n- id: fixture\n  languages: [go, javascript]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirs := make(map[string]string, len(rels))
	deps := make([]dependency.Dependency, 0, len(rels))
	for _, rel := range rels {
		dir := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		dirs[filepath.Base(rel)] = dir
		deps = append(deps, dependency.Dependency{Module: filepath.Base(rel), Version: "1", Dir: dir})
	}
	recorder := &batchRecorder{}
	registry := scanner.NewRegistry()
	registry.RegisterFactory("batch-scanner", func() scanner.Scanner { return &batchAdapter{batchRecorder: recorder} })
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: ecosystem, resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: deps}, nil
	}}
	cache := &storingFindingsCache{entries: map[string]*entities.InterimReport{}}
	return &batchFixture{
		ds:       NewDependencyScanner(orch, resolver, callgraph.NewBuilder(noopCallgraphParser{}), cache),
		recorder: recorder,
		cache:    cache,
		target:   target,
		dirs:     dirs,
	}
}

func (f *batchFixture) run(t *testing.T, workers int) (*DepScanResult, error) {
	t.Helper()
	f.recorder.reset()
	return f.ds.ScanWithDependencies(t.Context(), &entities.InterimReport{}, DepScanOptions{
		Workers:     workers,
		ScanOptions: ScanOptions{Target: f.target, ScannerName: "batch-scanner", ScannerConfig: scanner.Config{Timeout: 10 * time.Minute}},
	})
}

func (f *batchFixture) progress(t *testing.T, workers int) map[string]any {
	t.Helper()
	result, err := f.run(t, workers)
	if err != nil {
		t.Fatal(err)
	}
	return result.ProgressDetails()
}

func sortedRoots(batches [][]string) [][]string {
	out := make([][]string, 0, len(batches))
	for _, batch := range batches {
		roots := append([]string(nil), batch...)
		sort.Strings(roots)
		out = append(out, roots)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// Each worker runs one scanner process over its share of the dependencies
// the findings cache does not hold, and every dependency keeps its own
// cache entry, so the next scan reads them all from the cache.
func TestDependencyScanner_BatchesCacheMissesAcrossWorkers(t *testing.T) {
	f := newBatchFixture(t, "go", "a", "b", "c", "d", "e", "f")

	result, err := f.run(t, 2)
	if err != nil {
		t.Fatal(err)
	}
	batches := f.recorder.batchRoots()
	if len(batches) != 2 || len(batches[0]) != 3 || len(batches[1]) != 3 || len(f.recorder.singles) != 0 {
		t.Fatalf("six cache misses over two workers: batches = %v singles = %v, want two scanner processes over three roots each", batches, f.recorder.singles)
	}
	seen := map[string]int{}
	for _, batch := range batches {
		for _, root := range batch {
			seen[root]++
		}
	}
	for module, dir := range f.dirs {
		if seen[dir] != 1 {
			t.Errorf("dependency %s scanned %d times, want once", module, seen[dir])
		}
	}
	want := map[string]any{"deps_scanned": 6, "deps_skipped": 0, "deps_failed": 0, "deps_incomplete": 0, "deps_with_findings": 6, "total_dep_findings": 6}
	if got := result.ProgressDetails(); !reflect.DeepEqual(got, want) {
		t.Errorf("progress details = %v, want %v", got, want)
	}
	for _, finding := range result.Report.Findings {
		asset := finding.CryptographicAssets[0]
		if asset.DependencyInfo == nil || f.dirs[asset.DependencyInfo.Module] != asset.Metadata["root"] {
			t.Errorf("finding from %s attributed to %+v", asset.Metadata["root"], asset.DependencyInfo)
		}
		if finding.FilePath != "index.go" {
			t.Errorf("finding path = %q, want it relative to its own dependency root", finding.FilePath)
		}
	}
	if len(f.cache.entries) != 6 {
		t.Fatalf("cached %d reports, want one per dependency", len(f.cache.entries))
	}

	if got := f.progress(t, 2); !reflect.DeepEqual(got, want) || len(f.recorder.batches) != 0 || len(f.recorder.singles) != 0 {
		t.Fatalf("warm cache: details = %v batches = %v singles = %v, want no scanner process", got, f.recorder.batches, f.recorder.singles)
	}

	var evicted []string
	for key, report := range f.cache.entries {
		if len(evicted) == 2 {
			break
		}
		evicted = append(evicted, report.Findings[0].CryptographicAssets[0].Metadata["root"])
		delete(f.cache.entries, key)
	}
	sort.Strings(evicted)
	if got := f.progress(t, 1); !reflect.DeepEqual(got, want) {
		t.Errorf("after eviction: details = %v, want %v", got, want)
	}
	if batches := sortedRoots(f.recorder.batchRoots()); len(batches) != 1 || !reflect.DeepEqual(batches[0], evicted) || len(f.recorder.singles) != 0 {
		t.Fatalf("two cache misses: batches = %v singles = %v, want one process over exactly %v", batches, f.recorder.singles, evicted)
	}
}

// An npm dependency's scan excludes its nested node_modules, which is where
// another dependency may live. A root never shares a process with a root
// nested under it, and a batch carries every member's exclusion.
func TestDependencyScanner_NestedRootsNeverShareAScannerProcess(t *testing.T) {
	f := newBatchFixture(t, npmEcosystem, "node_modules/p", "node_modules/p/node_modules/c", "node_modules/s")
	if _, err := f.run(t, 1); err != nil {
		t.Fatal(err)
	}
	parent, child, sibling := f.dirs["p"], f.dirs["c"], f.dirs["s"]
	batches := f.recorder.batches
	if len(batches) != 1 || !reflect.DeepEqual(sortedRoots([][]string{batches[0].roots})[0], []string{parent, sibling}) {
		t.Fatalf("batches = %+v, want one process over the parent and its sibling", batches)
	}
	if !reflect.DeepEqual(f.recorder.singles, []string{child}) {
		t.Fatalf("single scans = %v, want the nested dependency alone", f.recorder.singles)
	}
	excludes := []string{}
	for _, pattern := range batches[0].config.SkipPatterns {
		if strings.HasSuffix(pattern, "/node_modules/") {
			excludes = append(excludes, pattern)
		}
	}
	sort.Strings(excludes)
	want := []string{filepath.ToSlash(parent) + "/node_modules/", filepath.ToSlash(sibling) + "/node_modules/"}
	if !reflect.DeepEqual(excludes, want) {
		t.Errorf("batch excludes = %v, want each member's own nested node_modules %v", excludes, want)
	}
	if !batches[0].config.IncludeGitIgnored || batches[0].config.RuleTimeoutSeconds != dependencyRuleTimeoutSeconds {
		t.Errorf("batch config = %+v, want Git-ignored files included and the dependency rule timeout", batches[0].config)
	}
}

// A failed process must not fail the healthy dependencies that shared it:
// each one is scanned alone, as before batching, and only the faulty one
// fails. A canceled scan stops instead of rescanning.
func TestDependencyScanner_BatchFailureFallsBackToSingleScans(t *testing.T) {
	f := newBatchFixture(t, "go", "a", "b", "bad", "c")
	f.recorder.batchErr = func([]string) error { return errors.New("opengrep exited 2") }
	f.recorder.rootErr = func(root string) error {
		if filepath.Base(root) == "bad" {
			return errors.New("bad dependency")
		}
		return nil
	}

	got := f.progress(t, 1)
	want := map[string]any{"deps_scanned": 3, "deps_skipped": 0, "deps_failed": 1, "deps_incomplete": 0, "deps_with_findings": 3, "total_dep_findings": 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("progress details = %v, want %v", got, want)
	}
	if len(f.recorder.batches) != 1 {
		t.Errorf("batches = %v, want the one failed process", f.recorder.batchRoots())
	}
	singles := append([]string(nil), f.recorder.singles...)
	sort.Strings(singles)
	wantSingles := []string{f.dirs["a"], f.dirs["b"], f.dirs["bad"], f.dirs["c"]}
	sort.Strings(wantSingles)
	if !reflect.DeepEqual(singles, wantSingles) {
		t.Errorf("single scans = %v, want every member of the failed batch %v", singles, wantSingles)
	}
	if len(f.cache.entries) != 3 {
		t.Errorf("cached %d reports, want the three healthy dependencies", len(f.cache.entries))
	}

	f.cache.entries = map[string]*entities.InterimReport{}
	canceled := failure.New(failure.CodeScannerCancelled, failure.StageScan, "scan canceled")
	f.recorder.batchErr = func([]string) error { return canceled }
	_, err := f.run(t, 1)
	structured, ok := failure.As(err)
	if !ok || structured.Code != failure.CodeScannerCancelled {
		t.Fatalf("error = %v, want the cancellation", err)
	}
	if len(f.recorder.singles) != 0 {
		t.Errorf("single scans after cancellation = %v, want none", f.recorder.singles)
	}
}

// A time or memory limit hit inside a shared process marks only the
// dependency whose files it stopped: that one keeps its partial findings,
// counts as incomplete and is not cached; the others are cached.
func TestDependencyScanner_BatchIncompletenessIsPerDependency(t *testing.T) {
	previous := log.Logger
	t.Cleanup(func() { log.Logger = previous })
	var logs bytes.Buffer
	log.Logger = zerolog.New(zerolog.SyncWriter(&logs))

	f := newBatchFixture(t, "go", "fast", "slow", "steady")
	f.recorder.slowRoot = f.dirs["slow"]

	got := f.progress(t, 1)
	want := map[string]any{"deps_scanned": 3, "deps_skipped": 0, "deps_failed": 0, "deps_incomplete": 1, "deps_with_findings": 3, "total_dep_findings": 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("progress details = %v, want %v", got, want)
	}
	if len(f.recorder.batches) != 1 || len(f.recorder.singles) != 0 {
		t.Fatalf("batches = %v singles = %v, want one shared process", f.recorder.batchRoots(), f.recorder.singles)
	}
	if len(f.cache.entries) != 2 {
		t.Fatalf("cached %d reports, want the two complete dependencies", len(f.cache.entries))
	}
	for _, report := range f.cache.entries {
		if root := report.Findings[0].CryptographicAssets[0].Metadata["root"]; root == f.dirs["slow"] {
			t.Fatal("the incomplete dependency was cached")
		}
	}
	var warnings []string
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, `"level":"warn"`) {
			warnings = append(warnings, line)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], `"module":"slow"`) || !strings.Contains(warnings[0], filepath.Join(f.dirs["slow"], "bundle.go")) {
		t.Fatalf("want one warning naming slow and its incomplete file, got:\n%s", strings.Join(warnings, "\n"))
	}
}

// A shared process gets the single-scan timeout once per ceil(roots / jobs):
// the scanner analyzes that many files at a time, so n roots consume about
// n / jobs single-scan budgets of wall time.
func TestBatchScanOptions_ScalesTheProcessTimeoutWithRoots(t *testing.T) {
	member := func(dir string, jobs int32) ScanOptions {
		return ScanOptions{Target: dir, ScannerConfig: scanner.Config{
			Timeout: 10 * time.Minute, Jobs: jobs, SkipPatterns: []string{"test/", filepath.ToSlash(dir) + "/node_modules/"},
		}}
	}
	tests := []struct {
		name  string
		roots int
		jobs  int32
		want  time.Duration
	}{
		{"one root keeps the single-scan timeout", 1, 4, 10 * time.Minute},
		{"as many roots as jobs", 4, 4, 10 * time.Minute},
		{"one more root than jobs", 5, 4, 20 * time.Minute},
		{"sixteen roots over four jobs", 16, 4, 40 * time.Minute},
		{"a lone worker uses every core", 2, 0, 10 * time.Minute * time.Duration((2+runtime.NumCPU()-1)/runtime.NumCPU())},
	}
	t.Run("a --jobs in ExtraArgs is the parallelism the process runs with", func(t *testing.T) {
		members := []ScanOptions{member("/deps/a", 8), member("/deps/b", 8), member("/deps/c", 8)}
		for i := range members {
			members[i].ScannerConfig.ExtraArgs = []string{"--jobs", "1"}
		}
		if got := batchScanOptions(members).ScannerConfig.Timeout; got != 30*time.Minute {
			t.Errorf("timeout = %v, want 30m: three roots at one job", got)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := make([]ScanOptions, 0, tt.roots)
			for i := range tt.roots {
				members = append(members, member(filepath.FromSlash("/deps/"+string(rune('a'+i))), tt.jobs))
			}
			got := batchScanOptions(members)
			if got.ScannerConfig.Timeout != tt.want {
				t.Errorf("timeout = %v, want %v", got.ScannerConfig.Timeout, tt.want)
			}
			if got.ScannerConfig.Jobs != tt.jobs {
				t.Errorf("jobs = %d, want %d", got.ScannerConfig.Jobs, tt.jobs)
			}
			wantPatterns := []string{"test/"}
			for _, m := range members {
				wantPatterns = append(wantPatterns, m.ScannerConfig.SkipPatterns[1])
			}
			if !reflect.DeepEqual(got.ScannerConfig.SkipPatterns, wantPatterns) {
				t.Errorf("skip patterns = %v, want the shared ones once and each member's own %v", got.ScannerConfig.SkipPatterns, wantPatterns)
			}
		})
	}
}

func TestNestingLevels(t *testing.T) {
	dirs := []string{"/m/a", "/m/a/node_modules/b", "/m/a/node_modules/b/node_modules/c", "/m/ab", "/m/c", "/m/c"}
	want := []int{0, 1, 2, 0, 0, 1}
	if got := nestingLevels(dirs); !reflect.DeepEqual(got, want) {
		t.Fatalf("nestingLevels = %v, want %v (a prefix only nests at a path separator, and an equal dir nests)", got, want)
	}
	work := []depWork{weighted("/m/a/", 1), weighted("/m/a/node_modules/b", 1)}
	if batches := shapeBatches(work, 1); len(batches) != 2 {
		t.Fatalf("a root with a trailing separator shared a batch with the root nested under it: %v", batches)
	}
}

func weighted(dir string, weight int64) depWork {
	return depWork{dep: dependency.Dependency{Module: filepath.Base(dir), Version: "1", Dir: dir}, weight: weight}
}

func batchWeights(batches []scanBatch) [][]int64 {
	out := make([][]int64, 0, len(batches))
	for _, batch := range batches {
		weights := make([]int64, 0, len(batch.items))
		for i := range batch.items {
			weights = append(weights, batch.items[i].weight)
		}
		out = append(out, weights)
	}
	return out
}

func TestShapeBatches(t *testing.T) {
	t.Run("one batch per worker, balanced by weight, heaviest first", func(t *testing.T) {
		work := []depWork{weighted("/d/a", 10), weighted("/d/b", 30), weighted("/d/c", 20), weighted("/d/d", 25), weighted("/d/e", 15)}
		got := batchWeights(shapeBatches(work, 2))
		want := [][]int64{{30, 15, 10}, {25, 20}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("batches = %v, want %v", got, want)
		}
	})
	t.Run("a very large dependency gets its own process", func(t *testing.T) {
		work := []depWork{weighted("/d/giant", 1000), weighted("/d/a", 10), weighted("/d/b", 10), weighted("/d/c", 10), weighted("/d/d", 10)}
		got := batchWeights(shapeBatches(work, 2))
		want := [][]int64{{1000}, {10, 10, 10, 10}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("batches = %v, want %v", got, want)
		}
	})
	t.Run("a batch holds at most maxBatchRoots roots", func(t *testing.T) {
		work := make([]depWork, 0, 40)
		for i := range 40 {
			work = append(work, weighted(filepath.FromSlash("/d/"+string(rune('a'+i%26))+"/"+string(rune('a'+i/26))), 1))
		}
		batches := shapeBatches(work, 2)
		if len(batches) != 3 {
			t.Fatalf("got %d batches, want 3 (ceil(40 / %d))", len(batches), maxBatchRoots)
		}
		total := 0
		for _, batch := range batches {
			if len(batch.items) > maxBatchRoots {
				t.Errorf("batch holds %d roots, want at most %d", len(batch.items), maxBatchRoots)
			}
			total += len(batch.items)
		}
		if total != 40 {
			t.Errorf("batches hold %d roots, want all 40", total)
		}
	})
	t.Run("nested roots go to different batches even with one worker", func(t *testing.T) {
		work := []depWork{weighted("/d/a", 5), weighted("/d/a/node_modules/b", 5), weighted("/d/c", 5)}
		batches := shapeBatches(work, 1)
		if len(batches) != 2 {
			t.Fatalf("got %d batches, want 2: %v", len(batches), batches)
		}
		for _, batch := range batches {
			for _, item := range batch.items {
				for _, other := range batch.items {
					if item.dep.Dir != other.dep.Dir && strings.HasPrefix(other.dep.Dir, item.dep.Dir+"/") {
						t.Errorf("%s shares a batch with %s nested under it", item.dep.Dir, other.dep.Dir)
					}
				}
			}
		}
	})
	t.Run("fewer roots than workers scan alone", func(t *testing.T) {
		work := []depWork{weighted("/d/a", 5), weighted("/d/b", 5)}
		if got := batchWeights(shapeBatches(work, 8)); !reflect.DeepEqual(got, [][]int64{{5}, {5}}) {
			t.Fatalf("batches = %v, want each root alone", got)
		}
	})
}

func TestSourceWeight_CountsOnlyTheEcosystemsSourceFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]int{
		"index.js":                     100,
		"lib/util.ts":                  50,
		"README.md":                    1000,
		"dist/bundle.js.map":           5000,
		"node_modules/nested/index.js": 700,
		"src/deep/tree/component.tsx":  25,
	}
	for rel, size := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := sourceWeight(dir, ecosystemToLanguages(npmEcosystem)); got != 175 {
		t.Fatalf("sourceWeight = %d, want 175: the JavaScript and TypeScript bytes outside nested node_modules", got)
	}
	if got := sourceWeight(filepath.Join(dir, "missing"), ecosystemToLanguages(npmEcosystem)); got != 0 {
		t.Fatalf("sourceWeight of a missing dir = %d, want 0", got)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skip(err)
	}
	if got := sourceWeight(link, ecosystemToLanguages(npmEcosystem)); got != 175 {
		t.Fatalf("sourceWeight through a symlinked root = %d, want 175", got)
	}
}
