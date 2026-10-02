package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
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

type invocationLog struct {
	mu      sync.Mutex
	batches [][]string
	singles []string
}

// batchingOpengrep is the real adapter, recording which entry point each
// dependency went through.
type batchingOpengrep struct {
	*opengrep.Scanner
	log *invocationLog
}

func (s *batchingOpengrep) Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	s.log.mu.Lock()
	s.log.singles = append(s.log.singles, target)
	s.log.mu.Unlock()
	return s.Scanner.Scan(ctx, target, rulePaths, toolInfo)
}

func (s *batchingOpengrep) ScanRoots(ctx context.Context, roots []scanner.Root, rulePaths []string, toolInfo entities.ToolInfo) ([]*entities.InterimReport, error) {
	s.log.mu.Lock()
	s.log.batches = append(s.log.batches, rootDirs(roots))
	s.log.mu.Unlock()
	return s.Scanner.ScanRoots(ctx, roots, rulePaths, toolInfo)
}

// singleOpengrep hides the adapter's batch entry point, so every dependency
// is scanned alone, which is the behavior batching must reproduce.
type singleOpengrep struct {
	scanner.Scanner
}

func npmBatchFixture(t *testing.T) (root string, dirs map[string]string) {
	t.Helper()
	root = t.TempDir()
	library := filepath.Join(root, "node_modules", "library")
	dirs = map[string]string{
		"library": library,
		"child":   filepath.Join(library, "node_modules", "child"),
		"other":   filepath.Join(root, "node_modules", "other"),
	}
	for _, rel := range []string{"library/index.js", "library/dist/index.js", "library/tests/index.js", "library/node_modules/child/index.js", "other/index.js"} {
		path := filepath.Join(root, "node_modules", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("const crypto = require('crypto'); crypto.createHash('sha256');\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":{"library":"1.0.0","other":"1.0.0"}}`
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"library":"1.0.0","other":"1.0.0"}},"node_modules/library":{"version":"1.0.0","dependencies":{"child":"1.0.0"}},"node_modules/library/node_modules/child":{"version":"1.0.0"},"node_modules/other":{"version":"1.0.0"}}}`
	for name, contents := range map[string]string{"package.json": manifest, "package-lock.json": lock, "crypto.yaml": nodeHashRule} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, dirs
}

func scanNpmFixture(t *testing.T, root string, factory func() scanner.Scanner) *DepScanResult {
	t.Helper()
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture-opengrep", factory)
	rule := filepath.Join(root, "crypto.yaml")
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	ds := NewDependencyScanner(orch, dependency.NewNpmResolver(), callgraph.NewBuilder(noopCallgraphParser{}), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := ds.ScanWithDependencies(ctx, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{
		Target: root, ScannerName: "fixture-opengrep",
		ScannerConfig: scanner.Config{SkipPatterns: skip.WithDefaultTestPatterns([]string{"node_modules", "dist", "index.js"}), Timeout: time.Minute, ExtraArgs: []string{"--jobs", "1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func findingsByModule(report *entities.InterimReport) map[string][]string {
	paths := map[string][]string{}
	for _, finding := range report.Findings {
		module := finding.CryptographicAssets[0].DependencyInfo.Module
		paths[module] = append(paths[module], filepath.ToSlash(finding.FilePath))
	}
	for module := range paths {
		sort.Strings(paths[module])
	}
	return paths
}

// Real OpenGrep over nested npm dependencies: the parent and its sibling
// share one process, the nested child runs alone, and the merged report is
// byte for byte what scanning every dependency alone produces.
func TestDependencyScanner_BatchedNpmScanMatchesSingleScansIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires real OpenGrep subprocesses")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("OpenGrep not installed")
	}
	root, dirs := npmBatchFixture(t)

	invocations := &invocationLog{}
	batched := scanNpmFixture(t, root, func() scanner.Scanner {
		return &batchingOpengrep{Scanner: opengrep.NewScanner(), log: invocations}
	})
	if want := [][]string{{dirs["library"], dirs["other"]}}; !reflect.DeepEqual(sortedRoots(invocations.batches), want) {
		t.Errorf("batches = %v, want %v", invocations.batches, want)
	}
	if want := []string{dirs["child"]}; !reflect.DeepEqual(invocations.singles, want) {
		t.Errorf("single scans = %v, want %v", invocations.singles, want)
	}
	want := map[string][]string{"library": {"dist/index.js", "index.js"}, "child": {"index.js"}, "other": {"index.js"}}
	if got := findingsByModule(batched.Report); !reflect.DeepEqual(got, want) {
		t.Errorf("findings by dependency = %v, want %v", got, want)
	}
	details := map[string]any{"deps_scanned": 3, "deps_skipped": 0, "deps_failed": 0, "deps_incomplete": 0, "deps_with_findings": 3, "total_dep_findings": 4}
	if got := batched.ProgressDetails(); !reflect.DeepEqual(got, details) {
		t.Errorf("progress details = %v, want %v", got, details)
	}

	single := scanNpmFixture(t, root, func() scanner.Scanner { return &singleOpengrep{Scanner: opengrep.NewScanner()} })
	batchedJSON, err := json.Marshal(batched.Report)
	if err != nil {
		t.Fatal(err)
	}
	singleJSON, err := json.Marshal(single.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(batchedJSON, singleJSON) {
		t.Fatalf("batched report differs from single scans:\n%s\n%s", batchedJSON, singleJSON)
	}
	if !reflect.DeepEqual(single.ProgressDetails(), details) {
		t.Errorf("single-scan details = %v, want %v", single.ProgressDetails(), details)
	}
	if fmt.Sprint(single.Dependencies) != fmt.Sprint(batched.Dependencies) {
		t.Errorf("dependencies differ: %v vs %v", single.Dependencies, batched.Dependencies)
	}
}
