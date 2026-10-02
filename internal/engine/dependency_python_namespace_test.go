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

const pythonMD5Rule = `rules:
  - id: python.md5
    languages: [python]
    message: MD5
    severity: INFO
    pattern: hashlib.md5()
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
        algorithmFamily: MD5
        algorithmPrimitive: hash
        operation: digest
`

// pythonNamespaceFixture is a project whose virtual environment holds ns-a
// and ns-b, two distributions installing into the namespace directory
// google/, and solo, a distribution with a directory of its own. Each
// installed module uses MD5. It returns the project and site-packages.
func pythonNamespaceFixture(t *testing.T) (project, sitePackages string) {
	t.Helper()
	root := t.TempDir()
	project = filepath.Join(root, "app")
	venv := filepath.Join(root, "venv")
	sitePackages = filepath.Join(venv, "lib", "python3.12", "site-packages")
	const md5 = "import hashlib\n\ndef digest():\n    return hashlib.md5()\n"
	files := map[string]string{
		"google/a/__init__.py":      "",
		"google/a/hash.py":          md5,
		"google/b/__init__.py":      "",
		"google/b/hash.py":          md5,
		"solo/__init__.py":          "",
		"solo/x.py":                 md5,
		"ns_a-1.0.dist-info/RECORD": "google/a/__init__.py,,\ngoogle/a/hash.py,sha256=x,60\nns_a-1.0.dist-info/RECORD,,\n",
		"ns_b-2.0.dist-info/RECORD": "google/b/__init__.py,,\ngoogle/b/hash.py,sha256=x,60\nns_b-2.0.dist-info/RECORD,,\n",
		"solo-3.0.dist-info/RECORD": "solo/__init__.py,,\nsolo/x.py,sha256=x,60\nsolo-3.0.dist-info/RECORD,,\n",
	}
	for rel, contents := range files {
		path := filepath.Join(sitePackages, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "crypto.yaml"), []byte(pythonMD5Rule), 0o600); err != nil {
		t.Fatal(err)
	}
	python := `#!/bin/sh
if [ "$1" = "-m" ] && [ "$3" = "list" ]; then
  echo '[{"name":"ns-a","version":"1.0"},{"name":"ns-b","version":"2.0"},{"name":"solo","version":"3.0"}]'
  exit 0
fi
if [ "$1" = "-m" ] && [ "$3" = "show" ]; then
  printf 'Name: ns-a\nVersion: 1.0\nLocation: ` + sitePackages + `\nRequires:\n---\n'
  printf 'Name: ns-b\nVersion: 2.0\nLocation: ` + sitePackages + `\nRequires:\n---\n'
  printf 'Name: solo\nVersion: 3.0\nLocation: ` + sitePackages + `\nRequires:\n'
  exit 0
fi
if [ "$1" = "-c" ]; then
  echo '{"google":["ns-a","ns-b"],"solo":["solo"]}'
  exit 0
fi
exit 1
`
	bin := filepath.Join(venv, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "python"), []byte(python), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VIRTUAL_ENV", venv)
	return project, sitePackages
}

func scanPythonFixture(t *testing.T, project string, factory func() scanner.Scanner) *DepScanResult {
	t.Helper()
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture-opengrep", factory)
	rule := filepath.Join(project, "crypto.yaml")
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	ds := NewDependencyScanner(orch, dependency.NewPipResolver(), callgraph.NewBuilder(noopCallgraphParser{}), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := ds.ScanWithDependencies(ctx, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{
		Target: project, ScannerName: "fixture-opengrep",
		ScannerConfig: scanner.Config{SkipPatterns: skip.WithDefaultTestPatterns(nil), Timeout: time.Minute, ExtraArgs: []string{"--jobs", "1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Distributions that install into one namespace directory share it as their
// root, but each owns only the files its RECORD lists: every file is scanned
// once and reported under the distribution that installed it, with the path
// a whole-directory scan gives it. The siblings share one scanner process.
func TestDependencyScanner_PythonNamespaceSiblingsOwnTheirFilesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires real OpenGrep subprocesses")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("OpenGrep not installed")
	}
	project, sitePackages := pythonNamespaceFixture(t)
	want := map[string][]string{
		"ns-a": {"a/hash.py"},
		"ns-b": {"b/hash.py"},
		"solo": {"x.py"},
	}

	invocations := &invocationLog{}
	batched := scanPythonFixture(t, project, func() scanner.Scanner {
		return &batchingOpengrep{Scanner: opengrep.NewScanner(), log: invocations}
	})
	if got := findingsByModule(batched.Report); !reflect.DeepEqual(got, want) {
		t.Errorf("batched findings by distribution = %v, want %v", got, want)
	}
	namespace, solo := filepath.Join(sitePackages, "google"), filepath.Join(sitePackages, "solo")
	if want := [][]string{{namespace, namespace, solo}}; !reflect.DeepEqual(sortedRoots(invocations.batches), want) {
		t.Errorf("batches = %v, want %v: namespace siblings scan disjoint files, so they share one process", invocations.batches, want)
	}

	single := scanPythonFixture(t, project, func() scanner.Scanner { return scopedOnlyOpengrep{inner: opengrep.NewScanner()} })
	if got := findingsByModule(single.Report); !reflect.DeepEqual(got, want) {
		t.Errorf("single-scan findings by distribution = %v, want %v", got, want)
	}
}
