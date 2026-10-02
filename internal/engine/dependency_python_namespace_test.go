package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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

const pythonMD5Source = "import hashlib\n\ndef digest():\n    return hashlib.md5()\n"

// pythonVenvFixture is a project whose virtual environment's site-packages
// holds files and the distributions dists (name@version), which
// importlib.metadata maps from import names as distributions, a JSON object.
// It returns the project and site-packages.
func pythonVenvFixture(t *testing.T, files map[string]string, dists []string, distributions string) (project, sitePackages string) {
	t.Helper()
	root := t.TempDir()
	project = filepath.Join(root, "app")
	venv := filepath.Join(root, "venv")
	sitePackages = filepath.Join(venv, "lib", "python3.12", "site-packages")
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
	list := make([]string, len(dists))
	show := ""
	for i, dist := range dists {
		name, version, _ := strings.Cut(dist, "@")
		list[i] = fmt.Sprintf(`{"name":%q,"version":%q}`, name, version)
		show += fmt.Sprintf("printf 'Name: %s\\nVersion: %s\\nLocation: %s\\nRequires:\\n---\\n'\n", name, version, sitePackages)
	}
	python := `#!/bin/sh
if [ "$1" = "-m" ] && [ "$3" = "list" ]; then
  echo '[` + strings.Join(list, ",") + `]'
  exit 0
fi
if [ "$1" = "-m" ] && [ "$3" = "show" ]; then
` + show + `  exit 0
fi
if [ "$1" = "-c" ]; then
  echo '` + distributions + `'
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

// pythonNamespaceFixture holds ns-a and ns-b, two distributions installing
// into the namespace directory google/, and solo, a distribution with a
// directory of its own. Each installed module uses MD5.
func pythonNamespaceFixture(t *testing.T) (project, sitePackages string) {
	t.Helper()
	return pythonVenvFixture(t, map[string]string{
		"google/a/__init__.py":      "",
		"google/a/hash.py":          pythonMD5Source,
		"google/b/__init__.py":      "",
		"google/b/hash.py":          pythonMD5Source,
		"solo/__init__.py":          "",
		"solo/x.py":                 pythonMD5Source,
		"ns_a-1.0.dist-info/RECORD": "google/a/__init__.py,,\ngoogle/a/hash.py,sha256=x,60\nns_a-1.0.dist-info/RECORD,,\n",
		"ns_b-2.0.dist-info/RECORD": "google/b/__init__.py,,\ngoogle/b/hash.py,sha256=x,60\nns_b-2.0.dist-info/RECORD,,\n",
		"solo-3.0.dist-info/RECORD": "solo/__init__.py,,\nsolo/x.py,sha256=x,60\nsolo-3.0.dist-info/RECORD,,\n",
	}, []string{"ns-a@1.0", "ns-b@2.0", "solo@3.0"}, `{"google":["ns-a","ns-b"],"solo":["solo"]}`)
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

// A distribution with several top-level packages and modules is rooted at
// site-packages and scans every one of them, with paths that name the
// package. Its scope names only its own files, so it shares one process with
// the roots below site-packages, and a scanner that cannot limit detection
// to files still reports only the distribution's own files.
func TestDependencyScanner_PythonDistributionScansEveryTopLevelRootIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires real OpenGrep subprocesses")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("OpenGrep not installed")
	}
	project, sitePackages := pythonVenvFixture(t, map[string]string{
		"configobj/__init__.py":     "",
		"configobj/hash.py":         pythonMD5Source,
		"validate/__init__.py":      "",
		"validate/hash.py":          pythonMD5Source,
		"six.py":                    pythonMD5Source,
		"solo/__init__.py":          "",
		"solo/x.py":                 pythonMD5Source,
		"google/a/hash.py":          pythonMD5Source,
		"google/b/hash.py":          pythonMD5Source,
		"nsb_util.py":               pythonMD5Source,
		"ns_a-1.0.dist-info/RECORD": "google/a/hash.py,,\n",
		"ns_b-2.0.dist-info/RECORD": "google/b/hash.py,,\nnsb_util.py,,\n",
	}, []string{"configobj@5.0", "six@1.16", "solo@3.0", "ns-a@1.0", "ns-b@2.0"},
		`{"validate":["configobj"],"configobj":["configobj"],"six":["six"],"solo":["solo"],"google":["ns-a","ns-b"],"nsb_util":["ns-b"]}`)
	want := map[string][]string{
		"configobj": {"configobj/hash.py", "validate/hash.py"},
		"six":       {"six.py"},
		"solo":      {"x.py"},
		"ns-a":      {"a/hash.py"},
		"ns-b":      {"google/b/hash.py", "nsb_util.py"},
	}

	invocations := &invocationLog{}
	batched := scanPythonFixture(t, project, func() scanner.Scanner {
		return &batchingOpengrep{Scanner: opengrep.NewScanner(), log: invocations}
	})
	if got := findingsByModule(batched.Report); !reflect.DeepEqual(got, want) {
		t.Errorf("batched findings by distribution = %v, want %v", got, want)
	}
	namespace, solo := filepath.Join(sitePackages, "google"), filepath.Join(sitePackages, "solo")
	if want := [][]string{{sitePackages, sitePackages, sitePackages, namespace, solo}}; !reflect.DeepEqual(sortedRoots(invocations.batches), want) {
		t.Errorf("batches = %v, want %v: roots at site-packages name only their files, so they hide no other root", invocations.batches, want)
	}

	whole := scanPythonFixture(t, project, func() scanner.Scanner { return singleOpengrep{opengrep.NewScanner()} })
	if got := findingsByModule(whole.Report); !reflect.DeepEqual(got, want) {
		t.Errorf("whole-directory findings by distribution = %v, want %v", got, want)
	}
}
