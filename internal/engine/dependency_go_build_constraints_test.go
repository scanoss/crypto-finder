package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
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

// A Go program contains only the files its build compiles, so a dependency
// scan reads only those: not a file for another GOOS, nor one whose build
// tag is unset, nor a //go:build ignore generator. Detection and the
// dependency call graph both follow.
func TestDependencyScanner_GoScansOnlyFilesTheHostBuildCompilesIntegration(t *testing.T) {
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
	t.Setenv("CGO_ENABLED", "0")

	other := "windows"
	if runtime.GOOS == other {
		other = "linux"
	}
	host := "plat/plat_" + runtime.GOOS + ".go"
	root := t.TempDir()
	files := map[string]string{
		"app/go.mod":                     "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ../dep\n",
		"app/main.go":                    "package main\n\nimport \"example.com/dep/plat\"\n\nfunc main() { plat.Host() }\n",
		"app/crypto.yaml":                goMD5Rule,
		"dep/go.mod":                     "module example.com/dep\n\ngo 1.22\n",
		"dep/" + host:                    "package plat\n\nimport \"crypto/md5\"\n\nfunc Host() { md5.New() }\n",
		"dep/plat/plat_" + other + ".go": "package plat\n\nimport \"crypto/md5\"\n\nfunc Other() { md5.New() }\n",
		"dep/plat/tagged.go":             "//go:build cfnotset\n\npackage plat\n\nimport \"crypto/md5\"\n\nfunc Tagged() { md5.New() }\n",
		"dep/plat/gen.go":                "//go:build ignore\n\npackage main\n\nimport \"crypto/md5\"\n\nfunc main() { md5.New() }\n",
		"dep/plat/cgo.go":                "package plat\n\n// int x;\nimport \"C\"\n\nimport \"crypto/md5\"\n\nfunc Cgo() { md5.New() }\n",
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
	app := filepath.Join(root, "app")
	dep := filepath.Join(root, "dep")

	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture-opengrep", func() scanner.Scanner { return opengrep.NewScanner() })
	rule := filepath.Join(app, "crypto.yaml")
	orch := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{rule}, nil }}), registry)
	ds := NewDependencyScanner(orch, dependency.NewGoResolver(), callgraph.NewBuilder(callgraph.NewGoParser()), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := ds.ScanWithDependencies(ctx, &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{
		Target: app, ScannerName: "fixture-opengrep",
		ScannerConfig: scanner.Config{SkipPatterns: skip.WithDefaultTestPatterns(nil), Timeout: time.Minute, ExtraArgs: []string{"--jobs", "1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := findingsByModule(result.Report), map[string][]string{"example.com/dep": {host}}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings by dependency = %v, want %v: the other GOOS, the unset tag, the ignore generator and the cgo file (CGO_ENABLED=0) are not compiled", got, want)
	}
	if result.CallGraph == nil {
		t.Fatal("no dependency call graph")
	}
	var parsed []string
	for _, fn := range result.CallGraph.Functions {
		if rel, err := filepath.Rel(dep, fn.FilePath); err == nil && !strings.HasPrefix(rel, "..") {
			parsed = append(parsed, filepath.ToSlash(rel)+":"+fn.ID.Name)
		}
	}
	sort.Strings(parsed)
	if want := []string{host + ":Host"}; !reflect.DeepEqual(parsed, want) {
		t.Errorf("dependency functions in the call graph = %v, want %v", parsed, want)
	}
}
