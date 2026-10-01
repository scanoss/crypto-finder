package dependency

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeExecutable(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", name, err)
	}
}

func prependPath(t *testing.T, dir string) {
	t.Helper()
	old := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+old)
}

func TestGoResolver_Resolve(t *testing.T) {
	tmpBin := t.TempDir()
	writeExecutable(t, tmpBin, "go", `#!/bin/sh
if [ "$1" = "list" ] && [ "$2" = "-m" ]; then
  echo '{"Path":"example.com/app","Main":true,"Dir":"/src/app"}'
  exit 0
fi
if [ "$1" = "list" ]; then
  cat <<'JSON'
{"Module":{"Path":"example.com/app","Main":true,"Dir":"/src/app"}}
{"Module":{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/deps/dep"}}
{"Module":{"Path":"example.com/no-dir","Version":"v1.2.0"}}
{}
JSON
  exit 0
fi
if [ "$1" = "mod" ] && [ "$2" = "graph" ]; then
  echo "example.com/app@v0.0.0 example.com/dep@v1.0.0"
  echo "example.com/app@v0.0.0 example.com/no-dir@v1.2.0"
  echo "malformed line"
  exit 0
fi
echo "unexpected args: $*" >&2
exit 1
`)
	prependPath(t, tmpBin)

	r := NewGoResolver()
	result, err := r.Resolve(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if result.RootModule != "example.com/app" {
		t.Fatalf("RootModule = %q, want example.com/app", result.RootModule)
	}
	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	if result.Dependencies[0].Module != "example.com/dep" {
		t.Fatalf("unexpected dependency module: %s", result.Dependencies[0].Module)
	}
	children := result.Graph["example.com/app"]
	if len(children) != 2 {
		t.Fatalf("graph children len = %d, want 2", len(children))
	}
}

func TestGoResolver_Resolve_GraphFailureIsNonFatal(t *testing.T) {
	tmpBin := t.TempDir()
	writeExecutable(t, tmpBin, "go", `#!/bin/sh
if [ "$1" = "list" ] && [ "$2" = "-m" ]; then
  echo '{"Path":"example.com/app","Main":true,"Dir":"/src/app"}'
  exit 0
fi
if [ "$1" = "list" ]; then
  echo '{"Module":{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/deps/dep"}}'
  exit 0
fi
if [ "$1" = "mod" ] && [ "$2" = "graph" ]; then
  echo "mod graph failed" >&2
  exit 2
fi
exit 1
`)
	prependPath(t, tmpBin)

	r := NewGoResolver()
	result, err := r.Resolve(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve should not fail when graph fails: %v", err)
	}

	if len(result.Dependencies) != 1 {
		t.Fatalf("Dependencies len = %d, want 1", len(result.Dependencies))
	}
	if len(result.Graph) != 0 {
		t.Fatalf("expected empty graph on graph command failure, got %#v", result.Graph)
	}
}

func TestGoResolver_GoListModules_InvalidJSON(t *testing.T) {
	tmpBin := t.TempDir()
	writeExecutable(t, tmpBin, "go", `#!/bin/sh
if [ "$1" = "list" ]; then
  echo "{invalid-json"
  exit 0
fi
exit 1
`)
	prependPath(t, tmpBin)

	r := NewGoResolver()
	_, err := r.goListModules(context.Background(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "failed to decode go list output") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestGoResolver_EcosystemAndStripVersion(t *testing.T) {
	if NewGoResolver().Ecosystem() != "go" {
		t.Fatal("Ecosystem() should return go")
	}

	tests := map[string]string{
		"golang.org/x/crypto@v0.17.0": "golang.org/x/crypto",
		"example.com/no-version":      "example.com/no-version",
	}

	for in, want := range tests {
		if got := stripVersion(in); got != want {
			t.Fatalf("stripVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoResolver_CanResolve(t *testing.T) {
	t.Parallel()

	resolver := NewGoResolver()

	t.Run("go-mod-at-root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/use\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = false, want true with go.mod at the root")
		}
	})

	t.Run("go-work-without-root-go-mod", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte("go 1.23.0\n\nuse ./svc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = false, want true: a workspace root lists its modules without a go.mod of its own")
		}
	})

	t.Run("package-directory-below-module-root", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/use\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pkg := filepath.Join(root, "internal", "cli")
		if err := os.MkdirAll(pkg, 0o750); err != nil {
			t.Fatal(err)
		}
		if !resolver.CanResolve(pkg) {
			t.Fatal("CanResolve() = false, want true: go list finds the go.mod above a package directory")
		}
	})

	t.Run("bare-go-source-without-go-mod", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "use.go"), []byte("package main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = true, want false for a Go source tree with no go.mod")
		}
	})

	t.Run("no-module-anywhere-above", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "a", "b", "c")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if resolver.CanResolve(dir) {
			t.Fatal("CanResolve() = true, want false when no go.mod or go.work exists at or above the target")
		}
	})

	t.Run("file-target-inside-module", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/use\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, "use.go")
		if err := os.WriteFile(file, []byte("package main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if resolver.CanResolve(file) {
			t.Fatal("CanResolve() = true, want false: go list cannot run with a file as its working directory")
		}
	})
}

// requireGoToolchain makes the real go tool resolve fixture modules offline and
// independently of the developer's GOFLAGS, GOWORK and toolchain settings.
func requireGoToolchain(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain required")
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "")
}

// localGoMod declares module path and requires each named sibling module
// through a replace that points at the sibling directory of that name.
func localGoMod(path string, requires ...string) string {
	var b strings.Builder
	b.WriteString("module " + path + "\n\ngo 1.22\n")
	for _, name := range requires {
		b.WriteString("\nrequire example.com/" + name + " v1.0.0\nreplace example.com/" + name + " => ../" + name + "\n")
	}
	return b.String()
}

func TestGoResolver_InventoriesOnlyTheProductionImportClosure(t *testing.T) {
	requireGoToolchain(t)
	root := writeTree(t, map[string]string{
		"used/go.mod":       localGoMod("example.com/used"),
		"used/used.go":      "package used\n",
		"testonly/go.mod":   localGoMod("example.com/testonly"),
		"testonly/t.go":     "package testonly\n",
		"tool/go.mod":       localGoMod("example.com/tool"),
		"tool/tool.go":      "package tool\n",
		"unused/go.mod":     localGoMod("example.com/unused"),
		"unused/unused.go":  "package unused\n",
		"nestedonly/go.mod": localGoMod("example.com/nestedonly"),
		"nestedonly/n.go":   "package nestedonly\n",
		"app/go.mod":        localGoMod("example.com/app", "used", "testonly", "tool", "unused"),
		"app/main.go":       "package app\n\nimport _ \"example.com/used\"\n",
		"app/app_test.go":   "package app\n\nimport _ \"example.com/testonly\"\n",
		"app/tools.go":      "//go:build tools\n\npackage app\n\nimport _ \"example.com/tool\"\n",
		"app/gen/go.mod":    "module example.com/app/gen\n\ngo 1.22\n\nrequire example.com/nestedonly v1.0.0\n\nreplace example.com/nestedonly => ../../nestedonly\n",
		"app/gen/gen.go":    "package gen\n\nimport _ \"example.com/nestedonly\"\n",
	})

	result, err := NewGoResolver().Resolve(context.Background(), filepath.Join(root, "app"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if result.RootModule != "example.com/app" {
		t.Errorf("RootModule = %q, want example.com/app", result.RootModule)
	}
	want := []Dependency{{Module: "example.com/used", Version: "v1.0.0", Dir: filepath.Join(root, "used")}}
	if !reflect.DeepEqual(result.Dependencies, want) {
		t.Fatalf("Dependencies = %+v, want %+v: no production package imports the test-only, build-tagged tool, unused or nested-module requirement", result.Dependencies, want)
	}
}

func TestGoResolver_PackageDirectoryResolvesItsWholeModule(t *testing.T) {
	requireGoToolchain(t)
	root := writeTree(t, map[string]string{
		"cli/go.mod":            localGoMod("example.com/cli"),
		"cli/cli.go":            "package cli\n",
		"store/go.mod":          localGoMod("example.com/store"),
		"store/store.go":        "package store\n",
		"app/go.mod":            localGoMod("example.com/app", "cli", "store"),
		"app/cmd/tool/main.go":  "package main\n\nimport _ \"example.com/cli\"\n\nfunc main() {}\n",
		"app/internal/db/db.go": "package db\n\nimport _ \"example.com/store\"\n",
	})

	result, err := NewGoResolver().Resolve(context.Background(), filepath.Join(root, "app", "cmd"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	deps := depsByModule(result)
	if len(deps) != 2 || deps["example.com/cli"].Dir == "" || deps["example.com/store"].Dir == "" {
		t.Fatalf("Dependencies = %+v, want cli and store: a package directory resolves the whole module above it, not only its own subtree", result.Dependencies)
	}
}

func TestGoResolver_CollectsProductionModulesAcrossWorkspace(t *testing.T) {
	requireGoToolchain(t)
	root := writeTree(t, map[string]string{
		"go.work":          "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n",
		"shared/go.mod":    localGoMod("example.com/shared"),
		"shared/shared.go": "package shared\n",
		"shared/sub/s.go":  "package sub\n",
		"a/go.mod":         localGoMod("example.com/a", "shared"),
		"a/a.go":           "package a\n\nimport _ \"example.com/shared\"\n",
		"b/go.mod":         localGoMod("example.com/b", "shared"),
		"b/b.go":           "package b\n\nimport _ \"example.com/shared/sub\"\n",
	})

	result, err := NewGoResolver().Resolve(context.Background(), root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	want := []Dependency{{Module: "example.com/shared", Version: "v1.0.0", Dir: filepath.Join(root, "shared")}}
	if !reflect.DeepEqual(result.Dependencies, want) {
		t.Fatalf("Dependencies = %+v, want %+v: both workspace modules import a package of shared, which is listed once", result.Dependencies, want)
	}
}

// Real trees carry packages the go tool cannot load, such as a directory that
// mixes two package names. One of them must not discard the closure of every
// package that does load.
func TestGoResolver_PackageThatFailsToLoadKeepsTheRestOfTheClosure(t *testing.T) {
	requireGoToolchain(t)
	root := writeTree(t, map[string]string{
		"used/go.mod":      localGoMod("example.com/used"),
		"used/used.go":     "package used\n",
		"app/go.mod":       localGoMod("example.com/app", "used"),
		"app/ok/ok.go":     "package ok\n\nimport _ \"example.com/used\"\n",
		"app/mixed/a.go":   "package a\n",
		"app/mixed/b.go":   "package b\n",
		"app/missing/m.go": "package missing\n\nimport _ \"example.com/notrequired\"\n",
	})

	result, err := NewGoResolver().Resolve(context.Background(), filepath.Join(root, "app"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	want := []Dependency{{Module: "example.com/used", Version: "v1.0.0", Dir: filepath.Join(root, "used")}}
	if !reflect.DeepEqual(result.Dependencies, want) {
		t.Fatalf("Dependencies = %+v, want %+v", result.Dependencies, want)
	}
}
