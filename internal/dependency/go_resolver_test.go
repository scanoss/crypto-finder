package dependency

import (
	"context"
	"os"
	"path/filepath"
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
if [ "$1" = "list" ]; then
  cat <<'JSON'
{"Path":"example.com/app","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/deps/dep"}
{"Path":"example.com/no-dir","Version":"v1.2.0"}
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
if [ "$1" = "list" ]; then
  cat <<'JSON'
{"Path":"example.com/app","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/deps/dep"}
JSON
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
