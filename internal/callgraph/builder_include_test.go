package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// serialParser hides the Go parser's cloning, so the builder walks the
// package on its serial path.
type serialParser struct{ Parser }

// IncludeFiles parses only the listed files, under the import path a whole
// walk gives their directory. Go packages nothing imports are never linked,
// so the dependency call graph lists only the files of imported packages.
func TestBuilder_PackageIncludeFilesParsesOnlyImportedGoPackages(t *testing.T) {
	t.Parallel()

	module := t.TempDir()
	for rel, name := range map[string]string{
		"root.go":           "Root",
		"used/used.go":      "Used",
		"used/inner/in.go":  "Inner",
		"deep/er/leaf/l.go": "Leaf",
		"deep/er/e.go":      "Er",
		"unused/unused.go":  "Unused",
	} {
		path := filepath.Join(module, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		pkg := filepath.Base(filepath.Dir(path))
		if rel == "root.go" {
			pkg = "mod"
		}
		if err := os.WriteFile(path, []byte("package "+pkg+"\n\nfunc "+name+"() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	parsers := map[string]Parser{"parallel": NewGoParser(), "serial": serialParser{NewGoParser()}}
	for name, parser := range parsers {
		t.Run(name, func(t *testing.T) {
			graph, err := NewBuilderForEcosystem("go", parser).BuildFromDirectories([]PackageDir{{
				Dir:          module,
				ImportPath:   "example.com/mod",
				Version:      "v1.0.0",
				IncludeFiles: []string{filepath.Join(module, "used", "used.go"), filepath.Join(module, "deep", "er", "leaf", "l.go")},
			}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			var got []string
			for _, fn := range graph.Functions {
				got = append(got, fn.ID.Package+"."+fn.ID.Name)
			}
			sort.Strings(got)
			want := []string{"example.com/mod/deep/er/leaf.Leaf", "example.com/mod/used.Used"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("functions = %v, want %v", got, want)
			}
		})
	}
}

// IncludeFiles keeps only the listed files of a directory that also holds
// files of another distribution. Python distributions sharing the namespace
// directory google/ each parse their own files, so every function is parsed
// once, for its owner.
func TestBuilder_PackageIncludeFilesKeepsOnlyTheOwnersFiles(t *testing.T) {
	t.Parallel()

	namespace := filepath.Join(t.TempDir(), "google")
	for rel, name := range map[string]string{
		"auth/creds.py":  "creds",
		"auth/shared.py": "shared",
		"proto/msg.py":   "msg",
		"api/core.py":    "core",
	} {
		path := filepath.Join(namespace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("def "+name+"():\n    pass\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	parsers := map[string]Parser{"parallel": NewPythonParser(), "serial": serialParser{NewPythonParser()}}
	for name, parser := range parsers {
		t.Run(name, func(t *testing.T) {
			graph, err := NewBuilderForEcosystem("python", parser).BuildFromDirectories([]PackageDir{{
				Dir:              namespace,
				ImportPath:       "google",
				DistributionName: "google-auth",
				Version:          "2.0",
				IncludeFiles:     []string{filepath.Join(namespace, "auth", "creds.py"), filepath.Join(namespace, "api", "core.py")},
			}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			var got []string
			for _, fn := range graph.Functions {
				got = append(got, fn.ID.Package+"."+fn.ID.Name)
			}
			sort.Strings(got)
			want := []string{"google.api.core.core", "google.auth.creds.creds"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("functions = %v, want %v", got, want)
			}
		})
	}
}
