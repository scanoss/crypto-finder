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

// IncludeDirs parses only the listed directories, each without its
// subdirectories, under the import path a whole walk gives it. Go packages
// nothing imports are never linked, so the dependency call graph leaves them
// out.
func TestBuilder_PackageIncludeDirsParsesOnlyThoseDirectories(t *testing.T) {
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
				Dir:         module,
				ImportPath:  "example.com/mod",
				Version:     "v1.0.0",
				IncludeDirs: []string{filepath.Join(module, "used"), filepath.Join(module, "deep", "er", "leaf")},
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
