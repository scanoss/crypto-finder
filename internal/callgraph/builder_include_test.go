package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
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

// recordingParser parses nothing and records every file it is asked to read.
type recordingParser struct {
	mu   *sync.Mutex
	read *[]string
}

func (p recordingParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	return p.ParseDirectorySelected(dir, packagePath, nil)
}

func (p recordingParser) ParseDirectorySelected(dir, _ string, keep func(string) bool) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if !entry.IsDir() && (keep == nil || keep(path)) {
			*p.read = append(*p.read, path)
		}
	}
	return nil, nil
}

func (p recordingParser) SubPackagePath(parent, dir string) string { return parent + "/" + dir }
func (p recordingParser) PackageSeparator() string                 { return "/" }

type cloningRecordingParser struct{ recordingParser }

func (p cloningRecordingParser) CloneParser() Parser { return p }

// A file that IncludeFiles leaves out is never read, not merely dropped
// after parsing: modernc.org/libc holds eight 4 MB generated files, one per
// platform, in the directory of a package the host build compiles one of.
func TestBuilder_PackageIncludeFilesNeverParsesUnlistedFiles(t *testing.T) {
	t.Parallel()

	module := t.TempDir()
	for _, rel := range []string{"plat/plat_linux.go", "plat/plat_windows.go", "plat/gen.go", "other/o.go"} {
		path := filepath.Join(module, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	listed := filepath.Join(module, "plat", "plat_linux.go")

	for name, wrap := range map[string]func(recordingParser) Parser{
		"parallel": func(p recordingParser) Parser { return cloningRecordingParser{p} },
		"serial":   func(p recordingParser) Parser { return p },
	} {
		t.Run(name, func(t *testing.T) {
			var read []string
			parser := wrap(recordingParser{mu: &sync.Mutex{}, read: &read})
			if _, err := NewBuilderForEcosystem("go", parser).BuildFromDirectories([]PackageDir{{
				Dir: module, ImportPath: "example.com/mod", Version: "v1.0.0", IncludeFiles: []string{listed},
			}}, nil); err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			if want := []string{listed}; !reflect.DeepEqual(read, want) {
				t.Errorf("files read = %v, want %v", read, want)
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

// A distribution rooted at site-packages with no import path parses each of
// its packages and modules under its own name (configobj, validate, six),
// as a distribution rooted at one package directory parses that package,
// and nothing of the distributions beside it.
func TestBuilder_PackageIncludeFilesAtSitePackagesKeepsModuleNames(t *testing.T) {
	t.Parallel()

	site := t.TempDir()
	for rel, name := range map[string]string{
		"configobj/__init__.py": "load",
		"validate/check.py":     "check",
		"six.py":                "wrap",
		"requests/api.py":       "get",
		"other.py":              "other",
	} {
		path := filepath.Join(site, filepath.FromSlash(rel))
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
				Dir:              site,
				DistributionName: "configobj",
				Version:          "5.0",
				IncludeFiles: []string{
					filepath.Join(site, "configobj", "__init__.py"),
					filepath.Join(site, "six.py"),
					filepath.Join(site, "validate", "check.py"),
				},
			}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			var got []string
			for _, fn := range graph.Functions {
				got = append(got, fn.ID.Package+"."+fn.ID.Name)
			}
			sort.Strings(got)
			want := []string{"configobj.load", "six.wrap", "validate.check.check"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("functions = %v, want %v", got, want)
			}
		})
	}
}
