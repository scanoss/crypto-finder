// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"slices"
	"testing"
)

const pythonScannerClassSrc = "import hashlib\n\n\nclass Scanner:\n    def __init__(self, cfg):\n        self.cfg = cfg\n\n    def scan(self, path):\n        return hashlib.md5(path)\n\n\nclass Other:\n    def scan(self, path):\n        return hashlib.sha1(path)\n"

func buildPythonProject(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	root := writePythonTree(t, files)
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "probe"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// A method called on a receiver built by a constructor call is the method of
// that class: the receiver is typed from the class it was built from, whether
// the class is imported or defined in the same file, and whether the receiver
// is a local or the constructor call itself. Only the constructed class's
// method gains the caller; a same-named method of another class does not.
func TestBuilder_PythonConstructedReceiverLinksTheClassMethod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		files      map[string]string
		wantDecl   string
		wantCaller string
		notDecl    string
	}{
		{
			name: "imported class bound to a local",
			files: map[string]string{
				"app/__init__.py": "",
				"app/scanner.py":  pythonScannerClassSrc,
				"app/main.py":     "from app.scanner import Scanner\n\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    return s.scan(p)\n",
			},
			wantDecl:   "probe.app.scanner.(Scanner).scan",
			wantCaller: "probe.app.main.run",
			notDecl:    "probe.app.scanner.(Other).scan",
		},
		{
			name: "imported class called inline",
			files: map[string]string{
				"app/__init__.py": "",
				"app/scanner.py":  pythonScannerClassSrc,
				"app/main.py":     "from app.scanner import Scanner\n\n\ndef run(cfg, p):\n    return Scanner(cfg).scan(p)\n",
			},
			wantDecl:   "probe.app.scanner.(Scanner).scan",
			wantCaller: "probe.app.main.run",
			notDecl:    "probe.app.scanner.(Other).scan",
		},
		{
			name: "class defined in the same file bound to a local",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    return s.scan(p)\n",
			},
			wantDecl:   "probe.m.(Scanner).scan",
			wantCaller: "probe.m.run",
			notDecl:    "probe.m.(Other).scan",
		},
		{
			name: "class defined in the same file called inline",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef run(cfg, p):\n    return Scanner(cfg).scan(p)\n",
			},
			wantDecl:   "probe.m.(Scanner).scan",
			wantCaller: "probe.m.run",
			notDecl:    "probe.m.(Other).scan",
		},
		{
			name: "class without an explicit constructor",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef run(p):\n    o = Other()\n    return o.scan(p)\n",
			},
			wantDecl:   "probe.m.(Other).scan",
			wantCaller: "probe.m.run",
			notDecl:    "probe.m.(Scanner).scan",
		},
		{
			name: "constructor annotated to return None",
			files: map[string]string{
				"app/__init__.py": "",
				"app/scanner.py":  "import hashlib\n\n\nclass Scanner:\n    def __init__(self, cfg) -> None:\n        self.cfg = cfg\n\n    def scan(self, path):\n        return hashlib.md5(path)\n",
				"app/main.py":     "from app.scanner import Scanner\n\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    return s.scan(p)\n",
			},
			wantDecl:   "probe.app.scanner.(Scanner).scan",
			wantCaller: "probe.app.main.run",
		},
		{
			name: "class re-exported by its package",
			files: map[string]string{
				"app/__init__.py": "from .scanner import Scanner\n",
				"app/scanner.py":  pythonScannerClassSrc,
				"app/main.py":     "from app import Scanner\n\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    return s.scan(p)\n",
			},
			wantDecl:   "probe.app.scanner.(Scanner).scan",
			wantCaller: "probe.app.main.run",
			notDecl:    "probe.app.scanner.(Other).scan",
		},
		{
			name: "chain of methods on a constructed receiver",
			files: map[string]string{
				"m.py": "class Builder:\n    def step(self) -> Builder:\n        return self\n\n    def build(self):\n        return 1\n\n\ndef run():\n    return Builder().step().build()\n",
			},
			wantDecl:   "probe.m.(Builder).build",
			wantCaller: "probe.m.run",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph := buildPythonProject(t, tc.files)
			if graph.Functions[tc.wantDecl] == nil {
				t.Fatalf("missing declaration %s in %v", tc.wantDecl, sortedFunctionKeys(graph.Functions))
			}
			if callers := graph.Callers[tc.wantDecl]; !slices.Contains(callers, tc.wantCaller) {
				t.Errorf("Callers[%s] = %v, want %s", tc.wantDecl, callers, tc.wantCaller)
			}
			if tc.notDecl != "" {
				if graph.Functions[tc.notDecl] == nil {
					t.Fatalf("missing declaration %s in %v", tc.notDecl, sortedFunctionKeys(graph.Functions))
				}
				if callers := graph.Callers[tc.notDecl]; slices.Contains(callers, tc.wantCaller) {
					t.Errorf("Callers[%s] = %v, must not include %s", tc.notDecl, callers, tc.wantCaller)
				}
			}
		})
	}
}

// A method never called on any receiver keeps no caller, however many classes
// are constructed around it.
func TestBuilder_PythonConstructedReceiverLeavesUncalledMethodsUncalled(t *testing.T) {
	t.Parallel()

	graph := buildPythonProject(t, map[string]string{
		"m.py": pythonScannerClassSrc + "\n\ndef run(cfg):\n    s = Scanner(cfg)\n    return s\n",
	})
	for _, decl := range []string{"probe.m.(Scanner).scan", "probe.m.(Other).scan"} {
		if callers := graph.Callers[decl]; len(callers) != 0 {
			t.Errorf("Callers[%s] = %v, want none", decl, callers)
		}
	}
}

// The receiver's type is the constructed class, so a subclass override is
// reached by the dispatch tier that already covers a typed receiver, beside
// the exact edge to the declared class.
func TestBuilder_PythonConstructedReceiverExpandsToSubclassOverrides(t *testing.T) {
	t.Parallel()

	graph := buildPythonProject(t, map[string]string{
		"m.py": "class Base:\n    def scan(self):\n        return 0\n\n\nclass Child(Base):\n    def scan(self):\n        return 1\n\n\ndef run():\n    b = Base()\n    return b.scan()\n",
	})
	for _, decl := range []string{"probe.m.(Base).scan", "probe.m.(Child).scan"} {
		if callers := graph.Callers[decl]; !slices.Contains(callers, "probe.m.run") {
			t.Errorf("Callers[%s] = %v, want probe.m.run", decl, callers)
		}
	}
}

// What the receiver was built from is not always knowable, and a type learned
// from an earlier statement must not outlive a rebind. The negative cases pin
// that nothing is guessed from the method name.
func TestBuilder_PythonConstructedReceiverIsNotGuessed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "rebound to a call of unknown type",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef make(x):\n    return x\n\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    s = make(cfg)\n    return s.scan(p)\n",
			},
		},
		{
			name: "receiver of unknown type",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef run(s, p):\n    return s.scan(p)\n",
			},
		},
		{
			name: "a function shadows the class name",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef Scanner(cfg):\n    return cfg\n\n\ndef run(cfg, p):\n    s = Scanner(cfg)\n    return s.scan(p)\n",
			},
		},
		{
			name: "inline call of a function that shares a class name",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef Scanner(cfg):\n    return cfg\n\n\ndef run(cfg, p):\n    return Scanner(cfg).scan(p)\n",
			},
		},
		{
			name: "call of a name that is no class",
			files: map[string]string{
				"m.py": pythonScannerClassSrc + "\n\ndef run(cfg, p):\n    s = Missing(cfg)\n    return s.scan(p)\n",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph := buildPythonProject(t, tc.files)
			for _, decl := range []string{"probe.m.(Scanner).scan", "probe.m.(Other).scan"} {
				if graph.Functions[decl] == nil {
					t.Fatalf("missing declaration %s in %v", decl, sortedFunctionKeys(graph.Functions))
				}
				if callers := graph.Callers[decl]; slices.Contains(callers, "probe.m.run") {
					t.Errorf("Callers[%s] = %v, must not include probe.m.run", decl, callers)
				}
			}
		})
	}
}
