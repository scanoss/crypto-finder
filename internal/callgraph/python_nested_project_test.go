// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import (
	"slices"
	"testing"
)

const (
	nestedScannerSrc = "import hashlib\n\n\nclass Scanner:\n    def scan(self, p):\n        return hashlib.sha256(p)\n"
	nestedCLISrc     = "from app_scanner.scanner import Scanner\n\n\ndef go(p):\n    return Scanner().scan(p)\n"
)

func buildPythonTree(t *testing.T, files map[string]string, importPath string) *CallGraph {
	t.Helper()
	root := writePythonTree(t, files)
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// A project nested below the scan root (a monorepo's packages/<name>) is what
// its imports are relative to: modules are keyed from the project directory
// down, with a src or lib layout directory transparent, so an import links to
// the declaration.
func TestBuilder_PythonNestedProjectModulesKeyedByImportName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		importPath string
		files      map[string]string
		wantDecl   string
		wantCaller string
	}{
		{
			name: "pyproject with src layout two levels deep",
			files: map[string]string{
				"packages/app/pyproject.toml":              "[project]\nname = \"app\"\n",
				"packages/app/src/app_scanner/__init__.py": "",
				"packages/app/src/app_scanner/scanner.py":  nestedScannerSrc,
				"packages/app/src/app_cli/__init__.py":     "",
				"packages/app/src/app_cli/main.py":         nestedCLISrc,
			},
			wantDecl:   "app_scanner.scanner.(Scanner).scan",
			wantCaller: "app_cli.main.go",
		},
		{
			name: "project directly below the root with a lib layout and setup.py",
			files: map[string]string{
				"app/setup.py":                    "from setuptools import setup\n",
				"app/lib/app_scanner/__init__.py": "",
				"app/lib/app_scanner/scanner.py":  nestedScannerSrc,
				"app/lib/app_cli/main.py":         nestedCLISrc,
			},
			wantDecl:   "app_scanner.scanner.(Scanner).scan",
			wantCaller: "app_cli.main.go",
		},
		{
			name: "flat layout project with setup.cfg",
			files: map[string]string{
				"packages/app/setup.cfg":               "[options]\npackages = find:\n",
				"packages/app/app_scanner/__init__.py": "",
				"packages/app/app_scanner/scanner.py":  nestedScannerSrc,
				"packages/app/app_cli/main.py":         nestedCLISrc,
			},
			wantDecl:   "app_scanner.scanner.(Scanner).scan",
			wantCaller: "app_cli.main.go",
		},
		{
			name:       "manifest-named root module is still prefixed",
			importPath: "probe",
			files: map[string]string{
				"packages/app/pyproject.toml":             "",
				"packages/app/src/app_scanner/scanner.py": nestedScannerSrc,
				"packages/app/src/app_cli/main.py":        nestedCLISrc,
			},
			wantDecl:   "probe.app_scanner.scanner.(Scanner).scan",
			wantCaller: "probe.app_cli.main.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildPythonTree(t, tc.files, tc.importPath)
			if graph.Functions[tc.wantDecl] == nil {
				t.Fatalf("missing declaration %s in %v", tc.wantDecl, sortedFunctionKeys(graph.Functions))
			}
			if callers := graph.Callers[tc.wantDecl]; !slices.Contains(callers, tc.wantCaller) {
				t.Errorf("Callers[%s] = %v, want %s", tc.wantDecl, callers, tc.wantCaller)
			}
		})
	}
}

// Without a project marker the directories keep naming modules, and a project
// directory that is itself a package is spelled relative to its parent, so
// neither is re-rooted and no import is matched by guesswork.
func TestBuilder_PythonNestedLayoutWithoutProjectKeepsPrefix(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]string{
		"no marker": {
			"packages/app/src/app_scanner/scanner.py": nestedScannerSrc,
			"packages/app/src/app_cli/main.py":        nestedCLISrc,
		},
		"project directory is a package": {
			"packages/app/pyproject.toml":             "",
			"packages/app/__init__.py":                "",
			"packages/app/src/app_scanner/scanner.py": nestedScannerSrc,
			"packages/app/src/app_cli/main.py":        nestedCLISrc,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			graph := buildPythonTree(t, files, "")
			if graph.Functions["app_scanner.scanner.(Scanner).scan"] != nil {
				t.Fatalf("re-rooted without a project root: %v", sortedFunctionKeys(graph.Functions))
			}
			for decl, callers := range graph.Callers {
				if len(callers) > 0 && decl != "" && graph.Functions[decl] != nil && graph.Functions[decl].ID.Name == "scan" {
					t.Errorf("Callers[%s] = %v, want none", decl, callers)
				}
			}
		})
	}
}

// Two projects that define the same top-level module are never merged: the
// first (in path order) is re-rooted, the later one keeps its directory
// prefix, so each declaration keeps its own key. Names every project has its
// own copy of (tests) do not count as a collision.
func TestBuilder_PythonNestedProjectsDoNotShareModuleKeys(t *testing.T) {
	t.Parallel()

	graph := buildPythonTree(t, map[string]string{
		"packages/a/pyproject.toml":         "",
		"packages/a/src/shared/__init__.py": "",
		"packages/a/src/shared/util.py":     "def work():\n    return 1\n",
		"packages/a/tests/test_a.py":        "def test_a():\n    return 1\n",
		"packages/b/pyproject.toml":         "",
		"packages/b/src/shared/__init__.py": "",
		"packages/b/src/shared/util.py":     "def work():\n    return 2\n",
		"packages/b/tests/test_b.py":        "def test_b():\n    return 1\n",
		"packages/c/pyproject.toml":         "",
		"packages/c/src/other/__init__.py":  "",
		"packages/c/src/other/mod.py":       "from shared.util import work\n\n\ndef call():\n    return work()\n",
	}, "")

	if graph.Functions["shared.util.work"] == nil {
		t.Fatalf("first project not re-rooted: %v", sortedFunctionKeys(graph.Functions))
	}
	if graph.Functions["packages.b.src.shared.util.work"] == nil {
		t.Fatalf("colliding project lost its own key: %v", sortedFunctionKeys(graph.Functions))
	}
	if graph.Functions["other.mod.call"] == nil {
		t.Fatalf("independent project not re-rooted: %v", sortedFunctionKeys(graph.Functions))
	}
}

func graphHasKey(g *CallGraph, key string) bool { return g.Functions[key] != nil }

// A marker directory that does not say where its packages are, or whose own
// directory path is spelled in an import, keeps the keys it always had, so an
// import that resolves today still does.
func TestBuilder_PythonMarkerDirectoryKeepsPrefixUnlessItIsAProjectRoot(t *testing.T) {
	t.Parallel()

	t.Run("setup.py tools directory imported from the root", func(t *testing.T) {
		t.Parallel()
		g := buildPythonTree(t, map[string]string{
			"tools/x/setup.py": "",
			"tools/x/mod.py":   "def f():\n    return 1\n",
			"main.py":          "from tools.x import mod\n\n\ndef run():\n    return mod.f()\n",
		}, "")
		if !graphHasKey(g, "tools.x.mod.f") || graphHasKey(g, "mod.f") {
			t.Fatalf("re-keyed: %v", sortedFunctionKeys(g.Functions))
		}
		if !slices.Contains(g.Callers["tools.x.mod.f"], "main.run") {
			t.Errorf("edge lost: %v", g.Callers["tools.x.mod.f"])
		}
	})
	t.Run("docs build with a pyproject", func(t *testing.T) {
		t.Parallel()
		g := buildPythonTree(t, map[string]string{
			"website/pyproject.toml": "[project]\nname = \"docs\"\n",
			"website/conf.py":        "def setup(app):\n    return app\n",
		}, "")
		if !graphHasKey(g, "website.conf.setup") || graphHasKey(g, "conf.setup") {
			t.Fatalf("re-keyed: %v", sortedFunctionKeys(g.Functions))
		}
	})
	t.Run("flat project whose manifest declares no packages", func(t *testing.T) {
		t.Parallel()
		g := buildPythonTree(t, map[string]string{
			"packages/app/pyproject.toml":         "[project]\nname = \"app\"\n",
			"packages/app/app_scanner/scanner.py": nestedScannerSrc,
		}, "")
		if graphHasKey(g, "app_scanner.scanner.(Scanner).scan") {
			t.Fatalf("re-keyed: %v", sortedFunctionKeys(g.Functions))
		}
	})
	t.Run("a file spells the directory prefix", func(t *testing.T) {
		t.Parallel()
		g := buildPythonTree(t, map[string]string{
			"packages/app/pyproject.toml":             "",
			"packages/app/src/app_scanner/scanner.py": nestedScannerSrc,
			"main.py": "from packages.app.src.app_scanner.scanner import Scanner\n\n\ndef run():\n    return Scanner().scan(1)\n",
		}, "")
		key := "packages.app.src.app_scanner.scanner.(Scanner).scan"
		if !graphHasKey(g, key) || !slices.Contains(g.Callers[key], "main.run") {
			t.Fatalf("kept prefix broke: %v callers=%v", sortedFunctionKeys(g.Functions), g.Callers[key])
		}
	})
	t.Run("manifest packages declaration is enough", func(t *testing.T) {
		t.Parallel()
		g := buildPythonTree(t, map[string]string{
			"packages/app/pyproject.toml":         "[tool.poetry]\npackages = [{include = \"app_scanner\"}]\n",
			"packages/app/app_scanner/scanner.py": nestedScannerSrc,
		}, "")
		if !graphHasKey(g, "app_scanner.scanner.(Scanner).scan") {
			t.Fatalf("not re-rooted: %v", sortedFunctionKeys(g.Functions))
		}
	})
}

// A vendored copy of a scanned dependency's top-level name is not re-keyed
// onto it.
func TestBuilder_PythonVendoredProjectCannotClaimADependencyName(t *testing.T) {
	t.Parallel()

	project := writePythonTree(t, map[string]string{
		"third_party/requests/pyproject.toml":      "",
		"third_party/requests/src/requests/api.py": "def get():\n    return 1\n",
	})
	dep := writePythonTree(t, map[string]string{
		"requests/__init__.py": "",
		"requests/api.py":      "def get():\n    return 2\n",
	})
	g, err := NewBuilderForEcosystem("python", NewPythonParser()).BuildFromDirectories([]PackageDir{
		{Dir: project},
		{Dir: dep, ImportPath: "requests", Version: "2.0"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !graphHasKey(g, "third_party.requests.src.requests.api.get") || !graphHasKey(g, "requests.requests.api.get") {
		t.Fatalf("vendored copy collided: %v", sortedFunctionKeys(g.Functions))
	}
}

// A root that is a project itself, with nested projects below it: the root's
// own modules are claimed first, nested hidden directories are skipped, and a
// nested manifest's scripts resolve against the new keys.
func TestBuilder_PythonRootProjectWithNestedProjects(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"pyproject.toml":                          "",
		"rootmod.py":                              "def r():\n    return 1\n",
		"packages/app/pyproject.toml":             "[project.scripts]\napp = \"app_cli.main:go\"\n",
		"packages/app/src/app_scanner/scanner.py": nestedScannerSrc,
		"packages/app/src/app_cli/main.py":        nestedCLISrc,
		"packages/dup/pyproject.toml":             "",
		"packages/dup/src/rootmod/x.py":           "def d():\n    return 1\n",
		".venv/lib/pkg/pyproject.toml":            "",
		".venv/lib/pkg/src/hidden/h.py":           "def h():\n    return 1\n",
	}
	g := buildPythonTree(t, files, "")
	if !graphHasKey(g, "rootmod.r") || !graphHasKey(g, "app_cli.main.go") {
		t.Fatalf("keys: %v", sortedFunctionKeys(g.Functions))
	}
	if g.Functions["app_cli.main.go"].EntryKind == "" {
		t.Errorf("nested [project.scripts] did not mark app_cli.main.go")
	}
	if !graphHasKey(g, "packages.dup.src.rootmod.x.d") {
		t.Errorf("project colliding with a root module was re-keyed: %v", sortedFunctionKeys(g.Functions))
	}
	for _, key := range sortedFunctionKeys(g.Functions) {
		if key == "hidden.h.h" {
			t.Errorf("hidden directory was treated as a project: %s", key)
		}
	}
}

// Projects that only share names every project has (tests) are both
// re-rooted, and the result does not depend on the run.
func TestBuilder_PythonNestedProjectsAuxiliaryOverlapIsDeterministic(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"packages/a/pyproject.toml":  "",
		"packages/a/src/alpha/m.py":  "def f():\n    return 1\n",
		"packages/a/tests/test_a.py": "def t():\n    return 1\n",
		"packages/b/pyproject.toml":  "",
		"packages/b/src/beta/m.py":   "def f():\n    return 1\n",
		"packages/b/tests/test_b.py": "def t():\n    return 1\n",
		"packages/c/pyproject.toml":  "",
		"packages/c/src/alpha/m.py":  "def f():\n    return 2\n",
	}
	var first []string
	for i := 0; i < 5; i++ {
		g := buildPythonTree(t, files, "")
		keys := sortedFunctionKeys(g.Functions)
		if !graphHasKey(g, "alpha.m.f") || !graphHasKey(g, "beta.m.f") || !graphHasKey(g, "packages.c.src.alpha.m.f") {
			t.Fatalf("keys: %v", keys)
		}
		if first == nil {
			first = keys
		} else if !slices.Equal(first, keys) {
			t.Fatalf("run %d differs: %v vs %v", i, keys, first)
		}
	}
}
