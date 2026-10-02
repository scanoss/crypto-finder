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
				"packages/app/setup.cfg":               "[metadata]\nname = app\n",
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
