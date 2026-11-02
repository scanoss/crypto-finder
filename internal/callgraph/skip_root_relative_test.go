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
	"os"
	"path/filepath"
	"testing"
)

// The default skip names (node_modules, venv, build, ...) apply to the
// directories below the root a package is built from, never to the root's own
// ancestors: an npm dependency lives in node_modules and a checkout may sit
// under a directory named build, and both must keep their files.
func TestBuilder_SkipNamesApplyBelowPackageRoot(t *testing.T) {
	t.Parallel()

	const source = "function hash() {}\nmodule.exports = { hash };\n"
	cases := []struct {
		name string
		// pkg is the package root below the temp dir; files are written
		// relative to it.
		pkg     PackageDir
		files   []string
		present []string
		absent  []string
	}{
		{
			name:    "dependency root inside node_modules keeps its files",
			pkg:     PackageDir{Dir: "x/node_modules/pkg", ImportPath: "pkg", Version: "1.0.0"},
			files:   []string{"index.js", "lib/util.js"},
			present: []string{"pkg/index.hash", "pkg/lib/util.hash"},
		},
		{
			name:    "project's own node_modules is still skipped",
			pkg:     PackageDir{Dir: "proj", ImportPath: "proj"},
			files:   []string{"index.js", "node_modules/dep/index.js"},
			present: []string{"proj/index.hash"},
			absent:  []string{"proj/node_modules/dep/index.hash", "dep/index.hash"},
		},
		{
			name:    "project root under a build directory keeps its files",
			pkg:     PackageDir{Dir: "home/u/build/repo", ImportPath: "repo"},
			files:   []string{"index.js", "src/app.js", "build/out.js"},
			present: []string{"repo/index.hash", "repo/src/app.hash"},
			absent:  []string{"repo/build/out.hash"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pkg := tc.pkg
			pkg.Dir = filepath.Join(t.TempDir(), filepath.FromSlash(pkg.Dir))
			for _, file := range tc.files {
				path := filepath.Join(pkg.Dir, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				writeCallgraphFixture(t, path, source)
			}

			graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{pkg}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			for _, key := range tc.present {
				if graph.Functions[key] == nil {
					t.Errorf("%s missing from the graph; functions: %v", key, functionKeys(graph))
				}
			}
			for _, key := range tc.absent {
				if graph.Functions[key] != nil {
					t.Errorf("%s is in the graph, want it skipped", key)
				}
			}
		})
	}
}

// A Python distribution installed in a virtualenv named venv is indexed: the
// dependency type resolver's walk starts at site-packages, below the venv.
func TestPythonDependencyTypeResolver_IndexesDistributionUnderVenv(t *testing.T) {
	t.Parallel()

	sitePackages := filepath.Join(t.TempDir(), "venv", "lib", "python3.12", "site-packages")
	pkgDir := filepath.Join(sitePackages, "venvlib")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCallgraphFixture(t, filepath.Join(pkgDir, "__init__.py"), "class Box:\n    pass\n\n\ndef make() -> Box:\n    return Box()\n")

	signatures, _ := NewPythonDependencyTypeResolver(nil).indexDistribution(PackageDir{
		Dir: sitePackages, ImportPath: "venvlib", Version: "1.0.0",
		IncludeFiles: []string{filepath.Join(pkgDir, "__init__.py")},
	}, newPythonDependencyParser())
	if len(signatures) == 0 {
		t.Fatal("no signatures indexed from a distribution under a venv directory")
	}
}

func functionKeys(graph *CallGraph) []string {
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	return keys
}
