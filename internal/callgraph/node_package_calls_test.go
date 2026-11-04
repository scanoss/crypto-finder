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
	"slices"
	"testing"
)

// A call the application makes through a dependency's package name reaches the
// function that package's entry module exports, so reachability crosses into
// npm dependencies.
func TestBuilder_LinksNodeCallsThroughPackageName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// dep is the dependency's import path; its files live in
		// app/node_modules/<dep>.
		dep      string
		depFiles map[string]string
		app      string
		// want is the function app/index.run must reach.
		want string
	}{
		{
			name: "module.exports = fn, called as the required value",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba","main":"index.js"}`,
				"index.js":     "module.exports = data => data;\n",
			},
			app:  "const liba = require('liba');\nfunction run() { liba(1); }\n",
			want: "liba/index.exports",
		},
		{
			name: "module.exports = { used }",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba"}`,
				"index.js":     "function used() {}\nmodule.exports = { used };\n",
			},
			app:  "const liba = require('liba');\nfunction run() { liba.used(); }\n",
			want: "liba/index.used",
		},
		{
			name: "exports.used = function, destructured require",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba","main":"lib/main"}`,
				"lib/main.js":  "exports.used = function used() {};\n",
			},
			app:  "const { used } = require('liba');\nfunction run() { used(); }\n",
			want: "liba/lib/main.used",
		},
		{
			name: "ESM export function through package.json exports",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json":  `{"name":"liba","exports":{".":{"import":"./esm/index.mjs","require":"./cjs/index.js"}}}`,
				"esm/index.mjs": "export function used() {}\n",
				"cjs/index.js":  "exports.used = function used() {};\n",
			},
			app:  "import { used } from 'liba';\nexport function run() { used(); }\n",
			want: "liba/cjs/index.used",
		},
		{
			name: "ESM named import of an ESM package",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba","type":"module","exports":"./index.mjs"}`,
				"index.mjs":    "export function used() {}\n",
			},
			app:  "import { used } from 'liba';\nexport function run() { used(); }\n",
			want: "liba/index.used",
		},
		{
			name: "scoped package",
			dep:  "@scope/pkg",
			depFiles: map[string]string{
				"package.json": `{"name":"@scope/pkg"}`,
				"index.js":     "function run() {}\nmodule.exports = { run };\n",
			},
			app:  "const pkg = require('@scope/pkg');\nfunction run() { pkg.run(); }\n",
			want: "@scope/pkg/index.run",
		},
		{
			name: "subpath import resolving to a file",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba"}`,
				"index.js":     "module.exports = {};\n",
				"sub.js":       "exports.go = function go() {};\n",
			},
			app:  "const sub = require('liba/sub');\nfunction run() { sub.go(); }\n",
			want: "liba/sub.go",
		},
		{
			name: "subpath mapped by package.json exports",
			dep:  "liba",
			depFiles: map[string]string{
				"package.json": `{"name":"liba","exports":{".":"./index.js","./sub":{"default":"./lib/sub.js"}}}`,
				"index.js":     "module.exports = {};\n",
				"lib/sub.js":   "exports.go = function go() {};\n",
			},
			app:  "const sub = require('liba/sub');\nfunction run() { sub.go(); }\n",
			want: "liba/lib/sub.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodeAppWithDependency(t, tc.dep, tc.depFiles, tc.app)
			if graph.Functions[tc.want] == nil {
				t.Fatalf("%s not declared; functions: %v", tc.want, functionKeys(graph))
			}
			if !slices.Contains(graph.Callers[tc.want], "app/index.run") {
				t.Fatalf("app/index.run does not reach %s; callers: %v; calls: %v", tc.want, graph.Callers[tc.want], appCalls(graph))
			}
		})
	}
}

// A call the package name cannot carry to a declared function keeps the name
// it was written with, and no edge into the dependency is made up.
func TestBuilder_KeepsNodeCallsThatDoNotResolve(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		dep      string
		depFiles map[string]string
		app      string
		callee   string
	}{
		{
			name:     "package not in the build",
			dep:      "liba",
			depFiles: map[string]string{"package.json": `{"name":"liba"}`, "index.js": "exports.used = function used() {};\n"},
			app:      "const missing = require('missing');\nfunction run() { missing.used(); }\n",
			callee:   "missing.used",
		},
		{
			name:     "export the entry module does not have",
			dep:      "liba",
			depFiles: map[string]string{"package.json": `{"name":"liba"}`, "index.js": "exports.used = function used() {};\n"},
			app:      "const liba = require('liba');\nfunction run() { liba.other(); }\n",
			callee:   "liba.other",
		},
		{
			name:     "subpath the exports map does not list",
			dep:      "liba",
			depFiles: map[string]string{"package.json": `{"name":"liba","exports":{".":"./index.js"}}`, "index.js": "exports.used = function used() {};\n", "lib/sub.js": "exports.go = function go() {};\n"},
			app:      "const sub = require('liba/sub');\nfunction run() { sub.go(); }\n",
			callee:   "liba/sub.go",
		},
		{
			name:     "Node built-in shadowing an installed package",
			dep:      "crypto",
			depFiles: map[string]string{"package.json": `{"name":"crypto"}`, "index.js": "exports.createHash = function createHash() {};\n"},
			app:      "const crypto = require('crypto');\nfunction run() { crypto.createHash('sha256'); }\n",
			callee:   "crypto.createHash",
		},
		{
			name:     "callee the KB models under its package name",
			dep:      "jsonwebtoken",
			depFiles: map[string]string{"package.json": `{"name":"jsonwebtoken"}`, "index.js": "exports.sign = function sign(a, b, c) {};\n"},
			app:      "const jwt = require('jsonwebtoken');\nfunction run() { jwt.sign({}, 'k', {}); }\n",
			callee:   "jsonwebtoken.sign",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodeAppWithDependency(t, tc.dep, tc.depFiles, tc.app)
			if calls := appCalls(graph); !slices.Contains(calls, tc.callee) {
				t.Fatalf("app/index.run calls %v, want %s kept as written", calls, tc.callee)
			}
			for key, callers := range graph.Callers {
				if graph.Functions[key] != nil && graph.Functions[key].ID.Package != "app/index" && slices.Contains(callers, "app/index.run") {
					t.Fatalf("app/index.run reaches dependency function %s", key)
				}
			}
		})
	}
}

// buildNodeAppWithDependency builds app (index.js, or index.mjs when the
// source imports) with dep installed in its node_modules.
func buildNodeAppWithDependency(t *testing.T, dep string, depFiles map[string]string, app string) *CallGraph {
	t.Helper()
	root := filepath.Join(t.TempDir(), "app")
	appFile := "index.js"
	if len(app) >= 6 && app[:6] == "import" {
		appFile = "index.mjs"
	}
	writeCallgraphFixture(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	writeCallgraphFixture(t, filepath.Join(root, appFile), app)
	depDir := filepath.Join(root, "node_modules", filepath.FromSlash(dep))
	for name, body := range depFiles {
		writeCallgraphFixture(t, filepath.Join(depDir, filepath.FromSlash(name)), body)
	}
	graph, err := NewBuilderForEcosystem(ecosystemNode, NewNodeParser()).BuildFromDirectories([]PackageDir{
		{Dir: root, ImportPath: "app"},
		{Dir: depDir, ImportPath: dep, Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func appCalls(graph *CallGraph) []string {
	run := graph.Functions["app/index.run"]
	if run == nil {
		return nil
	}
	var calls []string
	for i := range run.Calls {
		calls = append(calls, run.Calls[i].Callee.String())
	}
	return calls
}

// A minified main resolves to its unminified sibling, where the dependency's
// entry points are anchored; without a sibling it stays the minified file.
func TestNodePackageEntry_PrefersUnminifiedMain(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		sibling bool
		want    string
	}{
		{"sibling", true, "dist/acme.js"},
		{"no sibling", false, "dist/acme.min.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			files := map[string]string{"package.json": `{"name": "acme", "main": "dist/acme.min.js"}`, "dist/acme.min.js": ""}
			if tc.sibling {
				files["dist/acme.js"] = ""
			}
			for rel, body := range files {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got, want := nodePackageEntry(dir, "."), filepath.Join(dir, filepath.FromSlash(tc.want)); got != want {
				t.Errorf("nodePackageEntry = %q, want %q", got, want)
			}
		})
	}
}
