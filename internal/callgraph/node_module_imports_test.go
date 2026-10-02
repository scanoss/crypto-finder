// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"
)

func TestBuilder_NodeModuleImportEdges(t *testing.T) {
	t.Parallel()
	const edge = "app/main.<module> -> app/dep.<module>"
	tests := []struct {
		name   string
		main   string
		want   bool
		wantAt int
	}{
		{"side-effect import", "import './dep';\ninit();\n", true, 1},
		{"default import", "import d from './dep';\ninit(d);\n", true, 1},
		{"named import", "import { a } from './dep';\ninit(a);\n", true, 1},
		{"explicit extension", "import './dep.js';\ninit();\n", true, 1},
		{"re-export", "export { a } from './dep';\ninit();\n", true, 1},
		{"export star", "init();\nexport * from './dep';\n", true, 2},
		{"top-level require", "init();\nrequire('./dep');\n", true, 2},
		{"require bound to a name", "const d = require('./dep');\ninit(d);\n", true, 1},
		{"require in a conditional", "if (process.env.X) {\n  require('./dep');\n}\n", true, 2},
		{"only import in the file", "import './dep';\n", true, 1},
		{"package import", "import 'dep';\nimport x from 'dep/sub';\nrequire('dep');\ninit();\n", false, 0},
		{"unresolved relative path", "import './nowhere';\ninit();\n", false, 0},
		{"dynamic import", "import('./dep');\ninit();\n", false, 0},
		{"dynamic import in a function", "function f() { return import('./dep'); }\ninit(f);\n", false, 0},
		{"require in a function", "function f() { return require('./dep'); }\ninit(f);\n", false, 0},
		{"require in an arrow", "const f = () => require('./dep');\ninit(f);\n", false, 0},
		{"type-only import", "import type { T } from './dep';\ninit();\n", false, 0},
		{"type-only export", "export type { T } from './dep';\ninit();\n", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writePythonTree(t, map[string]string{
				"main.ts": tc.main,
				"dep.ts":  "register();\n",
			})
			graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			got := hasEdge(graph, splitEdge(t, edge))
			if got != tc.want {
				t.Fatalf("edge %s = %v, want %v (callers %v)", edge, got, tc.want, graph.Callers["app/dep.<module>"])
			}
			if !tc.want {
				return
			}
			callee := graph.Functions["app/main.<module>"]
			if callee == nil {
				t.Fatal("no importer <module> declaration")
			}
			found := false
			for _, call := range callee.ImplicitCalls {
				if call.Callee.Package == "app/dep" && call.Line == tc.wantAt {
					found = true
				}
			}
			if !found {
				t.Errorf("no import call at line %d: %+v", tc.wantAt, callee.ImplicitCalls)
			}
		})
	}
}

func TestBuilder_NodeModuleImportResolution(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"main.ts":           "import './handlers';\nimport './lib/util.js';\nimport '../outside';\n",
		"handlers/index.ts": "register();\n",
		"lib/util.ts":       "register();\n",
		"lib/unused.ts":     "register();\n",
	})
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for _, e := range []string{"app/main.<module> -> app/handlers/index.<module>", "app/main.<module> -> app/lib/util.<module>"} {
		if !hasEdge(graph, splitEdge(t, e)) {
			t.Errorf("missing edge %s", e)
		}
	}
	if len(graph.Callers["app/lib/unused.<module>"]) != 0 {
		t.Errorf("an unimported module gained callers: %v", graph.Callers["app/lib/unused.<module>"])
	}
}

func TestBuilder_NodeModuleImportCycle(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"a.ts": "import './b';\nrun();\n",
		"b.ts": "import './a';\nrun();\n",
	})
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for _, e := range []string{"app/a.<module> -> app/b.<module>", "app/b.<module> -> app/a.<module>"} {
		if !hasEdge(graph, splitEdge(t, e)) {
			t.Errorf("missing edge %s", e)
		}
	}
}
