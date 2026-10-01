// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A manifest-named project keys its modules under the root module
// (`probe.pkg.cli.main`), while the manifest spells the module as the code is
// imported (`pkg.cli:main`) and so does a Django URL pattern. Both must still
// mark the function, and a module nested under other segments, which is a
// different module, must not be marked.
func TestBuilder_PythonEntryRefsHonourTheRootModule(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"pyproject.toml":        "[project]\nname = \"probe\"\n\n[project.scripts]\ntool = \"pkg.cli:main\"\n",
		"pkg/__init__.py":       "",
		"pkg/cli.py":            "def main():\n    pass\n\n\ndef other():\n    pass\n",
		"urls.py":               "from django.urls import path\nfrom shop import views\n\nurlpatterns = [path(\"a/\", views.index)]\n",
		"shop/__init__.py":      "",
		"shop/views.py":         "def index(request):\n    pass\n",
		"x/__init__.py":         "",
		"x/shop/__init__.py":    "",
		"x/shop/views.py":       "def index(request):\n    pass\n",
		"x/pkg/__init__.py":     "",
		"x/pkg/cli.py":          "def main():\n    pass\n",
		"pkg/sub/__init__.py":   "",
		"pkg/sub/cli.py":        "def main():\n    pass\n",
		"deep/pkg/__init__.py":  "",
		"deep/pkg/cli.py":       "def main():\n    pass\n",
		"deep/__init__.py":      "",
		"deep/shop/__init__.py": "",
		"deep/shop/views.py":    "def index(request):\n    pass\n",
	}
	tests := []struct {
		name       string
		importPath string
		prefix     string
	}{
		{name: "manifest-named project", importPath: "probe", prefix: "probe."},
		{name: "no root module", importPath: "", prefix: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writePythonTree(t, files)
			graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
				BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: tc.importPath}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			entry := func(key string) RootKind {
				t.Helper()
				decl := graph.Functions[tc.prefix+key]
				if decl == nil {
					t.Fatalf("no function %s%s in %v", tc.prefix, key, sortedFunctionKeys(graph.Functions))
				}
				return decl.EntryKind
			}
			for _, key := range []string{"pkg.cli.main", "shop.views.index"} {
				if got := entry(key); got == "" {
					t.Errorf("%s%s is not an entry point, want one: the manifest and the URL pattern spell the module without the root", tc.prefix, key)
				}
			}
			for _, key := range []string{"pkg.cli.other", "x.pkg.cli.main", "x.shop.views.index", "pkg.sub.cli.main", "deep.pkg.cli.main", "deep.shop.views.index"} {
				if got := entry(key); got != "" {
					t.Errorf("%s%s is an entry point (%q), want none: it is a different module", tc.prefix, key, got)
				}
			}
		})
	}
}
