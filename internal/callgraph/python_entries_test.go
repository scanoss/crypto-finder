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

// The migration loader runs every Migration class under a migrations
// directory, so its class body, where RunPython registers the callbacks, is an
// entry point. A class of the same name elsewhere, or a migrations class that
// does not extend Django's Migration, is not.
func TestBuilder_PythonDjangoMigrationClassBodyIsAnEntry(t *testing.T) {
	t.Parallel()

	const body = "    operations = [migrations.RunPython(forwards)]\n"
	files := map[string]string{
		"app/__init__.py":                   "",
		"app/migrations/__init__.py":        "",
		"app/migrations/0001_module.py":     "from django.db import migrations\n\n\nclass Migration(migrations.Migration):\n" + body,
		"app/migrations/0002_direct.py":     "from django.db.migrations import Migration, RunPython\n\n\nclass Migration2(Migration):\n    operations = [RunPython(forwards)]\n",
		"app/migrations/0003_alias.py":      "from django.db import migrations as m\n\n\nclass Migration(m.Migration):\n    operations = [migrations.RunPython(forwards)]\n",
		"app/migrations/0004_other_base.py": "from other import Base\n\n\nclass Migration(Base):\n    operations = [migrations.RunPython(forwards)]\n",
		"app/migrations/0005_unrelated.py":  "from django.db import models\n\n\nclass Helper(models.Model):\n    operations = [migrations.RunPython(forwards)]\n",
		"app/migrations/0006_unimported.py": "class Migration(migrations.Migration):\n    operations = [migrations.RunPython(forwards)]\n",
		"app/models.py":                     "from django.db import migrations\n\n\nclass Migration(migrations.Migration):\n    operations = [migrations.RunPython(forwards)]\n",
		"app/migrationsx/0001_other_dir.py": "from django.db import migrations\n\n\nclass Migration(migrations.Migration):\n    operations = [migrations.RunPython(forwards)]\n",
	}
	root := writePythonTree(t, files)
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	kind := func(key string) RootKind {
		t.Helper()
		decl := graph.Functions[key]
		if decl == nil {
			t.Fatalf("no function %s in %v", key, sortedFunctionKeys(graph.Functions))
		}
		return decl.EntryKind
	}
	for _, key := range []string{
		"app.migrations.0001_module.(Migration).<clinit>",
		"app.migrations.0002_direct.(Migration2).<clinit>",
		"app.migrations.0003_alias.(Migration).<clinit>",
	} {
		if got := kind(key); got != RootKindFrameworkEntry {
			t.Errorf("%s entry kind = %q, want %q", key, got, RootKindFrameworkEntry)
		}
	}
	for _, key := range []string{
		"app.migrations.0004_other_base.(Migration).<clinit>",
		"app.migrations.0005_unrelated.(Helper).<clinit>",
		"app.migrations.0006_unimported.(Migration).<clinit>",
		"app.models.(Migration).<clinit>",
		"app.migrationsx.0001_other_dir.(Migration).<clinit>",
	} {
		if got := kind(key); got != "" {
			t.Errorf("%s is an entry point (%q), want none", key, got)
		}
	}
}

// A class-body call gives the class a synthetic <clinit>; it must carry the
// class's bases like its methods do, or the entry rules lose the bases of any
// class that has one and its view methods stop being entry points.
func TestBuilder_PythonClassBodyCallKeepsViewBases(t *testing.T) {
	t.Parallel()

	root := writePythonTree(t, map[string]string{
		"shop/__init__.py": "",
		"shop/views.py":    "from django.views import View\n\n\nclass Index(View):\n    template = load()\n\n    def get(self, request):\n        pass\n",
	})
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	decl := graph.Functions["shop.views.(Index).get"]
	if decl == nil || decl.EntryKind != RootKindFrameworkEntry {
		t.Fatalf("shop.views.(Index).get = %+v, want a framework_entry", decl)
	}
}
