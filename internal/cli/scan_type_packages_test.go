// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// twistedSite is a site-packages directory holding one installed
// distribution: a class whose constructor a client calls, and a factory
// annotated to return it.
func twistedSite(t *testing.T) string {
	t.Helper()
	site := t.TempDir()
	writeFiles(t, site, map[string]string{
		"twisted/__init__.py":     "",
		"twisted/web/__init__.py": "",
		"twisted/web/http_headers.py": "class Headers:\n    def __init__(self, raw=None):\n        self._raw = raw\n\n" +
			"    def addRawHeader(self, name, value):\n        pass\n\n\ndef make_headers() -> Headers:\n    return Headers()\n",
		"Twisted-25.5.0.dist-info/METADATA": "Metadata-Version: 2.4\nName: Twisted\nVersion: 25.5.0\n\n",
		"Twisted-25.5.0.dist-info/RECORD": "twisted/__init__.py,,\ntwisted/web/__init__.py,,\ntwisted/web/http_headers.py,,\n" +
			"Twisted-25.5.0.dist-info/METADATA,,\nTwisted-25.5.0.dist-info/RECORD,,\n",
	})
	return site
}

// --type-packages reads a site-packages directory (or a virtual environment,
// or an unpacked wheel) as one type-only package per installed distribution,
// limited to its RECORD; any other directory is one package; a missing path
// is skipped.
func TestTypeOnlyPythonPackages(t *testing.T) {
	site, plain := twistedSite(t), t.TempDir()
	got := typeOnlyPythonPackages(strings.Join([]string{site, plain, filepath.Join(plain, "missing")}, string(os.PathListSeparator)))
	want := []callgraph.PackageDir{
		{Dir: site, DistributionName: "twisted", Version: "25.5.0", IncludeFiles: []string{
			filepath.Join(site, "twisted", "__init__.py"), filepath.Join(site, "twisted", "web", "__init__.py"), filepath.Join(site, "twisted", "web", "http_headers.py"),
		}},
		{Dir: plain, DistributionName: filepath.Base(plain), Version: "type-only"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("type-only packages\n got %+v\nwant %+v", got, want)
	}
}

// A Python graph built with type-only packages types a local a dependency
// constructor builds, or a dependency factory is annotated to return: the
// call on it is the class's method, exact, instead of a name_only guess.
func TestPythonTypePackagesTypeDependencyValues(t *testing.T) {
	target := t.TempDir()
	writeFiles(t, target, map[string]string{"app/__init__.py": "", "app/web.py": "from twisted.web.http_headers import Headers, make_headers\n\n\n" +
		"def build():\n    headers = Headers()\n    headers.addRawHeader(\"a\", \"b\")\n\n\n" +
		"def made():\n    h = make_headers()\n    h.addRawHeader(\"a\", \"b\")\n"})
	targets := func(typePackages string) map[string]string {
		graphs := newGraphStore(target, "")
		graphs.typePackages = typePackages
		result, err := buildStandaloneCallGraphResult(graphs, target, &entities.InterimReport{}, []string{ecosystemPython},
			javaruntime.Config{}, false, "", skip.NewMatcher(nil, true))
		if err != nil {
			t.Fatal(err)
		}
		out := make(map[string]string)
		for _, fn := range result.CallGraph.Functions {
			for _, call := range fn.Calls {
				if call.Callee.Name == "addRawHeader" {
					out[fn.ID.Name] = call.Callee.String()
				}
			}
		}
		return out
	}
	without, with := targets(""), targets(twistedSite(t))
	want := "twisted.web.http_headers.(Headers).addRawHeader"
	if with["build"] != want || with["made"] != want {
		t.Errorf("with type packages: %v, want both %s", with, want)
	}
	if without["build"] == want || without["made"] == want {
		t.Errorf("without type packages the dependency class is unknown: %v", without)
	}
}
