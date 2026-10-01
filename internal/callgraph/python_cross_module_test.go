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

const pythonDigestHelperSrc = "import hashlib\n\n\ndef digest(alg, data):\n    return hashlib.new(alg, data).hexdigest()\n"

// A call from one module to a function another module of the same project
// defines links the caller to that function's declaration, whatever the
// layout and however the import spells the module. The declaration is keyed
// by the module that defines it, and a manifest-named project's root module
// is prefixed onto an absolute import of one of its own modules.
func TestBuilder_PythonCrossModuleCallLinksToTheDeclaration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		importPath string
		files      map[string]string
		wantDecl   string
		wantCaller string
	}{
		{
			name: "absolute import without a root module",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "from app.digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "app.digest.digest",
			wantCaller: "app.main.caller",
		},
		{
			name:       "absolute import under a root module that differs from the package",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "from app.digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.app.digest.digest",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "absolute import under a root module equal to the package",
			importPath: "app",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "from app.digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "app.app.digest.digest",
			wantCaller: "app.app.main.caller",
		},
		{
			name:       "relative import",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "from .digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.app.digest.digest",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "relative import of the module itself",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "from . import digest\n\n\ndef caller(d):\n    return digest.digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.app.digest.digest",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "dotted import called through the module path",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/main.py":     "import app.digest\n\n\ndef caller(d):\n    return app.digest.digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.app.digest.digest",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "flat layout",
			importPath: "probe",
			files: map[string]string{
				"digest.py": pythonDigestHelperSrc,
				"main.py":   "from digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.digest.digest",
			wantCaller: "probe.main.caller",
		},
		{
			name:       "a sibling module defines the same name",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/digest.py":   pythonDigestHelperSrc,
				"app/other.py":    "def digest(x, y):\n    return None\n",
				"app/main.py":     "from .digest import digest\n\n\ndef caller(d):\n    return digest(\"sha1\", d)\n",
			},
			wantDecl:   "probe.app.digest.digest",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "class constructor in another module",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "",
				"app/hasher.py":   "class Hasher:\n    def __init__(self, alg):\n        self.alg = alg\n\n    def digest(self, data):\n        return data\n",
				"app/main.py":     "from app.hasher import Hasher\n\n\ndef caller(d):\n    h = Hasher(\"sha1\")\n    return h.digest(d)\n",
			},
			wantDecl:   "probe.app.hasher.(Hasher).<init>",
			wantCaller: "probe.app.main.caller",
		},
		{
			name:       "a package re-exports the function",
			importPath: "probe",
			files: map[string]string{
				"app/__init__.py": "from .hashing import hash_it\n",
				"app/hashing.py":  "import hashlib\n\n\ndef hash_it(data):\n    return hashlib.sha1(data)\n",
				"app/main.py":     "from app import hash_it\n\n\ndef caller(d):\n    return hash_it(d)\n",
			},
			wantDecl:   "probe.app.hashing.hash_it",
			wantCaller: "probe.app.main.caller",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			root := writePythonTree(t, tc.files)
			graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
				BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: tc.importPath}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			if graph.Functions[tc.wantDecl] == nil {
				t.Fatalf("missing declaration %s in %v", tc.wantDecl, sortedFunctionKeys(graph.Functions))
			}
			if graph.Functions[tc.wantCaller] == nil {
				t.Fatalf("missing caller %s in %v", tc.wantCaller, sortedFunctionKeys(graph.Functions))
			}
			if callers := graph.Callers[tc.wantDecl]; !slices.Contains(callers, tc.wantCaller) {
				t.Errorf("Callers[%s] = %v, want %s", tc.wantDecl, callers, tc.wantCaller)
			}
		})
	}
}

// Prefixing the root module is gated on the graph: a call into the standard
// library, or into a module the project does not define, keeps the spelling
// the contracts key on.
func TestBuilder_PythonRootModuleQualifiesOnlyProjectModules(t *testing.T) {
	t.Parallel()

	root := writePythonTree(t, map[string]string{
		"app/__init__.py": "",
		"app/main.py":     "import hashlib\nfrom vendor.lib import helper\n\n\ndef caller(d):\n    helper(d)\n    return hashlib.sha256(d)\n",
	})
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "probe"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	caller := graph.Functions["probe.app.main.caller"]
	if caller == nil {
		t.Fatalf("missing probe.app.main.caller in %v", sortedFunctionKeys(graph.Functions))
	}
	got := make([]string, 0, len(caller.Calls))
	for _, call := range caller.Calls {
		got = append(got, call.Callee.String())
	}
	for _, want := range []string{"hashlib.sha256", "vendor.lib.helper"} {
		if !slices.Contains(got, want) {
			t.Errorf("callees = %v, want %s unchanged", got, want)
		}
	}
}

// A consumer calling a dependency's public path reaches the declaration
// behind the dependency's `__init__.py` re-export, through a chain of nested
// packages too, while the callee keeps the public spelling a contract keys on.
func TestBuilder_PythonDependencyReExportLinksTheCallerWithoutRewritingTheCallee(t *testing.T) {
	t.Parallel()

	depDir := writePythonTree(t, map[string]string{
		"__init__.py":          "from .api import encode\nfrom .jose import Signer\n",
		"api.py":               "def encode(payload, key):\n    return payload\n",
		"jose/__init__.py":     "from .rfc import Signer\n",
		"jose/rfc/__init__.py": "from .signer import Signer\n",
		"jose/rfc/signer.py":   "class Signer:\n    def __init__(self):\n        self.key = None\n",
	})
	appDir := writePythonTree(t, map[string]string{
		"user.py": "from jwtlike import encode, Signer\n\n\ndef run(payload, key):\n    Signer()\n    return encode(payload, key)\n",
	})

	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{
			{Dir: depDir, ImportPath: "jwtlike", Version: "1.0.0"},
			{Dir: appDir},
		}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	run := graph.Functions["user.run"]
	if run == nil {
		t.Fatalf("missing user.run in %v", sortedFunctionKeys(graph.Functions))
	}
	encode := findPythonCallByMethod(run, "encode")
	if encode == nil {
		t.Fatalf("encode call not found in %#v", run.Calls)
	}
	if want := (FunctionID{Package: "jwtlike", Name: "encode"}); encode.Callee != want {
		t.Errorf("encode callee = %+v, want the public %+v", encode.Callee, want)
	}

	for _, decl := range []string{"jwtlike.api.encode", "jwtlike.jose.rfc.signer.(Signer).<init>"} {
		if graph.Functions[decl] == nil {
			t.Fatalf("missing declaration %s in %v", decl, sortedFunctionKeys(graph.Functions))
		}
		if callers := graph.Callers[decl]; !slices.Contains(callers, "user.run") {
			t.Errorf("Callers[%s] = %v, want user.run", decl, callers)
		}
	}
}

func writePythonTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
