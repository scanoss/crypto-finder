// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBuilder_InitPyReexport_SiblingResolution proves the builder stitches a
// sibling file's `from pkg import Name` back to the symbol's true declaring
// module when `pkg/__init__.py` re-exports it via an explicit relative
// import, mirroring how pip-resolved packages commonly re-export their
// public API (e.g. `from .core import Cipher` in `__init__.py`). Layout:
//
//	pkg/__init__.py  -> from .mod import Cipher
//	pkg/user.py      -> from pkg import Cipher ; Cipher().encrypt(data)
//	pkg/mod/__init__.py -> class Cipher: def __init__(self): ... ; def encrypt(self, data): ...
//
// "mod" is its own subpackage directory (packagePath "pkg.mod") so Cipher's
// real declared FQN differs from the flat "pkg" packagePath that
// `from pkg import Cipher` naively resolves to without stitching.
func TestBuilder_InitPyReexport_SiblingResolution(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "mod")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	writePythonReexportFixture(t, root, "__init__.py", "from .mod import Cipher\n")
	writePythonReexportFixture(t, root, "user.py",
		"from pkg import Cipher\n\n\ndef run(data):\n    Cipher().encrypt(data)\n")
	writePythonReexportFixture(t, modDir, "__init__.py",
		"class Cipher:\n    def __init__(self):\n        pass\n\n    def encrypt(self, data):\n        pass\n")

	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "pkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	run, ok := graph.Functions[(FunctionID{Package: "pkg", Name: "run"}).String()]
	if !ok {
		t.Fatalf("expected a declared FunctionDecl for pkg.run, got none (keys: %v)", keysOf(graph.Functions))
	}

	ctor := findPythonCallByMethod(run, constructorMethodName)
	if ctor == nil {
		t.Fatalf("Cipher constructor call not found in run()'s calls")
	}
	want := FunctionID{Package: "pkg.mod", Type: "Cipher", Name: constructorMethodName}
	if ctor.Callee != want {
		t.Errorf("Cipher() constructor callee = %+v, want %+v (pkg/__init__.py's `from .mod import Cipher` re-export should stitch pkg.Cipher -> pkg.mod.Cipher)", ctor.Callee, want)
	}
}

// TestBuilder_InitPyReexport_NoInferredType proves re-export propagation
// resolves only the NAME BINDING recorded verbatim in `__init__.py` — it
// never chases the re-exported symbol's own internal aliasing inside the
// module it points to. Here `pkg/mod/__init__.py` aliases `Cipher` to an
// undeclared name instead of declaring a `Cipher` class, so no
// `pkg.mod.(Cipher).<init>` declaration ever exists in the graph; the
// stitching gate must leave the original (unresolved) `pkg.Cipher` binding
// untouched rather than rewrite to a non-existent declaration.
func TestBuilder_InitPyReexport_NoInferredType(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "mod")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	writePythonReexportFixture(t, root, "__init__.py", "from .mod import Cipher\n")
	writePythonReexportFixture(t, root, "user.py",
		"from pkg import Cipher\n\n\ndef run(data):\n    Cipher().encrypt(data)\n")
	writePythonReexportFixture(t, modDir, "__init__.py", "Cipher = SomeOtherThing\n")

	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "pkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	run, ok := graph.Functions[(FunctionID{Package: "pkg", Name: "run"}).String()]
	if !ok {
		t.Fatalf("expected a declared FunctionDecl for pkg.run, got none (keys: %v)", keysOf(graph.Functions))
	}

	ctor := findPythonCallByMethod(run, constructorMethodName)
	if ctor == nil {
		t.Fatalf("Cipher constructor call not found in run()'s calls")
	}
	want := FunctionID{Package: "pkg", Type: "Cipher", Name: constructorMethodName}
	if ctor.Callee != want {
		t.Errorf("Cipher() constructor callee = %+v, want %+v (no in-graph pkg.mod.Cipher declaration exists, so the unresolved binding must not be rewritten)", ctor.Callee, want)
	}
}

// TestBuilder_InitPyReexport_DoesNotRewriteKBKeyedDependency proves re-export
// stitching is restricted to project-local analyses and never rewrites a
// callee that lands inside a versioned (non-project-local) dependency
// package, even when that dependency's own `__init__.py` re-exports across a
// sub-package boundary. This mirrors a real authlib-shaped layout:
//
//	authlib/jose/__init__.py           -> from .rfc7515 import JsonWebSignature
//	authlib/jose/rfc7515/__init__.py   -> class JsonWebSignature: def __init__(self): ...
//	myapp/user.py (project-local)      -> from authlib.jose import JsonWebSignature; JsonWebSignature()
//
// Contract KB YAMLs key on the PUBLIC re-export path
// (`authlib.jose.(JsonWebSignature).<init>`, mirroring
// internal/callgraph/contracts/python/authlib.yaml), not the internal
// sub-package path. If re-export accumulation were not gated on
// projectLocal, this rewrite would silently move the callee to
// `authlib.jose.rfc7515.(JsonWebSignature).<init>`, breaking KB matching for
// every consumer of a dependency scanned alongside its own source (dependency
// scan / mining). The callee MUST stay at the original, KB-keyed FQN.
func TestBuilder_InitPyReexport_DoesNotRewriteKBKeyedDependency(t *testing.T) {
	root := t.TempDir()
	depDir := filepath.Join(root, "dep")
	consumerDir := filepath.Join(root, "consumer")
	authlibDir := filepath.Join(depDir, "jose")
	rfc7515Dir := filepath.Join(authlibDir, "rfc7515")
	if err := os.MkdirAll(rfc7515Dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(consumerDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	writePythonReexportFixture(t, authlibDir, "__init__.py", "from .rfc7515 import JsonWebSignature\n")
	writePythonReexportFixture(t, rfc7515Dir, "__init__.py",
		"class JsonWebSignature:\n    def __init__(self):\n        pass\n")
	writePythonReexportFixture(t, consumerDir, "user.py",
		"from authlib.jose import JsonWebSignature\n\n\ndef run():\n    JsonWebSignature()\n")

	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{
			{Dir: depDir, ImportPath: "authlib", Version: "1.6.0"},
			{Dir: consumerDir, ImportPath: "myapp"},
		}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	run, ok := graph.Functions[(FunctionID{Package: "myapp", Name: "run"}).String()]
	if !ok {
		t.Fatalf("expected a declared FunctionDecl for myapp.run, got none (keys: %v)", keysOf(graph.Functions))
	}

	ctor := findPythonCallByMethod(run, constructorMethodName)
	if ctor == nil {
		t.Fatalf("JsonWebSignature constructor call not found in run()'s calls")
	}
	want := FunctionID{Package: "authlib.jose", Type: "JsonWebSignature", Name: constructorMethodName}
	if ctor.Callee != want {
		t.Errorf("JsonWebSignature() constructor callee = %+v, want %+v (re-export stitching must not rewrite a non-project-local dependency's KB-keyed FQN)", ctor.Callee, want)
	}
}

func writePythonReexportFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s/%s: %v", dir, name, err)
	}
}
