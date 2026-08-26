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

func writePythonReexportFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %s/%s: %v", dir, name, err)
	}
}
