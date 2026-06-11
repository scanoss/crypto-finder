// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"testing"
)

// TestPythonParser_FromImportModule_PackagePath verifies that `from X import Y; Y.method()`
// where Y is a module (lowercase first letter) emits FQN Package="X.Y", Name="method".
//
// This is the pycryptodome bug: `from Crypto.Cipher import AES; AES.new(key, mode)`
// must emit Package="Crypto.Cipher.AES", Name="new" so the KB join hits
// `Crypto.Cipher.AES.new` (not `Crypto.Cipher.new`).
func TestPythonParser_FromImportModule_PackagePath(t *testing.T) {
	src := `from Crypto.Cipher import AES

def encrypt(key, mode, data):
    cipher = AES.new(key, mode)
    return cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "encrypt")
	if fn == nil {
		t.Fatal("encrypt function not found")
	}

	// AES.new(key, mode) — AES is a module import (lowercase: not a type).
	// Package must be "Crypto.Cipher.AES", Name must be "new".
	newCall := findPythonCallByMethod(fn, "new")
	if newCall == nil {
		t.Fatal("AES.new call not found")
	}
	const wantPkg = "Crypto.Cipher.AES"
	if newCall.Callee.Package != wantPkg {
		t.Errorf("AES.new Package = %q, want %q (pycryptodome FQN must be X.Y not X for from-import module)", newCall.Callee.Package, wantPkg)
	}
	if newCall.Callee.Name != "new" {
		t.Errorf("AES.new Name = %q, want %q", newCall.Callee.Name, "new")
	}
	// Type must be empty (it's a module-level function, not an instance method on a type).
	if newCall.Callee.Type != "" {
		t.Errorf("AES.new Type = %q, want empty (not a class method)", newCall.Callee.Type)
	}
}

// TestPythonParser_FromImportType_PackagePath verifies that `from X import Y; Y(...)` where
// Y IS a type (CapitalCase) emits Package="X", Type="Y", Name="<init>" — the existing
// behavior for imported types must NOT regress.
//
// This covers pyca: `from cryptography.hazmat.primitives.ciphers import Cipher; Cipher(a, m)`
// must emit Package="cryptography.hazmat.primitives.ciphers", Type="Cipher", Name="<init>".
func TestPythonParser_FromImportType_PackagePath(t *testing.T) {
	src := `from cryptography.hazmat.primitives.ciphers import Cipher

def make(algo, mode):
    c = Cipher(algo, mode)
    return c
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "make")
	if fn == nil {
		t.Fatal("make function not found")
	}

	initCall := findPythonCallByMethod(fn, constructorMethodName)
	if initCall == nil {
		t.Fatal("Cipher constructor call not found")
	}
	const wantPkg = "cryptography.hazmat.primitives.ciphers"
	if initCall.Callee.Package != wantPkg {
		t.Errorf("Cipher.<init> Package = %q, want %q", initCall.Callee.Package, wantPkg)
	}
	if initCall.Callee.Type != "Cipher" {
		t.Errorf("Cipher.<init> Type = %q, want %q", initCall.Callee.Type, "Cipher")
	}
	if initCall.Callee.Name != constructorMethodName {
		t.Errorf("Cipher.<init> Name = %q, want %q", initCall.Callee.Name, constructorMethodName)
	}
}

// TestPythonParser_FromImportModule_ChaCha20_PackagePath verifies the same from-import
// module fix for a second pycryptodome module: `from Crypto.Cipher import ChaCha20;
// ChaCha20.new(key=key)` → Package="Crypto.Cipher.ChaCha20".
func TestPythonParser_FromImportModule_ChaCha20_PackagePath(t *testing.T) {
	src := `from Crypto.Cipher import ChaCha20

def encrypt_stream(key, nonce, data):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "encrypt_stream")
	if fn == nil {
		t.Fatal("encrypt_stream function not found")
	}

	// ChaCha20 starts with a capital letter but is used as a module (ChaCha20.new),
	// not instantiated directly. The parser currently sees it as a type because of the
	// capital letter — but it's imported as a module and called as ChaCha20.new(...)
	// which is an attribute call (not a direct constructor). The fix must handle the
	// attribute-call path where the imported name is the object of a method call.
	newCall := findPythonCallByMethod(fn, "new")
	if newCall == nil {
		t.Fatal("ChaCha20.new call not found")
	}
	const wantPkg = "Crypto.Cipher.ChaCha20"
	if newCall.Callee.Package != wantPkg {
		t.Errorf("ChaCha20.new Package = %q, want %q", newCall.Callee.Package, wantPkg)
	}
}
