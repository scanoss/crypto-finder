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

// parsePythonInline is a test helper: writes src to a temp .py file, parses it,
// and returns the extracted functions.
func parsePythonInline(t *testing.T, src string) []FunctionDecl {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "src.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) == 0 {
		return nil
	}
	var fns []FunctionDecl
	for _, a := range analyses {
		fns = append(fns, a.Functions...)
	}
	return fns
}

// findPythonFuncByName returns the first FunctionDecl whose Name matches.
func findPythonFuncByName(fns []FunctionDecl, name string) *FunctionDecl {
	for i := range fns {
		if fns[i].ID.Name == name {
			return &fns[i]
		}
	}
	return nil
}

// findPythonCallByMethod returns the first call in fn whose callee Name matches.
func findPythonCallByMethod(fn *FunctionDecl, method string) *FunctionCall {
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if c.Callee.Name == method {
			return c
		}
	}
	return nil
}

// TestPythonParser_AssignedVar_SimpleConstructor verifies that a plain constructor
// call whose result is assigned to a variable records AssignedVar on that call.
//
// Source pattern: cipher = Cipher(algo, mode)
// Expected: call to Cipher.<init> has AssignedVar == "cipher".
func TestPythonParser_AssignedVar_SimpleConstructor(t *testing.T) {
	src := `from cryptography.hazmat.primitives.ciphers import Cipher

def make_cipher(algo, mode):
    cipher = Cipher(algo, mode)
    return cipher
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "make_cipher")
	if fn == nil {
		t.Fatal("make_cipher function not found")
	}

	call := findPythonCallByMethod(fn, constructorMethodName)
	if call == nil {
		t.Fatal("Cipher constructor call not found")
	}
	if call.AssignedVar != "cipher" {
		t.Errorf("constructor AssignedVar = %q, want %q", call.AssignedVar, "cipher")
	}
}

// TestPythonParser_ReceiverVar_MethodCall verifies that a method call on a local
// variable records ReceiverVar with that variable's name.
//
// Source pattern: enc = cipher.encryptor()
// Expected: call to encryptor has ReceiverVar == "cipher".
func TestPythonParser_ReceiverVar_MethodCall(t *testing.T) {
	src := `from cryptography.hazmat.primitives.ciphers import Cipher

def do_encrypt(algo, mode):
    cipher = Cipher(algo, mode)
    enc = cipher.encryptor()
    return enc
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "do_encrypt")
	if fn == nil {
		t.Fatal("do_encrypt function not found")
	}

	call := findPythonCallByMethod(fn, "encryptor")
	if call == nil {
		t.Fatal("encryptor call not found")
	}
	if call.ReceiverVar != "cipher" {
		t.Errorf("encryptor ReceiverVar = %q, want %q", call.ReceiverVar, "cipher")
	}
}

// TestPythonParser_ChainID_FluentChain verifies that all calls in a fluent chain
// share a non-empty ChainID that is equal across all links, and that the chain root
// (outermost call) carries AssignedVar when assigned.
//
// Source pattern: result = cipher.encryptor().update(data)
// Expected: both encryptor and update share the same non-empty ChainID;
// root (update, outermost) carries AssignedVar == "result".
func TestPythonParser_ChainID_FluentChain(t *testing.T) {
	src := `from cryptography.hazmat.primitives.ciphers import Cipher

def do_encrypt_chain(algo, mode, data):
    result = Cipher(algo, mode).encryptor().update(data)
    return result
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "do_encrypt_chain")
	if fn == nil {
		t.Fatal("do_encrypt_chain function not found")
	}

	// All three calls should share a ChainID.
	cipherInit := findPythonCallByMethod(fn, constructorMethodName)
	encryptor := findPythonCallByMethod(fn, "encryptor")
	update := findPythonCallByMethod(fn, "update")

	if cipherInit == nil || encryptor == nil || update == nil {
		t.Fatalf("expected <init>=%v encryptor=%v update=%v to all be present",
			cipherInit != nil, encryptor != nil, update != nil)
	}

	// At least the inner calls (encryptor and update) must share a ChainID.
	if encryptor.ChainID == "" {
		t.Error("encryptor ChainID is empty; fluent chain grouping not populated")
	}
	if update.ChainID == "" {
		t.Error("update ChainID is empty; fluent chain grouping not populated")
	}
	if encryptor.ChainID != update.ChainID {
		t.Errorf("encryptor.ChainID=%q != update.ChainID=%q; links should share ChainID",
			encryptor.ChainID, update.ChainID)
	}

	// The outermost call (update) is the chain root and should carry AssignedVar.
	if update.AssignedVar != "result" {
		t.Errorf("update (chain root) AssignedVar = %q, want %q", update.AssignedVar, "result")
	}
}

// TestPythonParser_ModuleCall_NoReceiverVar verifies that a module-qualified call
// (e.g., hashlib.sha256()) does NOT get a ReceiverVar — the object "hashlib" is a
// module, not a local variable.
func TestPythonParser_ModuleCall_NoReceiverVar(t *testing.T) {
	src := `import hashlib

def make_hash(data):
    h = hashlib.sha256(data)
    return h
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "make_hash")
	if fn == nil {
		t.Fatal("make_hash function not found")
	}

	sha := findPythonCallByMethod(fn, "sha256")
	if sha == nil {
		t.Fatal("sha256 call not found")
	}
	if sha.ReceiverVar != "" {
		t.Errorf("hashlib.sha256 ReceiverVar = %q, want empty (module call, not receiver var)",
			sha.ReceiverVar)
	}
}

// TestPythonParser_AssignedVar_OnMethodCall verifies that a method call result
// assigned to a variable records AssignedVar on that call (not just constructors).
//
// Source: enc = cipher.encryptor() → encryptor call AssignedVar == "enc".
func TestPythonParser_AssignedVar_OnMethodCall(t *testing.T) {
	src := `from cryptography.hazmat.primitives.ciphers import Cipher

def do_encrypt(algo, mode):
    cipher = Cipher(algo, mode)
    enc = cipher.encryptor()
    return enc.update(b"data")
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "do_encrypt")
	if fn == nil {
		t.Fatal("do_encrypt function not found")
	}

	enc := findPythonCallByMethod(fn, "encryptor")
	if enc == nil {
		t.Fatal("encryptor call not found")
	}
	if enc.AssignedVar != "enc" {
		t.Errorf("encryptor AssignedVar = %q, want %q", enc.AssignedVar, "enc")
	}
}
