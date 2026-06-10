// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// loadPythonKBForTest loads the embedded Python KB or returns an empty KB on error.
// The tests that call it only need a non-nil KB; failure to load is fatal.
func loadPythonKBForTest(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("failed to load python KB: %v", err)
	}
	return kb
}

// buildTestCallGraph constructs a minimal CallGraph with the supplied functions.
func buildTestCallGraph(fns ...*FunctionDecl) *CallGraph {
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	for _, fn := range fns {
		g.Functions[fn.ID.String()] = fn
	}
	return g
}

// TestNewTypeResolverForEcosystem_Python_NonNil asserts that
// NewTypeResolverForEcosystem("python", ...) returns a non-nil TypeResolver.
// Satisfies REQ-4.1.
func TestNewTypeResolverForEcosystem_Python_NonNil(t *testing.T) {
	resolver := NewTypeResolverForEcosystem("python", javaruntime.Config{})
	if resolver == nil {
		t.Fatal("NewTypeResolverForEcosystem(\"python\") returned nil; expected a non-nil TypeResolver")
	}
}

// TestPythonContractTypeResolver_SetsReturnTypeFromKB verifies that the resolver
// annotates a FunctionDecl whose ID matches a known contract method with the
// contract's declared return type. Satisfies REQ-4.2 (must-resolve case).
func TestPythonContractTypeResolver_SetsReturnTypeFromKB(t *testing.T) {
	kb := loadPythonKBForTest(t)

	// FunctionDecl that matches the smoke contract: Cipher.encryptor (arity 0).
	fn := &FunctionDecl{
		ID: FunctionID{
			Package: "cryptography.hazmat.primitives.ciphers",
			Type:    "Cipher",
			Name:    "encryptor",
		},
		Parameters: nil, // arity 0
		ReturnType: "",  // unset — resolver must fill it
	}

	g := buildTestCallGraph(fn)
	resolver := NewPythonContractTypeResolver(kb)

	if err := resolver.ResolveTypes(g, nil); err != nil {
		t.Fatalf("ResolveTypes returned unexpected error: %v", err)
	}

	want := "cryptography.hazmat.primitives.ciphers.CipherContext"
	got := fn.ReturnType
	if got != want {
		t.Errorf("ReturnType after ResolveTypes = %q, want %q", got, want)
	}
}

// TestPythonContractTypeResolver_DoesNotOverwriteExistingReturnType verifies that
// the resolver does not overwrite a ReturnType that was already set by the parser.
func TestPythonContractTypeResolver_DoesNotOverwriteExistingReturnType(t *testing.T) {
	kb := loadPythonKBForTest(t)

	fn := &FunctionDecl{
		ID: FunctionID{
			Package: "cryptography.hazmat.primitives.ciphers",
			Type:    "Cipher",
			Name:    "encryptor",
		},
		Parameters: nil,
		ReturnType: "AlreadySet", // pre-set by parser
	}

	g := buildTestCallGraph(fn)
	resolver := NewPythonContractTypeResolver(kb)

	if err := resolver.ResolveTypes(g, nil); err != nil {
		t.Fatalf("ResolveTypes returned unexpected error: %v", err)
	}

	if fn.ReturnType != "AlreadySet" {
		t.Errorf("ReturnType was overwritten: got %q, want %q", fn.ReturnType, "AlreadySet")
	}
}

// TestPythonContractTypeResolver_NonContractMethodUntouched verifies that a
// FunctionDecl whose method is NOT in the KB is left with an empty ReturnType.
// Asserts the documented "allowed not to resolve" behavior (REQ-4.2 scenario 2).
func TestPythonContractTypeResolver_NonContractMethodUntouched(t *testing.T) {
	kb := loadPythonKBForTest(t)

	fn := &FunctionDecl{
		ID: FunctionID{
			Package: "some.unknown.library",
			Type:    "Widget",
			Name:    "frobnicate",
		},
		Parameters: nil,
		ReturnType: "",
	}

	g := buildTestCallGraph(fn)
	resolver := NewPythonContractTypeResolver(kb)

	if err := resolver.ResolveTypes(g, nil); err != nil {
		t.Fatalf("ResolveTypes returned unexpected error: %v", err)
	}

	if fn.ReturnType != "" {
		t.Errorf("non-contract method ReturnType = %q, want empty (should be left untouched)", fn.ReturnType)
	}
}

// TestPythonContractTypeResolver_EmptyKB_NoPanic verifies that the resolver
// operates safely with an empty KB (nil or empty contracts map).
// Satisfies REQ-4.3.
func TestPythonContractTypeResolver_EmptyKB_NoPanic(t *testing.T) {
	emptyKB := &contracts.KnowledgeBase{
		Ecosystem: "python",
		Contracts: make(map[string][]contracts.Contract),
		Hierarchy: make(map[string][]string),
	}

	fn := &FunctionDecl{
		ID: FunctionID{
			Package: "cryptography.hazmat.primitives.ciphers",
			Type:    "Cipher",
			Name:    "encryptor",
		},
		Parameters: nil,
		ReturnType: "",
	}

	g := buildTestCallGraph(fn)
	resolver := NewPythonContractTypeResolver(emptyKB)

	if err := resolver.ResolveTypes(g, nil); err != nil {
		t.Fatalf("ResolveTypes on empty KB returned error: %v", err)
	}

	// ReturnType must remain empty — empty KB, nothing to resolve.
	if fn.ReturnType != "" {
		t.Errorf("empty-KB ReturnType = %q, want empty", fn.ReturnType)
	}
}

// TestPythonContractTypeResolver_NilKB_NoPanic verifies no panic when KB is nil.
// Satisfies REQ-4.3 (nil KB case).
func TestPythonContractTypeResolver_NilKB_NoPanic(t *testing.T) {
	resolver := NewPythonContractTypeResolver(nil)

	fn := &FunctionDecl{
		ID: FunctionID{
			Package: "some.lib",
			Type:    "Foo",
			Name:    "bar",
		},
		ReturnType: "",
	}
	g := buildTestCallGraph(fn)

	if err := resolver.ResolveTypes(g, nil); err != nil {
		t.Fatalf("ResolveTypes with nil KB returned error: %v", err)
	}
}

// TestNewTypeResolverForEcosystem_Java_StillWorks verifies that the Java path
// through NewTypeResolverForEcosystem is unaffected by the Python addition.
func TestNewTypeResolverForEcosystem_Java_StillWorks(t *testing.T) {
	resolver := NewTypeResolverForEcosystem("java", javaruntime.Config{})
	if resolver == nil {
		t.Fatal("NewTypeResolverForEcosystem(\"java\") returned nil; Java path was broken")
	}
}
