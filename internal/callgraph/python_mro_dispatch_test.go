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
	"sort"
	"testing"
)

// keysOf returns a sorted slice of all keys in a map[string]* for debugging.
func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestExpandPythonSubclassDispatch_BaseCallAliasesToSubclass proves that a call
// to a base-class method is aliased to the matching subclass override when the
// subclass declares the base in its OwnerBases. This mirrors the paramiko pattern:
// PKey.from_private_key_file → also resolves to RSAKey.from_private_key_file,
// ECDSAKey.from_private_key_file, etc.
func TestExpandPythonSubclassDispatch_BaseCallAliasesToSubclass(t *testing.T) {
	root := t.TempDir()

	// Caller that invokes the base-class method
	caller := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "SSHManager", Name: "loadKey#1"},
		FilePath:  filepath.Join(root, "ssh_manager.py"),
		StartLine: 1, EndLine: 5,
		OwnerType: "class",
		OwnerName: "SSHManager",
		Calls: []FunctionCall{
			{
				Callee:   FunctionID{Package: "paramiko.pkey", Type: "PKey", Name: "from_private_key_file#1"},
				Raw:      "PKey.from_private_key_file(path)",
				FilePath: filepath.Join(root, "ssh_manager.py"),
				Line:     3,
			},
		},
	}

	// Base class method
	baseMethod := FunctionDecl{
		ID:        FunctionID{Package: "paramiko.pkey", Type: "PKey", Name: "from_private_key_file#1"},
		FilePath:  filepath.Join(root, "pkey.py"),
		StartLine: 1, EndLine: 3,
		OwnerType:  "class",
		OwnerName:  "PKey",
		OwnerBases: nil, // PKey has no declared base in this fixture
		Parameters: []FunctionParameter{{Type: "filename"}},
	}

	// RSAKey subclass method — overrides from_private_key_file
	rsaMethod := FunctionDecl{
		ID:        FunctionID{Package: "paramiko.rsakey", Type: "RSAKey", Name: "from_private_key_file#1"},
		FilePath:  filepath.Join(root, "rsakey.py"),
		StartLine: 1, EndLine: 4,
		OwnerType:  "class",
		OwnerName:  "RSAKey",
		OwnerBases: []string{"PKey"}, // RSAKey(PKey) → declares base "PKey"
		Parameters: []FunctionParameter{{Type: "filename"}},
	}

	// ECDSAKey subclass method — also overrides from_private_key_file
	ecdsaMethod := FunctionDecl{
		ID:        FunctionID{Package: "paramiko.ecdsakey", Type: "ECDSAKey", Name: "from_private_key_file#1"},
		FilePath:  filepath.Join(root, "ecdsakey.py"),
		StartLine: 1, EndLine: 4,
		OwnerType:  "class",
		OwnerName:  "ECDSAKey",
		OwnerBases: []string{"PKey"}, // ECDSAKey(PKey)
		Parameters: []FunctionParameter{{Type: "filename"}},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{caller, baseMethod, rsaMethod, ecdsaMethod}}},
		},
	}

	graph, err := NewBuilderForEcosystem("python", parser).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	callerKey := caller.ID.String()
	rsaKey := rsaMethod.ID.String()
	ecdsaKey := ecdsaMethod.ID.String()

	// Assert RSAKey.from_private_key_file was added as a Python subclass dispatch alias
	if !containsString(graph.Callers[rsaKey], callerKey) {
		t.Errorf("expected %q to be a caller of subclass method %q (via Python MRO dispatch), but it is not in graph.Callers", callerKey, rsaKey)
	}

	// Assert ECDSAKey.from_private_key_file was also aliased
	if !containsString(graph.Callers[ecdsaKey], callerKey) {
		t.Errorf("expected %q to be a caller of subclass method %q (via Python MRO dispatch), but it is not in graph.Callers", callerKey, ecdsaKey)
	}

	// Assert edge resolutions carry the Python subclass dispatch kind
	foundRSA := false
	for _, res := range graph.EdgeResolutions {
		if res.Kind == EdgeKindPythonSubclassDispatch {
			foundRSA = true
			break
		}
	}
	if !foundRSA {
		t.Error("expected at least one EdgeKindPythonSubclassDispatch edge in graph.EdgeResolutions")
	}
}

// TestExpandPythonSubclassDispatch_NoDispatchForModuleOwnerType verifies that
// module-level functions (OwnerType == "module") are never aliased as subclass
// dispatch targets — only class methods participate in MRO expansion.
func TestExpandPythonSubclassDispatch_NoDispatchForModuleOwnerType(t *testing.T) {
	root := t.TempDir()

	caller := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "", Name: "main#0"},
		FilePath:  filepath.Join(root, "app.py"),
		StartLine: 1, EndLine: 3,
		OwnerType: "module",
		Calls: []FunctionCall{
			{
				Callee:   FunctionID{Package: "bcrypt", Type: "", Name: "hashpw#2"},
				Raw:      "bcrypt.hashpw(pwd, salt)",
				FilePath: filepath.Join(root, "app.py"),
				Line:     2,
			},
		},
	}

	bcryptHashpw := FunctionDecl{
		ID:        FunctionID{Package: "bcrypt", Type: "", Name: "hashpw#2"},
		FilePath:  filepath.Join(root, "bcrypt.py"),
		StartLine: 1, EndLine: 2,
		OwnerType:  "module",
		Parameters: []FunctionParameter{{Type: "pwd"}, {Type: "salt"}},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{caller, bcryptHashpw}}},
		},
	}

	graph, err := NewBuilderForEcosystem("python", parser).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	for _, res := range graph.EdgeResolutions {
		if res.Kind == EdgeKindPythonSubclassDispatch {
			t.Error("did not expect Python subclass dispatch edges for module-level functions")
		}
	}
}

// TestExpandPythonSubclassDispatch_JavaInterfaceDispatchUnchanged is a regression
// test asserting that Java interface dispatch still works after adding Python subclass
// dispatch. Java decls use OwnerType == "interface"; Python uses "class" with OwnerBases.
func TestExpandPythonSubclassDispatch_JavaInterfaceDispatchUnchanged(t *testing.T) {
	root := t.TempDir()

	controller := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "Controller", Name: "handle#0"},
		FilePath:  filepath.Join(root, "Controller.java"),
		StartLine: 1, EndLine: 5,
		OwnerType: "class",
		OwnerName: "Controller",
		Calls: []FunctionCall{
			{
				Callee:   FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"},
				Raw:      "sink.run()",
				FilePath: filepath.Join(root, "Controller.java"),
				Line:     3,
			},
		},
	}

	ifaceRun := FunctionDecl{
		ID:        FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"},
		FilePath:  filepath.Join(root, "Sink.java"),
		StartLine: 1, EndLine: 2,
		OwnerType:  ownerTypeInterface,
		OwnerName:  "Sink",
		Parameters: []FunctionParameter{},
	}

	implRun := FunctionDecl{
		ID:        FunctionID{Package: "com.dep.impl", Type: "SinkImpl", Name: "run#0"},
		FilePath:  filepath.Join(root, "SinkImpl.java"),
		StartLine: 1, EndLine: 4,
		OwnerType:  "class",
		OwnerName:  "SinkImpl",
		Parameters: []FunctionParameter{},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{controller, ifaceRun, implRun}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	callerKey := controller.ID.String()
	implKey := implRun.ID.String()

	if !containsString(graph.Callers[implKey], callerKey) {
		t.Errorf("Java interface dispatch regression: expected caller %q in callers of %q", callerKey, implKey)
	}

	foundIfaceDispatch := false
	for _, res := range graph.EdgeResolutions {
		if res.Kind == EdgeKindInterfaceDispatch {
			foundIfaceDispatch = true
			break
		}
	}
	if !foundIfaceDispatch {
		t.Error("Java interface dispatch regression: expected EdgeKindInterfaceDispatch edges in graph.EdgeResolutions")
	}
}

// TestPythonParser_ParsesOwnerBases proves the Python parser extracts base class
// names from class definitions (e.g. "class RSAKey(PKey):") into OwnerBases on
// each method declared within that class.
func TestPythonParser_ParsesOwnerBases(t *testing.T) {
	src := `
class PKey:
    def sign(self, data):
        pass

class RSAKey(PKey):
    def sign(self, data):
        return b"rsa-sig"

class Ed25519Key(PKey):
    def sign(self, data):
        return b"ed25519-sig"
`
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pkey.py"), []byte(src), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(root, "paramiko.pkey")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatal("expected at least one file analysis")
	}

	// Index functions by "Type#Name" for easy lookup.
	// The Python parser does NOT append #arity to FunctionID.Name.
	byType := make(map[string]*FunctionDecl)
	for i := range analyses[0].Functions {
		f := &analyses[0].Functions[i]
		byType[f.ID.Type+"#"+f.ID.Name] = f
	}

	// PKey.sign should have no OwnerBases (no parent in this source)
	pkeySign, ok := byType["PKey#sign"]
	if !ok {
		t.Fatalf("PKey.sign not found in parsed functions; keys: %v", keysOf(byType))
	}
	if len(pkeySign.OwnerBases) != 0 {
		t.Errorf("PKey.sign.OwnerBases = %v, want empty", pkeySign.OwnerBases)
	}

	// RSAKey.sign should have OwnerBases = ["PKey"]
	rsaSign, ok := byType["RSAKey#sign"]
	if !ok {
		t.Fatalf("RSAKey.sign not found in parsed functions; keys: %v", keysOf(byType))
	}
	if len(rsaSign.OwnerBases) != 1 || rsaSign.OwnerBases[0] != "PKey" {
		t.Errorf("RSAKey.sign.OwnerBases = %v, want [PKey]", rsaSign.OwnerBases)
	}

	// Ed25519Key.sign should have OwnerBases = ["PKey"]
	edSign, ok := byType["Ed25519Key#sign"]
	if !ok {
		t.Fatalf("Ed25519Key.sign not found in parsed functions; keys: %v", keysOf(byType))
	}
	if len(edSign.OwnerBases) != 1 || edSign.OwnerBases[0] != "PKey" {
		t.Errorf("Ed25519Key.sign.OwnerBases = %v, want [PKey]", edSign.OwnerBases)
	}
}
