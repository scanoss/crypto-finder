// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import "testing"

// AN ALIASED PYTHON from-IMPORT MUST EMIT THE LIBRARY'S OWN SYMBOL NAME, NEVER
// THE CONSUMER'S ALIAS.
//
// `analysis.Imports` records only the module path, so splicing the LOCAL
// binding into the callee key produced the consumer's spelling:
// `from eth_hash.auto import keccak as kek; kek(d)` emitted
// `eth_hash.auto.kek`. No contract can enumerate a consumer's aliases, so
// every aliased call site loaded a key that joined nothing -- and it looked
// exactly like having no contract at all.
//
// This is not a corner case. eth-utils 1.9.5 crypto.py:3 writes
// `from eth_hash.auto import keccak as keccak_256`, and eth-utils is how web3
// and most of the Ethereum Python stack reach eth-hash. Measured over
// crypto_rules' own 170-file python fixture corpus with the merged rule set,
// the fix moves 33 resolution sites across FOUR already-merged families --
// coincurve (`PrivateKey as DeepPrivateKey`), eth-account
// (`Account as EthAccount`), python-jose (`jwt as jose_jwt`) and authlib
// (`jwt as authlib_jwt`) -- from an alias-shaped key to the library's own,
// with the DISTINCT occurrence_key set byte-identical before and after
// (798/798: nothing gained, nothing lost).
//
// A corpus cannot contradict a shape it does not contain, so each shape the
// change touches gets its own unit assertion below, and each non-aliased shape
// is asserted UNCHANGED beside it.

// TestPythonAliasedFromImport_FreeFunction_EmitsExportedName covers the shape
// eth-utils writes.
func TestPythonAliasedFromImport_FreeFunction_EmitsExportedName(t *testing.T) {
	src := `from eth_hash.auto import keccak as keccak_256

def digest(data):
    return keccak_256(data)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "digest")
	if fn == nil {
		t.Fatal("digest function not found")
	}
	call := findPythonCallByMethod(fn, "keccak")
	if call == nil {
		t.Fatalf("no call resolved to the exported name `keccak`; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "eth_hash.auto"; got != want {
		t.Errorf("Package = %q, want %q", got, want)
	}
	if got, want := call.Callee.Name, "keccak"; got != want {
		t.Errorf("Name = %q, want %q (the alias `keccak_256` must not reach the key)", got, want)
	}
}

// TestPythonAliasedFromImport_MethodOnAliasedModule covers the python-jose and
// authlib shape: the ALIASED name lands in the PACKAGE position because a
// from-imported module is qualified with its own name.
func TestPythonAliasedFromImport_MethodOnAliasedModule(t *testing.T) {
	src := `from jose import jwt as jose_jwt

def issue(claims):
    return jose_jwt.encode(claims, "secret", algorithm="RS256")
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "issue")
	if fn == nil {
		t.Fatal("issue function not found")
	}
	call := findPythonCallByMethod(fn, "encode")
	if call == nil {
		t.Fatalf("encode call not found; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "jose.jwt"; got != want {
		t.Errorf("Package = %q, want %q (the alias `jose_jwt` must not reach the key)", got, want)
	}
}

// TestPythonAliasedFromImport_Class_EmitsExportedTypeAndInit covers the
// coincurve shape (`PrivateKey as DeepPrivateKey`) and asserts the `<init>`
// suffix survives, which requires the TYPE-ness to follow the ORIGINAL name:
// `from m import Thing as helper` binds a class even though the alias is
// lowercase.
func TestPythonAliasedFromImport_Class_EmitsExportedTypeAndInit(t *testing.T) {
	src := `from coincurve.keys import PrivateKey as DeepPrivateKey

def make(secret):
    return DeepPrivateKey(secret)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "make")
	if fn == nil {
		t.Fatal("make function not found")
	}
	call := findPythonCallByMethod(fn, constructorMethodName)
	if call == nil {
		t.Fatalf("constructor call not found; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "coincurve.keys"; got != want {
		t.Errorf("Package = %q, want %q", got, want)
	}
	if got, want := call.Callee.Type, "PrivateKey"; got != want {
		t.Errorf("Type = %q, want %q (the alias must not reach the key)", got, want)
	}
}

// TestPythonAliasedFromImport_LowercaseAliasOfAClass pins the type-ness rule
// directly: the alias is lowercase, so keying type-ness on the LOCAL name
// would drop the `<init>` suffix and the constructor contract would not join.
func TestPythonAliasedFromImport_LowercaseAliasOfAClass(t *testing.T) {
	src := `from coincurve.keys import PrivateKey as maker

def make(secret):
    return maker(secret)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "make")
	if fn == nil {
		t.Fatal("make function not found")
	}
	call := findPythonCallByMethod(fn, constructorMethodName)
	if call == nil {
		t.Fatalf("constructor call not found; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Type, "PrivateKey"; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
}

// TestPythonAliasedFromImport_UppercaseAliasOfAFunction is the MISSING
// DIRECTION of the type-ness rule, and it is the one the first revision of this
// change got wrong.
//
// `recordImportedPythonSymbol` runs first and has only the ALIAS to go on, so it
// sets `ImportedTypes` from the alias's own capitalisation. The first revision
// only ADDED on a capitalised original and never CLEARED on a lowercase one, so
// a capitalised alias of a lowercase function kept its constructor binding and
// the key gained an `<init>` the library has no constructor for. Measured on
// that revision: `from eth_hash.auto import keccak as Keccak; Keccak(d)` emitted
// `eth_hash.auto.keccak.<init>(?): keccak` while the contract declares
// `eth_hash.auto.keccak`, so the site joined nothing; with the clear in place
// the same probe emits
// `eth_hash.auto.keccak(typing.Union[bytearray, bytes]): builtins.bytes`.
//
// The 170-file python fixture corpus contains this shape NOWHERE, so it cannot
// contradict it: before and after are byte-identical there (317 resolution sites
// and 798 distinct occurrence keys either way). A corpus cannot refute a shape
// it does not hold, which is why this assertion is a unit test and not a corpus
// measurement.
func TestPythonAliasedFromImport_UppercaseAliasOfAFunction(t *testing.T) {
	src := `from eth_hash.auto import keccak as Keccak

def digest(data):
    return Keccak(data)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "digest")
	if fn == nil {
		t.Fatal("digest function not found")
	}
	call := findPythonCallByMethod(fn, "keccak")
	if call == nil {
		t.Fatalf("no call resolved to the exported name `keccak`; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "eth_hash.auto"; got != want {
		t.Errorf("Package = %q, want %q", got, want)
	}
	if got, want := call.Callee.Name, "keccak"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	// THE ASSERTION THAT WAS MISSING. A capitalised alias must not make a
	// FUNCTION look like a constructor.
	if call.Callee.Type != "" {
		t.Errorf("Type = %q, want empty: `keccak` is a function, and a capitalised "+
			"ALIAS must not bind it as a type (that appends an `<init>` no "+
			"contract declares)", call.Callee.Type)
	}
	if call.Callee.Name == constructorMethodName {
		t.Errorf("Name = %q: the key gained an `<init>` from the alias's capitalisation",
			call.Callee.Name)
	}
}

// TestPythonAliasedFromImport_ChainedAttribute covers `kek.new(d)` -- the
// method-on-an-aliased-instance shape eth-hash's incremental API uses.
func TestPythonAliasedFromImport_ChainedAttribute(t *testing.T) {
	src := `from eth_hash.auto import keccak as kek

def incremental(data):
    return kek.new(data)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "incremental")
	if fn == nil {
		t.Fatal("incremental function not found")
	}
	call := findPythonCallByMethod(fn, "new")
	if call == nil {
		t.Fatalf("new call not found; calls: %s", pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "eth_hash.auto.keccak"; got != want {
		t.Errorf("Package = %q, want %q (the alias `kek` must not reach the key)", got, want)
	}
}

// TestPythonUnaliasedFromImport_Unchanged is the other half of the assertion:
// every shape that already resolved correctly must be untouched. Without this
// the tests above cannot distinguish "aliases are now resolved" from "the
// local name is always discarded", and the second would be a regression.
func TestPythonUnaliasedFromImport_Unchanged(t *testing.T) {
	src := `from eth_hash.auto import keccak
from coincurve.keys import PrivateKey
from Crypto.Cipher import AES
import eth_hash.auto as mod

def digest(data):
    return keccak(data)

def make(secret):
    return PrivateKey(secret)

def encrypt(key, mode):
    return AES.new(key, mode)

def via_module_alias(data):
    return mod.keccak(data)
`
	fns := parsePythonInline(t, src)

	for _, tc := range []struct {
		fn, method, pkg, typ string
	}{
		// A plain from-import: no alias recorded, so nothing is substituted.
		{"digest", "keccak", "eth_hash.auto", ""},
		{"make", constructorMethodName, "coincurve.keys", "PrivateKey"},
		// A from-imported MODULE is qualified with its own name, as before.
		{"encrypt", "new", "Crypto.Cipher.AES", ""},
		// `import X as Y` is NOT a from-import: PythonFromImportOriginals is
		// never populated for it, and the module path already replaces the
		// alias, so this shape must be untouched.
		{"via_module_alias", "keccak", "eth_hash.auto", ""},
	} {
		fn := findPythonFuncByName(fns, tc.fn)
		if fn == nil {
			t.Errorf("%s: function not found", tc.fn)
			continue
		}
		call := findPythonCallByMethod(fn, tc.method)
		if call == nil {
			t.Errorf("%s: no %s call; calls: %s", tc.fn, tc.method, pythonCallKeys(fn))
			continue
		}
		if call.Callee.Package != tc.pkg {
			t.Errorf("%s: Package = %q, want %q", tc.fn, call.Callee.Package, tc.pkg)
		}
		if call.Callee.Type != tc.typ {
			t.Errorf("%s: Type = %q, want %q", tc.fn, call.Callee.Type, tc.typ)
		}
	}
}

// TestPythonNestedDefShadowingIsInvisible_KnownLimitation ASSERTS THE WRONG
// BEHAVIOR so that the day it changes, this test fails and tells the reader to
// delete it.
//
// A nested `def` that shadows an imported name is NOT seen by the binding
// layer: a nested def is not a separate FunctionDecl, so a pass that walks a
// decl's own scope never learns the name was rebound, and the call still
// resolves to the import. That is a PRE-EXISTING property and NOT a
// consequence of the alias fix -- measured on origin/main with the identical
// source, which resolves the shadowed call to `eth_hash.auto.kek` (package
// `eth_hash.auto`, name `kek`). The alias fix only corrects the last segment,
// so the same source now resolves to `eth_hash.auto.keccak`: equally wrong
// about the shadowing, and no more wrong than before.
//
// A rebinding that IS a plain assignment is handled -- pythonResolveIdentifierCallee
// consults the scope's binding layer -- so this is specific to the nested-def
// shape, which no fix at this layer can reach.
//
// DELETE THIS TEST if it ever starts failing: that means the parser learned to
// see a nested def's bindings, and the shadowed call correctly stopped
// resolving to the import.
func TestPythonNestedDefShadowingIsInvisible_KnownLimitation(t *testing.T) {
	src := `from eth_hash.auto import keccak as kek

def digest(data):
    def kek(x):
        return x
    return kek(data)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "digest")
	if fn == nil {
		t.Fatal("digest function not found")
	}
	call := findPythonCallByMethod(fn, "keccak")
	if call == nil {
		t.Fatalf("the shadowed call no longer resolves to the import -- if the "+
			"parser learned nested-def bindings, DELETE this test; calls: %s",
			pythonCallKeys(fn))
	}
	if got, want := call.Callee.Package, "eth_hash.auto"; got != want {
		t.Errorf("Package = %q, want %q", got, want)
	}
}

// TestPythonAliasedFromImport_ShadowedByAnAssignment is the shape that IS
// handled, asserted beside the limitation above so the two are not confused: a
// plain assignment in the same scope rebinds the name and the call must NOT
// resolve to the import.
func TestPythonAliasedFromImport_ShadowedByAnAssignment(t *testing.T) {
	src := `from eth_hash.auto import keccak as kek

def digest(data, other):
    kek = other
    return kek(data)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "digest")
	if fn == nil {
		t.Fatal("digest function not found")
	}
	if call := findPythonCallByMethod(fn, "keccak"); call != nil {
		t.Errorf("an assignment-shadowed name resolved to the import: %s.%s",
			call.Callee.Package, call.Callee.Name)
	}
}

// pythonCallKeys renders a decl's resolved callees, so a failure above names
// what WAS produced instead of only what was expected.
func pythonCallKeys(fn *FunctionDecl) string {
	out := ""
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if i > 0 {
			out += ", "
		}
		out += c.Callee.Package + "|" + c.Callee.Type + "|" + c.Callee.Name
	}
	if out == "" {
		return "(none)"
	}
	return out
}
