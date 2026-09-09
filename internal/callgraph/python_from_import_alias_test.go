// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A `from X import Y as Z` used to be keyed on the CONSUMER'S ALIAS Z rather
// than on the library's own symbol Y, so `from py_ecc.bn128 import pairing as
// bn_p; bn_p(q, p)` emitted the callee `py_ecc.bn128.bn_p` — a key no contract
// can hold and no entry-point synthesis can join. A renaming import is
// ordinary Python, and for py-ecc it is unavoidable: its four curve-flavor
// modules export BYTE-IDENTICAL names (`pairing`, `final_exponentiate`, `add`,
// `multiply`, ...) over two different curves, so a consumer importing two
// flavors in one file MUST alias at least one of them. The cross-variant case
// was therefore exactly the case that could not join.
//
// The parser records the original module-side name in
// FileAnalysis.PythonFromImportOriginals and keys on it. These tests pin both
// halves: the renamed forms resolve to the library's spelling, and the
// UNALIASED forms are unchanged — the second is what makes this a safe fix
// rather than a rename of the problem.
//
// THE PARSER CHANGE ITSELF IS NOT IN THIS BRANCH, and these six tests are kept
// deliberately without it. `pypi:eth-hash` fixes the same defect in the same
// two files, and its fix strictly SUBSUMES the one that was here — measured in
// both directions on isolated worktrees: all six of these pass against its
// parser, while two of its nine fail against the one that was here. So it owns
// the shared parser and merges first, and this file contributes six pins it did
// not write.
//
// THAT FIX IS NOW ON MAIN and all six of these pass against it. The parser it
// pins is `recordPythonFromImportOriginal` /
// `FileAnalysis.PythonFromImportOriginals` in
// internal/callgraph/python_parser.go, not anything this branch changes — this
// file adds no parser code and only asserts behavior.
//
// MAIN'S VERSION GOES FURTHER than the one these tests were first written
// against: it also clears the type binding for an aliased import
// (`delete(analysis.ImportedTypes, alias)`), so an upper-cased alias of a
// lower-case FUNCTION no longer gains a spurious `.<init>` — a case the earlier
// draft left open and which is therefore NOT asserted here. Main's own
// `python_parser_alias_key_test.go` owns that case, along with the module-level
// and nested-`def` shadow limitations; do not duplicate them here.

func parsePythonSource(t *testing.T, src string) *FileAnalysis {
	t.Helper()
	const name = "app.py"
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "consumer")
	if err != nil {
		t.Fatalf("ParseDirectory(%s): %v", dir, err)
	}
	for _, a := range analyses {
		if filepath.Base(a.FilePath) == name {
			return a
		}
	}
	t.Fatalf("ParseDirectory(%s) produced no analysis for %s", dir, name)
	return nil
}

// calleeKeys returns "package.name" (or "package.Type.name") for every call in
// every function of the analysis, so an assertion can name the key it wants.
func calleeKeys(analysis *FileAnalysis) []string {
	var keys []string
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for j := range fn.Calls {
			id := fn.Calls[j].Callee
			key := id.Package
			if id.Type != "" {
				key += "." + id.Type
			}
			if id.Name != "" {
				key += "." + id.Name
			}
			keys = append(keys, key)
		}
	}
	return keys
}

func hasKey(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// TestPythonFromImportAlias_FreeFunctionKeysOnTheOriginalName is the case that
// motivated the change: a renamed free-function import.
func TestPythonFromImportAlias_FreeFunctionKeysOnTheOriginalName(t *testing.T) {
	analysis := parsePythonSource(t, `
from py_ecc.bn128 import pairing as bn_pairing
from py_ecc.bls12_381 import pairing as bls_pairing


def check(g1, g2):
    a = bn_pairing(g2, g1)
    b = bls_pairing(g2, g1)
    return a, b
`)
	keys := calleeKeys(analysis)
	for _, want := range []string{
		"py_ecc.bn128.pairing",
		"py_ecc.bls12_381.pairing",
	} {
		if !hasKey(keys, want) {
			t.Errorf("missing callee %q; got %v", want, keys)
		}
	}
	// The alias must NOT survive into the key. Both flavors alias to a
	// different local name, and either leaking would be unjoinable.
	for _, unwanted := range []string{
		"py_ecc.bn128.bn_pairing",
		"py_ecc.bls12_381.bls_pairing",
	} {
		if hasKey(keys, unwanted) {
			t.Errorf("callee %q is keyed on the consumer's alias, which no contract "+
				"can join; got %v", unwanted, keys)
		}
	}
}

// TestPythonFromImportAlias_ClassMethodKeysOnTheOriginalName covers the second
// shape: a renamed CLASS import, whose method calls are keyed
// `<module>.<Class>.<method>`.
func TestPythonFromImportAlias_ClassMethodKeysOnTheOriginalName(t *testing.T) {
	analysis := parsePythonSource(t, `
from py_ecc.bls.ciphersuites import G2ProofOfPossession as PoP
from py_ecc.bls import G2Basic as Basic


def sign_both(sk, msg):
    a = PoP.Sign(sk, msg)
    b = Basic.Sign(sk, msg)
    return a, b
`)
	keys := calleeKeys(analysis)
	for _, want := range []string{
		"py_ecc.bls.ciphersuites.G2ProofOfPossession.Sign",
		"py_ecc.bls.G2Basic.Sign",
	} {
		if !hasKey(keys, want) {
			t.Errorf("missing callee %q; got %v", want, keys)
		}
	}
	for _, unwanted := range []string{
		"py_ecc.bls.ciphersuites.PoP.Sign",
		"py_ecc.bls.Basic.Sign",
	} {
		if hasKey(keys, unwanted) {
			t.Errorf("callee %q is keyed on the consumer's alias; got %v", unwanted, keys)
		}
	}
}

// TestPythonFromImportAlias_UnaliasedImportsAreUnchanged is the regression half
// (5.4). Every previously working shape must still produce the identical key:
// a plain `from X import Y`, a parenthesised group, a star import's sibling,
// and the module-attribute spelling that never went through the alias map at
// all.
func TestPythonFromImportAlias_UnaliasedImportsAreUnchanged(t *testing.T) {
	analysis := parsePythonSource(t, `
import hashlib
import py_ecc.optimized_bn128
from py_ecc.bn128 import final_exponentiate, pairing
from py_ecc.bls import (
    G2Basic,
    G2ProofOfPossession,
)
from py_ecc.secp256k1 import ecdsa_raw_sign


def everything(g1, g2, sk, msg, h, priv):
    a = pairing(g2, g1)
    b = final_exponentiate(a)
    c = G2ProofOfPossession.Sign(sk, msg)
    d = G2Basic.Sign(sk, msg)
    e = ecdsa_raw_sign(h, priv)
    f = py_ecc.optimized_bn128.pairing(g2, g1)
    g = hashlib.sha256(msg)
    return a, b, c, d, e, f, g
`)
	keys := calleeKeys(analysis)
	for _, want := range []string{
		"py_ecc.bn128.pairing",
		"py_ecc.bn128.final_exponentiate",
		"py_ecc.bls.G2ProofOfPossession.Sign",
		"py_ecc.bls.G2Basic.Sign",
		"py_ecc.secp256k1.ecdsa_raw_sign",
		"py_ecc.optimized_bn128.pairing",
		// A stdlib import through the same code path: `import hashlib` binds
		// hashlib to itself, so no alias is recorded and the key is unchanged.
		"hashlib.sha256",
	} {
		if !hasKey(keys, want) {
			t.Errorf("previously working callee %q regressed; got %v", want, keys)
		}
	}
}

// TestPythonFromImportAlias_ModuleAliasIsNotRewritten pins the boundary of the
// change. `import X as Y` and `from P import module as Y` bind a MODULE, not a
// symbol, and `Imports` already maps the local name to the module PATH for
// those — so rewriting the leaf there would corrupt a key that was correct.
// Only `from X import symbol as alias` is rewritten.
func TestPythonFromImportAlias_ModuleAliasIsNotRewritten(t *testing.T) {
	analysis := parsePythonSource(t, `
import py_ecc.bn128 as bn
from py_ecc import bn128 as bn2


def use(g1, g2):
    a = bn.pairing(g2, g1)
    b = bn2.pairing(g2, g1)
    return a, b
`)
	keys := calleeKeys(analysis)
	// `import py_ecc.bn128 as bn` binds the module; the key is the module path
	// plus the called name, with no `bn` anywhere in it.
	if !hasKey(keys, "py_ecc.bn128.pairing") {
		t.Errorf("module alias `import py_ecc.bn128 as bn` did not resolve to "+
			"py_ecc.bn128.pairing; got %v", keys)
	}
	for _, k := range keys {
		if k == "py_ecc.bn.pairing" || k == "py_ecc.bn2.pairing" {
			t.Errorf("a module alias leaked into the key as %q; got %v", k, keys)
		}
	}
}

// TestPythonFromImportAlias_FirstBindingStillWins pins the precedence rule
// recordImportedPythonSymbol documents: the first binding in document order
// wins, and adding the original-name map must not change that. A second import
// of the same LOCAL name is ignored, alias or not.
func TestPythonFromImportAlias_FirstBindingStillWins(t *testing.T) {
	analysis := parsePythonSource(t, `
from py_ecc.bn128 import pairing as p
from py_ecc.bls12_381 import pairing as p


def use(g1, g2):
    return p(g2, g1)
`)
	keys := calleeKeys(analysis)
	if !hasKey(keys, "py_ecc.bn128.pairing") {
		t.Errorf("the FIRST binding should win, giving py_ecc.bn128.pairing; got %v", keys)
	}
	if hasKey(keys, "py_ecc.bls12_381.pairing") {
		t.Errorf("the second binding of the same local name should be ignored; got %v", keys)
	}
}

// TestPythonFromImportAlias_ConsumerLocalSymbolIsUnaffected pins that the
// rewrite is scoped to imported names. A consumer's OWN function with a name
// that happens to match an alias in the map must keep its own package.
func TestPythonFromImportAlias_ConsumerLocalSymbolIsUnaffected(t *testing.T) {
	analysis := parsePythonSource(t, `
from py_ecc.bn128 import pairing as helper


def helper_local(a, b):
    return a * b


def use(g1, g2):
    a = helper(g2, g1)
    b = helper_local(1, 2)
    return a, b
`)
	keys := calleeKeys(analysis)
	if !hasKey(keys, "py_ecc.bn128.pairing") {
		t.Errorf("the aliased import did not resolve; got %v", keys)
	}
	for _, k := range keys {
		if k == "py_ecc.bn128.helper_local" || k == "py_ecc.bn128.pairing_local" {
			t.Errorf("a consumer-local function was keyed into the library's package "+
				"as %q; got %v", k, keys)
		}
	}
}
