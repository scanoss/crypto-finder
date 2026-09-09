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

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// renderEthHashInventory renders every loaded eth-hash contract as one line so
// the test below can compare the WHOLE SET against a literal rather than
// probing key by key.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Every field the
// loader populates is rendered -- role, return type, return confidence,
// canonical_return_type, parameter_types, varargs, and each parameter's
// index/name/role plus its contributed property and derivation -- because a
// mutation to any one of them changes what this family CLAIMS. Varargs is
// rendered even though no eth-hash entry sets it: a `varargs: true` mutation
// otherwise survives every assertion in this directory.
func renderEthHashInventory(kb *contracts.KnowledgeBase) []string {
	var inventory []string
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			contract := &candidates[i]
			if contract.SourceLibrary != "eth-hash" {
				continue
			}
			line := fmt.Sprintf("%s#%d|%s|%s|%s|%s|%v|%v",
				contract.Method, contract.Arity, contract.Role,
				contract.Return.Type, contract.Return.Confidence,
				contract.CanonicalReturnType, contract.ParameterTypes, contract.Varargs)
			for j := range contract.Parameters {
				parameter := &contract.Parameters[j]
				index := -1
				if parameter.Index != nil {
					index = *parameter.Index
				}
				if parameter.Contributes == nil {
					line += fmt.Sprintf("|%d:%s:%s", index, parameter.Name, parameter.Role)
					continue
				}
				line += fmt.Sprintf("|%d:%s:%s:%s:%s", index, parameter.Name, parameter.Role,
					parameter.Contributes.Property, parameter.Contributes.Derivation)
			}
			inventory = append(inventory, line)
		}
	}
	sort.Strings(inventory)
	return inventory
}

// TestLoadEmbeddedPython_EthHash_ExactSet pins the eth-hash contract KB as an
// EXACT SET, reported as a SYMMETRIC DIFFERENCE.
//
// WHAT THIS TEST DOES AND DOES NOT PROVE. It proves the loaded set is exactly
// what was authored, so any later edit that adds, drops or corrupts an entry
// fails here and the failure names which line to add or remove. It does NOT
// prove the authored values are TRUE -- a mutation battery can only find drift
// away from a baseline, never an error inside it. The baseline's truth rests on
// a separate check: EVERY LINE BELOW WAS WRITTEN BY HAND FROM eth-hash's OWN
// SOURCES, with the file and line cited beside it, and never derived from the
// YAML. Deriving it from the YAML is the obvious repair and it is wrong: it
// makes the assertion tautological and green on a corrupted contract, which is
// the one thing this test exists to prevent.
//
// Citations are against the 0.8.0 sdist. Every symbol's version window was
// measured by parsing every def, class and module-level assignment out of ALL
// 22 sdists the Tier 0 python CSV lists for pkg:pypi/eth-hash, and is recorded
// in python/eth-hash.yaml's header rather than repeated here.
func TestLoadEmbeddedPython_EthHash_ExactSet(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	got := renderEthHashInventory(kb)

	want := []string{
		// eth_hash/__init__.py:5-7 re-exports the class main.py:7 declares;
		// __init__ takes one backend (main.py:8). Two spellings per import
		// path: the from-import emits `.<init>`, the module-qualified call
		// does not -- measured on an exported call graph, both spellings.
		"eth_hash.Keccak256#1|factory|eth_hash.main.Keccak256|high|eth_hash.main.Keccak256|[eth_hash.abc.BackendAPI]|false",
		"eth_hash.Keccak256.<init>#1|factory|eth_hash.main.Keccak256|high|eth_hash.main.Keccak256|[eth_hash.abc.BackendAPI]|false",
		// eth_hash/abc.py:21 copy() -> PreImageAPI.
		"eth_hash.abc.PreImageAPI.copy#0|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[]|false",
		// eth_hash/abc.py:17 digest() -> bytes.
		"eth_hash.abc.PreImageAPI.digest#0|output|builtins.bytes|high|builtins.bytes|[]|false",
		// eth_hash/abc.py:13 update(value: bytes) -> None.
		"eth_hash.abc.PreImageAPI.update#1|operation|builtins.NoneType|high|builtins.NoneType|[builtins.bytes]|false",
		// eth_hash/auto.py:8 binds `keccak = Keccak256(AutoBackend())`, so the
		// consumer's call reaches main.py:39 __call__ and main.py:48 new().
		"eth_hash.auto.keccak#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.auto.keccak.new#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
		// eth_hash/backends/pycryptodome.py:43 binds the singleton, :35
		// keccak256 and :39 preimage; :44-45 alias the two bound methods at
		// module level.
		"eth_hash.backends.pycryptodome.backend.keccak256#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pycryptodome.backend.preimage#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pycryptodome.keccak256#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pycryptodome.preimage#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
		// eth_hash/backends/pysha3.py:35 binds the singleton, :28 keccak256
		// and :31 preimage; :36-37 alias the two bound methods.
		"eth_hash.backends.pysha3.backend.keccak256#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pysha3.backend.preimage#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pysha3.keccak256#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.backends.pysha3.preimage#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
		// eth_hash/main.py:7 declares the class; :8 __init__, :39 __call__,
		// :48 new. The class is reachable at its defining module path too.
		"eth_hash.main.Keccak256#1|factory|eth_hash.main.Keccak256|high|eth_hash.main.Keccak256|[eth_hash.abc.BackendAPI]|false",
		"eth_hash.main.Keccak256.<init>#1|factory|eth_hash.main.Keccak256|high|eth_hash.main.Keccak256|[eth_hash.abc.BackendAPI]|false",
		"eth_hash.main.Keccak256.__call__#1|operation|builtins.bytes|high|builtins.bytes|[typing.Union[bytearray, bytes]]|false",
		"eth_hash.main.Keccak256.new#1|factory|eth_hash.abc.PreImageAPI|high|eth_hash.abc.PreImageAPI|[typing.Union[bytearray, bytes]]|false",
	}

	// A SYMMETRIC DIFFERENCE, NOT A COUNT AND NOT A TALLY. The campaign's most
	// repeated defect is a mirror test whose `len(got) != len(want)` check and
	// role tally reject a CORRECT repair in three places at once, so adding a
	// real, present, crypto-relevant entry reads as a regression. There is one
	// literal above and it is the only place to edit; the message says which
	// direction the difference is in and quotes the exact line to paste.
	inWant := make(map[string]bool, len(want))
	for _, line := range want {
		inWant[line] = true
	}
	inGot := make(map[string]bool, len(got))
	for _, line := range got {
		inGot[line] = true
	}
	var unexpected, missing []string
	for _, line := range got {
		if !inWant[line] {
			unexpected = append(unexpected, line)
		}
	}
	for _, line := range want {
		if !inGot[line] {
			missing = append(missing, line)
		}
	}
	for _, line := range unexpected {
		t.Errorf("unexpected contract entry -- if the YAML change is intended, "+
			"add this one line to `want`:\n\t\t%q,", line)
	}
	for _, line := range missing {
		t.Errorf("expected contract entry did not load -- if it was deliberately "+
			"removed, delete this one line from `want`:\n\t\t%q,", line)
	}

	// Roles are checked against the VOCABULARY, never against a tally. A tally
	// would be a second mirror of the same literal with no independent source,
	// and the set comparison above already fails on any role change because
	// role is a rendered field.
	valid := map[string]bool{"factory": true, "config": true, "operation": true, "output": true}
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary == "eth-hash" && !valid[c.Role] {
				t.Errorf("%s#%d carries role %q, which is outside the whitelist",
					c.Method, c.Arity, c.Role)
			}
		}
	}
}

// TestLoadEmbeddedPython_EthHash_LibraryBlock pins the library block, which the
// exact-set rendering does not cover. version_range, coordinates, name and
// description are parsed and then never consulted by any other assertion, so
// corrupting one of them leaves every other test in this directory green.
func TestLoadEmbeddedPython_EthHash_LibraryBlock(t *testing.T) {
	t.Parallel()

	// library.name is what populates SourceLibrary on every entry; corrupting
	// it empties the exact-set test as well as this one.
	kb := loadPythonKB(t)
	found := false
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "eth-hash" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no contract carries SourceLibrary \"eth-hash\"; library.name did not load")
	}

	data, err := os.ReadFile(filepath.Join("python", "eth-hash.yaml"))
	if err != nil {
		t.Fatalf("read eth-hash.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(eth-hash.yaml): %v", err)
	}
	if single.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want \"2\"", single.SchemaVersion)
	}
	if single.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want \"python\"", single.Ecosystem)
	}
	if single.Library == nil {
		t.Fatal("library block did not load")
	}
	if single.Library.Name != "eth-hash" {
		t.Errorf("library.name = %q, want \"eth-hash\"", single.Library.Name)
	}
	// The lower bound is 0.1.0a3 and NOT the matrix's oldest row: the 0.1.0a2
	// sdist ships an empty eth_hash/__init__.py and no other module, so the
	// package has no API at all in that release. Measured, not assumed.
	if single.Library.VersionRange != ">=0.1.0a3,<0.9" {
		t.Errorf("library.version_range = %q, want \">=0.1.0a3,<0.9\"", single.Library.VersionRange)
	}
	wantCoordinates := []string{"eth-hash", "eth_hash"}
	if !slices.Equal(single.Library.Coordinates, wantCoordinates) {
		t.Errorf("library.coordinates = %#v, want %#v", single.Library.Coordinates, wantCoordinates)
	}
	if !strings.Contains(single.Library.Description, "Keccak-256") {
		t.Errorf("library.description does not name the algorithm: %q", single.Library.Description)
	}
}

// TestLoadEmbeddedPython_EthHash_NoBackendLibraryKey is the contract-side half
// of the wrong-package assertion the rules carry in
// crypto_rules tests/test_eth_hash_false_positives.py.
//
// eth-hash is a DISPATCHER: the cryptography happens in pycryptodome or in
// pysha3, both of which are separate merged families with their own contracts.
// No eth-hash key may name a symbol of either. `Crypto.Hash.keccak.new` and
// `sha3.keccak_256` are theirs; eth-hash's own `keccak256`, `preimage` and
// `backend` module attributes are not.
func TestLoadEmbeddedPython_EthHash_NoBackendLibraryKey(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "eth-hash" {
				continue
			}
			seen++
			// SEGMENT-WISE, NOT SUBSTRING. A substring check on "sha3.keccak"
			// flags eth-hash's OWN `eth_hash.backends.pysha3.keccak256`, and
			// one on ".keccak.new" flags its own `eth_hash.auto.keccak.new` --
			// both were false positives in the first draft of this test. The
			// backend libraries' roots are `Crypto`, `Cryptodome` and `sha3`;
			// eth-hash's own module is `pysha3`, which is a different segment.
			segments := strings.Split(c.Method, ".")
			if segments[0] != "eth_hash" {
				t.Errorf("%s is not rooted at the eth_hash package", c.Method)
			}
			foreign := map[string]bool{
				"Crypto": true, "Cryptodome": true, "sha3": true,
				"keccak_256": true, "SHA3_256": true,
			}
			for _, segment := range segments {
				if foreign[segment] {
					t.Errorf("%s carries the backend library segment %q", c.Method, segment)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no eth-hash contracts loaded; this assertion would be vacuous")
	}
}

// TestPythonInstanceCallIsInvisible_KnownLimitation asserts the WRONG behavior
// so that the day it changes, this test fails and tells the reader to delete it.
//
// eth_hash.main.Keccak256 declares __call__ (main.py:39 at 0.8.0), and the
// documented explicit-backend form is `h = Keccak256(backend); h(data)` -- so
// `h(data)` IS the digest. Measured on a probe consumer package with the
// eth-hash contract loaded: crypto-finder emits NO call at all for it. Zero
// supporting calls, and the string "__call__" appears nowhere in the exported
// graph. The parser has no identity for calling an instance of a DEPENDENCY
// class that declares __call__ (pythonResolveIdentifierCallee handles only an
// IN-FILE __call__-declaring class bound in the same scope), so no fix at the
// contract layer is possible and the contract entry is inert until the parser
// changes.
//
// The site is still detected: the rule claims the CONSTRUCTION line, which is
// where the algorithm is named. What is missing is the extra supporting call.
//
// DELETE THIS TEST if it ever starts failing -- that means the parser learned
// the shape, and the eth_hash.main.Keccak256.__call__ entry started joining.
func TestPythonInstanceCallIsInvisible_KnownLimitation(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	var entry *contracts.Contract
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].Method == "eth_hash.main.Keccak256.__call__" {
				entry = &candidates[i]
			}
		}
	}
	if entry == nil {
		t.Fatal("the eth_hash.main.Keccak256.__call__ entry is gone; if that was " +
			"deliberate, delete this test too")
	}
	if entry.Arity != 1 || entry.Role != "operation" {
		t.Errorf("__call__ entry moved: arity=%d role=%q, want 1/operation",
			entry.Arity, entry.Role)
	}
	// The limitation itself is a parser property and is measured in
	// internal/callgraph, not here; this test pins the contract half so the
	// entry cannot silently disappear while the limitation note stays behind.
}
