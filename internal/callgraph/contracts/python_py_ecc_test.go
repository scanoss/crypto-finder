// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// py-ecc is the Ethereum Foundation's pure-python elliptic-curve library. Its
// contract is keyed in TWO module spellings per ciphersuite method because the
// Python call-graph key follows the CONSUMER'S IMPORT: `from py_ecc.bls import
// G2ProofOfPossession` emits `py_ecc.bls.G2ProofOfPossession.Sign` while
// `from py_ecc.bls.ciphersuites import G2ProofOfPossession` emits
// `py_ecc.bls.ciphersuites.G2ProofOfPossession.Sign`, and neither key resolves
// the other.
//
// THIS IS AN EXACT-SET COMPARISON REPORTED AS A SYMMETRIC DIFFERENCE. A per-key
// subset assertion cannot see an entry that should not be there, an entry that
// was dropped, or a field that was corrupted. And a comparison reported as
// `len(got) != len(want)` plus an index-by-index diff turns ONE legitimate
// addition into a cascade of off-by-one errors down the whole list, which is the
// most repeated defect on this campaign — five families, four ecosystems. This
// one names what is MISSING and what is UNEXPECTED, and quotes the exact literal
// to paste for an intended addition.
//
// THE EXPECTATION IS SOURCED FROM THE LIBRARY, NOT FROM THE YAML, and that
// distinction is the whole point. `pyEccAPI` below is a hand-written table of
// py-ecc's OWN declarations with a `src` citation per row, read from the sdists;
// the two module spellings and the three ciphersuite classes are then expanded
// mechanically, because the SHAPE of the key set is a fact about how the Python
// parser keys imports rather than a fact about py-ecc. Deriving the expectation
// from the contract file instead would make this assertion tautological and
// green on a corrupted contract, which is the one thing it exists to prevent.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE IS
// TRUE. Every row's `src` citation is the baseline's own evidence, and the
// version windows in the contract header were resolved against ALL 32 published
// sdists by a script rather than reasoned about. Vacuity and truth are separate
// gates.

const pyEccLibrary = "py-ecc"

// The three published ciphersuite classes, from `py_ecc/bls/__init__.py`, which
// re-exports exactly these three and nothing else in every release 2.0.0 -
// 9.0.0b1.
var pyEccCiphersuites = []string{"G2Basic", "G2MessageAugmentation", "G2ProofOfPossession"}

// The two module paths a consumer can reach a ciphersuite class through: the
// `py_ecc.bls` root re-export and the `py_ecc.bls.ciphersuites` defining module.
var pyEccCiphersuiteModules = []string{"py_ecc.bls", "py_ecc.bls.ciphersuites"}

// pyEccEntry is one declaration read from py-ecc's own source.
type pyEccEntry struct {
	method     string // the key, or the bare attribute name for a ciphersuite method
	arity      int
	role       string
	returnType string
	confidence string
	params     []string
	src        string // file:line in the archive the declaration was read from
}

// pyEccSharedCiphersuiteAPI: methods every ciphersuite carries, whether declared
// on BaseG2Ciphersuite or overridden. Expanded over the three classes and both
// module spellings.
var pyEccSharedCiphersuiteAPI = []pyEccEntry{
	{
		"KeyGen", 2, "factory", "builtins.int", "high",
		[]string{"builtins.bytes", "builtins.bytes"},
		"8.0.0 py_ecc/bls/ciphersuites.py:101",
	},
	{
		"KeyGen", 1, "factory", "builtins.int", "low",
		[]string{"builtins.bytes"},
		"2.0.0 py_ecc/bls/ciphersuites.py:53",
	},
	{
		"SkToPk", 1, "factory", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.int"},
		"8.0.0 py_ecc/bls/ciphersuites.py:87",
	},
	{
		"PrivToPub", 1, "factory", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.int"},
		"2.0.0 py_ecc/bls/ciphersuites.py:49 (2.0.0 ONLY)",
	},
	{
		"Sign", 2, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.int", "builtins.bytes"},
		"8.0.0 py_ecc/bls/ciphersuites.py:249",
	},
	{
		"Verify", 3, "operation", "builtins.bool", "high",
		[]string{"eth_typing.BLSPubkey", "builtins.bytes", "eth_typing.BLSSignature"},
		"8.0.0 py_ecc/bls/ciphersuites.py:253",
	},
	{
		"Aggregate", 1, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.list"},
		"8.0.0 py_ecc/bls/ciphersuites.py:182",
	},
	{
		"AggregateVerify", 3, "operation", "builtins.bool", "high",
		[]string{"builtins.list", "builtins.list", "eth_typing.BLSSignature"},
		"8.0.0 py_ecc/bls/ciphersuites.py:258",
	},
	{
		"AggregateVerify", 2, "operation", "builtins.bool", "low",
		[]string{"builtins.list", "eth_typing.BLSSignature"},
		"2.0.0 py_ecc/bls/ciphersuites.py:126 (the `pairs` era)",
	},
}

// pyEccPopOnlyAPI: declared on G2ProofOfPossession ONLY. Neither G2Basic nor
// G2MessageAugmentation declares any of them in any release.
var pyEccPopOnlyAPI = []pyEccEntry{
	{
		"FastAggregateVerify", 3, "operation", "builtins.bool", "high",
		[]string{"builtins.list", "builtins.bytes", "eth_typing.BLSSignature"},
		"8.0.0 py_ecc/bls/ciphersuites.py:359",
	},
	{
		"PopProve", 1, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.int"},
		"8.0.0 py_ecc/bls/ciphersuites.py:334",
	},
	{
		"PopVerify", 2, "operation", "builtins.bool", "high",
		[]string{"eth_typing.BLSPubkey", "eth_typing.BLSSignature"},
		"8.0.0 py_ecc/bls/ciphersuites.py:339",
	},
}

// pyEccFlatAPI: fully-qualified keys that are not a ciphersuite method. The
// era-1 free functions carry two spellings (`py_ecc.bls` re-export and
// `py_ecc.bls.api` defining module) and are listed individually; everything else
// has exactly one reachable module path.
var pyEccFlatAPI = []pyEccEntry{
	// ── era 1, py_ecc/bls/api.py, 1.6.0 - 1.7.1 ──
	{
		"py_ecc.bls.sign", 3, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.bytes", "builtins.int", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:36",
	},
	{
		"py_ecc.bls.api.sign", 3, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.bytes", "builtins.int", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:36",
	},
	{
		"py_ecc.bls.verify", 4, "operation", "builtins.bool", "high",
		[]string{"builtins.bytes", "eth_typing.BLSPubkey", "eth_typing.BLSSignature", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:50",
	},
	{
		"py_ecc.bls.api.verify", 4, "operation", "builtins.bool", "high",
		[]string{"builtins.bytes", "eth_typing.BLSPubkey", "eth_typing.BLSSignature", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:50",
	},
	{
		"py_ecc.bls.verify_multiple", 4, "operation", "builtins.bool", "high",
		[]string{"builtins.list", "builtins.list", "eth_typing.BLSSignature", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:83",
	},
	{
		"py_ecc.bls.api.verify_multiple", 4, "operation", "builtins.bool", "high",
		[]string{"builtins.list", "builtins.list", "eth_typing.BLSSignature", "builtins.int"},
		"1.6.0 py_ecc/bls/api.py:83",
	},
	{
		"py_ecc.bls.aggregate_signatures", 1, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.list"},
		"1.6.0 py_ecc/bls/api.py:69",
	},
	{
		"py_ecc.bls.api.aggregate_signatures", 1, "operation", "eth_typing.BLSSignature", "high",
		[]string{"builtins.list"},
		"1.6.0 py_ecc/bls/api.py:69",
	},
	{
		"py_ecc.bls.aggregate_pubkeys", 1, "operation", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.list"},
		"1.6.0 py_ecc/bls/api.py:76",
	},
	{
		"py_ecc.bls.api.aggregate_pubkeys", 1, "operation", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.list"},
		"1.6.0 py_ecc/bls/api.py:76",
	},
	{
		"py_ecc.bls.privtopub", 1, "factory", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.int"},
		"1.6.0 py_ecc/bls/api.py:46",
	},
	{
		"py_ecc.bls.api.privtopub", 1, "factory", "eth_typing.BLSPubkey", "high",
		[]string{"builtins.int"},
		"1.6.0 py_ecc/bls/api.py:46",
	},

	// ── hash-to-curve. ONE spelling: `py_ecc/bls/__init__.py` re-exports the
	// three ciphersuite classes and nothing else, so there is no shallower path.
	{
		"py_ecc.bls.hash_to_curve.hash_to_G2", 3, "operation", "py_ecc.typing.G2Uncompressed", "high",
		[]string{"builtins.bytes", "builtins.bytes", "builtins.object"},
		"8.0.0 py_ecc/bls/hash_to_curve.py:38",
	},
	{
		"py_ecc.bls.hash_to_curve.hash_to_G2", 2, "operation", "py_ecc.typing.G2Uncompressed", "high",
		[]string{"builtins.bytes", "builtins.bytes"},
		"2.0.0 py_ecc/bls/hash_to_curve.py:26 (arity 2 at 2.0.0 ONLY; hash_function lands in 3.0.0)",
	},
	{
		"py_ecc.bls.hash_to_curve.hash_to_G1", 3, "operation", "py_ecc.typing.G1Uncompressed", "high",
		[]string{"builtins.bytes", "builtins.bytes", "builtins.object"},
		"8.0.0 py_ecc/bls/hash_to_curve.py:107 (>= 8.0.0b1 only)",
	},

	// ── pairings. The MODULE PATH names the curve: the four flavors export
	// byte-identical names over two different curves, so no entry is shared.
	{
		"py_ecc.bn128.pairing", 2, "operation", "py_ecc.fields.bn128_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/bn128/bn128_pairing.py:109",
	},
	{
		"py_ecc.bn128.final_exponentiate", 1, "operation", "py_ecc.fields.bn128_FQ12", "high",
		[]string{"py_ecc.fields.bn128_FQ12"},
		"1.1.0 py_ecc/bn128/bn128_pairing.py:73 (8.0.0 :117; NOT defined at all below 1.1.0)",
	},
	{
		"py_ecc.optimized_bn128.pairing", 2, "operation", "py_ecc.fields.optimized_bn128_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/optimized_bn128/optimized_pairing.py:228",
	},
	{
		"py_ecc.optimized_bn128.final_exponentiate", 1, "operation", "py_ecc.fields.optimized_bn128_FQ12", "high",
		[]string{"py_ecc.fields.optimized_bn128_FQ12"},
		// THIS ROW IS THE RE-EXPORT PATH, so its first version is the first
		// version `__init__.py` binds the name — 1.1.0, not 1.0.0. 1.0.0's
		// `py_ecc/optimized_bn128/__init__.py:3` reads
		// `from .optimized_pairing import pairing` and nothing else; 1.1.0 adds
		// `, final_exponentiate`. The DEFINING module has it at 1.0.0:112, which
		// is what the deep row below cites. Swept over all 32 sdists.
		"1.1.0 py_ecc/optimized_bn128/__init__.py:3 (defined at 1.0.0 optimized_pairing.py:112, 8.0.0 :242)",
	},
	{
		"py_ecc.bls12_381.pairing", 2, "operation", "py_ecc.fields.bls12_381_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/bls12_381/bls12_381_pairing.py:108 (>= 1.4.5; 1.4.5 :95)",
	},
	{
		"py_ecc.bls12_381.final_exponentiate", 1, "operation", "py_ecc.fields.bls12_381_FQ12", "high",
		[]string{"py_ecc.fields.bls12_381_FQ12"},
		"8.0.0 py_ecc/bls12_381/bls12_381_pairing.py:116 (>= 1.4.5; 1.4.5 :101)",
	},
	{
		"py_ecc.optimized_bls12_381.pairing", 2, "operation", "py_ecc.fields.optimized_bls12_381_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/optimized_bls12_381/optimized_pairing.py:223 (>= 1.4.5; 1.4.5 :138)",
	},
	{
		"py_ecc.optimized_bls12_381.final_exponentiate", 1, "operation", "py_ecc.fields.optimized_bls12_381_FQ12", "high",
		[]string{"py_ecc.fields.optimized_bls12_381_FQ12"},
		"8.0.0 py_ecc/optimized_bls12_381/optimized_pairing.py:245 (>= 1.4.5; 1.4.5 :146)",
	},

	// ── THE DEEP DEFINING-MODULE PATH FOR EACH FLAVOR. Not a second name for
	// the same key: the Python call-graph key is the CONSUMER'S LITERAL MODULE
	// PATH, so `from py_ecc.bn128.bn128_pairing import pairing` emits
	// `py_ecc.bn128.bn128_pairing.pairing` and the flavor entry above does not
	// resolve it. MEASURED with `crypto-finder scan --export-callgraph` over a
	// probe importing each path unaliased: before these entries every one came
	// back as `name(?, ?)` with empty parameter_types — the absent-contract
	// rendering — while the shallow spellings in the same run were fully typed.
	// The contract file once claimed the opposite and cited a wiring test that
	// did not exist; TestPythonPyEccGraphEmitsBothImportSpellings in
	// internal/callgraph/python_py_ecc_contract_wiring_test.go now drives all
	// eleven through the real builder.
	//
	// Types are identical to the flavor entry by construction: it is the SAME
	// function object, reached by the module that defines it, so the `src`
	// citations below are the same lines the flavor rows already cite.
	{
		"py_ecc.bn128.bn128_pairing.pairing", 2, "operation", "py_ecc.fields.bn128_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/bn128/bn128_pairing.py:109",
	},
	{
		"py_ecc.bn128.bn128_pairing.final_exponentiate", 1, "operation", "py_ecc.fields.bn128_FQ12", "high",
		[]string{"py_ecc.fields.bn128_FQ12"},
		"1.1.0 py_ecc/bn128/bn128_pairing.py:73 (8.0.0 :117; NOT defined at all below 1.1.0)",
	},
	{
		"py_ecc.optimized_bn128.optimized_pairing.pairing", 2, "operation", "py_ecc.fields.optimized_bn128_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/optimized_bn128/optimized_pairing.py:228",
	},
	{
		"py_ecc.optimized_bn128.optimized_pairing.final_exponentiate", 1, "operation", "py_ecc.fields.optimized_bn128_FQ12", "high",
		[]string{"py_ecc.fields.optimized_bn128_FQ12"},
		"1.0.0 py_ecc/optimized_bn128/optimized_pairing.py:112 (8.0.0 :242; the DEFINING module has it at 1.0.0, the __init__.py re-export only from 1.1.0)",
	},
	{
		"py_ecc.bls12_381.bls12_381_pairing.pairing", 2, "operation", "py_ecc.fields.bls12_381_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/bls12_381/bls12_381_pairing.py:108 (>= 1.4.5; 1.4.5 :95)",
	},
	{
		"py_ecc.bls12_381.bls12_381_pairing.final_exponentiate", 1, "operation", "py_ecc.fields.bls12_381_FQ12", "high",
		[]string{"py_ecc.fields.bls12_381_FQ12"},
		"8.0.0 py_ecc/bls12_381/bls12_381_pairing.py:116 (>= 1.4.5; 1.4.5 :101)",
	},
	{
		"py_ecc.optimized_bls12_381.optimized_pairing.pairing", 2, "operation", "py_ecc.fields.optimized_bls12_381_FQ12", "high",
		[]string{"builtins.tuple", "builtins.tuple"},
		"8.0.0 py_ecc/optimized_bls12_381/optimized_pairing.py:223 (>= 1.4.5; 1.4.5 :138)",
	},
	{
		"py_ecc.optimized_bls12_381.optimized_pairing.final_exponentiate", 1, "operation", "py_ecc.fields.optimized_bls12_381_FQ12", "high",
		[]string{"py_ecc.fields.optimized_bls12_381_FQ12"},
		"8.0.0 py_ecc/optimized_bls12_381/optimized_pairing.py:245 (>= 1.4.5; 1.4.5 :146)",
	},

	// ── secp256k1 ECDSA. Present unchanged 1.0.0 - 9.0.0b1.
	{
		"py_ecc.secp256k1.ecdsa_raw_sign", 2, "operation", "builtins.tuple", "high",
		[]string{"builtins.bytes", "builtins.bytes"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:226",
	},
	{
		"py_ecc.secp256k1.ecdsa_raw_recover", 2, "operation", "builtins.tuple", "high",
		[]string{"builtins.bytes", "builtins.tuple"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:249",
	},
	{
		"py_ecc.secp256k1.privtopub", 1, "factory", "builtins.tuple", "high",
		[]string{"builtins.bytes"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:196",
	},

	// ── secp256k1 BY ITS DEFINING MODULE. `py_ecc/secp256k1/__init__.py`
	// re-exports these three from `py_ecc/secp256k1/secp256k1.py`, and both
	// spellings occur in real code. Same measurement as the flavors above: the
	// deep path is its own key and the shallow entries do not reach it.
	{
		"py_ecc.secp256k1.secp256k1.ecdsa_raw_sign", 2, "operation", "builtins.tuple", "high",
		[]string{"builtins.bytes", "builtins.bytes"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:226",
	},
	{
		"py_ecc.secp256k1.secp256k1.ecdsa_raw_recover", 2, "operation", "builtins.tuple", "high",
		[]string{"builtins.bytes", "builtins.tuple"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:249",
	},
	{
		"py_ecc.secp256k1.secp256k1.privtopub", 1, "factory", "builtins.tuple", "high",
		[]string{"builtins.bytes"},
		"8.0.0 py_ecc/secp256k1/secp256k1.py:196",
	},
}

// renderPyEccEntry renders one expectation in exactly the format
// renderPyEccContract produces for a loaded contract, so the two sets are
// directly comparable.
func renderPyEccEntry(key string, e pyEccEntry) string {
	params := "-"
	if len(e.params) > 0 {
		params = strings.Join(e.params, "|")
	}
	return fmt.Sprintf("%s#%d %s/%s/%s/%s/%s/-/params=-/varargs=false/when=-/lib=%s",
		key, e.arity, key, e.role, e.returnType, e.confidence, params, pyEccLibrary)
}

// pyEccWant expands the hand-written API table into the full expected key set.
func pyEccWant() map[string]string {
	want := make(map[string]string)
	add := func(key string, e pyEccEntry) {
		line := renderPyEccEntry(key, e)
		want[fmt.Sprintf("%s#%d", key, e.arity)] = line
	}
	for _, cs := range pyEccCiphersuites {
		for _, mod := range pyEccCiphersuiteModules {
			for _, e := range pyEccSharedCiphersuiteAPI {
				add(mod+"."+cs+"."+e.method, e)
			}
		}
	}
	for _, mod := range pyEccCiphersuiteModules {
		for _, e := range pyEccPopOnlyAPI {
			add(mod+".G2ProofOfPossession."+e.method, e)
		}
	}
	for _, e := range pyEccFlatAPI {
		add(e.method, e)
	}
	return want
}

// renderPyEccContract renders one loaded contract as a single line holding every
// field Load() populates. Anything omitted here is a field no mutation of which
// this test can detect — `varargs` and the `parameters:` block are rendered for
// exactly that reason, even though this contract uses neither: a family that
// later adds one must not find the assertion blind to it.
func renderPyEccContract(key string, c contracts.Contract) string {
	params := "-"
	if len(c.ParameterTypes) > 0 {
		params = strings.Join(c.ParameterTypes, "|")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	canonical := c.CanonicalReturnType
	if canonical == "" {
		canonical = "-"
	}
	paramRoles := "-"
	if len(c.Parameters) > 0 {
		rendered := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			rendered = append(rendered, fmt.Sprintf("%d:%s:%s:%s:%s",
				p.Index, p.Name, p.Role, p.Contributes.Property, p.Contributes.Derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, canonical, paramRoles, c.Varargs, when, c.SourceLibrary)
}

// loadedPyEccContracts returns every rendered line for the py-ecc library,
// indexed by `method#arity`. It fails the test if nothing was loaded at all: a
// zero-length set would make every "not present" assertion in this file pass
// vacuously, which is the failure mode the whole file exists to prevent.
func loadedPyEccContracts(t *testing.T) map[string]string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	got := make(map[string]string)
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != pyEccLibrary {
				continue
			}
			got[key] = renderPyEccContract(key, list[i])
		}
	}
	if len(got) == 0 {
		t.Fatal("no py-ecc contracts loaded from the embedded python KB")
	}
	return got
}

func TestPythonPyEccContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := pyEccWant()
	got := loadedPyEccContracts(t)

	var missing, unexpected, differing []string
	for key, wantLine := range want {
		gotLine, ok := got[key]
		if !ok {
			missing = append(missing, fmt.Sprintf(
				"  MISSING contract entry %s — the API table says py-ecc declares it; "+
					"if it does not, remove its row from pyEccSharedCiphersuiteAPI / "+
					"pyEccPopOnlyAPI / pyEccFlatAPI and say why", key))
			continue
		}
		if gotLine != wantLine {
			differing = append(differing, fmt.Sprintf(
				"  DIFFERS %s\n    loaded: %s\n    wanted: %s", key, gotLine, wantLine))
		}
	}
	for key, gotLine := range got {
		if _, ok := want[key]; !ok {
			unexpected = append(unexpected, fmt.Sprintf(
				"  UNEXPECTED contract entry %s — if the YAML change is intended, add "+
					"the corresponding row to the hand-written API table, sourced from "+
					"py-ecc's OWN files with a src citation. Loaded line, for reference:\n"+
					"    %s", key, gotLine))
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	sort.Strings(differing)

	if len(missing)+len(unexpected)+len(differing) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "py-ecc contract set does not match the API table read from "+
			"py-ecc's own sources (%d loaded, %d expected)\n", len(got), len(want))
		for _, l := range missing {
			b.WriteString(l + "\n")
		}
		for _, l := range unexpected {
			b.WriteString(l + "\n")
		}
		for _, l := range differing {
			b.WriteString(l + "\n")
		}
		t.Error(b.String())
	}
}

// TestPythonPyEccContract_LibraryBlock renders the `library:` block, which the
// exact-set test above cannot see. Measured twice on this campaign: corrupting
// `version_range`, `coordinates`, `name` or `description` leaves every
// per-contract assertion green, because those fields are parsed and then never
// consulted by any other test.
func TestPythonPyEccContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "py-ecc.yaml"))
	if err != nil {
		t.Fatalf("read contract file: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if kb.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want %q", kb.Ecosystem, "python")
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want %q", kb.SchemaVersion, "2")
	}
	if kb.Library == nil {
		t.Fatal("library block absent")
	}
	if kb.Library.Name != pyEccLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, pyEccLibrary)
	}
	// The import name is `py_ecc` while the DISTRIBUTION is `py-ecc` (PEP 503
	// normalizes both to the same project). The coordinate is the IMPORT name,
	// because that is what the call-graph key is built from.
	if got, want := strings.Join(kb.Library.Coordinates, ","), "py_ecc"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// `version_range` IS THE UNION OF RELEASES IN WHICH SOME DECLARED KEY IS
	// REACHABLE. It is NOT a range in which the whole declared surface holds, and
	// the criterion this test used to state implied otherwise ("`py_ecc.secp256k1`
	// and the bn128 pairings exist at 1.0.0, so the lower bound is the first
	// release") — true about the bound, but it reads as a claim about the API as a
	// whole, and that claim is false.
	//
	// MEASURED over all 32 published sdists by walking each dotted key against
	// the on-disk package (module path -> __init__ import bindings -> class body,
	// following base classes). The contract declares 97 entries over 84 unique
	// method keys, and:
	//
	//   - NO SINGLE VERSION SATISFIES ALL 84. The best is 66/84, at 8.0.0-9.0.0b1.
	//   - 1.0.0, the lower bound, reaches 11/84 — the six secp256k1 keys and five
	//     bn128/optimized_bn128 pairing keys. Every BLS and bls12_381 key is
	//     unreachable there.
	//   - The two BLS ERAS ARE DISJOINT: era-1 `py_ecc.bls.api.*` lives only in
	//     1.6.0-1.7.1 (the `py_ecc/bls/` package does not exist below 1.6.0, and
	//     `api.py` is deleted in 2.0.0), while the ciphersuite classes exist only
	//     from 2.0.0. No version has both, so no version can satisfy the set.
	//
	// So the field is DOCUMENTARY: it bounds which distributions this contract is
	// about, and per-key windows live in the header comments and the `src`
	// citations on each API-table row above. 28 merged python contracts are
	// equally coarse, so this is the ecosystem's convention rather than a py-ecc
	// shortcut — narrowing it here alone would misdescribe the field.
	//
	// The pin stays, because the VALUE is still asserted and a change to it must
	// be deliberate; what is fixed is the reason given for it.
	if got, want := kb.Library.VersionRange, ">=1.0.0,<10"; got != want {
		t.Errorf("library.version_range = %q, want %q — this is the union of "+
			"releases in which SOME declared key is reachable, not a range in which "+
			"all 84 hold (no version does; the best is 66/84). If you are narrowing "+
			"it, check the per-key windows in the contract header first.", got, want)
	}
	for _, needle := range []string{"BLS12-381", "BN254", "secp256k1"} {
		if !strings.Contains(kb.Library.Description, needle) {
			t.Errorf("library.description does not name %q: %q", needle, kb.Library.Description)
		}
	}
}

// TestPythonPyEccContract_DocumentedCallShapesResolve checks that every call
// shape documented below resolves to a py-ecc contract in the EMBEDDED KB.
//
// WHAT THIS TEST IS NOT: it does not touch a call graph. It calls
// `ContractsForTolerant` with a HAND-TYPED key, so it can only ever tell you
// that the KB contains the key someone typed here — not that the key is the one
// a real consumer's imports produce. It was previously named
// `KeysMeasuredOffTheGraph`, which claimed exactly the guarantee it does not
// give, and under that name it sat green while eleven deep-module spellings
// joined nothing. That is the mirror-test trap this campaign has hit
// repeatedly: the assertion and the thing it asserts about were both derived
// from the same typed string.
//
// The real graph-level guarantee lives in
// internal/callgraph/python_py_ecc_contract_wiring_test.go, which builds a graph
// from consumer source with the full builder and reads the keys off it. THAT is
// the test to change if the parser's keying changes. This one is kept because
// it is cheap, it documents the call shape each key corresponds to in prose,
// and it fails fast on a KB that did not load.
func TestPythonPyEccContract_DocumentedCallShapesResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	cases := []struct {
		method string
		arity  int
		shape  string
	}{
		{"py_ecc.bls.G2ProofOfPossession.Sign", 2, "from py_ecc.bls import G2ProofOfPossession; G2ProofOfPossession.Sign(sk, msg)"},
		{"py_ecc.bls.G2ProofOfPossession.Verify", 3, "the same import; .Verify(pk, msg, sig)"},
		{"py_ecc.bls.G2ProofOfPossession.KeyGen", 1, "the same import; .KeyGen(ikm) — arity 1 via the tolerant fallback and as its own entry"},
		{"py_ecc.bls.G2ProofOfPossession.SkToPk", 1, "the same import; .SkToPk(sk)"},
		{"py_ecc.bls.G2ProofOfPossession.Aggregate", 1, "the same import; .Aggregate([sig, sig])"},
		{"py_ecc.bls.G2ProofOfPossession.FastAggregateVerify", 3, "the same import; .FastAggregateVerify(pks, msg, agg)"},
		{"py_ecc.bls.G2ProofOfPossession.PopProve", 1, "the same import; .PopProve(sk)"},
		{"py_ecc.bls.G2Basic.Sign", 2, "from py_ecc.bls import G2Basic; G2Basic.Sign(sk, msg)"},
		{"py_ecc.bls.G2MessageAugmentation.Verify", 3, "from py_ecc.bls import G2MessageAugmentation; .Verify(..)"},
		{"py_ecc.bls.ciphersuites.G2ProofOfPossession.Sign", 2, "from py_ecc.bls.ciphersuites import G2ProofOfPossession as DeepPoP; DeepPoP.Sign(sk, msg)"},
		{"py_ecc.bls.ciphersuites.G2Basic.Sign", 2, "from py_ecc.bls.ciphersuites import G2Basic as AliasedBasic; AliasedBasic.Sign(sk, msg)"},
		{"py_ecc.bls.hash_to_curve.hash_to_G2", 3, "from py_ecc.bls.hash_to_curve import hash_to_G2"},
		{"py_ecc.bls.hash_to_curve.hash_to_G1", 3, "from py_ecc.bls.hash_to_curve import hash_to_G1"},
		{"py_ecc.bn128.pairing", 2, "from py_ecc.bn128 import pairing; pairing(g2, g1)"},
		{"py_ecc.bn128.final_exponentiate", 1, "the same import; final_exponentiate(x)"},
		{"py_ecc.bls12_381.pairing", 2, "from py_ecc.bls12_381 import pairing as bls_pairing — the ALIASED form, keyed on the library's own name"},
		{"py_ecc.optimized_bls12_381.pairing", 2, "from py_ecc.optimized_bls12_381 import pairing as opt_bls_pairing"},
		{"py_ecc.optimized_bn128.pairing", 2, "from py_ecc.optimized_bn128 import pairing as opt_bn_pairing"},
		{"py_ecc.optimized_bn128.final_exponentiate", 1, "import py_ecc.optimized_bn128; py_ecc.optimized_bn128.final_exponentiate(r)"},
		{"py_ecc.secp256k1.ecdsa_raw_sign", 2, "from py_ecc.secp256k1 import ecdsa_raw_sign"},
		{"py_ecc.secp256k1.ecdsa_raw_recover", 2, "from py_ecc.secp256k1 import ecdsa_raw_recover"},
		{"py_ecc.secp256k1.privtopub", 1, "from py_ecc.secp256k1 import privtopub"},

		// The deep defining-module spellings. Each is its OWN key — the shallow
		// entry above does not resolve it — and each was verified against an
		// exported call graph, not typed from the source layout.
		{"py_ecc.bn128.bn128_pairing.pairing", 2, "from py_ecc.bn128.bn128_pairing import pairing"},
		{"py_ecc.bn128.bn128_pairing.final_exponentiate", 1, "the same import; final_exponentiate(a)"},
		{"py_ecc.optimized_bn128.optimized_pairing.pairing", 2, "from py_ecc.optimized_bn128.optimized_pairing import pairing"},
		{"py_ecc.optimized_bn128.optimized_pairing.final_exponentiate", 1, "the same import; final_exponentiate(a)"},
		{"py_ecc.bls12_381.bls12_381_pairing.pairing", 2, "from py_ecc.bls12_381.bls12_381_pairing import pairing"},
		{"py_ecc.bls12_381.bls12_381_pairing.final_exponentiate", 1, "the same import; final_exponentiate(a)"},
		{"py_ecc.optimized_bls12_381.optimized_pairing.pairing", 2, "from py_ecc.optimized_bls12_381.optimized_pairing import pairing"},
		{"py_ecc.optimized_bls12_381.optimized_pairing.final_exponentiate", 1, "the same import; final_exponentiate(a)"},
		{"py_ecc.secp256k1.secp256k1.ecdsa_raw_sign", 2, "from py_ecc.secp256k1.secp256k1 import ecdsa_raw_sign — the DEEP path, its own key"},
		{"py_ecc.secp256k1.secp256k1.ecdsa_raw_recover", 2, "the same import; ecdsa_raw_recover(msghash, vrs)"},
		{"py_ecc.secp256k1.secp256k1.privtopub", 1, "the same import; privtopub(priv)"},
	}

	for _, tc := range cases {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d does not resolve (call shape: %s)", tc.method, tc.arity, tc.shape)
			continue
		}
		if got[0].SourceLibrary != pyEccLibrary {
			t.Errorf("%s#%d resolved to library %q, want %q",
				tc.method, tc.arity, got[0].SourceLibrary, pyEccLibrary)
		}
	}
}

// TestPythonPyEccContract_ArithmeticIsNotContracted asserts the keys this
// contract deliberately does NOT declare. py-ecc is a CURVE LIBRARY: most of
// its exported surface is arithmetic, and contracting arithmetic would
// synthesize an entry point for every consumer that touches a point. This is
// the same disposition already settled for the equivalent Rust BLS12-381 and
// arkworks curve crates, inherited here on purpose.
//
// The positive control matters: `py_ecc.bn128.pairing` MUST resolve, or every
// assertion below would pass just as well against an empty KB.
func TestPythonPyEccContract_ArithmeticIsNotContracted(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if got := kb.ContractsForTolerant("py_ecc.bn128.pairing", 2); len(got) == 0 {
		t.Fatal("positive control failed: py_ecc.bn128.pairing#2 does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	absent := []struct {
		key    string
		reason string
	}{
		{"py_ecc.bn128.add", "group arithmetic"},
		{"py_ecc.bn128.double", "group arithmetic"},
		{"py_ecc.bn128.neg", "group arithmetic"},
		{"py_ecc.bn128.multiply", "scalar multiplication — what a keygen is built FROM, and on its own silent about which operation"},
		{"py_ecc.bn128.eq", "comparison"},
		{"py_ecc.bn128.is_inf", "predicate"},
		{"py_ecc.bn128.is_on_curve", "predicate"},
		{"py_ecc.bn128.twist", "group arithmetic"},
		{"py_ecc.optimized_bn128.normalize", "affine conversion"},
		{"py_ecc.optimized_bls12_381.optimized_swu_G2", "an internal step of hash-to-curve; the composite is contracted"},
		{"py_ecc.optimized_bls12_381.iso_map_G2", "an internal step of hash-to-curve"},
		{"py_ecc.optimized_bls12_381.multiply_clear_cofactor_G2", "an internal step of hash-to-curve"},
		{"py_ecc.bls.hash_to_curve.map_to_curve_G2", "an internal step of hash-to-curve"},
		{"py_ecc.bls.hash_to_curve.hash_to_field_FQ2", "an internal step of hash-to-curve"},
		{"py_ecc.bls.hash_to_curve.clear_cofactor_G2", "an internal step of hash-to-curve"},
		{"py_ecc.bls.point_compression.compress_G1", "serialization"},
		{"py_ecc.bls.point_compression.decompress_G2", "serialization"},
		{"py_ecc.bls.g2_primitives.G1_to_pubkey", "serialization"},
		{"py_ecc.bls.g2_primitives.signature_to_G2", "serialization"},
		{"py_ecc.bls.g2_primitives.subgroup_check", "a membership check, not an operation"},
		{"py_ecc.bls.hash.hash_eth2", "a keccak-256 wrapper over eth_hash.auto.keccak — the primitive belongs to pkg:pypi/eth-hash"},
		{"py_ecc.secp256k1.multiply", "group arithmetic, and not re-exported from __init__.py"},
		{"py_ecc.secp256k1.deterministic_generate_k", "RFC 6979 nonce derivation: real cryptography, but not re-exported and reachable only through ecdsa_raw_sign, which is already an entry point"},
		{"py_ecc.secp256k1.bytes_to_int", "byte plumbing"},
	}

	for _, a := range absent {
		for _, c := range kb.ContractsForTolerant(a.key, 1) {
			if c.SourceLibrary == pyEccLibrary {
				t.Errorf("%s resolves to a py-ecc contract, but it is deliberately not "+
					"declared (%s). If this is an intended addition, add its row to the "+
					"API table and delete this entry.", a.key, a.reason)
			}
		}
	}
}

// TestPythonPyEccContract_UnreachableSpellingsAreNotDeclared asserts the module
// spellings that resolve in NO published release. Declaring one would ship an
// entry matching code that raises ImportError or AttributeError, which loads
// cleanly and joins a call site that cannot exist.
func TestPythonPyEccContract_UnreachableSpellingsAreNotDeclared(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if got := kb.ContractsForTolerant("py_ecc.bls.hash_to_curve.hash_to_G2", 3); len(got) == 0 {
		t.Fatal("positive control failed: py_ecc.bls.hash_to_curve.hash_to_G2#3 does not " +
			"resolve, so the negative assertions below prove nothing")
	}

	unreachable := []struct {
		key    string
		reason string
	}{
		// `py_ecc/bls/__init__.py` re-exports the three ciphersuite classes and
		// NOTHING else, in every release 2.0.0 - 9.0.0b1, checked file by file.
		{"py_ecc.bls.hash_to_G2", "hash_to_G2 is not re-exported from py_ecc.bls in any release"},
		{"py_ecc.bls.hash_to_G1", "hash_to_G1 is not re-exported from py_ecc.bls in any release"},
		{"py_ecc.bls.Sign", "the ciphersuite methods are not module-level bindings"},
		{"py_ecc.bls.KeyGen", "the ciphersuite methods are not module-level bindings"},
		// PoP-only methods on the wrong ciphersuite raise AttributeError.
		{"py_ecc.bls.G2Basic.FastAggregateVerify", "declared on G2ProofOfPossession only"},
		{"py_ecc.bls.G2Basic.PopProve", "declared on G2ProofOfPossession only"},
		{"py_ecc.bls.G2Basic.PopVerify", "declared on G2ProofOfPossession only"},
		{"py_ecc.bls.ciphersuites.G2MessageAugmentation.FastAggregateVerify", "declared on G2ProofOfPossession only"},
		{"py_ecc.bls.ciphersuites.G2MessageAugmentation.PopProve", "declared on G2ProofOfPossession only"},
		// The era-1 names as ciphersuite methods, and the reverse.
		{"py_ecc.bls.G2ProofOfPossession.sign", "an era-1 free-function name; the classes carry only the capitalised names"},
		{"py_ecc.bls.G2ProofOfPossession.privtopub", "an era-1 free-function name"},
		// THREE ENTRIES WERE DELETED FROM HERE, and the deletion is the point.
		// This list used to forbid `py_ecc.secp256k1.secp256k1.ecdsa_raw_sign`,
		// `py_ecc.secp256k1.secp256k1.privtopub` and
		// `py_ecc.bn128.bn128_pairing.pairing` on the stated ground that "the
		// graph keys both import spellings" on the shallow module. That was
		// never measured and it is FALSE: the graph keys the consumer's literal
		// module path, so those three — and eight more deep spellings — resolved
		// to nothing while eleven rule arms matched them. All eleven are now
		// declared, and this test forbidding them was the thing standing in the
		// way. Do not re-add them without an exported call graph that shows the
		// shallow key being emitted for a deep import.
		//
		// `py_ecc.pairing` stays: there genuinely is no py_ecc-ROOT pairing, and
		// that is a different claim from the deep-vs-flavor one. The flavor
		// module and the defining module are both real; the package root is not.
		{"py_ecc.pairing", "there is no py_ecc-root pairing; py_ecc/__init__.py re-exports no curve function"},
	}

	for _, u := range unreachable {
		for _, arity := range []int{1, 2, 3, 4} {
			for _, c := range kb.ContractsForTolerant(u.key, arity) {
				if c.SourceLibrary == pyEccLibrary {
					t.Errorf("%s resolves to a py-ecc contract, but %s", u.key, u.reason)
				}
			}
		}
	}
}
