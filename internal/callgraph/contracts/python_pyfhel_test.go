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
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// renderPyfhelInventory renders every loaded Pyfhel contract as one line so the
// test below compares the WHOLE SET rather than probing key by key.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Every field the loader
// populates is rendered: role, return type, return confidence,
// canonical_return_type, parameter_types, varargs, and each parameter's
// index/name/role plus its contributed property and derivation.
//
// Varargs is rendered even though NO Pyfhel entry sets it, deliberately twice
// over: a `varargs: true` mutation otherwise survives every assertion in this
// directory, and for Python the field is INERT anyway -- the only consumer of
// `Contract.Varargs` is `javaVarargsChainContracts`, whose single call site is
// gated on `kb.Ecosystem == ecosystemJava` (builder.go:1562). Rendering it pins
// the field at false so nobody later adds it believing it collapses an arity.
func renderPyfhelInventory(kb *contracts.KnowledgeBase) []string {
	var inventory []string
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			contract := &candidates[i]
			if contract.SourceLibrary != "Pyfhel" {
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

// pyfhelMethod is one row of the HAND-WRITTEN signature table below.
//
// Pyfhel reaches 116 contract entries from 65 keys because arity is an EXACT
// match key for Python -- `ContractsFor` returns nil on a miss for every
// ecosystem but rust (contracts.go:203-211) -- so a method callable at four
// different argument counts needs four entries.
//
// WRITING 116 LITERALS BY HAND WOULD BE UNAUDITABLE, so the EXPECTATION IS THIS
// TABLE: one row per key, every field READ OFF THE `cpdef`/`def` LINE CITED in
// the sdist, and the test expands min..max into the 116 lines it compares. The
// expansion rule is the one stated in pyfhel.yaml's header and derived from the
// signatures: min is the parameters without a default (`self` excluded), max is
// the parameters declared.
//
// WHAT MAKES THIS NON-TAUTOLOGICAL, which is this campaign's most repeated
// defect: the table is written from `Pyfhel/Pyfhel.pyx` in the published sdists
// and is INDEPENDENT of the YAML. Deriving it from the YAML instead is the
// obvious repair and it is wrong -- it makes the assertion green on a corrupted
// contract, which is the one thing the test exists to prevent. A legitimate
// change to the contract is a ONE-FIELD edit to one row here.
type pyfhelMethod struct {
	method     string // the contract key, read off an EXPORTED CALL GRAPH
	cite       string // the `cpdef`/`def` line, sdist version and file line
	minArity   int
	maxArity   int
	role       string
	returnTyp  string
	confidence string
	canonical  bool // whether canonical_return_type is declared
}

// pyfhelSignatures is the whole expectation. Citations are against the Pyfhel
// 3.5.0 sdist (`Pyfhel/Pyfhel.pyx`) except where a symbol exists ONLY in the 2.x
// line, where the citation is against 2.3.1, the last 2.x release. Version
// windows live in the YAML header and were derived by parsing every `def` and
// `cpdef` out of ALL 32 archived sdists.
//
// THERE ARE THREE CONSTRUCTOR KEYS BECAUSE THE PACKAGE AND THE CLASS SHARE THE
// NAME `Pyfhel`. Measured on an exported call graph, one call per file:
// `import Pyfhel; Pyfhel.Pyfhel()` emits no `.<init>`;
// `from Pyfhel import Pyfhel; Pyfhel()` emits `Pyfhel.Pyfhel.<init>`; and
// `from Pyfhel.Pyfhel import Pyfhel; Pyfhel()` emits a FOUR-segment
// `Pyfhel.Pyfhel.Pyfhel.<init>`. The third is not hypothetical: the
// distribution's own `__init__.py` writes that import at 2.0.0a2.
var pyfhelSignatures = []pyfhelMethod{
	// 3.5.0 Pyfhel.pyx:49 `cdef class Pyfhel`, :67 `def __init__(self,
	// context_params=None, key_gen=False, pub_key_file=None,
	// sec_key_file=None)` -- 4 parameters, all with defaults, so 0..4.
	// BEFORE 2.3.1 THE CONSTRUCTOR TAKES NO ARGUMENTS: 2.2.5 declares only
	// `def __cinit__(self)` and no `__init__`, so arities 1-4 are unreachable
	// on those releases. Declared anyway; an entry that never matches costs
	// nothing and omitting them would break 2.3.1-3.5.0.
	{"Pyfhel.Pyfhel", "3.5.0 Pyfhel.pyx:67", 0, 4, "factory", "Pyfhel.Pyfhel", "high", true},
	{"Pyfhel.Pyfhel.<init>", "3.5.0 Pyfhel.pyx:67", 0, 4, "factory", "Pyfhel.Pyfhel", "high", true},
	{"Pyfhel.Pyfhel.Pyfhel.<init>", "3.5.0 Pyfhel.pyx:67", 0, 4, "factory", "Pyfhel.Pyfhel", "high", true},

	// :194 `cpdef string contextGen(self, str scheme, int n, int t_bits=0,
	// int64_t t=0, int sec=128, double scale=1, int scale_bits=0,
	// vector[int] qi_sizes={}, vector[uint64_t] qi={})` -- 9 parameters, 2
	// required. The 2.x signature is different and needs only one: 2.3.1
	// Pyfhel.pyx:182 `cpdef contextGen(self, long p, long m=2048, ...)` with 7
	// parameters. Union 1..9. Returns the SEAL validation string.
	{"Pyfhel.Pyfhel.contextGen", "3.5.0 Pyfhel.pyx:194 / 2.3.1 :182", 1, 9, "operation", "builtins.str", "high", true},

	// :290 `cpdef void keyGen(self)` -- NO parameters, in every one of the 32
	// archived releases (2.0.0a2 Pyfhel.pyx:128). This is why no rule in this
	// family publishes a key size: no call site states one.
	{"Pyfhel.Pyfhel.keyGen", "3.5.0 Pyfhel.pyx:290", 0, 0, "operation", "builtins.NoneType", "high", true},
	// :323 `cpdef void relinKeyGen(self)` -- arity 0. 2.x REQUIRES TWO:
	// 2.3.1 :602 `cpdef void relinKeyGen(self, int bitCount, int size)`.
	{"Pyfhel.Pyfhel.relinKeyGen", "3.5.0 Pyfhel.pyx:323 / 2.3.1 :602", 0, 2, "operation", "builtins.NoneType", "high", true},
	// :303 `cpdef void rotateKeyGen(self, vector[int] rot_steps={})` -- 0..1.
	// 2.x REQUIRES one: 2.3.1 :583 `rotateKeyGen(self, int bitCount)`.
	{"Pyfhel.Pyfhel.rotateKeyGen", "3.5.0 Pyfhel.pyx:303 / 2.3.1 :583", 0, 1, "operation", "builtins.NoneType", "high", true},

	// ENCRYPTION. :491 `def encrypt(self, ptxt not None, PyCtxt ctxt=None,
	// scale=None)` -- 3 parameters, 1 required; the 2.x form has 2 (2.3.1 :368).
	{"Pyfhel.Pyfhel.encrypt", "3.5.0 Pyfhel.pyx:491", 1, 3, "operation", "Pyfhel.PyCtxt", "high", true},
	// :343 `cpdef PyCtxt encryptInt(self, int64_t[:] arr, PyCtxt ctxt=None)`.
	{"Pyfhel.Pyfhel.encryptInt", "3.5.0 Pyfhel.pyx:343", 1, 2, "operation", "Pyfhel.PyCtxt", "high", true},
	// :366 `cpdef PyCtxt encryptFrac(self, double[:] arr, PyCtxt ctxt=None,
	// double scale=0, int scale_bits=0)` -- 4; 2.3.1 :260 declares 2.
	{"Pyfhel.Pyfhel.encryptFrac", "3.5.0 Pyfhel.pyx:366", 1, 4, "operation", "Pyfhel.PyCtxt", "high", true},
	// :397 `cpdef PyCtxt encryptComplex(self, complex[:] arr, PyCtxt ctxt=None,
	// double scale=0, int scale_bits=0)`. 3.0.0b1-3.5.0.
	{"Pyfhel.Pyfhel.encryptComplex", "3.5.0 Pyfhel.pyx:397", 1, 4, "operation", "Pyfhel.PyCtxt", "high", true},
	// :428 `cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt=None)`.
	{"Pyfhel.Pyfhel.encryptPtxt", "3.5.0 Pyfhel.pyx:428", 1, 2, "operation", "Pyfhel.PyCtxt", "high", true},
	// :454 `cpdef PyCtxt encryptBGV(self, int64_t[:] arr, PyCtxt ctxt=None)`.
	// ARRIVES AT 3.4.0; exists in no earlier release, which is why the matching
	// rule may name BGV from the method name alone.
	{"Pyfhel.Pyfhel.encryptBGV", "3.5.0 Pyfhel.pyx:454", 1, 2, "operation", "Pyfhel.PyCtxt", "high", true},
	// The vectorized family, 3.0.0b1-3.5.0. :476, :479, :482, :485, :488.
	{"Pyfhel.Pyfhel.encryptAInt", "3.5.0 Pyfhel.pyx:476", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.encryptAFrac", "3.5.0 Pyfhel.pyx:479", 1, 3, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.encryptAComplex", "3.5.0 Pyfhel.pyx:482", 1, 3, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.encryptAPtxt", "3.5.0 Pyfhel.pyx:485", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.encryptABGV", "3.5.0 Pyfhel.pyx:488", 1, 1, "operation", "numpy.ndarray", "high", true},
	// The 2.x-only encoders, REMOVED at 3.0.0b1. 2.3.1 :286 and :312.
	{"Pyfhel.Pyfhel.encryptBatch", "2.3.1 Pyfhel.pyx:286", 1, 2, "operation", "Pyfhel.PyCtxt", "high", true},
	{"Pyfhel.Pyfhel.encryptArray", "2.3.1 Pyfhel.pyx:312", 1, 2, "operation", "Pyfhel.PyCtxt", "high", true},

	// DECRYPTION. Three keys carry a DIVERGENT return and therefore declare
	// `confidence: low` with canonical_return_type WITHHELD -- a divergent
	// return on one (method, arity) key is a hard load error
	// (contracts.go:936-968 Rule 2), so one value is declared rather than
	// asserting one era's type holds for both.
	//
	// :643 `def decrypt(self, PyCtxt ctxt, bool decode=True, PyPtxt ptxt=None)`
	// returns a decoded array when `decode` is true and a PyPtxt otherwise.
	{"Pyfhel.Pyfhel.decrypt", "3.5.0 Pyfhel.pyx:643", 1, 3, "operation", "numpy.ndarray", "low", false},
	// :523 `cpdef np.ndarray[int64_t, ndim=1] decryptInt(self, PyCtxt ctxt)`,
	// against 2.3.1 :409 `cpdef int64_t decryptInt(self, PyCtxt ctxt)` -- a
	// python int in 2.x, an array in 3.x, at the SAME arity.
	{"Pyfhel.Pyfhel.decryptInt", "3.5.0 Pyfhel.pyx:523 / 2.3.1 :409", 1, 1, "operation", "numpy.ndarray", "low", false},
	// :546 vs 2.3.1 :432 `cpdef double decryptFrac` -- same shape.
	{"Pyfhel.Pyfhel.decryptFrac", "3.5.0 Pyfhel.pyx:546 / 2.3.1 :432", 1, 1, "operation", "numpy.ndarray", "low", false},
	// :569, :592, :612 -- these do NOT diverge.
	{"Pyfhel.Pyfhel.decryptComplex", "3.5.0 Pyfhel.pyx:569", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptPtxt", "3.5.0 Pyfhel.pyx:592", 1, 2, "operation", "Pyfhel.PyPtxt", "high", true},
	{"Pyfhel.Pyfhel.decryptBGV", "3.5.0 Pyfhel.pyx:612", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptAInt", "3.5.0 Pyfhel.pyx:633", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptAFrac", "3.5.0 Pyfhel.pyx:635", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptAComplex", "3.5.0 Pyfhel.pyx:637", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptAPtxt", "3.5.0 Pyfhel.pyx:639", 1, 1, "operation", "numpy.ndarray", "high", true},
	{"Pyfhel.Pyfhel.decryptABGV", "3.5.0 Pyfhel.pyx:641", 1, 1, "operation", "numpy.ndarray", "high", true},
	// 2.x only. 2.3.1 :455 `cpdef vector[int64_t] decryptBatch` -> a python
	// list; :477 `cpdef int64_t[::1] decryptArray` -> an array.
	{"Pyfhel.Pyfhel.decryptBatch", "2.3.1 Pyfhel.pyx:455", 1, 1, "operation", "builtins.list", "high", true},
	{"Pyfhel.Pyfhel.decryptArray", "2.3.1 Pyfhel.pyx:477", 1, 1, "operation", "numpy.ndarray", "high", true},

	// KEY I/O, 3.x spellings. `save_*` take `(fileName, compr_mode="zstd")`;
	// `load_*` and `from_bytes_*` take one argument. All return `size_t`.
	{"Pyfhel.Pyfhel.save_public_key", "3.5.0 Pyfhel.pyx:1541", 1, 2, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.load_public_key", "3.5.0 Pyfhel.pyx:1555", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.save_secret_key", "3.5.0 Pyfhel.pyx:1568", 1, 2, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.load_secret_key", "3.5.0 Pyfhel.pyx:1582", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.save_relin_key", "3.5.0 Pyfhel.pyx:1595", 1, 2, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.load_relin_key", "3.5.0 Pyfhel.pyx:1609", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.save_rotate_key", "3.5.0 Pyfhel.pyx:1622", 1, 2, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.load_rotate_key", "3.5.0 Pyfhel.pyx:1636", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_public_key", "3.5.0 Pyfhel.pyx:1693", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_secret_key", "3.5.0 Pyfhel.pyx:1719", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_relin_key", "3.5.0 Pyfhel.pyx:1745", 1, 1, "operation", "builtins.int", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_rotate_key", "3.5.0 Pyfhel.pyx:1771", 1, 1, "operation", "builtins.int", "high", true},
	// `to_bytes_*` take only `compr_mode="zstd"`, so 0..1, and return bytes.
	{"Pyfhel.Pyfhel.to_bytes_public_key", "3.5.0 Pyfhel.pyx:1680", 0, 1, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_secret_key", "3.5.0 Pyfhel.pyx:1706", 0, 1, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_relin_key", "3.5.0 Pyfhel.pyx:1732", 0, 1, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_rotate_key", "3.5.0 Pyfhel.pyx:1758", 0, 1, "output", "builtins.bytes", "high", true},

	// KEY I/O, 2.x camelCase spellings. GONE at 3.0.0b1. All return `bool`,
	// which is why they need their own keys rather than a widened arity: the
	// 3.x siblings return `size_t`, and two different returns on ONE key would
	// be a hard load error.
	{"Pyfhel.Pyfhel.savepublicKey", "2.3.1 Pyfhel.pyx:1268", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.restorepublicKey", "2.3.1 Pyfhel.pyx:1281", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.savesecretKey", "2.3.1 Pyfhel.pyx:1294", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.restoresecretKey", "2.3.1 Pyfhel.pyx:1307", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.saverelinKey", "2.3.1 Pyfhel.pyx:1320", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.restorerelinKey", "2.3.1 Pyfhel.pyx:1333", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.saverotateKey", "2.3.1 Pyfhel.pyx:1346", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.restorerotateKey", "2.3.1 Pyfhel.pyx:1359", 1, 1, "operation", "builtins.bool", "high", true},
	// The 2.x byte spellings exist in 2.3.1 ALONE -- they arrive in the last
	// 2.x release and the 3.x rename lands in the next one. :1405, :1420,
	// :1435, :1450, :1465, :1480, :1495, :1510.
	{"Pyfhel.Pyfhel.to_bytes_publicKey", "2.3.1 Pyfhel.pyx:1405", 0, 0, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_publicKey", "2.3.1 Pyfhel.pyx:1420", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_secretKey", "2.3.1 Pyfhel.pyx:1435", 0, 0, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_secretKey", "2.3.1 Pyfhel.pyx:1450", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_relinKey", "2.3.1 Pyfhel.pyx:1465", 0, 0, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_relinKey", "2.3.1 Pyfhel.pyx:1480", 1, 1, "operation", "builtins.bool", "high", true},
	{"Pyfhel.Pyfhel.to_bytes_rotateKey", "2.3.1 Pyfhel.pyx:1495", 0, 0, "output", "builtins.bytes", "high", true},
	{"Pyfhel.Pyfhel.from_bytes_rotateKey", "2.3.1 Pyfhel.pyx:1510", 1, 1, "operation", "builtins.bool", "high", true},
}

func expandPyfhelSignatures() []string {
	var want []string
	for _, m := range pyfhelSignatures {
		for arity := m.minArity; arity <= m.maxArity; arity++ {
			canonical := ""
			if m.canonical {
				canonical = m.returnTyp
			}
			// parameter_types is deliberately absent from every entry: most of
			// these methods take keyword arguments in any order, so at a given
			// arity the positional types are not knowable. The loader renders
			// the empty slice as [].
			want = append(want, fmt.Sprintf("%s#%d|%s|%s|%s|%s|[]|false",
				m.method, arity, m.role, m.returnTyp, m.confidence, canonical))
		}
	}
	sort.Strings(want)
	return want
}

// TestLoadEmbeddedPython_Pyfhel_ExactSet pins the Pyfhel contract KB as an
// EXACT SET, reported as a SYMMETRIC DIFFERENCE.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the loaded set is exactly
// what the signature table describes, so any edit that adds, drops or corrupts
// an entry fails here and the failure names the exact line. It does NOT prove
// the table is TRUE -- a comparison can only find drift away from a baseline,
// never an error inside it. The baseline's truth rests on the per-row citations
// into the published sdists and on the assertions below.
func TestLoadEmbeddedPython_Pyfhel_ExactSet(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	got := renderPyfhelInventory(kb)
	want := expandPyfhelSignatures()

	if len(got) == 0 {
		t.Fatal("no Pyfhel contracts loaded; every assertion here would be vacuous")
	}

	// A SYMMETRIC DIFFERENCE, NOT A COUNT AND NOT A TALLY. A `len(got) !=
	// len(want)` check plus a role tally is this campaign's most repeated
	// defect: it rejects a CORRECT repair in several places at once, so adding
	// a real, present, crypto-relevant entry reads as a regression. There is
	// ONE expectation -- the table above -- and the message quotes the exact
	// line and says which direction the difference is in.
	inWant := make(map[string]bool, len(want))
	for _, line := range want {
		inWant[line] = true
	}
	inGot := make(map[string]bool, len(got))
	for _, line := range got {
		inGot[line] = true
	}
	for _, line := range got {
		if !inWant[line] {
			t.Errorf("unexpected contract entry -- if the YAML change is intended, "+
				"widen or add the matching row in pyfhelSignatures:\n\t\t%q", line)
		}
	}
	for _, line := range want {
		if !inGot[line] {
			t.Errorf("expected contract entry did not load -- if it was deliberately "+
				"removed, narrow or delete the matching row in "+
				"pyfhelSignatures:\n\t\t%q", line)
		}
	}

	// Roles are checked against the VOCABULARY, never against a tally. A tally
	// would be a second mirror of the same table with no independent source,
	// and the set comparison above already fails on any role change because
	// role is a rendered field.
	valid := map[string]bool{"factory": true, "config": true, "operation": true, "output": true}
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary == "Pyfhel" && !valid[c.Role] {
				t.Errorf("%s#%d carries role %q, which is outside the whitelist",
					c.Method, c.Arity, c.Role)
			}
		}
	}
}

// TestLoadEmbeddedPython_Pyfhel_EveryKeyIsRootedAtTheDistribution pins the fact
// that the package and the class share the name `Pyfhel`, which is this
// library's particular trap and the reason there are THREE constructor keys.
//
// Every key must start `Pyfhel.Pyfhel` -- the module, then the class. A key
// with only one `Pyfhel` segment would be the MODULE's own namespace and would
// join a free function this distribution does not have; a key rooted anywhere
// else would belong to another distribution. Measured on an exported call
// graph rather than assumed: the three spellings a consumer can write emit
// `Pyfhel.Pyfhel`, `Pyfhel.Pyfhel.<init>` and `Pyfhel.Pyfhel.Pyfhel.<init>`.
func TestLoadEmbeddedPython_Pyfhel_EveryKeyIsRootedAtTheDistribution(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "Pyfhel" {
				continue
			}
			seen++
			if !strings.HasPrefix(c.Method, "Pyfhel.Pyfhel") {
				t.Errorf("%s#%d is not rooted at the `Pyfhel.Pyfhel` module/class pair",
					c.Method, c.Arity)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no Pyfhel contracts loaded; this assertion would be vacuous")
	}
}

// TestLoadEmbeddedPython_Pyfhel_NoKeyDeclaresAKeySize is the contract-side half
// of a claim the rule headers make: Pyfhel states NO key size anywhere, so
// nothing in this family may publish one.
//
// `keyGen()` takes no parameters in any of the 32 archived releases (3.5.0
// Pyfhel/Pyfhel.pyx:290, 2.0.0a2 :128), and `contextGen`'s `sec=` is a security
// level in AES-equivalent bits (3.5.0 :246 "Security level equivalent in AES"),
// which maps to `algorithmClassicalSecurityLevel` -- a field the crypto_rules
// metadata contract FORBIDS outright. This test pins the contract side: no
// Pyfhel entry may contribute a key-size property.
//
// IT ASSERTS LOADED CONTRACT FIELDS ONLY. It cannot see what a rule publishes;
// the rules-repository metadata lint covers that half.
func TestLoadEmbeddedPython_Pyfhel_NoKeyDeclaresAKeySize(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "Pyfhel" {
				continue
			}
			seen++
			for j := range c.Parameters {
				p := &c.Parameters[j]
				if p.Contributes == nil {
					continue
				}
				switch p.Contributes.Property {
				case "keySize", "keyLength", "materialSize":
					t.Errorf("%s#%d contributes %q; Pyfhel states no key size at any call site",
						c.Method, c.Arity, p.Contributes.Property)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no Pyfhel contracts loaded; this assertion would be vacuous")
	}
}

// TestLoadEmbeddedPython_Pyfhel_LibraryBlock pins the `library:` block.
//
// THIS TEST EXISTS BECAUSE THE MUTATION BATTERY FOUND IT MISSING. With only the
// exact-set assertion above, corrupting `version_range` or `coordinates` left
// every other assertion GREEN: both fields are parsed by the loader and then
// consulted by nothing the entry-level render touches. Two of twelve mutations
// survived, and these are the two. `name` was already killed, but only
// incidentally -- the inventory render filters on `SourceLibrary`, so renaming
// the library loads zero contracts and trips the vacuity guard rather than
// reporting the rename.
//
// Every value here is checked against the SOURCE rather than against the YAML:
//
//	version_range ">=2.0.0a2,<4"  -- the oldest and newest archived releases.
//	  PyPI serves an sdist for all 32 committed CSV rows, 2.0.0a2 (the first
//	  published release) through 3.5.0, and no wheel for any of them. The upper
//	  bound is open at 4 because no 4.x exists.
//	coordinates  -- the PURL spells the distribution `pyfhel` (the matrix row
//	  is `pkg:pypi/pyfhel`) while PyPI and the import name spell it `Pyfhel`.
//	  PEP 503 normalises the NAME but the two spellings both occur in the wild,
//	  so both are declared. There is no third form: the distribution name has
//	  no `-`, `_` or `.` for PEP 503 to collapse.
func TestLoadEmbeddedPython_Pyfhel_LibraryBlock(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	// The python KB is a Merge() over many libraries, so kb.Library is nil and
	// the block must be read from a contract's own SourceLibrary plus the
	// loader's per-library metadata. Find any Pyfhel contract to prove the
	// library loaded at all, then assert the block.
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "Pyfhel" {
				seen++
			}
		}
	}
	if seen == 0 {
		t.Fatal("no Pyfhel contracts loaded; this assertion would be vacuous")
	}

	lib := pyfhelLibraryMetadata(t)
	if lib.Name != "Pyfhel" {
		t.Errorf("library.name = %q, want %q", lib.Name, "Pyfhel")
	}
	if lib.VersionRange != ">=2.0.0a2,<4" {
		t.Errorf("library.version_range = %q, want %q -- the archived range is "+
			"2.0.0a2 (first published sdist) through 3.5.0, all 32 CSV rows",
			lib.VersionRange, ">=2.0.0a2,<4")
	}
	wantCoords := []string{"Pyfhel", "pyfhel"}
	gotCoords := append([]string(nil), lib.Coordinates...)
	sort.Strings(gotCoords)
	if strings.Join(gotCoords, ",") != strings.Join(wantCoords, ",") {
		t.Errorf("library.coordinates = %v, want %v -- the PURL spells the "+
			"distribution `pyfhel` and PyPI spells it `Pyfhel`; both occur",
			gotCoords, wantCoords)
	}
}

// pyfhelLibraryMetadata loads the Pyfhel contract file ON ITS OWN so the
// `library:` block survives. The embedded python KB is a Merge() over every
// python library, and Merge() sets Library to nil by design (a merged KB has no
// single library), so the block is unreachable from the merged value.
func pyfhelLibraryMetadata(t *testing.T) *contracts.Library {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("python", "pyfhel.yaml"))
	if err != nil {
		t.Fatalf("reading python/pyfhel.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("loading pyfhel.yaml on its own: %v", err)
	}
	if kb.Library == nil {
		t.Fatal("pyfhel.yaml loaded with no library block")
	}
	return kb.Library
}
