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

// renderPythonGnupgInventory renders every loaded python-gnupg contract as one
// line so the test below can compare the WHOLE SET rather than probing key by
// key.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Every field the loader
// populates is rendered -- role, return type, return confidence,
// canonical_return_type, parameter_types, varargs, and each parameter's
// index/name/role plus its contributed property and derivation. Varargs is
// rendered even though NO python-gnupg entry sets it, and that is deliberate
// twice over: a `varargs: true` mutation otherwise survives every assertion in
// this directory, and for Python the field would be INERT anyway --
// `javaVarargsChainContracts` is the only consumer of `Contract.Varargs` and
// its single call site is gated on `kb.Ecosystem == ecosystemJava`
// (builder.go:1562). Rendering it pins the field at false so nobody adds it
// later believing it collapses an arity.
func renderPythonGnupgInventory(kb *contracts.KnowledgeBase) []string {
	var inventory []string
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			contract := &candidates[i]
			if contract.SourceLibrary != "python-gnupg" {
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

// pythonGnupgMethod is one row of the HAND-WRITTEN signature table below.
//
// python-gnupg reaches 118 contract entries from 24 methods because arity is an
// EXACT match key for Python -- `ContractsFor` returns nil on a miss for every
// ecosystem but rust (contracts.go:203-211) -- and eight of these methods
// forward `**kwargs` to a `_file` sibling, so one method is genuinely callable
// at up to nine different argument counts.
//
// Writing 118 literals by hand would be unreadable and, worse, unauditable: a
// reader could not check them against the library. So the EXPECTATION IS THIS
// TABLE, one row per method, every field READ OFF THE `def` LINE CITED, and the
// test expands min..max into the 118 lines it compares. The expansion rule is
// not invented here -- it is the rule stated in python-gnupg.yaml's header and
// derived from the signatures: min is the parameters without a default (self
// excluded), max is the parameters declared plus the forwarded target's
// remaining parameters when the tail is `**kwargs`.
//
// WHAT MAKES THIS NON-TAUTOLOGICAL, which is the campaign's most repeated
// defect: this table is written from `gnupg.py` and is INDEPENDENT of the YAML.
// Deriving it from the YAML instead is the obvious repair and it is wrong -- it
// makes the assertion green on a corrupted contract, which is the one thing
// the test exists to prevent. A legitimate change to the contract is a
// ONE-FIELD edit to one row here.
type pythonGnupgMethod struct {
	method     string // the contract key, read off an exported call graph
	line       int    // the `def` line in the 0.5.6 sdist's gnupg.py
	minArity   int
	maxArity   int
	role       string
	returnTyp  string
	confidence string
	canonical  bool // whether canonical_return_type is declared
}

// pythonGnupgSignatures is the whole expectation. Citations are against the
// python-gnupg 0.5.6 sdist (`gnupg.py`), which is the single module the whole
// distribution ships. Version windows are in the YAML header, measured by
// parsing every class and def out of all 25 archived sdists.
var pythonGnupgSignatures = []pythonGnupgMethod{
	// :1072 `class GPG(object)`, :1100 `def __init__(self, gpgbinary='gpg',
	// gnupghome=None, verbose=False, use_agent=False, keyring=None,
	// options=None, secret_keyring=None, env=None)` -- 8 parameters, all with
	// defaults, so 0..8. TWO KEYS for one constructor: measured on an exported
	// call graph, `import gnupg; gnupg.GPG(...)` emits no `.<init>` while
	// `from gnupg import GPG; GPG(...)` does. Both are ordinary consumer code.
	{"gnupg.GPG", 1100, 0, 8, "factory", "gnupg.GPG", "high", true},
	{"gnupg.GPG.<init>", 1100, 0, 8, "factory", "gnupg.GPG", "high", true},

	// :2172 `def encrypt(self, data, recipients, **kwargs)`. Two required, and
	// the kwargs forward to encrypt_file (:2104), whose 9 parameters leave 7
	// beyond `data` and `recipients` -- so 2..9. Returns result_map['crypt']
	// (:1083) = Crypt.
	{"gnupg.GPG.encrypt", 2172, 2, 9, "operation", "gnupg.Crypt", "high", true},
	// :2104 `def encrypt_file(self, fileobj_or_path, recipients, sign=None,
	// always_trust=False, passphrase=None, armor=True, output=None,
	// symmetric=False, extra_args=None)` -- 9 parameters, 2 required.
	{"gnupg.GPG.encrypt_file", 2104, 2, 9, "operation", "gnupg.Crypt", "high", true},

	// :2202 `def decrypt(self, message, **kwargs)`, forwarding to decrypt_file
	// (:2225) whose 5 parameters leave 4 beyond `message` -- so 1..5.
	{"gnupg.GPG.decrypt", 2202, 1, 5, "operation", "gnupg.Crypt", "high", true},
	// :2225 `def decrypt_file(self, fileobj_or_path, always_trust=False,
	// passphrase=None, output=None, extra_args=None)` -- 5 parameters.
	{"gnupg.GPG.decrypt_file", 2225, 1, 5, "operation", "gnupg.Crypt", "high", true},

	// :1387 `def sign(self, message, **kwargs)`, forwarding to sign_file
	// (:1442) whose 8 parameters leave 7 beyond `message` -- so 1..8. Returns
	// result_map['sign'] (:1092) = Sign.
	{"gnupg.GPG.sign", 1387, 1, 8, "operation", "gnupg.Sign", "high", true},
	// :1442 `def sign_file(self, fileobj_or_path, keyid=None, passphrase=None,
	// clearsign=True, detach=False, binary=False, output=None,
	// extra_args=None)` -- 8 parameters.
	{"gnupg.GPG.sign_file", 1442, 1, 8, "operation", "gnupg.Sign", "high", true},

	// :1520 `def verify(self, data, **kwargs)`, forwarding to verify_file
	// (:1542) whose 4 parameters leave 3 beyond `data` -- so 1..4. Returns
	// result_map['verify'] (:1094) = Verify.
	{"gnupg.GPG.verify", 1520, 1, 4, "operation", "gnupg.Verify", "high", true},
	// :1542 `def verify_file(self, fileobj_or_path, data_filename=None,
	// close_file=True, extra_args=None)` -- 4 parameters.
	{"gnupg.GPG.verify_file", 1542, 1, 4, "operation", "gnupg.Verify", "high", true},
	// :1581 `def verify_data(self, sig_filename, data, extra_args=None)` --
	// 3 parameters, 2 required. ARRIVES AT 0.3.6.
	{"gnupg.GPG.verify_data", 1581, 2, 3, "operation", "gnupg.Verify", "high", true},

	// :2002 `def gen_key(self, input)` -- one parameter, no kwargs, so the
	// arity is exactly 1. Returns result_map['generate'] (:1085) = GenKey.
	{"gnupg.GPG.gen_key", 2002, 1, 1, "operation", "gnupg.GenKey", "high", true},
	// :2016 `def gen_key_input(self, **kwargs)` -- NO declared parameters, so
	// the arity is unbounded in principle. CAPPED AT 8, which is the one
	// bounded choice in this table: the highest arity measured anywhere (the
	// 24-package consumer draw, the library's own test_gnupg.py and the probe)
	// is 6. Returns the rendered `--gen-key` block as a str (:2039-2045).
	{"gnupg.GPG.gen_key_input", 2016, 0, 8, "factory", "builtins.str", "high", true},
	// :2069 `def add_subkey(self, master_key, master_passphrase=None,
	// algorithm='rsa', usage='encrypt', expire='-')` -- 5 parameters, 1
	// required. ARRIVES AT 0.4.9. Returns result_map['addSubkey'] (:1086).
	{"gnupg.GPG.add_subkey", 2069, 1, 5, "operation", "gnupg.AddSubkey", "high", true},

	// :1606 `def import_keys(self, key_data, extra_args=None,
	// passphrase=None)` -- 3 parameters. Returns result_map['import'] (:1087).
	{"gnupg.GPG.import_keys", 1606, 1, 3, "operation", "gnupg.ImportResult", "high", true},
	// :1628 `def import_keys_file(self, key_path, **kwargs)`, which reads the
	// file and calls import_keys(f.read(), **kwargs) -- so the kwargs are
	// import_keys' `extra_args` and `passphrase`, giving 1..3. ARRIVES AT 0.5.0.
	{"gnupg.GPG.import_keys_file", 1628, 1, 3, "operation", "gnupg.ImportResult", "high", true},

	// :1743 `def export_keys(self, keyids, secret=False, armor=True,
	// minimal=False, passphrase=None, expect_passphrase=True, output=None)` --
	// 7 parameters, 1 required. THE ONE DIVERGENT RETURN: it returns
	// `result.data`, decoded to str only when `armor` is set (:1811-1814), so
	// the value is str or bytes decided by an argument. One value is declared
	// at LOW confidence and canonical_return_type is WITHHELD rather than
	// asserting the armored form holds for every call.
	{"gnupg.GPG.export_keys", 1743, 1, 7, "output", "builtins.str", "low", false},

	// :1839 `def list_keys(self, secret=False, keys=None, sigs=False)` --
	// 3 parameters, none required. Returns _get_list_output(p, 'list')
	// (:1868 -> :1833-1837), i.e. result_map['list'] (:1089) = ListKeys.
	{"gnupg.GPG.list_keys", 1839, 0, 3, "output", "gnupg.ListKeys", "high", true},
	// :1883 `def scan_keys(self, filename)` -- one parameter. Returns
	// _get_list_output(p, 'scan') (:1907), i.e. ScanKeys (:1090). ARRIVES 0.3.7.
	{"gnupg.GPG.scan_keys", 1883, 1, 1, "output", "gnupg.ScanKeys", "high", true},
	// :1909 `def scan_keys_mem(self, key_data)` -- one parameter, same result
	// class (:1925, :1938). ARRIVES AT 0.5.1.
	{"gnupg.GPG.scan_keys_mem", 1909, 1, 1, "output", "gnupg.ScanKeys", "high", true},
	// :1939 `def search_keys(self, query, keyserver='pgp.mit.edu',
	// extra_args=None)` -- 3 parameters. Returns result_map['search'] (:1091)
	// = SearchKeys (:1976). ARRIVES AT 0.3.5.
	{"gnupg.GPG.search_keys", 1939, 1, 3, "output", "gnupg.SearchKeys", "high", true},

	// :1662 `def send_keys(self, keyserver, *keyids, **kwargs)` -- the varargs
	// make the arity unbounded. CAPPED AT 4 (keyserver plus two key ids plus
	// extra_args), the second bounded choice in this table. Returns
	// result_map['send'] (:1088) = SendResult (:1675). ARRIVES AT 0.3.5.
	{"gnupg.GPG.send_keys", 1662, 1, 4, "operation", "gnupg.SendResult", "high", true},
	// :1638 `def recv_keys(self, keyserver, *keyids, **kwargs)` -- same shape,
	// same cap. Returns result_map['import'] (:1641) = ImportResult.
	{"gnupg.GPG.recv_keys", 1638, 1, 4, "operation", "gnupg.ImportResult", "high", true},
	// :1978 `def auto_locate_key(self, email, mechanisms=None, **kwargs)` --
	// 2 declared plus `extra_args` in kwargs, so 1..3. Returns
	// result_map['auto-locate-key'] (:1992) = AutoLocateKey. ARRIVES AT 0.5.3.
	{"gnupg.GPG.auto_locate_key", 1978, 1, 3, "output", "gnupg.AutoLocateKey", "high", true},
}

// expandPythonGnupgSignatures turns the hand-written table into the exact set
// of rendered lines the loader must produce. The only arithmetic is min..max,
// which is the rule the table's own citations establish.
func expandPythonGnupgSignatures() []string {
	var want []string
	for _, m := range pythonGnupgSignatures {
		for arity := m.minArity; arity <= m.maxArity; arity++ {
			canonical := ""
			if m.canonical {
				canonical = m.returnTyp
			}
			// parameter_types is deliberately absent from every entry -- eight
			// of these methods take **kwargs and eight take keyword arguments
			// in any order, so at a given arity the positional types are not
			// knowable. The loader renders the empty slice as [].
			want = append(want, fmt.Sprintf("%s#%d|%s|%s|%s|%s|[]|false",
				m.method, arity, m.role, m.returnTyp, m.confidence, canonical))
		}
	}
	sort.Strings(want)
	return want
}

// TestLoadEmbeddedPython_PythonGnupg_ExactSet pins the python-gnupg contract KB
// as an EXACT SET, reported as a SYMMETRIC DIFFERENCE.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the loaded set is exactly
// what the signature table describes, so any edit that adds, drops or corrupts
// an entry fails here and the failure names the exact line. It does NOT prove
// the table is TRUE -- a comparison can only find drift away from a baseline,
// never an error inside it. The baseline's truth rests on the per-row citations
// into python-gnupg 0.5.6's `gnupg.py`, and on the separate assertion below
// that every contracted method is a real public method of the real class.
func TestLoadEmbeddedPython_PythonGnupg_ExactSet(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	got := renderPythonGnupgInventory(kb)
	want := expandPythonGnupgSignatures()

	if len(got) == 0 {
		t.Fatal("no python-gnupg contracts loaded; every assertion here would be vacuous")
	}

	// A SYMMETRIC DIFFERENCE, NOT A COUNT AND NOT A TALLY. A `len(got) !=
	// len(want)` check plus a role tally is the campaign's most repeated
	// defect: it rejects a CORRECT repair in several places at once, so adding
	// a real, present, crypto-relevant entry reads as a regression. There is
	// ONE expectation -- the table above -- and the message says which
	// direction the difference is in and quotes the exact line.
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
				"widen or add the matching row in pythonGnupgSignatures:\n\t\t%q", line)
		}
	}
	for _, line := range want {
		if !inGot[line] {
			t.Errorf("expected contract entry did not load -- if it was deliberately "+
				"removed, narrow or delete the matching row in "+
				"pythonGnupgSignatures:\n\t\t%q", line)
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
			if c.SourceLibrary == "python-gnupg" && !valid[c.Role] {
				t.Errorf("%s#%d carries role %q, which is outside the whitelist",
					c.Method, c.Arity, c.Role)
			}
		}
	}
}

// TestLoadEmbeddedPython_PythonGnupg_EveryKeyIsRootedAtTheModule is the
// contract-side half of the wrong-package assertion the rules carry in
// the rules repository's own python-gnupg false-positive test module.
//
// A SECOND PyPI DISTRIBUTION IMPORTS AS `gnupg`: pkg:pypi/gnupg 2.3.1, a fork
// of this library. python-gnupg is a SINGLE MODULE -- the sdist ships `gnupg.py`
// and nothing else importable -- while the fork is a PACKAGE with submodules
// `gnupg.gnupg`, `gnupg._meta`, `gnupg._parsers` and `gnupg._util`. So a key
// carrying any of those segments would be the fork's, not this library's, and
// no key here may name one. `pretty_bad_protocol` is the renamed continuation
// of the same fork and is a different module root entirely.
func TestLoadEmbeddedPython_PythonGnupg_EveryKeyIsRootedAtTheModule(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	seen := 0
	forkOnly := map[string]bool{
		"_meta": true, "_parsers": true, "_util": true, "_trust": true,
		"_logger": true, "_ansistrm": true, "copyleft": true,
		"pretty_bad_protocol": true,
	}
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "python-gnupg" {
				continue
			}
			seen++
			segments := strings.Split(c.Method, ".")
			if segments[0] != "gnupg" {
				t.Errorf("%s is not rooted at the gnupg module", c.Method)
			}
			// python-gnupg has no submodule at all, so the second segment is
			// always the class `GPG`. A `gnupg.gnupg.` key would be the fork's.
			if len(segments) > 1 && segments[1] != "GPG" {
				t.Errorf("%s: the second segment is %q; python-gnupg is a single "+
					"module whose only contracted class is GPG, so anything else "+
					"is the forked pkg:pypi/gnupg distribution's shape",
					c.Method, segments[1])
			}
			for _, segment := range segments {
				if forkOnly[segment] {
					t.Errorf("%s carries the forked distribution's module segment %q",
						c.Method, segment)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no python-gnupg contracts loaded; this assertion would be vacuous")
	}
}

// TestLoadEmbeddedPython_PythonGnupg_NoNonCryptoMethodIsContracted pins the
// deliberate NON-claims, which the exact-set test cannot express: it fails on
// an entry that IS there and says nothing about one that is correctly absent.
//
// Each of these is a real public `GPG` method with real consumer call sites and
// none performs or requests an operation on material this scan can name.
// `delete_keys` and `trust_keys` have 4 and 2 real call sites respectively in
// the 24-package consumer draw, so their absence is a decision, not an
// oversight, and this test is what stops one being added without the decision
// being revisited.
func TestLoadEmbeddedPython_PythonGnupg_NoNonCryptoMethodIsContracted(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	// gnupg.py line numbers at 0.5.6, for a reader auditing the decision.
	skipped := map[string]int{
		"gnupg.GPG.delete_keys":                     1688,
		"gnupg.GPG.trust_keys":                      2290,
		"gnupg.GPG.get_recipients":                  2255,
		"gnupg.GPG.get_recipients_file":             2271,
		"gnupg.GPG.make_args":                       1179,
		"gnupg.GPG.set_output_without_confirmation": 1414,
		"gnupg.GPG.is_valid_passphrase":             1429,
		"gnupg.GPG.is_valid_file":                   1331,
	}
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "python-gnupg" {
				continue
			}
			seen++
			if line, ok := skipped[c.Method]; ok {
				t.Errorf("%s#%d is contracted, but it is a deliberate "+
					"skipped-non-crypto entry (gnupg.py:%d at 0.5.6): it builds "+
					"an argv, validates a string, reads an existing message's "+
					"recipients, writes gpg's trustdb or removes a keyring "+
					"entry. If the disposition has changed, change it in "+
					"python-gnupg.yaml's API audit and here together.",
					c.Method, c.Arity, line)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no python-gnupg contracts loaded; this assertion would be vacuous")
	}
}

// TestLoadEmbeddedPython_PythonGnupg_LibraryBlock pins the library block, which
// the exact-set rendering does not cover. version_range, coordinates, name and
// description are parsed and then never consulted by any other assertion, so
// corrupting one of them leaves every other test in this directory green.
func TestLoadEmbeddedPython_PythonGnupg_LibraryBlock(t *testing.T) {
	t.Parallel()

	// library.name is what populates SourceLibrary on every entry; corrupting
	// it empties the exact-set test as well as this one.
	kb := loadPythonKB(t)
	found := false
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "python-gnupg" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no contract carries SourceLibrary \"python-gnupg\"; library.name did not load")
	}

	data, err := os.ReadFile(filepath.Join("python", "python-gnupg.yaml"))
	if err != nil {
		t.Fatalf("read python-gnupg.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(python-gnupg.yaml): %v", err)
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
	if single.Library.Name != "python-gnupg" {
		t.Errorf("library.name = %q, want \"python-gnupg\"", single.Library.Name)
	}
	// The lower bound is 0.3.3 and NOT the matrix's oldest row (0.2.3): PyPI
	// serves NO FILES AT ALL for 0.2.3 through 0.3.2 -- nine of the 34
	// committed CSV rows have an index entry with an empty file list, so no
	// API could be read for them and none is claimed. Measured against
	// https://pypi.org/pypi/python-gnupg/json, not assumed.
	if single.Library.VersionRange != ">=0.3.3,<0.6" {
		t.Errorf("library.version_range = %q, want \">=0.3.3,<0.6\"", single.Library.VersionRange)
	}
	// The DISTRIBUTION is `python-gnupg`; the IMPORT is `gnupg`. All three
	// spellings are coordinates because the contract keys use the import name
	// while the PURL uses the distribution name, and PEP 503 normalization
	// (the mining service's PEP 503 normalizer) collapses
	// `python_gnupg` onto `python-gnupg`.
	wantCoordinates := []string{"python-gnupg", "python_gnupg", "gnupg"}
	if !slices.Equal(single.Library.Coordinates, wantCoordinates) {
		t.Errorf("library.coordinates = %#v, want %#v", single.Library.Coordinates, wantCoordinates)
	}
	if !strings.Contains(single.Library.Description, "IMPLEMENTS NO CRYPTOGRAPHY") {
		t.Errorf("library.description does not state that the library runs the "+
			"gpg binary rather than computing anything: %q", single.Library.Description)
	}
}
