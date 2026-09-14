// Package contracts_test pins the liboqs-python callgraph contract KB.
//
// liboqs-python is a ctypes binding over the liboqs C library (0.16.0
// oqs/oqs.py:255 `_load_liboqs`). These contracts type the PYTHON API only.
//
// THE SIGNATURE TABLE BELOW IS WRITTEN BY HAND FROM THE LIBRARY'S OWN SOURCES,
// NOT FROM THE YAML. Deriving an expectation from the file it checks makes the
// assertion tautological and green on a corrupted contract, which is the one
// thing it exists to prevent. Every row carries the `oqs/oqs.py` line its arity
// was read from, in liboqs-python 0.16.0 -- the only release PyPI serves --
// with the older archives cited where a symbol's window is narrower.
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

// liboqsPythonSignature is one method of one class, with every arity at which
// a consumer can call it. Arity is an exact match key for
// `KnowledgeBase.ContractsFor`, and `varargs` is inert for Python
// (builder.go:1562 is Java-gated), so each arity is its own entry.
//
// NOT ONE METHOD OF THIS LIBRARY TAKES *args OR **kwargs, so every arity here
// is exact and none is a cap -- which is unusual for a Python KB and is why
// these ranges are single values rather than spans.
type liboqsPythonSignature struct {
	method  string
	arities []int
	role    string
	ret     string
	// canonical is the canonical_return_type; it equals ret for every entry in
	// this family.
	source string // the `def` line this arity was read from
}

// The three entry-point classes. Each constructor is reachable under FOUR key
// spellings, read off an exported call graph rather than reasoned about:
//
//	import oqs;                       oqs.X(..)  -> oqs.X
//	from oqs import X;                X(..)      -> oqs.X.<init>
//	import oqs.oqs;                   oqs.oqs.X(..) -> oqs.oqs.X
//	from oqs.oqs import X;            X(..)      -> oqs.oqs.X.<init>
//
// liboqs-python re-exports every public name from `oqs/oqs.py` through
// `oqs/__init__.py` (0.16.0 __init__.py:1-21; 0.12.0 __init__.py:1 is
// `from oqs.oqs import *`), so all four are ordinary consumer code.
var liboqsPythonClasses = []string{"KeyEncapsulation", "Signature", "StatefulSignature"}

func liboqsPythonCtorKeys(class string) []string {
	return []string{
		"oqs." + class,
		"oqs." + class + ".<init>",
		"oqs.oqs." + class,
		"oqs.oqs." + class + ".<init>",
	}
}

// liboqsPythonMethods is the per-class method table, hand-written from
// liboqs-python 0.16.0 `oqs/oqs.py`.
var liboqsPythonMethods = map[string][]liboqsPythonSignature{
	// class KeyEncapsulation(ct.Structure) -- 0.16.0 oqs/oqs.py:367
	"KeyEncapsulation": {
		{"__enter__", []int{0}, "factory", "oqs.KeyEncapsulation", ":444 def __enter__(self) -> Self"},
		{"generate_keypair", []int{0}, "operation", "builtins.bytes", ":488 def generate_keypair(self) -> bytes"},
		{"generate_keypair_seed", []int{1}, "operation", "builtins.bytes", ":455 def generate_keypair_seed(self, seed) -> bytes; ARRIVES 0.14.0"},
		{"encap_secret", []int{1}, "operation", "builtins.tuple", ":510 def encap_secret(self, public_key) -> tuple[bytes, bytes]"},
		{"decap_secret", []int{1}, "operation", "builtins.bytes", ":537 def decap_secret(self, ciphertext) -> bytes"},
		{"export_secret_key", []int{0}, "output", "builtins.bytes", ":506 def export_secret_key(self) -> bytes"},
	},
	// class Signature(ct.Structure) -- 0.16.0 oqs/oqs.py:607
	"Signature": {
		{"__enter__", []int{0}, "factory", "oqs.Signature", ":683 def __enter__(self) -> Self"},
		{"generate_keypair", []int{0}, "operation", "builtins.bytes", ":694 def generate_keypair(self) -> bytes"},
		{"sign", []int{1}, "operation", "builtins.bytes", ":718 def sign(self, message) -> bytes"},
		{"sign_with_ctx_str", []int{2}, "operation", "builtins.bytes", ":773 def sign_with_ctx_str(self, message, context) -> bytes; ARRIVES 0.12.0"},
		{"verify", []int{3}, "operation", "builtins.bool", ":745 def verify(self, message, signature, public_key) -> bool"},
		{"verify_with_ctx_str", []int{4}, "operation", "builtins.bool", ":815 def verify_with_ctx_str(self, message, signature, context, public_key) -> bool; ARRIVES 0.12.0"},
		{"export_secret_key", []int{0}, "output", "builtins.bytes", ":714 def export_secret_key(self) -> bytes"},
	},
	// class StatefulSignature(ct.Structure) -- 0.16.0 oqs/oqs.py:991.
	// THE WHOLE CLASS ARRIVES AT 0.14.0 (CHANGES.md `Version 0.14.0`).
	"StatefulSignature": {
		{"__enter__", []int{0}, "factory", "oqs.StatefulSignature", ":1249 def __enter__(self) -> Self"},
		{"generate_keypair", []int{0}, "operation", "builtins.bytes", ":1111 def generate_keypair(self) -> bytes"},
		{"sign", []int{1}, "operation", "builtins.bytes", ":1147 def sign(self, message) -> bytes"},
		{"verify", []int{3}, "operation", "builtins.bool", ":1187 def verify(self, message, signature, public_key) -> bool"},
		{"export_secret_key", []int{0}, "output", "builtins.bytes", ":1202 def export_secret_key(self) -> bytes"},
		{"export_used_keys", []int{0}, "output", "builtins.list", ":1245 def export_used_keys(self) -> list[bytes]"},
	},
}

// ctorArities is `__init__(self, alg_name, secret_key=None)` -- 0.16.0
// oqs/oqs.py:398 (KeyEncapsulation), :638 (Signature), :1024
// (StatefulSignature). All three declare the identical two-parameter shape.
var liboqsPythonCtorArities = []int{1, 2}

func renderLiboqsPythonInventory(kb *contracts.KnowledgeBase) []string {
	var inventory []string
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "liboqs-python" {
				continue
			}
			inventory = append(inventory, fmt.Sprintf("%s#%d|%s|%s|%s|%s|%v|%v",
				c.Method, c.Arity, c.Role, c.Return.Type, c.Return.Confidence,
				c.CanonicalReturnType, c.ParameterTypes, c.Varargs))
		}
	}
	sort.Strings(inventory)
	return inventory
}

func expandLiboqsPythonSignatures() []string {
	var want []string
	for _, class := range liboqsPythonClasses {
		for _, key := range liboqsPythonCtorKeys(class) {
			for _, arity := range liboqsPythonCtorArities {
				want = append(want, fmt.Sprintf("%s#%d|factory|oqs.%s|high|oqs.%s|[]|false",
					key, arity, class, class))
			}
		}
		for _, sig := range liboqsPythonMethods[class] {
			for _, arity := range sig.arities {
				want = append(want, fmt.Sprintf("oqs.%s.%s#%d|%s|%s|high|%s|[]|false",
					class, sig.method, arity, sig.role, sig.ret, sig.ret))
			}
		}
	}
	sort.Strings(want)
	return want
}

// TestLoadEmbeddedPython_LiboqsPython_ExactSet pins the KB as an EXACT SET,
// reported as a SYMMETRIC DIFFERENCE.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the loaded set is exactly
// what the hand-written table describes, so any edit that adds, drops or
// corrupts an entry fails here and the failure names the exact line. It does
// NOT prove the table is TRUE: a comparison can only find drift away from a
// baseline, never an error inside it. The baseline's truth rests on the
// per-row `oqs/oqs.py` citations above and on
// TestLoadEmbeddedPython_LiboqsPython_NoNonCryptoMethodIsContracted below.
func TestLoadEmbeddedPython_LiboqsPython_ExactSet(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	got := renderLiboqsPythonInventory(kb)
	want := expandLiboqsPythonSignatures()

	if len(got) == 0 {
		t.Fatal("no liboqs-python contracts loaded; every assertion here would be vacuous")
	}

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
			t.Errorf("unexpected contract entry -- if the YAML change is intended, add "+
				"the matching row to liboqsPythonMethods with its oqs/oqs.py citation:\n\t\t%q", line)
		}
	}
	for _, line := range want {
		if !inGot[line] {
			t.Errorf("expected contract entry did not load -- if it was deliberately "+
				"removed, delete the matching row from liboqsPythonMethods:\n\t\t%q", line)
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
			if c.SourceLibrary == "liboqs-python" && !valid[c.Role] {
				t.Errorf("%s#%d carries role %q, which is outside the whitelist",
					c.Method, c.Arity, c.Role)
			}
		}
	}
}

// TestLoadEmbeddedPython_LiboqsPython_EveryKeyIsRootedAtTheOqsModule is the
// contract-side half of the wrong-package assertion the rules carry.
//
// `oqs` is a short, generic import name, and Python has no receiver filtering
// in crypto-finder (internal/scan/foreign_receiver_filter.go returns 0 unless
// the ecosystem is rust), so a key that is not rooted at the module would
// attach this library's types to somebody else's calls.
func TestLoadEmbeddedPython_LiboqsPython_EveryKeyIsRootedAtTheOqsModule(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	seen := 0
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			c := &candidates[i]
			if c.SourceLibrary != "liboqs-python" {
				continue
			}
			seen++
			if !strings.HasPrefix(c.Method, "oqs.") {
				t.Errorf("%s#%d is not rooted at the oqs module", c.Method, c.Arity)
			}
			if c.CanonicalReturnType == "" {
				t.Errorf("%s#%d has an empty canonical_return_type, which renders "+
					"identically to having no contract at all", c.Method, c.Arity)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no liboqs-python contracts loaded; this assertion would be vacuous")
	}
}

// TestLoadEmbeddedPython_LiboqsPython_NoNonCryptoMethodIsContracted asserts the
// DELIBERATE NON-CLAIMS.
//
// Each name below performs no cryptography and names no mechanism: the
// enumeration and interrogation helpers read a list out of the loaded C
// library, `free`/`__exit__` release the structure, and `sigs_total` /
// `sigs_remaining` read a counter. Contracting any of them would attach a
// crypto type to a call that computes nothing. They are listed here rather
// than left implicit so that adding one later is a visible decision.
func TestLoadEmbeddedPython_LiboqsPython_NoNonCryptoMethodIsContracted(t *testing.T) {
	t.Parallel()

	kb := loadPythonKB(t)
	forbidden := []string{
		"oqs.get_enabled_kem_mechanisms", "oqs.get_supported_kem_mechanisms",
		"oqs.get_enabled_sig_mechanisms", "oqs.get_supported_sig_mechanisms",
		"oqs.get_enabled_stateful_sig_mechanisms",
		"oqs.get_supported_stateful_sig_mechanisms",
		"oqs.is_kem_enabled", "oqs.is_sig_enabled", "oqs.is_stateful_sig_enabled",
		"oqs.sig_supports_context", "oqs.oqs_version", "oqs.oqs_python_version",
		"oqs.native", "oqs.version",
		"oqs.KeyEncapsulation.free", "oqs.Signature.free",
		"oqs.StatefulSignature.free",
		"oqs.KeyEncapsulation.__exit__", "oqs.Signature.__exit__",
		"oqs.StatefulSignature.__exit__",
		"oqs.StatefulSignature.sigs_total", "oqs.StatefulSignature.sigs_remaining",
		// oqs/rand.py is a genuine DRBG surface and is covered by NEITHER
		// repository for this family. Named so the boundary is visible.
		"oqs.rand.randombytes", "oqs.rand.randombytes_switch_algorithm",
	}
	contracted := map[string]bool{}
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "liboqs-python" {
				contracted[candidates[i].Method] = true
			}
		}
	}
	if len(contracted) == 0 {
		t.Fatal("no liboqs-python contracts loaded; this assertion would be vacuous")
	}
	for _, name := range forbidden {
		if contracted[name] {
			t.Errorf("%s is contracted but performs no cryptography; either it does "+
				"after all -- in which case say why on its entry -- or the entry is wrong",
				name)
		}
	}
}

// TestLoadEmbeddedPython_LiboqsPython_LibraryBlock pins the coordinates and the
// version range, which are parsed and never consulted by any other assertion,
// so a corruption there is otherwise silent.
func TestLoadEmbeddedPython_LiboqsPython_LibraryBlock(t *testing.T) {
	t.Parallel()

	// library.name is what populates SourceLibrary on every entry; corrupting
	// it empties the exact-set test as well as this one.
	kb := loadPythonKB(t)
	found := false
	for _, candidates := range kb.Contracts {
		for i := range candidates {
			if candidates[i].SourceLibrary == "liboqs-python" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no contract carries SourceLibrary \"liboqs-python\"; library.name did not load")
	}

	data, err := os.ReadFile(filepath.Join("python", "liboqs-python.yaml"))
	if err != nil {
		t.Fatalf("read liboqs-python.yaml: %v", err)
	}
	single, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(liboqs-python.yaml): %v", err)
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
	if single.Library.Name != "liboqs-python" {
		t.Errorf("library.name = %q, want \"liboqs-python\"", single.Library.Name)
	}
	// THE DISTRIBUTION IS `liboqs-python`; THE IMPORT NAME IS `oqs`. Both, plus
	// the PEP 503 underscore form, are declared so a resolver keying on either
	// coordinate joins. This is the same distribution-versus-import split the
	// merged `python-gnupg` (imports as `gnupg`) and `pycryptodome` (imports as
	// `Crypto`) families carry.
	wantCoords := map[string]bool{"liboqs-python": false, "liboqs_python": false, "oqs": false}
	for _, c := range single.Library.Coordinates {
		if _, ok := wantCoords[c]; !ok {
			t.Errorf("unexpected coordinate %q", c)
			continue
		}
		wantCoords[c] = true
	}
	for c, seen := range wantCoords {
		if !seen {
			t.Errorf("coordinate %q is missing; a consumer keying on it would not join", c)
		}
	}
	// The lower bound is 0.7.2 -- the oldest GitHub archive whose API could
	// actually be read -- and NOT either of the two rows in the committed CSV.
	// PyPI serves EXACTLY ONE release of this distribution: 0.16.0. 0.14.1 and
	// 0.15.0 return HTTP 404 from the JSON API, are absent from the PEP 503
	// simple index, have no GitHub tag, and appear in liboqs-python's own
	// CHANGES.md not at all; deps.dev's live API also lists only 0.16.0.
	if single.Library.VersionRange != ">=0.7.2,<0.17" {
		t.Errorf("version_range = %q, want \">=0.7.2,<0.17\"", single.Library.VersionRange)
	}
}
