// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

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

// PGPy is a pure-Python OpenPGP implementation, so its whole contracted surface
// is a lifecycle: a factory types a receiver, the receiver's operations return
// the next object. Before this contract existed an exported call graph over a
// probe consumer keyed every operation on the CONSUMER'S VARIABLE PATH --
// `probe.key.sign(?)`, `probe.ring.sign(?)` -- which no contract can ever join.
// The factory return types are therefore load bearing for every operation entry
// below them, and this file is what proves each of them resolves.
//
// Two spellings of every type are declared and both are exercised here.
// Measured on that probe: `from pgpy import PGPKey` and the written-out
// `import pgpy; pgpy.PGPKey.new(..)` emit the SAME key `pgpy.PGPKey.new`, while
// `from pgpy.pgp import PGPKey` emits `pgpy.pgp.PGPKey.new`. Neither resolves
// the other.

// pgpyContract is one hand-written expectation, sourced from PGPy's own
// releases rather than from the YAML. Deriving these from the contract file is
// the one repair that must not be made: it makes the assertion tautological and
// green on a corrupted contract, which is the single thing this test exists to
// prevent.
type pgpyContract struct {
	method     string
	arity      int
	role       string
	returnType string
	canonical  string
	params     []string
	confidence string
	varargs    bool
}

func (c pgpyContract) render() string {
	return fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/varargs=%t",
		c.method, c.arity, c.role, c.returnType, c.canonical,
		strings.Join(c.params, ", "), c.confidence, c.varargs)
}

// pgpyLifecycle returns the contracts expected for one module spelling of the
// PGPKey / PGPMessage / PGPSignature trio.
//
// EVERY FIELD BELOW WAS READ FROM PGPy's SOURCE, per entry:
//
//	PGPKey.new(key_algorithm, key_size, created=None)   0.6.0 pgpy/pgp.py:1588
//	  -- two REQUIRED arguments; `created=` arrives at 0.5.0 and the Python
//	  arity-tolerant fallback covers it. Returns a PGPKey (pgp.py:1612).
//	PGPKey.from_file / from_blob                       0.6.0 pgpy/types.py
//	  -- `Armorable.from_file` returns `(obj, po)` when `parse` yields
//	  leftovers, and `PGPKey.parse` returns its `keys` dict (pgp.py:2676), so
//	  the declared return is a tuple and the semantic one is the key.
//	PGPKey()                                           0.6.0 pgpy/pgp.py:1627
//	  -- zero-argument shell, `self._key = None`.
//	PGPKey.sign(subject, **prefs)                      0.6.0 pgpy/pgp.py:2007
//	PGPKey.certify(subject, level=..., **prefs)        0.6.0 pgpy/pgp.py:2058
//	PGPKey.revoke(target, **prefs)                     0.6.0 pgpy/pgp.py:2225
//	PGPKey.bind(key, **prefs)                          0.6.0 pgpy/pgp.py:2307
//	  -- all four build and return a PGPSignature through `_sign`.
//	PGPKey.verify(subject, signature=None)             0.6.0 pgpy/pgp.py:2414
//	  -- returns the SignatureVerification built at :2469, returned at :2496.
//	  `medium` because the type moved module inside the version range:
//	  pgpy.types at 0.2.3+ (0.2.3 pgpy/types.py:141), pgpy.signature at 0.1.0
//	  (0.1.0 pgpy/signature.py:5).
//	PGPKey.encrypt(message, sessionkey=None, **prefs)  0.6.0 pgpy/pgp.py:2499
//	PGPKey.decrypt(message)                            0.6.0 pgpy/pgp.py:2567
//	  -- both return a PGPMessage.
//	PGPKey.protect(passphrase, enc_alg, hash_alg)      0.6.0 pgpy/pgp.py:1734
//	  -- three REQUIRED arguments, mutates in place, returns None.
//	PGPKey.unlock(passphrase)                          0.6.0 pgpy/pgp.py:1766
//	  -- a @contextlib.contextmanager yielding `self` (pgp.py:1800), hence
//	  `medium`: the declared return is a context manager.
//	PGPMessage.new(message, **kwargs)                  0.6.0 pgpy/pgp.py:1097
//	PGPMessage.from_file / from_blob                   0.6.0 pgpy/types.py
//	  -- NO tuple here: `PGPMessage.parse` returns None (pgp.py:1269-1296), so
//	  `from_file` falls through to `return obj`.
//	PGPMessage.encrypt(passphrase, sessionkey=None, **prefs)
//	                                                   0.6.0 pgpy/pgp.py:1189
//	PGPMessage.decrypt(passphrase)                     0.6.0 pgpy/pgp.py:1239
//	PGPSignature.from_file / from_blob                 0.6.0 pgpy/types.py
//	  -- single object; `PGPSignature.parse` returns None (pgp.py:573-594).
//	PGPSignature.new(sigtype, pkalg, halg, signer, created=None)
//	                                                   0.6.0 pgpy/pgp.py:324
//	  -- four REQUIRED arguments; `created=` arrives at 0.5.0.
func pgpyLifecycle(mod string) []pgpyContract {
	key := mod + ".PGPKey"
	msg := mod + ".PGPMessage"
	sig := mod + ".PGPSignature"
	return []pgpyContract{
		{method: key + ".new", arity: 2, role: "factory", returnType: key, confidence: "high"},
		{method: key + ".from_file", arity: 1, role: "factory", returnType: key, canonical: "builtins.tuple", params: []string{"builtins.str"}, confidence: "high"},
		{method: key + ".from_blob", arity: 1, role: "factory", returnType: key, canonical: "builtins.tuple", params: []string{"builtins.str"}, confidence: "high"},
		{method: key + ".<init>", arity: 0, role: "factory", returnType: key, confidence: "high"},
		{method: key, arity: 0, role: "factory", returnType: key, confidence: "high"},
		{method: key + ".sign", arity: 1, role: "operation", returnType: sig, confidence: "high"},
		{method: key + ".certify", arity: 1, role: "operation", returnType: sig, confidence: "high"},
		{method: key + ".revoke", arity: 1, role: "operation", returnType: sig, confidence: "high"},
		{method: key + ".bind", arity: 1, role: "operation", returnType: sig, confidence: "high"},
		{method: key + ".verify", arity: 1, role: "operation", returnType: "pgpy.types.SignatureVerification", confidence: "medium"},
		{method: key + ".encrypt", arity: 1, role: "operation", returnType: msg, confidence: "high"},
		{method: key + ".decrypt", arity: 1, role: "operation", returnType: msg, confidence: "high"},
		{method: key + ".protect", arity: 3, role: "operation", returnType: "builtins.NoneType", confidence: "high"},
		{method: key + ".unlock", arity: 1, role: "operation", returnType: key, confidence: "medium"},

		{method: msg + ".new", arity: 1, role: "factory", returnType: msg, confidence: "high"},
		{method: msg + ".from_file", arity: 1, role: "factory", returnType: msg, params: []string{"builtins.str"}, confidence: "high"},
		{method: msg + ".from_blob", arity: 1, role: "factory", returnType: msg, params: []string{"builtins.str"}, confidence: "high"},
		{method: msg + ".<init>", arity: 0, role: "factory", returnType: msg, confidence: "high"},
		{method: msg, arity: 0, role: "factory", returnType: msg, confidence: "high"},
		{method: msg + ".encrypt", arity: 1, role: "operation", returnType: msg, confidence: "high"},
		{method: msg + ".decrypt", arity: 1, role: "operation", returnType: msg, confidence: "high"},

		{method: sig + ".from_file", arity: 1, role: "factory", returnType: sig, params: []string{"builtins.str"}, confidence: "high"},
		{method: sig + ".from_blob", arity: 1, role: "factory", returnType: sig, params: []string{"builtins.str"}, confidence: "high"},
		{method: sig + ".new", arity: 4, role: "factory", returnType: sig, confidence: "high"},
		{method: sig + ".<init>", arity: 0, role: "factory", returnType: sig, confidence: "high"},
		{method: sig, arity: 0, role: "factory", returnType: sig, confidence: "high"},
	}
}

// pgpyModernKeyring returns the 0.3.0-onward keyring, which declares `load`,
// `key`, `fingerprints` and `unload` and NO `sign` or `verify`
// (0.6.0 pgpy/pgp.py:2679 onward).
//
//	PGPKeyring(*args)      0.6.0 pgpy/pgp.py:2680 -- variadic, so arity 1 with
//	                       varargs: a variadic parameter occupies one slot, and
//	                       the loader refuses varargs at arity 0 outright.
//	PGPKeyring.load(*args) 0.6.0 pgpy/pgp.py:110, returning list(loaded) at :139
//	PGPKeyring.key(id)     0.6.0 pgpy/pgp.py:2820, a @contextmanager yielding
//	                       self._get_key(identifier) at :2837 -- hence `medium`.
func pgpyModernKeyring(mod string) []pgpyContract {
	ring := mod + ".PGPKeyring"
	return []pgpyContract{
		{method: ring + ".<init>", arity: 1, role: "factory", returnType: ring, confidence: "high", varargs: true},
		{method: ring, arity: 1, role: "factory", returnType: ring, confidence: "high", varargs: true},
		{method: ring + ".load", arity: 1, role: "factory", returnType: "builtins.list", confidence: "high", varargs: true},
		{method: ring + ".key", arity: 1, role: "operation", returnType: mod + ".PGPKey", confidence: "medium"},
	}
}

// pgpyLegacyKeyringRootSpelling returns the two entries that exist ONLY under
// the package-root path, because `api` is joined against the FQN the call graph
// emits for the METHOD DEFINITION and that FQN drops the module filename.
//
// Measured on the extracted 0.2.3 sdist with crypto-finder built from this
// worktree: `pgpy/keys.py`'s methods emit `pgpy.(PGPKeyring).sign` and
// `pgpy.(PGPKeyring).verify`, normalized by the entry-point synthesis to
// `pgpy.PGPKeyring.sign` / `.verify` -- NOT `pgpy.keys.PGPKeyring.sign`, which
// could match no definition FQN in any release.
//
// Note what fixing it did NOT change, because the obvious inference is wrong:
// mining 0.1.0 still synthesizes ZERO pgpy entry points, and that is correct.
// internal/engine/rule_entrypoint_synthesis.go emits a synthetic entry point
// only for a method whose body has no already-detected crypto finding, and both
// legacy methods hash inside themselves (0.1.0 pgpy/keys.py:284 in `sign`, :356
// in `verify`).
//
//	sign(subject, inline=False)   0.2.3 pgpy/keys.py:551; 0.1.0 keys.py:226
//	verify(subject, signature)    0.2.3 pgpy/keys.py:706; 0.1.0 keys.py:309
//
// There is NO `pgpy.pgp.PGPKeyring.sign` counterpart: the modern class in
// pgpy/pgp.py declares neither method, and that absence is real.
func pgpyLegacyKeyringRootSpelling() []pgpyContract {
	return []pgpyContract{
		{method: "pgpy.PGPKeyring.sign", arity: 1, role: "operation", returnType: "pgpy.pgp.PGPSignature", confidence: "medium"},
		{method: "pgpy.PGPKeyring.verify", arity: 2, role: "operation", returnType: "pgpy.types.SignatureVerification", confidence: "medium"},
	}
}

// pgpyLegacyKeyring returns the 0.1.0 - 0.2.3 keyring. `pgpy/keys.py` is
// DELETED at 0.3.0, so the module path itself bounds every entry above by
// 0.2.3, and this is the only crypto-relevant surface those five committed CSV
// rows have.
//
//	PGPKeyring(*args)          0.2.3 pgpy/keys.py:315 onward
//	PGPKeyring.load(*args)     0.2.3 pgpy/keys.py:357; 0.1.0 keys.py:133 --
//	                           returns nothing, UNLIKE the modern `load`, hence
//	                           `medium`.
//	PGPKeyring.key(fp=None)    0.2.3 pgpy/keys.py:436, a @contextmanager
//	                           yielding SELF at :479 -- not a key object, which
//	                           is why this era signs through the keyring.
//	PGPKeyring.sign(subject, inline=False)
//	                           0.2.3 pgpy/keys.py:551; 0.1.0 keys.py:226 --
//	                           returns the signature built at 0.2.3 keys.py:703,
//	                           whose class is the PGPBlock-era
//	                           pgpy.pgp.PGPSignature (0.2.3 pgpy/pgp.py:269;
//	                           0.1.0 pgpy/pgp.py:265), hence `medium`.
//	PGPKeyring.verify(subject, signature)
//	                           0.2.3 pgpy/keys.py:706; 0.1.0 keys.py:309.
//	PGPKeyring.export_key(pub=True, priv=False)
//	                           0.2.3 pgpy/keys.py:491 -- 0.2.3 only, hence
//	                           `medium`; 0.1.0 has no such method.
func pgpyLegacyKeyring() []pgpyContract {
	ring := "pgpy.keys.PGPKeyring"
	return []pgpyContract{
		{method: ring + ".<init>", arity: 1, role: "factory", returnType: ring, confidence: "high", varargs: true},
		{method: ring, arity: 1, role: "factory", returnType: ring, confidence: "high", varargs: true},
		{method: ring + ".load", arity: 1, role: "factory", returnType: "builtins.NoneType", confidence: "medium", varargs: true},
		{method: ring + ".key", arity: 1, role: "operation", returnType: ring, confidence: "medium"},
		{method: ring + ".sign", arity: 1, role: "operation", returnType: "pgpy.pgp.PGPSignature", confidence: "medium"},
		{method: ring + ".verify", arity: 2, role: "operation", returnType: "pgpy.types.SignatureVerification", confidence: "medium"},
		{method: ring + ".export_key", arity: 0, role: "output", returnType: "builtins.str", confidence: "medium"},
	}
}

// pgpyConstants returns the two METHODS on SymmetricKeyAlgorithm.
//
//	gen_key(self)  os.urandom(self.key_size // 8)    0.6.0 pgpy/constants.py:243-245
//	gen_iv(self)   os.urandom(self.block_size // 8)  0.6.0 pgpy/constants.py:240-242
func pgpyConstants() []pgpyContract {
	return []pgpyContract{
		{method: "pgpy.constants.SymmetricKeyAlgorithm.gen_key", arity: 0, role: "operation", returnType: "builtins.bytes", confidence: "high"},
		{method: "pgpy.constants.SymmetricKeyAlgorithm.gen_iv", arity: 0, role: "operation", returnType: "builtins.bytes", confidence: "high"},
	}
}

func wantPGPyContracts() []string {
	all := make([]pgpyContract, 0, 71)
	for _, mod := range []string{"pgpy", "pgpy.pgp"} {
		all = append(all, pgpyLifecycle(mod)...)
		all = append(all, pgpyModernKeyring(mod)...)
	}
	all = append(all, pgpyLegacyKeyringRootSpelling()...)
	all = append(all, pgpyLegacyKeyring()...)
	all = append(all, pgpyConstants()...)

	out := make([]string, 0, len(all))
	for _, c := range all {
		out = append(out, c.render())
	}
	sort.Strings(out)
	return out
}

func renderPGPyContracts(kb *contracts.KnowledgeBase) []string {
	var out []string
	for key, list := range kb.Contracts {
		method := strings.SplitN(key, "#", 2)[0]
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "pgpy" {
				continue
			}
			out = append(out, pgpyContract{
				method:     method,
				arity:      c.Arity,
				role:       c.Role,
				returnType: c.Return.Type,
				canonical:  c.CanonicalReturnType,
				params:     c.ParameterTypes,
				confidence: c.Return.Confidence,
				varargs:    c.Varargs,
			}.render())
		}
	}
	sort.Strings(out)
	return out
}

// THE EXACT SET, ASSERTED AS A SYMMETRIC DIFFERENCE. A per-key lookup cannot
// see an entry that should not be there, an entry that was dropped, or a field
// corrupted in a way no probe call reaches. A count or a role tally cannot
// either, and duplicates the map with no independent origin -- the single most
// repeated defect on this campaign.
//
// The failure message quotes the exact literal to paste, so a legitimate change
// is a one-line edit rather than an exercise in reading a diff of two lists.
func TestPGPyContractSetIsExactlyThis(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	got := renderPGPyContracts(kb)
	want := wantPGPyContracts()
	if slices.Equal(got, want) {
		return
	}

	inWant := map[string]bool{}
	for _, w := range want {
		inWant[w] = true
	}
	inGot := map[string]bool{}
	for _, g := range got {
		inGot[g] = true
	}
	for _, w := range want {
		if !inGot[w] {
			t.Errorf("missing contract entry -- the sources declare it and the YAML does not: %q", w)
		}
	}
	for _, g := range got {
		if !inWant[g] {
			t.Errorf("unexpected contract entry -- if the YAML change is intended, add this one line to the hand-written table (sourced from PGPy, never from the YAML): %q", g)
		}
	}
}

// The `library:` block is parsed and never consulted at lookup, so an
// over-claiming range is a silent false statement rather than a caught error --
// and LoadEmbedded merges the libraries, dropping the per-file metadata. This
// loads the one file on its own.
func TestPGPyLibraryMetadataIsDeclared(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("contracts", "python", "pgpy.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(pgpy.yaml): %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pgpy.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatalf("pgpy.yaml: no library metadata")
	}
	if got, want := kb.Library.Name, "pgpy"; got != want {
		t.Errorf("library.name = %q, want %q", got, want)
	}
	// The committed CSV lists 15 releases, 0.1.0 through 0.6.0, and the range
	// has to cover every one of them: the legacy keyring entries are the ONLY
	// crypto surface 0.1.0 - 0.2.3 have, so a range starting at 0.3.0 would
	// silently disclaim a third of the matrix.
	if got, want := kb.Library.VersionRange, ">=0.1.0,<0.7"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if !slices.Contains(kb.Library.Coordinates, "pgpy") {
		t.Errorf("library.coordinates = %v, want it to contain %q", kb.Library.Coordinates, "pgpy")
	}
}

// Roles are checked against the ALLOWED VOCABULARY, never against a tally. A
// tally is a second copy of the map with no independent source, and one real
// addition then fails in two places at once for one reason.
func TestPGPyRolesAreFromTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	allowed := []string{
		string(contracts.RoleFactory),
		string(contracts.RoleConfig),
		string(contracts.RoleOutput),
		string(contracts.RoleOperation),
	}
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != "pgpy" {
				continue
			}
			if !slices.Contains(allowed, list[i].Role) {
				t.Errorf("%s: role %q is not in the allowed vocabulary %v", key, list[i].Role, allowed)
			}
		}
	}
}

// THIS TEST LOOKS UP KEYS; IT DOES NOT PARSE. An earlier revision was called
// TestPGPyContractsResolveParsedCallIdentities and wrote three probe modules to
// a TempDir that nothing ever read -- the file-writing implied a parse that did
// not happen, which is a test promising more than it checks. The probe sources
// are kept below as a COMMENT, because the spellings they record are the point:
// they are the import forms whose emitted keys were read off a real exported
// call graph during authoring. What this test asserts is narrower and true:
// every one of those emitted keys is declared in the contract at the arity the
// call site writes.
//
//	root_import.py    from pgpy import PGPKey, PGPMessage, PGPSignature, PGPKeyring
//	module_import.py  import pgpy; pgpy.PGPKey.new(...)
//	deep_import.py    from pgpy.pgp import PGPKey; from pgpy.keys import PGPKeyring
//
// Before this contract existed those same call sites keyed on the consumer's own
// variable -- `probe.key.sign(?)` -- which no contract can join.
func TestPGPyContractKeysAreDeclaredForEveryImportSpelling(t *testing.T) {
	t.Parallel()

	want := []struct {
		method string
		arity  int
	}{
		{"pgpy.PGPKey.new", 2},
		{"pgpy.PGPKey.sign", 2},
		{"pgpy.PGPKey.sign", 1},
		{"pgpy.PGPKey.verify", 2},
		{"pgpy.PGPKey.encrypt", 2},
		{"pgpy.PGPKey.encrypt", 1},
		{"pgpy.PGPKey.decrypt", 1},
		{"pgpy.PGPKey.protect", 3},
		{"pgpy.PGPKey.certify", 1},
		{"pgpy.PGPKey.revoke", 1},
		{"pgpy.PGPKey.bind", 1},
		{"pgpy.PGPMessage.new", 1},
		{"pgpy.PGPMessage.encrypt", 2},
		{"pgpy.PGPMessage.decrypt", 1},
		{"pgpy.PGPSignature.from_file", 1},
		{"pgpy.PGPSignature.from_blob", 1},
		{"pgpy.pgp.PGPKey.new", 2},
		{"pgpy.pgp.PGPKey.sign", 2},
		{"pgpy.pgp.PGPKey.encrypt", 2},
		{"pgpy.pgp.PGPSignature.from_file", 1},
		{"pgpy.keys.PGPKeyring.sign", 1},
		{"pgpy.keys.PGPKeyring.verify", 2},
		// The root spelling of the same two, which is the key the METHOD
		// DEFINITION emits and therefore what the rules' `api` joins on.
		{"pgpy.PGPKeyring.sign", 1},
		{"pgpy.PGPKeyring.verify", 2},
	}

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, w := range want {
		if got := kb.ContractsForTolerant(w.method, w.arity); len(got) == 0 {
			t.Errorf("no contract resolves %s at arity %d -- a receiver call site with this "+
				"shape would key on the consumer's own variable path instead", w.method, w.arity)
		}
	}
}

// The module segment is load bearing, and this is the assertion that says so.
// A contract written with only the root spelling loads WITHOUT ERROR and joins
// nothing for a consumer that imported the submodule -- which looks exactly
// like having no contract at all.
func TestPGPyBothModuleSpellingsAreDeclaredAndNeitherCoversTheOther(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, method := range []string{"pgpy.PGPKey.sign", "pgpy.pgp.PGPKey.sign"} {
		if got := kb.ContractsForTolerant(method, 1); len(got) == 0 {
			t.Errorf("%s is not declared", method)
		}
	}
	// A spelling PGPy does not export must NOT resolve. `pgpy/__init__.py`
	// re-exports `constants` as a MODULE and does not re-export the enum
	// classes, so `pgpy.SymmetricKeyAlgorithm` resolves in no release.
	for _, method := range []string{
		"pgpy.SymmetricKeyAlgorithm.gen_key",
		"pgpy.keys.PGPKey.sign",
	} {
		if got := kb.ContractsForTolerant(method, 0); len(got) != 0 {
			t.Errorf("%s resolves, but PGPy exports no such path in any release", method)
		}
	}
}

// KNOWN LIMITATION, PINNED. `PGPKey.from_file` / `from_blob` return a 2-tuple,
// so real code writes `key, _ = PGPKey.from_file(path)` -- and the python
// resolver does not type a tuple-unpacked assignment target, so the receiver
// keys on the consumer's variable path. Measured with crypto-finder built from
// this worktree, BOTH with and without the `canonical_return_type: builtins.tuple`
// line on those entries: identical result, so the accurate declaration costs
// nothing and dropping it buys nothing.
//
// WHAT THIS TEST ACTUALLY CHECKS: that the DECLARATION is present and shaped as
// described -- `canonical_return_type: builtins.tuple` with the semantic element
// in `return.type`. It does NOT exercise the resolver, so it would not fail if
// the resolver learned to type tuple-unpacked targets. An earlier revision was
// named ..._KnownLimitation_TupleUnpackedTargetIsNotTyped and carried a "DELETE
// THIS TEST if it ever starts failing" instruction it could never honor. The
// limitation itself was verified by EXPORTING a call graph (the receiver keys on
// the consumer variable path), not here.
func TestPGPyContractDeclaresTupleReturnForKeyLoaders(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	// The contract IS declared -- the limitation is in the resolver, not here.
	if got := kb.ContractsForTolerant("pgpy.PGPKey.from_file", 1); len(got) == 0 {
		t.Fatalf("pgpy.PGPKey.from_file is not declared; this test is pinning the wrong thing")
	}
	if got := kb.ContractsForTolerant("pgpy.PGPKey.from_file", 1); got[0].CanonicalReturnType != "builtins.tuple" {
		t.Errorf("canonical_return_type = %q, want %q -- the method returns (key, others)",
			got[0].CanonicalReturnType, "builtins.tuple")
	}
	if got := kb.ContractsForTolerant("pgpy.PGPKey.from_file", 1); got[0].Return.Type != "pgpy.PGPKey" {
		t.Errorf("return.type = %q, want %q -- the semantic element a receiver binds",
			got[0].Return.Type, "pgpy.PGPKey")
	}
}

// KNOWN LIMITATION, PINNED. `PGPKeyring.key` and `PGPKey.unlock` are
// @contextlib.contextmanager generators whose SEMANTIC return is what
// `with ... as` binds. Both are declared, and the python resolver does not type
// a `with ... as` binding from them: probed directly with
// `with protected.unlock("pw") as opened: opened.sign(msg)` -- where a rule DOES
// match, so the shape is observable -- the graph emits `probe.opened.sign(?)`.
//
// An earlier revision of this family's contract comments claimed the opposite,
// reasoning from the declaration rather than from a probe. It was wrong, and it
// is corrected in place rather than left as a stale "known limitation" note.
//
// WHAT THIS TEST ACTUALLY CHECKS: that both context-manager entries declare the
// semantic `with ... as` element at `confidence: medium`. It asserts YAML fields
// only and does not exercise the resolver, so it cannot detect the resolver
// learning to type such a binding. Same correction as the loader test above: the
// limitation was verified by exporting a call graph, not by this assertion.
func TestPGPyContractDeclaresContextManagerSemanticReturns(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for _, tc := range []struct {
		method string
		want   string
	}{
		{"pgpy.PGPKeyring.key", "pgpy.PGPKey"},
		{"pgpy.PGPKey.unlock", "pgpy.PGPKey"},
	} {
		got := kb.ContractsForTolerant(tc.method, 1)
		if len(got) == 0 {
			t.Errorf("%s is not declared; this test is pinning the wrong thing", tc.method)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("%s return.type = %q, want %q", tc.method, got[0].Return.Type, tc.want)
		}
		// `medium`, not `high`, precisely because the declared return is a
		// context manager and this is the semantic element.
		if got[0].Return.Confidence != "medium" {
			t.Errorf("%s confidence = %q, want %q -- the declared return is a context manager",
				tc.method, got[0].Return.Confidence, "medium")
		}
	}
}
