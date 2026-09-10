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

// `gpg` on PyPI is the GnuPG project's own GPGME Python binding -- a SWIG
// wrapper over libgpgme, which drives the `gpg` executable. Three facts shape
// this file:
//
//  1. TWO MODULE SPELLINGS, DECLARED ON PURPOSE. The Python call-graph key
//     follows the CONSUMER'S IMPORT, so `from gpg import Context` emits
//     `gpg.Context.<init>` while `from gpg.core import Context` emits
//     `gpg.core.Context.<init>`, and neither key resolves the other. Every
//     operation therefore appears twice.
//
//  2. THE EXPECTATION BELOW IS WRITTEN FROM THE PACKAGE'S OWN SOURCES, NOT
//     FROM THE YAML. Each line carries the `gpg/core.py` line the method is
//     declared at in 2.0.0, and the version window that boundary was read
//     against. Deriving the expectation from the contract file is the obvious
//     repair for a failing mirror test and it is wrong: it makes the assertion
//     tautological and green on a corrupted contract, which is the one thing
//     this test exists to prevent.
//
//  3. IT IS A SYMMETRIC DIFFERENCE, NOT A COUNT AND NOT A POSITIONAL DIFF. A
//     count moves for any change and says nothing about which; a positional
//     diff turns one legitimate addition into a cascade of off-by-one errors.
//     A failure here names the entry that is missing or unexpected and quotes
//     the exact literal to paste, so a genuine repair is a one-line edit.
//
// AND AN EXACT-SET TEST PROVES THE TEST DETECTS CHANGE, NOT THAT THE BASELINE
// IS TRUE. The baseline's truth rests on the per-symbol tracing in the contract
// file's header: every method cited at its `gpg/core.py` line in 2.0.0 AND
// checked against the archive on the other side of its version boundary.
// Vacuity and truth are separate gates and this file is only the first.

const gpgLibrary = "gpg"

// renderGpgContract renders one loaded contract as a single line holding every
// field Load() populates. A field omitted here is a field no mutation of which
// this test can detect -- which is why `parameter_types`, the `parameters:`
// roles including the contributed property and its derivation, `varargs` and
// `when` are all rendered even though most entries leave them unset.
func renderGpgContract(key string, c contracts.Contract) string {
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
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprintf("%d", *p.Index)
			}
			property, derivation := "-", "-"
			if p.Contributes != nil {
				property = p.Contributes.Property
				derivation = p.Contributes.Derivation
			}
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s",
				idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, canonical, paramRoles, c.Varargs, when, c.SourceLibrary)
}

// loadedGpgContracts returns every rendered line for the gpg library, sorted.
// It fails outright if nothing was loaded: a zero-length set makes every
// "not present" assertion pass vacuously, which is the failure mode this whole
// file exists to prevent.
func loadedGpgContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != gpgLibrary {
				continue
			}
			lines = append(lines, renderGpgContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no gpg contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

// wantGpgContracts is the hand-written baseline. Every entry cites the
// `gpg/core.py` line that declares the method in 2.0.0, and the version window
// read from the archive on each side of its boundary.
func wantGpgContracts() []string {
	return []string{
		// ── Context construction ────────────────────────────────────────────
		// `Context.__init__` takes only keyword arguments, so the required
		// count is 0. 2.0.0 gpg/core.py:198; :176 in 1.10.0, 1.8.0 and
		// 1.7.2-beta7. The `<init>`-suffixed key is the from-import spelling
		// and the bare key is the module-attribute spelling; both were
		// observed in an exported call graph.
		"gpg.Context#0 gpg.Context/factory/gpg.Context/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.<init>#0 gpg.Context.<init>/factory/gpg.Context/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context#0 gpg.core.Context/factory/gpg.core.Context/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.<init>#0 gpg.core.Context.<init>/factory/gpg.core.Context/high/-/-/params=-/varargs=false/when=-/lib=gpg",

		// ── The four message operations, in ALL FOUR released versions ──────
		// 1.7.2-beta7 and 1.8.0 gpg/core.py:207/289/373/416; 1.10.0
		// :228/316/406/449; 2.0.0 :254/352/475/518. Each returns a tuple:
		// `encrypt` a 3-tuple (2.0.0 :350), `sign` a 2-tuple (:516),
		// `decrypt` and `verify` the `results` tuple they assemble
		// (:473, :578). No `parameter_types`: every one documents a
		// bytes-or-file-like UNION (:270-272).
		"gpg.Context.decrypt#1 gpg.Context.decrypt/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.encrypt#1 gpg.Context.encrypt/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.sign#1 gpg.Context.sign/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.verify#1 gpg.Context.verify/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.decrypt#1 gpg.core.Context.decrypt/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.encrypt#1 gpg.core.Context.encrypt/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.sign#1 gpg.core.Context.sign/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.verify#1 gpg.core.Context.verify/operation/builtins.tuple/high/-/-/params=-/varargs=false/when=-/lib=gpg",

		// ── Key generation, 1.10.0 AND LATER ────────────────────────────────
		// 1.10.0 gpg/core.py:547 and :625; 2.0.0 :774 and :864. Read on the
		// other side of the boundary: `grep -n 'def create' gpg/core.py`
		// returns nothing at 1.8.0 or 1.7.2-beta7. Declared at arity 2 so the
		// `algorithm=` argument has an index; both end in
		// `return self.op_genkey_result()` (2.0.0 :862, :944), whose SWIG
		// typemap wraps the C struct as `gpg/results.py:124 GenkeyResult`
		// (gpgme.i:464, helpers.c:313-333).
		"gpg.Context.create_key#2 gpg.Context.create_key/operation/gpg.GenkeyResult/high/builtins.str|builtins.str/-/params=0:userid:none:-:-,1:algorithm:metadata-contributing:keyType:argument_value/varargs=false/when=-/lib=gpg",
		"gpg.Context.create_subkey#2 gpg.Context.create_subkey/operation/gpg.GenkeyResult/high/builtins.object|builtins.str/-/params=0:key:none:-:-,1:algorithm:metadata-contributing:keyType:argument_value/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.create_key#2 gpg.core.Context.create_key/operation/gpg.GenkeyResult/high/builtins.str|builtins.str/-/params=0:userid:none:-:-,1:algorithm:metadata-contributing:keyType:argument_value/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.create_subkey#2 gpg.core.Context.create_subkey/operation/gpg.GenkeyResult/high/builtins.object|builtins.str/-/params=0:key:none:-:-,1:algorithm:metadata-contributing:keyType:argument_value/varargs=false/when=-/lib=gpg",

		// ── Key certification, 1.10.0 AND LATER ─────────────────────────────
		// 1.10.0 gpg/core.py:721; 2.0.0 :970. The body ends at
		// `self.op_keysign(...)` with no `return` (2.0.0 :1008), so the
		// return is None.
		"gpg.Context.key_sign#1 gpg.Context.key_sign/operation/builtins.NoneType/high/builtins.object/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.key_sign#1 gpg.core.Context.key_sign/operation/builtins.NoneType/high/builtins.object/-/params=-/varargs=false/when=-/lib=gpg",

		// ── Keyring import and export, 2.0.0 ONLY ───────────────────────────
		// 2.0.0 gpg/core.py:580, 627, 661, 696. Read on the other side of the
		// boundary: `grep -n 'def key_' gpg/core.py` at 1.10.0 returns only
		// key_add_uid / key_revoke_uid / key_sign / key_tofu_policy, and
		// nothing at all at 1.8.0 or 1.7.2-beta7. `key_import` returns a
		// wrapped `gpg/results.py:120 ImportResult` (gpgme.i:463). The three
		// exporters return bytes OR None -- `if len(pk_result) > 0: result =
		// pk_result else: result = None` (2.0.0 :654-659) -- hence low
		// confidence on a genuinely uncertain type.
		"gpg.Context.key_export#0 gpg.Context.key_export/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.key_export_minimal#0 gpg.Context.key_export_minimal/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.key_export_secret#0 gpg.Context.key_export_secret/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.key_import#1 gpg.Context.key_import/operation/gpg.ImportResult/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.key_export#0 gpg.core.Context.key_export/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.key_export_minimal#0 gpg.core.Context.key_export_minimal/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.key_export_secret#0 gpg.core.Context.key_export_secret/operation/builtins.bytes/low/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.key_import#1 gpg.core.Context.key_import/operation/gpg.ImportResult/high/-/-/params=-/varargs=false/when=-/lib=gpg",

		// ── Keyring lookup, in ALL FOUR released versions ───────────────────
		// `keylist` at 1.7.2-beta7 and 1.8.0 gpg/core.py:476, 1.10.0 :512,
		// 2.0.0 :737; `get_key` at :673, :969, :1220. `keylist` is a
		// GENERATOR function -- it `yield`s inside a while loop (2.0.0 :770)
		// and has no `return`. `get_key` returns the raw SWIG `gpgme_key_t`
		// (:1247): `grep -n '^class Key' gpg/*.py` finds nothing in any of the
		// four releases and gpgme.i declares no `wrapresult` for it, so
		// `builtins.object` at low confidence is what is knowable without
		// claiming a libgpgme C name.
		"gpg.Context.get_key#1 gpg.Context.get_key/operation/builtins.object/low/builtins.str/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.Context.keylist#0 gpg.Context.keylist/operation/builtins.generator/high/-/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.get_key#1 gpg.core.Context.get_key/operation/builtins.object/low/builtins.str/-/params=-/varargs=false/when=-/lib=gpg",
		"gpg.core.Context.keylist#0 gpg.core.Context.keylist/operation/builtins.generator/high/-/-/params=-/varargs=false/when=-/lib=gpg",
	}
}

func TestPythonGpgContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantGpgContracts()
	sort.Strings(want)
	got := loadedGpgContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		wantSet[line] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, line := range got {
		gotSet[line] = struct{}{}
	}

	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			t.Errorf("unexpected contract entry -- if the YAML change is intended, add this one line to wantGpgContracts():\n\t%q,", line)
		}
	}
	for _, line := range want {
		if _, ok := gotSet[line]; !ok {
			t.Errorf("contract entry declared in the expectation but NOT loaded from the YAML:\n\t%q,", line)
		}
	}
}

// TestPythonGpgContract_RolesAreInTheAllowedVocabulary checks roles against the
// vocabulary rather than against a tally. A count of factories versus
// operations moves for any legitimate addition and identifies nothing; the
// question worth asking is whether a role is a legal value at all, and whether
// the four Context constructors are the only factories -- which is a structural
// claim about this API, not an arithmetic one.
func TestPythonGpgContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	allowed := map[string]struct{}{
		"factory":   {},
		"config":    {},
		"output":    {},
		"operation": {},
	}
	seen := 0
	for key, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != gpgLibrary {
				continue
			}
			seen++
			if _, ok := allowed[c.Role]; !ok {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, c.Role)
			}
			// Every factory in this API is a Context constructor, and every
			// Context constructor returns its own module spelling. Anything
			// else is either a mis-keyed factory or an operation wrongly
			// marked as one.
			if c.Role == "factory" {
				if !strings.HasSuffix(c.Method, "Context") && !strings.HasSuffix(c.Method, "Context.<init>") {
					t.Errorf("%s: role=factory but the method is not a Context constructor", key)
				}
				if c.Return.Type != strings.TrimSuffix(c.Method, ".<init>") {
					t.Errorf("%s: factory returns %q, want its own spelling %q",
						key, c.Return.Type, strings.TrimSuffix(c.Method, ".<init>"))
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no gpg contracts loaded -- every assertion above passed vacuously")
	}
}

// TestPythonGpgContract_LibraryBlock renders the `library:` block, which the
// exact-set test cannot see. Measured twice on this campaign: corrupting
// `version_range`, `coordinates`, `name` or `description` leaves every
// per-contract assertion green, because those fields are parsed and then never
// consulted by any other test.
func TestPythonGpgContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "gpg.yaml"))
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
	if kb.Library.Name != gpgLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, gpgLibrary)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "gpg"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// PyPI publishes exactly four releases of this distribution and the
	// committed CSV carries all four: 1.7.2-beta7, 1.8.0, 1.10.0 and 2.0.0.
	// The lower bound is written `1.7.2b7` because that is the PEP 440
	// normalization of `1.7.2-beta7`, and it sorts BELOW `1.7.2`; a bound
	// written `>=1.7.2` would exclude the oldest row in the range it claims to
	// cover.
	if got, want := kb.Library.VersionRange, ">=1.7.2b7,<2.1"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
	if !strings.Contains(kb.Library.Description, "GPGME") {
		t.Errorf("library.description does not name the bound C library: %q", kb.Library.Description)
	}
}

// TestPythonGpgContract_KeysMeasuredOffTheGraph pins the keys an exported call
// graph actually emits for a consumer of this package, in both module
// spellings, read off `crypto-finder scan --export-callgraph` rather than
// written from the API. A key that is merely plausible loads without error and
// joins nothing, which looks identical to having no contract at all.
//
// Before this contract existed the same probe emitted the CONSUMER'S variable
// path for every one of these -- `gpgprobe317.ctx.encrypt(?, ?)` and fourteen
// siblings -- so the four factory entries are what make every line below
// resolve at all.
func TestPythonGpgContract_KeysMeasuredOffTheGraph(t *testing.T) {
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
		{"gpg.Context.<init>", 0, "from gpg import Context; Context(armor=True)"},
		{"gpg.Context", 0, "import gpg; gpg.Context()"},
		{"gpg.core.Context.<init>", 0, "from gpg.core import Context as C; C()"},
		{"gpg.core.Context", 0, "import gpg.core; gpg.core.Context() -- and the resolved alias import gpg.core as gc; gc.Context()"},
		{"gpg.Context.encrypt", 1, "ctx.encrypt(message, recipients) after the root-import constructor"},
		{"gpg.Context.decrypt", 1, "ctx.decrypt(cipher)"},
		{"gpg.Context.sign", 1, "ctx.sign(message)"},
		{"gpg.Context.verify", 1, "ctx.verify(signed)"},
		{"gpg.Context.create_key", 2, "ctx.create_key(userid, algorithm=\"rsa3072\")"},
		{"gpg.Context.create_subkey", 2, "ctx.create_subkey(key, algorithm=\"ed25519\")"},
		{"gpg.Context.key_sign", 1, "ctx.key_sign(key)"},
		{"gpg.Context.key_import", 1, "ctx.key_import(blob)"},
		{"gpg.Context.key_export", 0, "ctx.key_export(pattern)"},
		{"gpg.Context.key_export_minimal", 0, "ctx.key_export_minimal(pattern)"},
		{"gpg.Context.key_export_secret", 0, "ctx.key_export_secret(pattern)"},
		{"gpg.Context.keylist", 0, "ctx.keylist(pattern)"},
		{"gpg.Context.get_key", 1, "ctx.get_key(fingerprint)"},
		{"gpg.core.Context.encrypt", 1, "the deep-module receiver, after gpg.core.Context()"},
		{"gpg.core.Context.sign", 1, "the deep-module sign receiver"},
	}
	for _, tc := range cases {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) == 0 {
			t.Errorf("no contract for %s#%d, which an exported call graph emits for: %s",
				tc.method, tc.arity, tc.shape)
		}
	}

	// The spelling that is NOT the emitted key. `gpg.results.GenkeyResult`
	// reads like the import path a consumer would write, and it is not what the
	// parser emits for a class declared in `gpg/results.py`: the definition key
	// drops the module FILE name and keeps the directory path, measured on the
	// thirteen `gpg/core.py` declarations. This pins the negative so a future
	// edit toward the plausible spelling fails here rather than silently
	// joining nothing.
	for _, method := range []string{
		"gpg.results.Context",
		"gpg.results.GenkeyResult",
		"gpg.core.Context.encrypt.<init>",
	} {
		if got := kb.ContractsFor(method, 0); len(got) != 0 {
			t.Errorf("%s resolves, but it is not a key any exported call graph emits", method)
		}
	}
}
