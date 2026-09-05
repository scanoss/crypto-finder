// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// rustls-native-certs exposes only CRATE-ROOT FREE FUNCTIONS, so every emitted
// key carries a single dot and rustAuthoredKey (contracts.go:267) returns it
// unchanged — the authored key IS the emitted key here, which is the opposite of
// the usual Rust rule. Authoring `rustls_native::certs.load_native_certs`, the
// mechanical application of the second-to-last-dot substitution, would load
// without error and join nothing.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot see
// an entry that should not be there, an entry that was dropped, or a field that
// was corrupted; only the whole-set comparison does.
//
// The family is spread over three FILES with three ranges, because two of its
// three entry points exist in almost none of the published range, so the render
// below matches on the three library names rather than on one.
var rustlsNativeCertsLibraries = map[string]bool{
	"rustls-native-certs":     true,
	"rustls-native-certs-0.5": true,
	"rustls-native-certs-0.8": true,
}

func renderRustlsNativeCertsContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !rustlsNativeCertsLibraries[c.SourceLibrary] {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence, c.SourceLibrary))
		}
	}
	sort.Strings(got)
	return got
}

var wantRustlsNativeCertsContracts = []string{
	"rustls_native_certs.build_native_certs#1/operation/()/core::result::Result<(), std::io::Error>/[&mut B]/high/rustls-native-certs-0.5",
	"rustls_native_certs.load_certs_from_paths#2/factory/rustls_native_certs::CertificateResult/rustls_native_certs::CertificateResult/[core::option::Option<&std::path::Path>,core::option::Option<&std::path::Path>]/high/rustls-native-certs-0.8",
	"rustls_native_certs.load_native_certs#0/factory/rustls_native_certs::CertificateResult/rustls_native_certs::CertificateResult/[]/low/rustls-native-certs",
}

func TestLoadEmbeddedRustRustlsNativeCertsContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderRustlsNativeCertsContracts(t)
	want := append([]string(nil), wantRustlsNativeCertsContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("rustls-native-certs contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected rustls-native-certs contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing rustls-native-certs contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Every key
// below was read off an exported call graph of a probe consumer that calls the
// crate the way its own examples and every published consumer do.
func TestRustlsNativeCertsEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := []struct {
		method string
		arity  int
	}{
		{"rustls_native_certs.load_native_certs", 0},
		{"rustls_native_certs.build_native_certs", 1},
		{"rustls_native_certs.load_certs_from_paths", 2},
	}
	for _, e := range emitted {
		got := kb.ContractsFor(e.method, e.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", e.method, e.arity)
			continue
		}
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): got %d contracts, want exactly 1", e.method, e.arity, len(got))
		}
		if !rustlsNativeCertsLibraries[got[0].SourceLibrary] {
			t.Errorf("%s: library = %q, want a rustls-native-certs file", e.method, got[0].SourceLibrary)
		}
	}
}

// A "::" SPELLING MUST NOT RESOLVE, and this is the assertion that would have
// caught the mechanical application of the Rust key substitution. rustAuthoredKey
// moves the second-to-last dot only when the key has at least two dots; these
// keys have one, so the "::" form is not an alias for them and must be absent.
func TestRustlsNativeCertsDoubleColonSpellingDoesNotResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []string{
		"rustls_native::certs.load_native_certs",
		"rustls_native_certs::load_native_certs",
	} {
		if got := kb.ContractsFor(m, 0); len(got) != 0 {
			t.Errorf("ContractsFor(%q, 0) resolved to %d contracts; a crate-root free "+
				"function is keyed with a dot and this spelling must not exist", m, len(got))
		}
	}
}

// THE ERAS ARE KEYED APART BY ARITY, and the ranges they carry are disjoint in
// two of three cases. `build_native_certs` exists in 0.5.0 alone and
// `load_certs_from_paths` only from 0.8.2, so folding either into the base file
// would silently over-claim its range — the mistake biscuit-jwks-ignore-kid.yaml
// was split out to correct. This pins the split.
func TestRustlsNativeCertsErasAreSeparateLibraries(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method  string
		arity   int
		library string
	}{
		{"rustls_native_certs.load_native_certs", 0, "rustls-native-certs"},
		{"rustls_native_certs.build_native_certs", 1, "rustls-native-certs-0.5"},
		{"rustls_native_certs.load_certs_from_paths", 2, "rustls-native-certs-0.8"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d): got %d contracts, want 1", tc.method, tc.arity, len(got))
		}
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s: library = %q, want %q", tc.method, got[0].SourceLibrary, tc.library)
		}
	}
}

// NO ALGORITHM IS DECLARED ANYWHERE IN THIS FAMILY, and that is the family's
// central claim rather than an omission. The crate reads the operating system's
// root certificates and performs no cryptography, so the algorithms are whatever
// the machine ships. `load_native_certs` additionally carries `confidence: low`
// because its declared return takes FIVE DISTINCT FORMS across six eras of
// 0.1.0-0.8.4 while its name and arity never change, so no single concrete type
// is true for the whole range. Both return fields name the current era and both
// are flagged low; naming one in `return.type` while omitting
// `canonical_return_type` would be the same guess made once and withheld once,
// and it also left the exported signature byte-identical to an absent contract.
func TestRustlsNativeCertsDeclaresNoAlgorithmAndFlagsTheUnstableReturn(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	load := kb.ContractsFor("rustls_native_certs.load_native_certs", 0)
	if len(load) != 1 {
		t.Fatalf("load_native_certs: got %d contracts, want 1", len(load))
	}
	if load[0].Return.Confidence != "low" {
		t.Errorf("load_native_certs: confidence = %q, want low; the declared return "+
			"takes five distinct forms across the version range",
			load[0].Return.Confidence)
	}
	// Both return fields must name the current era. An empty canonical return
	// renders the exported signature identically to an absent contract, which is
	// what this family's own header calls the shape of a contract gap.
	if load[0].CanonicalReturnType != "rustls_native_certs::CertificateResult" {
		t.Errorf("load_native_certs: canonical_return_type = %q, want "+
			"rustls_native_certs::CertificateResult; an empty value renders the same "+
			"signature as no contract at all", load[0].CanonicalReturnType)
	}
	if load[0].Return.Type != load[0].CanonicalReturnType {
		t.Errorf("load_native_certs: return.type %q and canonical_return_type %q must "+
			"name the same era; declaring one and withholding the other is the same "+
			"guess made once and hidden once",
			load[0].Return.Type, load[0].CanonicalReturnType)
	}

	// build_native_certs fills a caller-supplied builder and constructs nothing.
	build := kb.ContractsFor("rustls_native_certs.build_native_certs", 1)
	if len(build) != 1 {
		t.Fatalf("build_native_certs: got %d contracts, want 1", len(build))
	}
	if build[0].Role != "operation" {
		t.Errorf("build_native_certs: role = %q, want operation; it returns "+
			"Result<(), Error> and constructs nothing", build[0].Role)
	}
	// `()` and not `void`: every other user of `void` in this directory is a
	// RustCrypto digest or MAC crate whose update() returns () with no wrapper.
	if build[0].Return.Type != "()" {
		t.Errorf("build_native_certs: return.type = %q, want (); the Result<(), E> "+
			"shape is spelled () with the wrapper in canonical_return_type",
			build[0].Return.Type)
	}
}

// THE THREE-FILE SPLIT EXISTS SOLELY TO KEEP THESE RANGES CORRECT, so the ranges
// are asserted rather than left to the file headers. `version_range` is parsed
// and never consulted at lookup, so a range that over-claims is a SILENT false
// statement rather than a caught error: a 0.8.0 consumer would be served a
// signature for `load_certs_from_paths`, which does not exist before 0.8.2. That
// is the exact mistake biscuit-jwks-ignore-kid.yaml was split out to correct.
//
// BE CLEAR ABOUT WHAT THIS TEST IS, in the terms rust_biscuit_test.go sets: a
// tripwire, not a guard. It compares the YAML to a constant in this file, so
// editing both together passes and a wrong bound passes from the start. The
// bounds here were verified by enumerating `pub fn` in `src/` for all 23
// published archives — `build_native_certs` present at 0.5.0 and absent at 0.4.0
// and 0.6.0; `load_certs_from_paths` absent at 0.8.1 and present at 0.8.2 — and
// this only stops them drifting unnoticed.
func TestRustlsNativeCertsFilesDeclareTheirOwnEra(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ file, name, wantRange string }{
		{"rust/rustls-native-certs.yaml", "rustls-native-certs", ">=0.1.0,<0.9.0"},
		{"rust/rustls-native-certs-0.5.yaml", "rustls-native-certs-0.5", ">=0.5.0,<0.6.0"},
		{"rust/rustls-native-certs-0.8.yaml", "rustls-native-certs-0.8", ">=0.8.2,<0.9.0"},
	} {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("read %s: %v", tc.file, err)
			continue
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Errorf("Load(%s): %v", tc.file, err)
			continue
		}
		if kb.Library == nil {
			t.Errorf("%s declares no library: block", tc.file)
			continue
		}
		if kb.Library.Name != tc.name {
			t.Errorf("%s: library.name = %q, want %q", tc.file, kb.Library.Name, tc.name)
		}
		if kb.Library.VersionRange != tc.wantRange {
			t.Errorf("%s: version_range = %q, want %q — the range must cover only "+
				"versions for which every entry in this file is true",
				tc.file, kb.Library.VersionRange, tc.wantRange)
		}
		// Both crate spellings, in every file: the callgraph key uses the
		// underscore form and the PURL uses the hyphen form.
		want := map[string]bool{"rustls-native-certs": false, "rustls_native_certs": false}
		for _, c := range kb.Library.Coordinates {
			if _, ok := want[c]; ok {
				want[c] = true
			}
		}
		for c, seen := range want {
			if !seen {
				t.Errorf("%s: coordinates = %v, missing %q", tc.file, kb.Library.Coordinates, c)
			}
		}
	}
}
