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

// native-tls is a facade over the platform TLS stack and performs no
// cryptography of its own, so NO entry in this family declares an algorithm.
// What the KB types is the shape of the session: which builder produced which
// connector, what trust and identity material entered it, and which protocol
// version — the one statically knowable cryptographic fact — was selected.
//
// EVERY KEY BELOW WAS READ OFF AN EXPORTED CALL GRAPH, then had the Rust
// substitution applied: `rustAuthoredKey` (contracts.go:267) moves the
// second-to-last dot to "::" when a key carries at least two dots, and every key
// in this family does. The graph emits `native_tls.TlsConnector.identity` and
// this file must contain `native_tls::TlsConnector.identity`.
//
// THE EMITTED KEY FOR A BUILDER METHOD DEPENDS ON WHICH CONTRACTS ARE ALREADY
// LOADED, and this family is where that bites. With NO contract present the graph
// emits `native_tls.TlsConnector.min_protocol_version`, keyed on the type whose
// associated function produced the receiver. Once
// `native_tls::TlsConnector.builder -> native_tls::TlsConnectorBuilder` is in the
// KB the receiver resolves and the SAME line emits
// `native_tls.TlsConnectorBuilder.min_protocol_version` — so the keys authored
// from the first export stop joining. The key list here is a FIXED POINT, reached
// by exporting, authoring and re-exporting until nothing moved.
// TestNativeTLSBuilderTypeSpellingDoesNotResolve pins the superseded spelling so
// a later author cannot reintroduce it from a stale export.
//
// The set is compared EXACTLY. A per-key assertion cannot see an entry that
// should not be there, an entry that was dropped, or a field that was corrupted.
// The render carries the parameter-role block and the varargs flag as well,
// because a contract can be mutated in both and every other assertion stays green.
var nativeTLSLibraries = map[string]bool{
	"native-tls":        true,
	"native-tls-0.1":    true,
	"native-tls-0.1.2":  true,
	"native-tls-0.1.5":  true,
	"native-tls-0.2":    true,
	"native-tls-0.2.9":  true,
	"native-tls-0.2.16": true,
}

func renderNativeTLSContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !nativeTLSLibraries[c.SourceLibrary] {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				params = append(params, fmt.Sprintf("%d:%s:%s", p.Index, p.Name, p.Role))
			}
			sort.Strings(params)
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/varargs=%t/params={%s}/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				c.Varargs, strings.Join(params, ";"), c.SourceLibrary))
		}
	}
	sort.Strings(got)
	return got
}

var wantNativeTLSContracts = []string{
	"native_tls::Certificate.from_der#1/factory/native_tls::Certificate/core::result::Result<native_tls::Certificate, native_tls::Error>/[&[u8]]/high/varargs=false/params={}/native-tls-0.1.2",
	"native_tls::Certificate.from_pem#1/factory/native_tls::Certificate/core::result::Result<native_tls::Certificate, native_tls::Error>/[&[u8]]/high/varargs=false/params={}/native-tls-0.1.5",
	"native_tls::Certificate.stack_from_pem#1/factory/alloc::vec::Vec<native_tls::Certificate>/core::result::Result<alloc::vec::Vec<native_tls::Certificate>, native_tls::Error>/[&[u8]]/high/varargs=false/params={}/native-tls-0.2.16",
	"native_tls::Identity.from_pkcs12#2/factory/native_tls::Identity/core::result::Result<native_tls::Identity, native_tls::Error>/[&[u8],&str]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::Identity.from_pkcs8#2/factory/native_tls::Identity/core::result::Result<native_tls::Identity, native_tls::Error>/[&[u8],&[u8]]/high/varargs=false/params={}/native-tls-0.2.9",
	"native_tls::Pkcs12.from_der#2/factory/native_tls::Pkcs12/core::result::Result<native_tls::Pkcs12, native_tls::Error>/[&[u8],&str]/high/varargs=false/params={}/native-tls-0.1",
	"native_tls::TlsAcceptor.accept#1/operation/native_tls::TlsStream<S>/core::result::Result<native_tls::TlsStream<S>, native_tls::HandshakeError<S>>/[S]/high/varargs=false/params={}/native-tls",
	"native_tls::TlsAcceptor.builder#1/factory/native_tls::TlsAcceptorBuilder/native_tls::TlsAcceptorBuilder/[native_tls::Identity]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsAcceptor.new#1/factory/native_tls::TlsAcceptor/core::result::Result<native_tls::TlsAcceptor, native_tls::Error>/[native_tls::Identity]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsAcceptorBuilder.build#0/factory/native_tls::TlsAcceptor/core::result::Result<native_tls::TlsAcceptor, native_tls::Error>/[]/high/varargs=false/params={}/native-tls",
	"native_tls::TlsAcceptorBuilder.max_protocol_version#1/operation/&mut native_tls::TlsAcceptorBuilder/&mut native_tls::TlsAcceptorBuilder/[core::option::Option<native_tls::Protocol>]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsAcceptorBuilder.min_protocol_version#1/operation/&mut native_tls::TlsAcceptorBuilder/&mut native_tls::TlsAcceptorBuilder/[core::option::Option<native_tls::Protocol>]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnector.builder#0/factory/native_tls::TlsConnectorBuilder/native_tls::TlsConnectorBuilder/[]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnector.connect#2/operation/native_tls::TlsStream<S>/core::result::Result<native_tls::TlsStream<S>, native_tls::HandshakeError<S>>/[&str,S]/high/varargs=false/params={}/native-tls",
	"native_tls::TlsConnector.new#0/factory/native_tls::TlsConnector/core::result::Result<native_tls::TlsConnector, native_tls::Error>/[]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.add_root_certificate#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[native_tls::Certificate]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.build#0/factory/native_tls::TlsConnector/core::result::Result<native_tls::TlsConnector, native_tls::Error>/[]/high/varargs=false/params={}/native-tls",
	"native_tls::TlsConnectorBuilder.danger_accept_invalid_certs#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[bool]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.danger_accept_invalid_hostnames#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[bool]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.identity#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[native_tls::Identity]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.max_protocol_version#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[core::option::Option<native_tls::Protocol>]/high/varargs=false/params={}/native-tls-0.2",
	"native_tls::TlsConnectorBuilder.min_protocol_version#1/operation/&mut native_tls::TlsConnectorBuilder/&mut native_tls::TlsConnectorBuilder/[core::option::Option<native_tls::Protocol>]/high/varargs=false/params={}/native-tls-0.2",
}

func TestLoadEmbeddedRustNativeTLSContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderNativeTLSContracts(t)
	want := append([]string(nil), wantNativeTLSContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("native-tls contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected native-tls contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing native-tls contract:    %s", w)
		}
	}
}

// The DOT-JOINED spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Every key here
// was read off an exported call graph of a probe consumer that calls the crate
// the way its own examples/ and the M20 published consumers do.
func TestNativeTLSEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := []struct {
		method string
		arity  int
	}{
		{"native_tls.TlsConnector.builder", 0},
		{"native_tls.TlsConnectorBuilder.build", 0},
		{"native_tls.TlsConnector.new", 0},
		{"native_tls.TlsConnector.connect", 2},
		{"native_tls.TlsConnectorBuilder.identity", 1},
		{"native_tls.TlsConnectorBuilder.add_root_certificate", 1},
		{"native_tls.TlsConnectorBuilder.min_protocol_version", 1},
		{"native_tls.TlsConnectorBuilder.max_protocol_version", 1},
		{"native_tls.TlsAcceptor.builder", 1},
		{"native_tls.TlsAcceptorBuilder.build", 0},
		{"native_tls.TlsAcceptor.new", 1},
		{"native_tls.TlsAcceptor.accept", 1},
		{"native_tls.TlsAcceptorBuilder.min_protocol_version", 1},
		{"native_tls.TlsAcceptorBuilder.max_protocol_version", 1},
		{"native_tls.Identity.from_pkcs12", 2},
		{"native_tls.Identity.from_pkcs8", 2},
		{"native_tls.Certificate.from_pem", 1},
		{"native_tls.Certificate.from_der", 1},
		{"native_tls.Certificate.stack_from_pem", 1},
		{"native_tls.Pkcs12.from_der", 2},
		{"native_tls.TlsConnectorBuilder.danger_accept_invalid_certs", 1},
		{"native_tls.TlsConnectorBuilder.danger_accept_invalid_hostnames", 1},
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
		if !nativeTLSLibraries[got[0].SourceLibrary] {
			t.Errorf("%s: library = %q, want a native-tls file", e.method, got[0].SourceLibrary)
		}
	}
}

// THE SUPERSEDED SPELLING MUST NOT RESOLVE. Keying a builder method on
// `TlsConnector` / `TlsAcceptor` is exactly what an export taken BEFORE the
// factory contracts existed tells you to write, and it is what this family wrote
// first: the keys load without error and join nothing once the factories are
// typed. This is the assertion that catches an author working from a stale
// export.
//
// The crate-root free-function form is asserted here too. These keys carry two
// dots, so rustAuthoredKey DOES move the separator and the single-dot spelling is
// not an alias for them.
func TestNativeTLSBuilderTypeSpellingDoesNotResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"native_tls::TlsConnector.identity", 1},
		{"native_tls::TlsConnector.min_protocol_version", 1},
		{"native_tls::TlsConnector.add_root_certificate", 1},
		{"native_tls::TlsAcceptor.min_protocol_version", 1},
		{"native_tls::TlsConnector.build", 0},
		{"native_tls::TlsAcceptor.build", 0},
		{"native_tls.identity", 1},
		{"native_tls.min_protocol_version", 1},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved to %d contracts; the parser keys a "+
				"builder receiver on the type whose associated function produced it, so "+
				"this spelling must not exist", tc.method, tc.arity, len(got))
		}
	}
}

// `unwrap` AND `expect` MUST NOT BE TYPED, and this is not hygiene. The exported
// call graph of the probe consumer emits `native_tls.Certificate.unwrap`,
// `native_tls.Identity.unwrap` and `native_tls.TlsConnector.unwrap`, because the
// parser attributes a Result combinator to the crate type that produced the
// Result. Those are core::result::Result's methods. A contract for them would
// route every `?`-free call site in every consumer of this crate through a
// native-tls signature.
func TestNativeTLSDoesNotTypeResultCombinators(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []string{
		"native_tls::Certificate.unwrap", "native_tls::Identity.unwrap",
		"native_tls::TlsConnector.unwrap", "native_tls::TlsAcceptor.unwrap",
		"native_tls::Certificate.expect", "native_tls::TlsConnector.expect",
	} {
		for _, a := range []int{0, 1} {
			if got := kb.ContractsFor(m, a); len(got) != 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %d contracts; Result "+
					"combinators belong to core, not to this crate", m, a, len(got))
			}
		}
	}
}

// EVERY ENTRY IS TRUE FOR ITS FILE'S WHOLE DECLARED RANGE, which is what the
// seven-file split is for and what an earlier revision of this family got wrong.
// That revision kept `TlsConnector::builder`, `TlsConnectorBuilder::identity`,
// `TlsAcceptor::builder` and `add_root_certificate` in files claiming 0.1.x while
// declaring the 0.2 shapes for them, and marked the mismatch with
// `confidence: low` — but `parameter_types` and `canonical_return_type` carry no
// confidence field, so what actually reached an exported call graph was
// `native_tls.TlsAcceptor.builder(native_tls::Identity)` for a 0.1 call site that
// passes a `Pkcs12`. `version_range` is never consulted at lookup, so that is a
// silent false statement rather than a caught error. All four now live in
// native-tls-0.2.yaml, and NO entry in this family carries `confidence: low`:
// where a declared shape is not true for a range, the fix is the range.
//
// The four eras that diverge, each read from its own archive:
//
//	TlsConnector::builder    0.1.0 lib.rs:324 Result<TlsConnectorBuilder> / 0.2.0 lib.rs:444 the builder
//	TlsConnectorBuilder::identity 0.1.0 lib.rs:289 fn(Pkcs12)->Result / 0.2.0 lib.rs:330 fn(Identity)
//	TlsAcceptor::builder     0.1.0 lib.rs:406 fn(Pkcs12)->Result / 0.2.0 lib.rs:568 fn(Identity)
//	add_root_certificate     0.1.5 lib.rs:353 Result<&mut b> / 0.2.0 lib.rs:361 &mut b
//
// The four entries that DO span 0.1.0-0.2.18 are byte-identical in both eras:
// `connect(domain, stream)` at 0.1.0 lib.rs:338 and 0.2.18 lib.rs:514,
// `accept(stream)` at 0.1.0 lib.rs:417 and 0.2.18 lib.rs:645, and both `build()`s
// returning `Result<TlsConnector>` / `Result<TlsAcceptor>` in every release.
func TestNativeTLSDeclaresNoLowConfidenceAndNoAlgorithm(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !nativeTLSLibraries[c.SourceLibrary] {
				continue
			}
			if c.Return.Confidence != "high" {
				t.Errorf("%s#%d in %s: confidence = %q. In this family a shape that "+
					"is not true for the whole range belongs in a file whose range "+
					"is right, not behind a low-confidence marker that "+
					"parameter_types and canonical_return_type do not carry",
					c.Method, c.Arity, c.SourceLibrary, c.Return.Confidence)
			}
			// An empty canonical return renders the exported signature
			// identically to an absent contract, which is what a gap looks like.
			if c.CanonicalReturnType == "" {
				t.Errorf("%s#%d: canonical_return_type is empty; that renders the "+
					"same signature as no contract at all", c.Method, c.Arity)
			}
		}
	}

	// The four keys that span the whole range must live in the base file, and
	// the four era-divergent ones must not.
	for _, tc := range []struct {
		method, library string
		arity           int
	}{
		{"native_tls::TlsConnector.connect", "native-tls", 2},
		{"native_tls::TlsAcceptor.accept", "native-tls", 1},
		{"native_tls::TlsConnectorBuilder.build", "native-tls", 0},
		{"native_tls::TlsAcceptorBuilder.build", "native-tls", 0},
		{"native_tls::TlsConnector.builder", "native-tls-0.2", 0},
		{"native_tls::TlsAcceptor.builder", "native-tls-0.2", 1},
		{"native_tls::TlsConnectorBuilder.identity", "native-tls-0.2", 1},
		{"native_tls::TlsConnectorBuilder.add_root_certificate", "native-tls-0.2", 1},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d): got %d contracts, want 1", tc.method, tc.arity, len(got))
		}
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s#%d: library = %q, want %q — a shape that is not true for "+
				"0.1.x may not sit in a file claiming it",
				tc.method, tc.arity, got[0].SourceLibrary, tc.library)
		}
	}
}

// THE SEVEN-FILE SPLIT EXISTS SOLELY TO KEEP THESE RANGES CORRECT, so the ranges
// are asserted rather than left to the file headers. `version_range` is parsed
// and never consulted at lookup, so a range that over-claims is a SILENT false
// statement: a 0.1.0 consumer would be served a signature for
// `add_root_certificate`, which does not exist before 0.1.2.
//
// BE CLEAR ABOUT WHAT THIS TEST IS: a tripwire, not a guard. It compares the YAML
// to a constant in this file, so editing both together passes and a wrong bound
// passes from the start. The bounds were verified by enumerating `pub fn` and
// `pub struct` in `src/lib.rs` for all 25 published archives in the matrix range
// — Certificate and add_root_certificate absent at 0.1.1 and present at 0.1.2;
// Certificate::from_pem absent at 0.1.4 and present at 0.1.5; Identity,
// min_protocol_version and TlsConnector::new absent at 0.1.5 and present at
// 0.2.0; Identity::from_pkcs8 absent at 0.2.8 and present at 0.2.9;
// Certificate::stack_from_pem absent at 0.2.15 and present at 0.2.16 — and this
// only stops them drifting unnoticed.
func TestNativeTLSFilesDeclareTheirOwnEra(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ file, name, wantRange string }{
		{"rust/native-tls.yaml", "native-tls", ">=0.1.0,<0.3.0"},
		{"rust/native-tls-0.1.yaml", "native-tls-0.1", ">=0.1.0,<0.2.0"},
		{"rust/native-tls-0.1.2.yaml", "native-tls-0.1.2", ">=0.1.2,<0.3.0"},
		{"rust/native-tls-0.1.5.yaml", "native-tls-0.1.5", ">=0.1.5,<0.3.0"},
		{"rust/native-tls-0.2.yaml", "native-tls-0.2", ">=0.2.0,<0.3.0"},
		{"rust/native-tls-0.2.9.yaml", "native-tls-0.2.9", ">=0.2.9,<0.3.0"},
		{"rust/native-tls-0.2.16.yaml", "native-tls-0.2.16", ">=0.2.16,<0.3.0"},
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
		want := map[string]bool{"native-tls": false, "native_tls": false}
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
