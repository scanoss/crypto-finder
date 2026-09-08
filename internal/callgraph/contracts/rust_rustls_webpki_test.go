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

// rustls-webpki is the crates.io package; `webpki` is the Rust library it
// builds. Every published release 0.100.0-0.104.0-alpha.7 declares
// `[lib] name = "webpki"`, so the parser emits `webpki.` keys for it and for
// briansmith/webpki alike, and the two crates cannot be told apart by import
// path. The keys below therefore say `webpki` while the library block says
// `rustls-webpki`, and only symbols absent from every published
// briansmith/webpki release are declared.
//
// Each key was read off `crypto-finder scan --export-callgraph` for a probe
// consumer -- emitted as `webpki.EndEntityCert.verify_for_usage(?, ?, ?, ?, ?, ?)`
// and `(?, ?, ?, ?, ?, ?, ?)` -- and then had its second-to-last dot rewritten
// to `::` (rustAuthoredKey, contracts.go:267).
//
// The set is compared EXACTLY, not per key, and it renders the `parameters:`
// block and `Varargs` as well as the scalar fields. Neither entry declares a
// parameter contribution or is variadic, so those render empty here; rendering
// them anyway is what makes a later addition, or a `varargs: true` slipped onto
// an entry, fail instead of loading silently.

// renderRustlsWebpkiContracts renders every loaded rustls-webpki contract as one
// deterministic line, sorted.
func renderRustlsWebpkiContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "rustls-webpki" {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				idx := "-"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contributes := "-"
				if p.Contributes != nil {
					contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
				}
				params = append(params, fmt.Sprintf("%s=%s:%s:%s", idx, p.Name, p.Role, contributes))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/{%s}/v=%t",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				strings.Join(params, ";"), c.Varargs))
		}
	}
	sort.Strings(got)
	return got
}

// `TrustAnchor` CARRIES A DIFFERENT CRATE PREFIX IN THE TWO ENTRIES, AND THAT IS
// NOT A TYPO. At 0.101.7 the webpki root re-exports it, so the arity-6 entry reads
// `webpki::TrustAnchor`; from 0.102.0 the root re-exports none and end_entity.rs
// imports it from `pki_types`, so the arity-7 entry reads `pki_types::TrustAnchor`.
//
// TWO ARITIES BECAUSE THE 0.102.0 BREAK CHANGED BOTH THE ARGUMENTS AND THE
// RETURN. arity 6 is 0.101.2-0.101.7 and returns `Result<(), Error>`; arity 7 is
// 0.102.0 onwards, takes `Option<RevocationOptions>` plus a `verify_path`
// callback in place of the CRL slice, and returns `Result<VerifiedPath, Error>`.
// Different arities are different keys, so neither era has to be chosen and the
// divergent-return hard error (contracts.go:936-968, Rule 2) does not arise.
var wantRustlsWebpkiContracts = []string{
	"webpki::EndEntityCert.verify_for_usage#6/operation/core::result::Result/core::result::Result<(), webpki::Error>/" +
		"[&[&webpki::SignatureAlgorithm],&[webpki::TrustAnchor],&[&[u8]],webpki::Time,webpki::KeyUsage," +
		"&[&dyn webpki::CertRevocationList]]/high/{}/v=false",
	"webpki::EndEntityCert.verify_for_usage#7/operation/core::result::Result/core::result::Result<webpki::VerifiedPath, webpki::Error>/" +
		"[&[&dyn pki_types::SignatureVerificationAlgorithm],&[pki_types::TrustAnchor],&[pki_types::CertificateDer]," +
		"pki_types::UnixTime,impl webpki::ExtendedKeyUsageValidator,core::option::Option<webpki::RevocationOptions>," +
		"core::option::Option<&dyn Fn(&webpki::VerifiedPath) -> core::result::Result<(), webpki::Error>>]/high/{}/v=false",
}

func TestLoadEmbeddedRustRustlsWebpkiContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderRustlsWebpkiContracts(t)
	want := append([]string(nil), wantRustlsWebpkiContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("rustls-webpki contracts: got %d, want %d", len(got), len(want))
	}
	for i := 0; i < len(got) || i < len(want); i++ {
		switch {
		case i >= len(got):
			t.Errorf("missing contract: %s", want[i])
		case i >= len(want):
			t.Errorf("unexpected contract: %s", got[i])
		case got[i] != want[i]:
			t.Errorf("contract mismatch:\n got: %s\nwant: %s", got[i], want[i])
		}
	}
}

// THE EMITTED KEY MUST RESOLVE TO THE AUTHORED SPELLING. The call graph emits
// `webpki.EndEntityCert.verify_for_usage`, which carries two dots, so
// rustAuthoredKey rewrites the second-to-last one at load time. A file keyed in
// the emitted spelling loads without error and then misses every lookup.
func TestRustRustlsWebpkiEmittedKeyResolves(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, arity := range []int{6, 7} {
		got := kb.ContractsFor("webpki.EndEntityCert.verify_for_usage", arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(webpki.EndEntityCert.verify_for_usage, %d): the EMITTED key does not resolve", arity)
			continue
		}
		if want := "webpki::EndEntityCert.verify_for_usage"; got[0].Method != want {
			t.Errorf("arity %d resolved to method %q, want the authored spelling %q", arity, got[0].Method, want)
		}
		if got[0].SourceLibrary != "rustls-webpki" {
			t.Errorf("arity %d resolved to library %q, want rustls-webpki", arity, got[0].SourceLibrary)
		}
	}
}

// THE FAMILY'S CENTRAL CLAIM, ASSERTED RATHER THAN DESCRIBED.
//
// rustls-webpki and briansmith/webpki both build a library called `webpki`, so
// their shared entry points collide on one key. Those keys belong to webpki.yaml
// and must NOT be declared by this library: a second declaration would be a
// divergent-return hard load error, and even a matching one would attribute a
// briansmith/webpki call site to pkg:cargo/rustls-webpki.
func TestRustRustlsWebpkiDoesNotClaimTheSharedWebpkiSurface(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	shared := []struct {
		method string
		arity  int
	}{
		{"webpki::EndEntityCert.try_from", 1},
		{"webpki::EndEntityCert.verify_signature", 3},
		{"webpki::EndEntityCert.verify_is_valid_tls_server_cert", 4},
		{"webpki::EndEntityCert.verify_is_valid_tls_client_cert", 4},
	}
	for _, s := range shared {
		for _, c := range kb.ContractsFor(s.method, s.arity) {
			if c.SourceLibrary == "rustls-webpki" {
				t.Errorf("%s#%d is declared by rustls-webpki; that key is spelled identically "+
					"in briansmith/webpki and belongs to webpki.yaml", s.method, s.arity)
			}
		}
	}
	// The other half of the same claim: the keys are still typed, by webpki.
	for _, s := range shared {
		if len(kb.ContractsFor(s.method, s.arity)) == 0 {
			t.Errorf("%s#%d resolves to nothing at all; the assertion above would pass "+
				"vacuously if webpki.yaml stopped declaring it", s.method, s.arity)
		}
	}
}

// The library block is parsed and then never consulted by any assertion above,
// so corrupting version_range, coordinates, name or description loads cleanly
// and leaves every contract assertion green. Read the file itself and pin them.
//
// The range starts at 0.101.2 because that is where `verify_for_usage` and the
// public `KeyUsage` type first appear -- 0.101.1 has neither, measured by
// extracting both archives. The upper bound admits every 0.104.0-alpha row the
// Tier 0 matrix lists, all of which still declare the method at arity 7.
func TestRustRustlsWebpkiLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("rust/rustls-webpki.yaml")
	if err != nil {
		t.Fatalf("read rust/rustls-webpki.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rust/rustls-webpki.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("rustls-webpki.yaml declares no library block")
	}
	lib := kb.Library

	if lib.Name != "rustls-webpki" {
		t.Errorf("library.name = %q, want %q -- the crates.io package, not the lib name", lib.Name, "rustls-webpki")
	}
	if want := ">=0.101.2,<0.105.0"; lib.VersionRange != want {
		t.Errorf("version_range = %q, want %q -- verify_for_usage arrives at 0.101.2", lib.VersionRange, want)
	}
	wantCoords := []string{"rustls-webpki", "rustls_webpki"}
	if len(lib.Coordinates) != len(wantCoords) {
		t.Fatalf("coordinates = %v, want %v", lib.Coordinates, wantCoords)
	}
	for i, c := range wantCoords {
		if lib.Coordinates[i] != c {
			t.Errorf("coordinates[%d] = %q, want %q", i, lib.Coordinates[i], c)
		}
	}
	if lib.Description == "" {
		t.Error("library.description is empty")
	}
	if kb.Ecosystem != "rust" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema_version = %q/%q, want rust/2", kb.Ecosystem, kb.SchemaVersion)
	}
}
