// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"os"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// biscuit publishes every JOSE type under TWO spellings, and a contract that
// covers only one of them resolves against nothing — which looks exactly like
// having no contract. `JWT` and `JWE` are type ALIASES (lib.rs:206, :323) for
// `jws::Compact` and `jwe::Compact`, and the Rust parser keys a call by the
// path the CONSUMER wrote, not by what it resolves to. Read off an exported
// call graph, not written from the API: a probe calling `JWT::new_decoded(..)`
// emits `biscuit.JWT.new_decoded`, one calling `jws::Compact::new_decoded(..)`
// emits `biscuit::jws.Compact.new_decoded`, and both are in real use.
func TestLoadEmbeddedRustIncludesBiscuitContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method  string
		arity   int
		role    string
		library string
	}{
		// Arities exclude the receiver and are read from the declarations.
		{"biscuit::JWT.new_decoded", 2, "factory", "biscuit"},
		{"biscuit::JWT.encode", 1, "operation", "biscuit"},
		{"biscuit::JWT.decode", 2, "operation", "biscuit"},
		{"biscuit::JWT.signature", 0, "output", "biscuit"},
		{"biscuit::jws::Compact.new_encoded", 1, "factory", "biscuit"},
		{"biscuit::jws::Compact.into_encoded", 1, "operation", "biscuit"},
		{"biscuit::jws::Compact.into_decoded", 2, "operation", "biscuit"},
		{"biscuit::jws::Compact.unverified_header", 0, "output", "biscuit"},
		{"biscuit::JWE.new_encrypted", 1, "factory", "biscuit"},
		{"biscuit::JWE.encrypt", 2, "operation", "biscuit"},
		{"biscuit::JWE.decrypt", 3, "operation", "biscuit"},
		{"biscuit::jwe::Compact.into_encrypted", 2, "operation", "biscuit"},
		{"biscuit::jwe::Compact.into_decrypted", 3, "operation", "biscuit"},
		{"biscuit::jwa::SignatureAlgorithm.sign", 2, "operation", "biscuit"},
		{"biscuit::jwa::SignatureAlgorithm.verify", 3, "operation", "biscuit"},
		{"biscuit::jwa::ContentEncryptionAlgorithm.encrypt", 4, "operation", "biscuit"},
		{"biscuit::jwa::ContentEncryptionAlgorithm.decrypt", 2, "operation", "biscuit"},
		{"biscuit::jwa::ContentEncryptionAlgorithm.generate_key", 0, "operation", "biscuit"},
		{"biscuit::jwa::KeyManagementAlgorithm.wrap_key", 3, "operation", "biscuit"},
		{"biscuit::jwa::KeyManagementAlgorithm.unwrap_key", 3, "operation", "biscuit"},
		{"biscuit::jwa::KeyManagementAlgorithm.cek", 2, "operation", "biscuit"},
		// The two era-split files.
		{"biscuit::JWT.decode_with_jwks", 2, "operation", "biscuit-jwks"},
		{"biscuit::jws::Compact.decode_with_jwks_ignore_kid", 1, "operation", "biscuit-jwks-ignore-kid"},
		{"biscuit::JWT.decode_with_jwks_ignore_kid", 1, "operation", "biscuit-jwks-ignore-kid"},
		{"biscuit::jws::Signable.new", 2, "factory", "biscuit-flattened"},
		{"biscuit::jws::Signable.sign", 1, "operation", "biscuit-flattened"},
		{"biscuit::jws::SignedData.sign", 2, "operation", "biscuit-flattened"},
		{"biscuit::jws::SignedData.verify_flattened", 3, "operation", "biscuit-flattened"},
		{"biscuit::jws::SignedData.serialize_flattened", 0, "output", "biscuit-flattened"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): %d contracts, want exactly 1", tc.method, tc.arity, len(got))
			continue
		}
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s: library = %q, want %q", tc.method, got[0].SourceLibrary, tc.library)
		}
		if got[0].Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, got[0].Role, tc.role)
		}
	}
}

// The dot-joined call-site spelling the graph actually emits must resolve. The
// key normalization moves ONE separator (contracts.go:267), so an authored
// `biscuit::jwa::SignatureAlgorithm.sign` is reached from the emitted
// `biscuit::jwa.SignatureAlgorithm.sign` — getting that backwards produces a
// contract nothing joins to.
func TestBiscuitEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The arity is given per entry rather than -1. A re-review pointed out that
	// -1 takes the name-only `lowestArityByName` fallback (contracts.go:250),
	// so the test could not fail on a wrong arity while its comment invited the
	// reader to think the emitted key was fully checked. With real arities it
	// is both an arity guard and a key-shape guard.
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"biscuit.JWT.encode", 1},
		{"biscuit.JWT.decode", 2},
		{"biscuit.JWT.new_decoded", 2},
		{"biscuit.JWT.decode_with_jwks", 2},
		{"biscuit.JWT.decode_with_jwks_ignore_kid", 1},
		{"biscuit.JWE.encrypt", 2},
		{"biscuit.JWE.into_decrypted", 3},
		{"biscuit::jws.Compact.encode", 1},
		{"biscuit::jws.Compact.decode_with_jwks_ignore_kid", 1},
		{"biscuit::jwe.Compact.decrypt", 3},
		{"biscuit::jwa.SignatureAlgorithm.sign", 2},
		{"biscuit::jwa.SignatureAlgorithm.verify", 3},
		{"biscuit::jwa.ContentEncryptionAlgorithm.generate_key", 0},
		{"biscuit::jwa.KeyManagementAlgorithm.wrap_key", 3},
		{"biscuit::jws.Signable.new", 2},
		{"biscuit::jws.Signable.sign", 1},
		{"biscuit::jws.SignedData.verify_flattened", 3},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key at that arity",
				tc.method, tc.arity)
		}
	}
}

// `return.type` is the resolution type a caller chains from; the full declared
// type belongs in `canonical_return_type`. Putting the wrapper in `return.type`
// hands `Result` back as the next receiver and produces `core::result.(Result).*`
// edges downstream.
func TestBiscuitReturnTypesFollowTheKBConvention(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	checked := 0
	for _, ctrs := range kb.Contracts {
		for i := range ctrs {
			c := &ctrs[i]
			if !strings.HasPrefix(c.SourceLibrary, "biscuit") {
				continue
			}
			checked++
			if strings.HasPrefix(c.Return.Type, "core::result::Result") ||
				strings.HasPrefix(c.Return.Type, "core::option::Option") {
				t.Errorf("%s: return.type is the wrapper %q; it must be the type a "+
					"caller chains from, with the wrapper in canonical_return_type",
					c.Method, c.Return.Type)
			}
			if n := len(c.ParameterTypes); n != 0 && n != c.Arity {
				t.Errorf("%s: %d parameter_types for arity %d; declare all or none",
					c.Method, n, c.Arity)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no biscuit contracts were checked")
	}
}

// THE FOUR FILES AND THEIR FOUR ERAS MOVE TOGETHER. `version_range` is
// declared per LIBRARY and may only claim versions for which EVERY entry in
// that file is true, which is why this crate needs four files rather than one:
// `decode_with_jwks` does not exist before 0.5.0, the `Signable`/`SignedData`
// surface not before 0.6.0, and `decode_with_jwks_ignore_kid` -- which reads
// like a sibling of the first and is not -- not before 0.7.0, while the core
// API goes back to 0.0.8. Folding them together would force the core's range up
// and silently under-document it.
//
// `version_range` is parsed (contracts.go:383, :471) and never consulted by any
// lookup, so it documents the era rather than gating it — a 0.0.8 consumer is
// still served the flattened signatures. That makes the bound a claim about
// what was verified, not a runtime guard, which is exactly why it has to be
// true. Widening any of them means re-reading the crate source first.
//
// BE CLEAR ABOUT WHAT THIS TEST IS: a tripwire, not a guard. It compares the
// YAML to a constant in this file, so editing both together passes and a WRONG
// bound passes from the start — the original `>=0.5.0` on the ignore-kid entry
// sailed through it and was caught by a cold read of the crate sources
// instead. What would make it a real guard is asserting each contracted method
// exists at its file's lower bound and is absent one published version below,
// which needs the crate sources and so cannot run here. Until then the bound is
// verified by hand and this only stops it drifting unnoticed.
func TestBiscuitFilesDeclareTheirOwnEra(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ file, name, wantRange string }{
		{"rust/biscuit.yaml", "biscuit", ">=0.0.8,<0.9.0"},
		{"rust/biscuit-jwks.yaml", "biscuit-jwks", ">=0.5.0,<0.9.0"},
		{"rust/biscuit-jwks-ignore-kid.yaml", "biscuit-jwks-ignore-kid", ">=0.7.0,<0.9.0"},
		{"rust/biscuit-flattened.yaml", "biscuit-flattened", ">=0.6.0,<0.9.0"},
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
		// All three describe the one crate, whatever the library.name is.
		if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "biscuit" {
			t.Errorf("%s: coordinates = %v, want [biscuit]", tc.file, kb.Library.Coordinates)
		}
	}
}

// The two spellings must agree on every shared method, or a consumer's
// resolution would depend on which path they happened to write.
func TestBiscuitAliasAndFullPathSpellingsAgree(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	pairs := []struct {
		alias, full string
		arity       int
	}{
		{"biscuit::JWT.new_decoded", "biscuit::jws::Compact.new_decoded", 2},
		{"biscuit::JWT.new_encoded", "biscuit::jws::Compact.new_encoded", 1},
		{"biscuit::JWT.encode", "biscuit::jws::Compact.encode", 1},
		{"biscuit::JWT.into_encoded", "biscuit::jws::Compact.into_encoded", 1},
		{"biscuit::JWT.decode", "biscuit::jws::Compact.decode", 2},
		{"biscuit::JWT.into_decoded", "biscuit::jws::Compact.into_decoded", 2},
		{"biscuit::JWT.signature", "biscuit::jws::Compact.signature", 0},
		{"biscuit::JWT.unverified_header", "biscuit::jws::Compact.unverified_header", 0},
		{"biscuit::JWT.decode_with_jwks", "biscuit::jws::Compact.decode_with_jwks", 2},
		{"biscuit::JWT.decode_with_jwks_ignore_kid", "biscuit::jws::Compact.decode_with_jwks_ignore_kid", 1},
		{"biscuit::JWE.new_decrypted", "biscuit::jwe::Compact.new_decrypted", 2},
		{"biscuit::JWE.new_encrypted", "biscuit::jwe::Compact.new_encrypted", 1},
		{"biscuit::JWE.encrypt", "biscuit::jwe::Compact.encrypt", 2},
		{"biscuit::JWE.into_encrypted", "biscuit::jwe::Compact.into_encrypted", 2},
		{"biscuit::JWE.decrypt", "biscuit::jwe::Compact.decrypt", 3},
		{"biscuit::JWE.into_decrypted", "biscuit::jwe::Compact.into_decrypted", 3},
	}

	for _, p := range pairs {
		a := kb.ContractsFor(p.alias, p.arity)
		f := kb.ContractsFor(p.full, p.arity)
		if len(a) != 1 || len(f) != 1 {
			t.Errorf("%s / %s: %d and %d contracts, want 1 each", p.alias, p.full, len(a), len(f))
			continue
		}
		if a[0].Return.Type != f[0].Return.Type {
			t.Errorf("%s vs %s: return.type %q != %q", p.alias, p.full, a[0].Return.Type, f[0].Return.Type)
		}
		if a[0].CanonicalReturnType != f[0].CanonicalReturnType {
			t.Errorf("%s vs %s: canonical_return_type %q != %q",
				p.alias, p.full, a[0].CanonicalReturnType, f[0].CanonicalReturnType)
		}
		if a[0].Role != f[0].Role {
			t.Errorf("%s vs %s: role %q != %q", p.alias, p.full, a[0].Role, f[0].Role)
		}
		if strings.Join(a[0].ParameterTypes, ",") != strings.Join(f[0].ParameterTypes, ",") {
			t.Errorf("%s vs %s: parameter_types %v != %v",
				p.alias, p.full, a[0].ParameterTypes, f[0].ParameterTypes)
		}
	}
}

// `SignedData::verify_flattened` and `SignedData::sign` are ASSOCIATED
// FUNCTIONS, not methods, and an earlier revision of this family's rules
// matched `$signed.verify_flattened(..)` — a shape that does not compile,
// guessed from a probe instead of read from the declaration
// (flattened.rs:234, and the crate's own tests at :378 and :422). Arity is the
// visible half of that mistake: as a method it looks like 2, as the associated
// function it is 3.
func TestBiscuitAssociatedFunctionsCarryTheirFullArity(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	if got := kb.ContractsFor("biscuit::jws::SignedData.verify_flattened", 2); len(got) != 0 {
		t.Errorf("verify_flattened is contracted at arity 2; it takes (data, secret, "+
			"algorithm) and no receiver, so only arity 3 is correct (got %d)", len(got))
	}
	got := kb.ContractsFor("biscuit::jws::SignedData.verify_flattened", 3)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(verify_flattened, 3): %d contracts, want 1", len(got))
	}
	if n := len(got[0].ParameterTypes); n != 3 {
		t.Errorf("verify_flattened: %d parameter_types, want 3", n)
	}

	// `Signable::new` fails while serializing the protected header, before any
	// crypto happens, so its error type is serde_json's and not the crate's.
	sn := kb.ContractsFor("biscuit::jws::Signable.new", 2)
	if len(sn) != 1 {
		t.Fatalf("ContractsFor(Signable.new, 2): %d contracts, want 1", len(sn))
	}
	if !strings.Contains(sn[0].CanonicalReturnType, "serde_json::Error") {
		t.Errorf("Signable::new: canonical_return_type = %q, want the serde_json "+
			"error it actually returns", sn[0].CanonicalReturnType)
	}
}

// A WRONG parameter_types VALUE USED TO PASS EVERY TEST, and a cold review
// showed it: the convention test checks only the COUNT, and the alias/full-path
// test compares the two spellings to each other, so a mistake copied into both
// went unnoticed. These pin the values themselves, read from the 0.8.0
// declarations: one entry per DISTINCT parameter shape in the family, so every
// shape has a representative even though not every one of the 45 entries is
// listed. A re-review counted the shapes and found eight with none; adding a
// shape here is one line, and leaving one out means a wrong value in it passes
// the whole suite.
func TestBiscuitParameterTypesArePinnedNotJustCounted(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		params []string
	}{
		{
			"biscuit::jwa::SignatureAlgorithm.sign", 2,
			[]string{"&[u8]", "&biscuit::jws::Secret"},
		},
		{
			"biscuit::jwa::SignatureAlgorithm.verify", 3,
			[]string{"&[u8]", "&[u8]", "&biscuit::jws::Secret"},
		},
		{
			"biscuit::jwa::ContentEncryptionAlgorithm.encrypt", 4,
			[]string{"&[u8]", "&[u8]", "&biscuit::jwk::JWK", "&biscuit::jwa::EncryptionOptions"},
		},
		{
			"biscuit::jwa::KeyManagementAlgorithm.unwrap_key", 3,
			[]string{"&biscuit::jwa::EncryptionResult", "biscuit::jwa::ContentEncryptionAlgorithm", "&biscuit::jwk::JWK"},
		},
		{
			"biscuit::jws::Compact.decode", 2,
			[]string{"&biscuit::jws::Secret", "biscuit::jwa::SignatureAlgorithm"},
		},
		{
			"biscuit::jwe::Compact.decrypt", 3,
			[]string{"&biscuit::jwk::JWK", "biscuit::jwa::KeyManagementAlgorithm", "biscuit::jwa::ContentEncryptionAlgorithm"},
		},
		{
			"biscuit::jws::Compact.decode_with_jwks", 2,
			[]string{"&biscuit::jwk::JWKSet", "core::option::Option<biscuit::jwa::SignatureAlgorithm>"},
		},
		{
			"biscuit::jws::Compact.decode_with_jwks_ignore_kid", 1,
			[]string{"&biscuit::jwk::JWKSet"},
		},
		{
			"biscuit::jws::SignedData.verify_flattened", 3,
			[]string{"&[u8]", "biscuit::jws::Secret", "biscuit::jwa::SignatureAlgorithm"},
		},
		{
			"biscuit::jws::Signable.new", 2,
			[]string{"biscuit::jws::Header", "alloc::vec::Vec<u8>"},
		},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): %d contracts, want 1", tc.method, tc.arity, len(got))
			continue
		}
		if strings.Join(got[0].ParameterTypes, ", ") != strings.Join(tc.params, ", ") {
			t.Errorf("%s: parameter_types = %v, want %v",
				tc.method, got[0].ParameterTypes, tc.params)
		}
	}
}
