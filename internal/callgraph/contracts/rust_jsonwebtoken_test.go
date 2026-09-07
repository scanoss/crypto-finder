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

// jsonwebtoken (Keats/jsonwebtoken) signs and verifies JWTs. Its surface mixes
// the two Rust key shapes in one crate, and they are authored differently:
// `encode`, `decode` and the 2.0-6.x root re-exports of `sign`/`verify` are
// CRATE-ROOT FREE FUNCTIONS whose emitted key carries a single dot, so the
// authored key IS the emitted key; `Header`, `Validation`, `EncodingKey` and
// `DecodingKey` are types whose methods emit two dots and take "::" before the
// type. `jsonwebtoken::crypto.sign` is a third case that reads like the second
// and is not: the module segment is already spelled with "::" in the emitted
// key, leaving one dot, so it too is authored unchanged.
// rustAuthoredKey (contracts.go:267) rewrites the second-to-last dot only when a
// key has at least two dots, and every one of these was read off an exported
// call graph rather than written from the API.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot see
// an entry that should not be there, an entry that was dropped, or a field that
// was corrupted. It renders `parameters:` and `Varargs` as well as
// method/arity/role/return/params/confidence, because a renamed contributed
// property and a stray `varargs: true` both load cleanly through the schema's
// presence checks and would otherwise pass unnoticed.
//
// The family is spread over EIGHT files with eight ranges -- the eras genuinely
// differ, and `version_range` is declared per LIBRARY -- so the render matches on
// the eight library names rather than on one. Three of the eight exist because a
// PER-SYMBOL window is narrower than the file it would otherwise have sat in:
// `from_ec_components`, `from_ed_components` and `from_jwk` arrive at 8.2.0 and
// not 8.0.0, `Validation::new_for_family` at 10.4.0 and not 10.0.0. An earlier
// revision had the first three under `>=8.0.0`, which asserted three symbols
// that exist in no 8.0.0 or 8.1.1 release.
var jsonwebtokenLibraries = map[string]bool{
	"jsonwebtoken":             true,
	"jsonwebtoken-header":      true,
	"jsonwebtoken-validation":  true,
	"jsonwebtoken-8":           true,
	"jsonwebtoken-8.2":         true,
	"jsonwebtoken-10":          true,
	"jsonwebtoken-10.4":        true,
	"jsonwebtoken-root-crypto": true,
}

func renderJsonwebtokenParameters(c *contracts.Contract) string {
	if len(c.Parameters) == 0 {
		return "-"
	}
	var parts []string
	for _, p := range c.Parameters {
		contrib := "-"
		if p.Contributes != nil {
			contrib = p.Contributes.Property + ":" + p.Contributes.Derivation
		}
		index := "?"
		if p.Index != nil {
			index = fmt.Sprintf("%d", *p.Index)
		}
		parts = append(parts, fmt.Sprintf("%s=%s/%s/%s", index, p.Name, p.Role, contrib))
	}
	return strings.Join(parts, ";")
}

func renderJsonwebtokenContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !jsonwebtokenLibraries[c.SourceLibrary] {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/%s/%s/va=%v",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				c.SourceLibrary, renderJsonwebtokenParameters(c), c.Varargs))
		}
	}
	sort.Strings(got)
	return got
}

var wantJsonwebtokenContracts = []string{
	"jsonwebtoken.decode#3/operation/jsonwebtoken::TokenData/core::result::Result<jsonwebtoken::TokenData, jsonwebtoken::errors::Error>/[&str,&jsonwebtoken::DecodingKey,&jsonwebtoken::Validation]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken.encode#3/operation/alloc::string::String/core::result::Result<alloc::string::String, jsonwebtoken::errors::Error>/[&jsonwebtoken::Header,&T,&jsonwebtoken::EncodingKey]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken.sign#3/operation/alloc::string::String/core::result::Result<alloc::string::String, jsonwebtoken::errors::Error>/[&str,&[u8],jsonwebtoken::Algorithm]/high/jsonwebtoken-root-crypto/-/va=false",
	"jsonwebtoken.verify#4/operation/bool/core::result::Result<bool, jsonwebtoken::errors::Error>/[&str,&str,&[u8],jsonwebtoken::Algorithm]/high/jsonwebtoken-root-crypto/-/va=false",
	"jsonwebtoken::DecodingKey.from_base64_secret#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&str]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::DecodingKey.from_ec_components#2/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&str,&str]/high/jsonwebtoken-8.2/-/va=false",
	"jsonwebtoken::DecodingKey.from_ec_der#1/factory/jsonwebtoken::DecodingKey/jsonwebtoken::DecodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::DecodingKey.from_ec_pem#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::DecodingKey.from_ed_components#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&str]/high/jsonwebtoken-8.2/-/va=false",
	"jsonwebtoken::DecodingKey.from_ed_der#1/factory/jsonwebtoken::DecodingKey/jsonwebtoken::DecodingKey/[&[u8]]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::DecodingKey.from_ed_pem#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::DecodingKey.from_jwk#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&jsonwebtoken::jwk::Jwk]/high/jsonwebtoken-8.2/-/va=false",
	"jsonwebtoken::DecodingKey.from_rsa_components#2/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&str,&str]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::DecodingKey.from_rsa_der#1/factory/jsonwebtoken::DecodingKey/jsonwebtoken::DecodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::DecodingKey.from_rsa_pem#1/factory/jsonwebtoken::DecodingKey/core::result::Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::DecodingKey.from_rsa_raw_components#2/factory/jsonwebtoken::DecodingKey/jsonwebtoken::DecodingKey/[&[u8],&[u8]]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::DecodingKey.from_secret#1/factory/jsonwebtoken::DecodingKey/jsonwebtoken::DecodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_base64_secret#1/factory/jsonwebtoken::EncodingKey/core::result::Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error>/[&str]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_ec_der#1/factory/jsonwebtoken::EncodingKey/jsonwebtoken::EncodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_ec_pem#1/factory/jsonwebtoken::EncodingKey/core::result::Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_ed_der#1/factory/jsonwebtoken::EncodingKey/jsonwebtoken::EncodingKey/[&[u8]]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::EncodingKey.from_ed_pem#1/factory/jsonwebtoken::EncodingKey/core::result::Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::EncodingKey.from_rsa_der#1/factory/jsonwebtoken::EncodingKey/jsonwebtoken::EncodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_rsa_pem#1/factory/jsonwebtoken::EncodingKey/core::result::Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error>/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_secret#1/factory/jsonwebtoken::EncodingKey/jsonwebtoken::EncodingKey/[&[u8]]/high/jsonwebtoken/-/va=false",
	"jsonwebtoken::EncodingKey.from_urlsafe_base64_secret#1/factory/jsonwebtoken::EncodingKey/core::result::Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error>/[&str]/high/jsonwebtoken-10/-/va=false",
	"jsonwebtoken::Header.new#1/factory/jsonwebtoken::Header/jsonwebtoken::Header/[jsonwebtoken::Algorithm]/high/jsonwebtoken-header/-/va=false",
	"jsonwebtoken::Validation.new#1/factory/jsonwebtoken::Validation/jsonwebtoken::Validation/[jsonwebtoken::Algorithm]/high/jsonwebtoken-validation/-/va=false",
	"jsonwebtoken::crypto.sign#3/operation/alloc::string::String/core::result::Result<alloc::string::String, jsonwebtoken::errors::Error>/[&[u8],&jsonwebtoken::EncodingKey,jsonwebtoken::Algorithm]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::crypto.verify#4/operation/bool/core::result::Result<bool, jsonwebtoken::errors::Error>/[&str,&[u8],&jsonwebtoken::DecodingKey,jsonwebtoken::Algorithm]/high/jsonwebtoken-8/-/va=false",
	"jsonwebtoken::Validation.new_for_family#1/factory/jsonwebtoken::Validation/jsonwebtoken::Validation/[jsonwebtoken::AlgorithmFamily]/high/jsonwebtoken-10.4/-/va=false",
	"jsonwebtoken::jws.decode#3/operation/jsonwebtoken::TokenData/core::result::Result<jsonwebtoken::TokenData, jsonwebtoken::errors::Error>/[&jsonwebtoken::jws::Jws,&jsonwebtoken::DecodingKey,&jsonwebtoken::Validation]/high/jsonwebtoken-10/-/va=false",
	"jsonwebtoken::jws.encode#3/operation/jsonwebtoken::jws::Jws/core::result::Result<jsonwebtoken::jws::Jws, jsonwebtoken::errors::Error>/[&jsonwebtoken::Header,core::option::Option<&T>,&jsonwebtoken::EncodingKey]/high/jsonwebtoken-10/-/va=false",
}

func TestLoadEmbeddedRustJsonwebtokenContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderJsonwebtokenContracts(t)
	want := append([]string(nil), wantJsonwebtokenContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("jsonwebtoken contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected jsonwebtoken contract: %q,", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing jsonwebtoken contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that -- not the authored spelling -- is what the parser looks up. Every key
// below was read off an exported call graph of a probe consumer BEFORE this
// contract existed, where each came back as `<key>(?, ?, ...)` with empty
// parameter types, which is what an absent contract looks like and is what the
// family matrix reported as contract_gap=Y.
func TestJsonwebtokenEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := []struct {
		method string
		arity  int
	}{
		{"jsonwebtoken.encode", 3},
		{"jsonwebtoken.decode", 3},
		{"jsonwebtoken.sign", 3},
		{"jsonwebtoken.verify", 4},
		{"jsonwebtoken.Header.new", 1},
		{"jsonwebtoken.Validation.new", 1},
		{"jsonwebtoken.EncodingKey.from_secret", 1},
		{"jsonwebtoken.EncodingKey.from_rsa_pem", 1},
		{"jsonwebtoken.EncodingKey.from_ed_der", 1},
		{"jsonwebtoken.EncodingKey.from_urlsafe_base64_secret", 1},
		{"jsonwebtoken.DecodingKey.from_secret", 1},
		{"jsonwebtoken.DecodingKey.from_jwk", 1},
		{"jsonwebtoken.DecodingKey.from_rsa_components", 2},
		{"jsonwebtoken.DecodingKey.from_ec_components", 2},
		{"jsonwebtoken::crypto.sign", 3},
		{"jsonwebtoken::crypto.verify", 4},
		{"jsonwebtoken::jws.encode", 3},
		{"jsonwebtoken::jws.decode", 3},
		{"jsonwebtoken.Validation.new_for_family", 1},
	}
	for _, e := range emitted {
		got := kb.ContractsFor(e.method, e.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", e.method, e.arity)
			continue
		}
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): got %d contracts, want exactly 1", e.method, e.arity, len(got))
			continue
		}
		if !jsonwebtokenLibraries[got[0].SourceLibrary] {
			t.Errorf("%s: library = %q, want a jsonwebtoken file", e.method, got[0].SourceLibrary)
		}
		if len(got[0].ParameterTypes) != e.arity {
			t.Errorf("%s#%d: %d parameter_types, want %d -- an entry whose declared "+
				"parameters do not match its arity renders a signature the parser "+
				"cannot fill", e.method, e.arity, len(got[0].ParameterTypes), e.arity)
		}
	}
}

// A "::" SPELLING MUST NOT RESOLVE FOR THE CRATE-ROOT FREE FUNCTIONS. This is
// the assertion that catches the mechanical application of the Rust key
// substitution: rustAuthoredKey moves the second-to-last dot only when a key has
// at least two dots, and `jsonwebtoken.encode`, `jsonwebtoken.decode`,
// `jsonwebtoken.sign`, `jsonwebtoken.verify` and `jsonwebtoken::crypto.sign`
// each have exactly one, so the "::" form is not an alias and must be absent.
// Authoring it would load without error and join nothing.
func TestJsonwebtokenDoubleColonSpellingDoesNotResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"jsonwebtoken::encode", 3},
		{"jsonwebtoken::decode", 3},
		{"jsonwebtoken::sign", 3},
		{"jsonwebtoken::verify", 4},
		{"jsonwebtoken::crypto::sign", 3},
		{"jsonwebtoken::crypto::verify", 4},
		{"jsonwebtoken::jws::encode", 3},
		{"jsonwebtoken::jws::decode", 3},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved to %d contracts; a crate-root free "+
				"function is keyed with a dot and this spelling must not exist",
				tc.method, tc.arity, len(got))
		}
	}
}

// NO ENTRY CONTRIBUTES `algorithm`, AND THAT IS THIS FAMILY'S CENTRAL CHOICE
// RATHER THAN AN OVERSIGHT.
//
// `Header::new` and `Validation::new` each take the algorithm as argument 0, and
// `crypto::sign` / `crypto::verify` take it as their last, so a
// `contributes: { property: algorithm, derivation: argument_value }` looks
// obviously right. It is not. A JWT carries its own `alg` header, that header is
// chosen by whoever minted the token, and `Validation::new(decode_header(t)?.alg)`
// -- an idiom that occurs in real published consumers, jwt-authorizer 0.2.0
// among them -- passes it straight through. A contribution fires on the argument
// whatever it holds, and the derivation is exported verbatim for a downstream
// consumer to apply (scan/export.go:1232, fragment_export.go:1728), so this KB
// cannot bound what that consumer does with a non-literal. The RULES name the
// algorithm exactly where the source states a literal `Algorithm::<VARIANT>`,
// and nothing here widens that.
//
// The same test also pins that no parameter contributes the secret: every
// `from_secret` / `from_base64_secret` call site in the crate's own tests passes
// a byte-string LITERAL, and lifting it would publish the key.
func TestJsonwebtokenContributesNoAlgorithmOrKeyMaterial(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	forbidden := map[string]bool{
		"algorithm": true, "keyMaterial": true, "secret": true, "key": true,
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !jsonwebtokenLibraries[c.SourceLibrary] {
				continue
			}
			for _, p := range c.Parameters {
				if p.Contributes == nil {
					continue
				}
				if forbidden[p.Contributes.Property] {
					t.Errorf("%s#%d parameter %s contributes %q; the algorithm of a JWT "+
						"call site is claimed by the rules only when the source states a "+
						"literal, and the secret must never be lifted into the payload",
						c.Method, c.Arity, p.Name, p.Contributes.Property)
				}
			}
		}
	}
}

// THE SIX FILES DECLARE THEIR OWN ERA.
//
// BE CLEAR ABOUT WHAT THIS TEST IS: a tripwire, not a guard. It compares the
// YAML to a constant in this file, so editing both together passes and a wrong
// bound passes from the start. The bounds were derived by reading `pub fn` and
// `pub enum Algorithm` out of the crate archives at 0.1.0, 0.2.0, 1.0.0, 1.1.7,
// 2.0.0, 2.0.3, 3.0.0, 4.0.1, 5.0.1, 6.0.0, 6.0.1, 7.0.0, 7.2.0, 8.0.0, 8.3.0,
// 9.0.0, 9.3.1, 10.0.0 and 10.4.0. This only stops them drifting unnoticed.
func TestJsonwebtokenFilesDeclareTheirOwnEra(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ file, name, wantRange, wantDesc string }{
		{
			"rust/jsonwebtoken.yaml", "jsonwebtoken", ">=7.0.0,<11.0.0",
			"JWT signing and verification for Rust, and the typed key material the 7.0 API introduced",
		},
		{
			"rust/jsonwebtoken-header.yaml", "jsonwebtoken-header", ">=0.1.0,<11.0.0",
			"jsonwebtoken's JWS header constructor, the point at which a signing algorithm is chosen",
		},
		{
			"rust/jsonwebtoken-validation.yaml", "jsonwebtoken-validation", ">=4.0.0,<11.0.0",
			"jsonwebtoken's decoding validation constructor, which fixes the algorithm a token is allowed to be verified with",
		},
		{
			"rust/jsonwebtoken-8.yaml", "jsonwebtoken-8", ">=8.0.0,<11.0.0",
			"the key material and low-level signing surface jsonwebtoken 8.0 added: Ed25519 PEM and DER keys, raw RSA components, and the crypto module's byte-slice signing",
		},
		{
			"rust/jsonwebtoken-8.2.yaml", "jsonwebtoken-8.2", ">=8.2.0,<11.0.0",
			"the JWK and coordinate-based verification key constructors jsonwebtoken 8.2 added",
		},
		{
			"rust/jsonwebtoken-10.yaml", "jsonwebtoken-10", ">=10.0.0,<11.0.0",
			"the url-safe base64 secret constructor and the detached-JWS entry points jsonwebtoken 10.0 added",
		},
		{
			"rust/jsonwebtoken-10.4.yaml", "jsonwebtoken-10.4", ">=10.4.0,<11.0.0",
			"jsonwebtoken 10.4's family-shaped validation constructor, which accepts every algorithm in one AlgorithmFamily",
		},
		{
			"rust/jsonwebtoken-root-crypto.yaml", "jsonwebtoken-root-crypto", ">=2.0.0,<7.0.0",
			"jsonwebtoken's low-level sign and verify while they were re-exported at the crate root, before the 7.0 key types",
		},
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
			t.Errorf("%s: version_range = %q, want %q -- the range must cover only "+
				"versions for which every entry in this file is true",
				tc.file, kb.Library.VersionRange, tc.wantRange)
		}
		if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "jsonwebtoken" {
			t.Errorf("%s: coordinates = %v, want exactly [jsonwebtoken] -- the crate name "+
				"and the callgraph key spelling are the same here, so there is no second "+
				"form to declare", tc.file, kb.Library.Coordinates)
		}
		// Compared EXACTLY, not merely for non-emptiness. A corrupted description
		// is parsed and never consulted, so nothing else in this package would
		// notice it.
		if kb.Library.Description != tc.wantDesc {
			t.Errorf("%s: library.description = %q, want %q",
				tc.file, kb.Library.Description, tc.wantDesc)
		}
	}
}
