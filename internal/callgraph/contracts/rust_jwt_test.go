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

// The `jwt` crate (mikkyang/rust-jwt) is a JOSE implementation whose surface
// arrives in FOUR disjoint waves, which is why it takes four contract files
// rather than one: `version_range` is declared per LIBRARY, and folding any two
// together would force every entry in the merged file to claim a range that is
// false for part of it.
//
//	jwt.yaml              >=0.6.0,<0.17.0  the modern Token / trait surface
//	jwt-store.yaml        >=0.7.0,<0.17.0  Store, SignWithStore, VerifyWithStore
//	jwt-legacy-root.yaml  >=0.1.0,<0.6.0   jwt::Token signed / verify / parse
//	jwt-legacy.yaml       >=0.6.0,<0.10.0  jwt::legacy::Token, the same four
//
// THE LAST TWO ARE THE SAME METHODS UNDER TWO PATHS AND THEIR RANGES DO NOT
// OVERLAP. From 0.6.0 `jwt::Token` is the MODERN token and carries no `signed`,
// so a single `>=0.1.0,<0.10.0` file would have claimed `jwt::Token.signed` for
// five releases where it does not exist. jwt-store.yaml was split out for a
// ONE-version difference on exactly that argument.
//
// EVERY KEY WAS READ OFF `crypto-finder scan --export-callgraph` OVER A PROBE
// CONSUMER, then had its second-to-last dot rewritten to `::` because all of
// them carry two or more dots (rustAuthoredKey, contracts.go:267):
//
//	Token::parse_unverified(s)             -> jwt.Token.parse_unverified
//	                                       -> jwt::Token.parse_unverified
//	jwt::SigningAlgorithm::sign(&k, h, c)  -> jwt.SigningAlgorithm.sign
//	                                       -> jwt::SigningAlgorithm.sign
//	token.signed(k, Sha256::new())         -> jwt.Token.signed          (root era)
//	                                       -> jwt::Token.signed
//	                                       -> jwt::legacy.Token.signed  (0.6.0+)
//	                                       -> jwt::legacy::Token.signed
//
// THE LAST PAIR IS THE ONE THAT MATTERS: the emitted key follows the CONSUMER'S
// IMPORT PATH, not what the type resolves to, so the same `token.signed(..)`
// line emits two different keys depending on whether the file writes
// `use jwt::Token;` (0.1.0 - 0.5.0) or `use jwt::legacy::Token;` (0.6.0 -
// 0.9.0). Both are declared. Contracting only one leaves the other resolving
// against nothing, which is indistinguishable from having no contract at all.
//
// The set is compared EXACTLY rather than per key, and it renders the
// `parameters:` block and `Varargs` as well as the scalar fields — a per-key
// subset assertion cannot see an entry that should not be there, an entry that
// was dropped, or a field that was corrupted. `Varargs` is rendered because it
// is parsed and defaults to false, so a `varargs: true` slipped onto any entry
// would otherwise load cleanly and survive an otherwise-exact comparison; Rust
// has no variadic methods here, so every rendered value is `v=false`. The
// `library:` blocks are pinned separately in TestJwtLibraryBlocks, because
// `coordinates`, `version_range`, `name` and `description` are parsed and never
// consulted by any other assertion.
//
// WHAT THIS TEST CANNOT DO, said plainly: an exact-set comparison proves the
// test detects DRIFT from what was written. It cannot prove what was written is
// TRUE. Every method, arity and return type below was traced to a `pub fn` in
// the crate's own source at both ends of its range — the file:line citations
// are in the three YAML headers — and that tracing, not this test, is what
// makes the baseline correct.

// renderJwtContracts renders every loaded jwt-family contract as one
// deterministic line, sorted. The three source libraries are rendered together
// because they are one family; the library name is part of each line so an
// entry moving between files fails here.
func renderJwtContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			switch c.SourceLibrary {
			case "jwt", "jwt-store", "jwt-legacy", "jwt-legacy-root":
			default:
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
			pt := make([]string, 0, len(c.ParameterTypes))
			for _, s := range c.ParameterTypes {
				pt = append(pt, fmt.Sprintf("%q", s))
			}
			when := "nil"
			if c.When != nil {
				when = "set"
			}
			got = append(got, fmt.Sprintf("%s@%s#%d/%s/%s/%s/[%s]/%s/{%s}/v=%t/w=%s",
				c.Method, c.SourceLibrary, c.Arity, c.Role, c.Return.Type,
				c.CanonicalReturnType, strings.Join(pt, ","), c.Return.Confidence,
				strings.Join(params, ";"), c.Varargs, when))
		}
	}
	sort.Strings(got)
	return got
}

var wantJwtContracts = []string{
	// --- jwt.yaml, the modern surface, >=0.6.0,<0.17.0 -----------------------
	`jwt::SigningAlgorithm.sign@jwt#3/operation/alloc::string::String/core::result::Result<alloc::string::String, jwt::error::Error>/[]/high/{}/v=false/w=nil`,
	`jwt::Token.as_str@jwt#0/output/&str/&str/[]/high/{}/v=false/w=nil`,
	`jwt::Token.parse_unverified@jwt#1/factory/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/["&str"]/high/{}/v=false/w=nil`,
	`jwt::Token.remove_signature@jwt#0/factory/jwt::Token/jwt::Token/[]/high/{}/v=false/w=nil`,
	`jwt::Token.sign_with_key@jwt#1/operation/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/[]/high/{}/v=false/w=nil`,
	`jwt::Token.verify_with_key@jwt#1/operation/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/[]/high/{}/v=false/w=nil`,
	`jwt::VerifyingAlgorithm.verify@jwt#4/operation/bool/core::result::Result<bool, jwt::error::Error>/[]/high/{}/v=false/w=nil`,
	`jwt::VerifyingAlgorithm.verify_bytes@jwt#4/operation/bool/core::result::Result<bool, jwt::error::Error>/[]/high/{}/v=false/w=nil`,

	// --- jwt-store.yaml, >=0.7.0,<0.17.0 -------------------------------------
	`jwt::Token.sign_with_store@jwt-store#1/operation/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/[]/high/{}/v=false/w=nil`,
	`jwt::Token.verify_with_store@jwt-store#1/operation/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/[]/high/{}/v=false/w=nil`,

	// --- jwt-legacy-root.yaml >=0.1.0,<0.6.0 and jwt-legacy.yaml >=0.6.0,<0.10.0
	`jwt::Token.parse@jwt-legacy-root#1/factory/jwt::Token/core::result::Result<jwt::Token, jwt::error::Error>/["&str"]/high/{}/v=false/w=nil`,
	`jwt::Token.signed@jwt-legacy-root#2/operation/alloc::string::String/core::result::Result<alloc::string::String, jwt::error::Error>/["&[u8]","D"]/high/{1=digest:operation-determining:algorithmName:argument_type}/v=false/w=nil`,
	`jwt::Token.verify@jwt-legacy-root#2/operation/bool/bool/["&[u8]","D"]/high/{1=digest:operation-determining:algorithmName:argument_type}/v=false/w=nil`,
	`jwt::legacy::Token.parse@jwt-legacy#1/factory/jwt::legacy::Token/core::result::Result<jwt::legacy::Token, jwt::error::Error>/["&str"]/high/{}/v=false/w=nil`,
	`jwt::legacy::Token.signed@jwt-legacy#2/operation/alloc::string::String/core::result::Result<alloc::string::String, jwt::error::Error>/["&[u8]","D"]/high/{1=digest:operation-determining:algorithmName:argument_type}/v=false/w=nil`,
	`jwt::legacy::Token.verify@jwt-legacy#2/operation/bool/bool/["&[u8]","D"]/high/{1=digest:operation-determining:algorithmName:argument_type}/v=false/w=nil`,
}

func TestJwtContractsExactSet(t *testing.T) {
	got := renderJwtContracts(t)
	want := append([]string(nil), wantJwtContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("jwt-family contract count = %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("MISSING or ALTERED contract:\n  want %s", w)
		}
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("UNEXPECTED contract:\n  got  %s", g)
		}
	}
}

// TestJwtLibraryBlocks pins the fields that are parsed and then never consulted
// by any other assertion in this file. Corrupting `version_range`,
// `coordinates`, `name` or `description` leaves the exact-set test green, and
// the version ranges are the whole reason this family takes three files.
func TestJwtLibraryBlocks(t *testing.T) {
	cases := []struct {
		file         string
		name         string
		versionRange string
		description  string
	}{
		{
			file:         "jwt.yaml",
			name:         "jwt",
			versionRange: ">=0.6.0,<0.17.0",
			description:  "JOSE — JWT and JWS — for Rust, per mikkyang/rust-jwt",
		},
		{
			file:         "jwt-store.yaml",
			name:         "jwt-store",
			versionRange: ">=0.7.0,<0.17.0",
			description:  "jwt's key-store signing and verification surface (0.7.0 and later)",
		},
		{
			file:         "jwt-legacy-root.yaml",
			name:         "jwt-legacy-root",
			versionRange: ">=0.1.0,<0.6.0",
			description:  "jwt's original crate-root Token API, before the 0.6.0 rewrite moved it under jwt::legacy",
		},
		{
			file:         "jwt-legacy.yaml",
			name:         "jwt-legacy",
			versionRange: ">=0.6.0,<0.10.0",
			description:  "jwt's deprecated jwt::legacy Token API, present from the 0.6.0 rewrite until the module is removed at 0.10.0",
		},
	}

	for _, tc := range cases {
		data, err := os.ReadFile(filepath.Join("rust", tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Fatalf("Load(%s): %v", tc.file, err)
		}
		if kb.Library == nil {
			t.Fatalf("%s: library block is nil", tc.file)
		}
		if kb.Library.Name != tc.name {
			t.Errorf("%s: library.name = %q, want %q", tc.file, kb.Library.Name, tc.name)
		}
		if kb.Library.VersionRange != tc.versionRange {
			t.Errorf("%s: library.version_range = %q, want %q", tc.file, kb.Library.VersionRange, tc.versionRange)
		}
		if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "jwt" {
			t.Errorf("%s: library.coordinates = %v, want [jwt]", tc.file, kb.Library.Coordinates)
		}
		if kb.Library.Description != tc.description {
			t.Errorf("%s: library.description = %q, want %q", tc.file, kb.Library.Description, tc.description)
		}
		if kb.SchemaVersion != "2" {
			t.Errorf("%s: schema_version = %q, want 2", tc.file, kb.SchemaVersion)
		}
		if kb.Ecosystem != "rust" {
			t.Errorf("%s: ecosystem = %q, want rust", tc.file, kb.Ecosystem)
		}
	}
}

// TestJwtAuthoredKeySpellingHolds pins the two spellings that are easy to get
// wrong in opposite directions, so a mechanical "apply the substitution
// everywhere" edit — or a mechanical "the emitted key is the authored key"
// edit — fails here rather than silently joining nothing.
func TestJwtAuthoredKeySpellingHolds(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// The authored `::` spelling resolves; the emitted `.` spelling must not.
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"jwt::Token.parse_unverified", 1},
		{"jwt::SigningAlgorithm.sign", 3},
		{"jwt::legacy::Token.signed", 2},
	} {
		if len(kb.ContractsFor(tc.method, tc.arity)) == 0 {
			t.Errorf("authored key %s#%d does not resolve", tc.method, tc.arity)
		}
	}

	// The BOTH-ERAS pair: the same source line emits a different key depending
	// on the consumer's import path, and both must resolve.
	if len(kb.ContractsFor("jwt::Token.signed", 2)) == 0 {
		t.Error("crate-root legacy key jwt::Token.signed#2 does not resolve")
	}
	if len(kb.ContractsFor("jwt::legacy::Token.signed", 2)) == 0 {
		t.Error("jwt::legacy::Token.signed#2 does not resolve")
	}

	// THE EMITTED DOTTED FORM RESOLVES, AND THAT IS THE MECHANISM RATHER THAN A
	// BUG. `rustContractsFor` (contracts.go:241) applies `rustAuthoredKey` to
	// the LOOKUP key before matching, so the graph's `jwt.Token.parse_unverified`
	// finds the authored `jwt::Token.parse_unverified`. Asserting it here pins
	// the round trip: the authored spelling is what the FILE must contain, and
	// the emitted spelling is what the CALL SITE produces.
	for _, emitted := range []struct {
		method string
		arity  int
	}{
		{"jwt.Token.parse_unverified", 1},
		{"jwt.SigningAlgorithm.sign", 3},
		{"jwt::legacy.Token.signed", 2},
	} {
		if len(kb.ContractsFor(emitted.method, emitted.arity)) == 0 {
			t.Errorf("emitted key %s#%d does not normalize onto an authored key",
				emitted.method, emitted.arity)
		}
	}

	// Spellings that must NOT resolve: applying the `::` substitution ONE
	// SEGMENT TOO FAR, which is what a mechanical "make every separator `::`"
	// edit produces. `rustAuthoredKey` moves only the separator in front of the
	// receiver type, so the method separator stays a `.`; a file written with
	// `::` throughout loads without error and joins nothing.
	for _, bad := range []struct {
		method string
		arity  int
	}{
		{"jwt::Token::parse_unverified", 1},
		{"jwt::legacy::Token::signed", 2},
		{"jwt::SigningAlgorithm::sign", 3},
	} {
		if len(kb.ContractsFor(bad.method, bad.arity)) != 0 {
			t.Errorf("spelling %s#%d resolves and must not", bad.method, bad.arity)
		}
	}
}

// TestJwtNoContractDeclaresWhen pins that no jwt entry uses a conditional
// contract. Nothing in this crate's API selects behavior on an argument
// literal, so a `when:` appearing here would be a copied block rather than a
// modeled one.
func TestJwtNoContractDeclaresWhen(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			switch c.SourceLibrary {
			case "jwt", "jwt-store", "jwt-legacy", "jwt-legacy-root":
				if c.When != nil {
					t.Errorf("%s#%d declares a `when:` condition", c.Method, c.Arity)
				}
			}
		}
	}
}

// TestJwtLegacyVerifyReturnsBareBool pins the one entry whose two return fields
// are NOT a Result wrapping a value. `Token::verify` returns a plain `bool`
// (0.5.0 lib.rs:88, 0.9.0 legacy/mod.rs:63) — it swallows every error into
// `false` — while every other operation here returns a `Result`. An edit that
// "normalises" this family's returns by wrapping them all fails here.
func TestJwtLegacyVerifyReturnsBareBool(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []string{"jwt::Token.verify", "jwt::legacy::Token.verify"} {
		cs := kb.ContractsFor(m, 2)
		if len(cs) != 1 {
			t.Fatalf("%s#2: got %d contracts, want 1", m, len(cs))
		}
		if cs[0].Return.Type != "bool" || cs[0].CanonicalReturnType != "bool" {
			t.Errorf("%s#2 returns %q/%q, want bool/bool",
				m, cs[0].Return.Type, cs[0].CanonicalReturnType)
		}
	}
}

// TestJwtUndeclaredTraitPathKeyShape pins a gap so that a future change making
// it resolve is a signal to update the note rather than a silent behavior
// change. `SignWithKey<T>` and `VerifyWithKey<T>` are generic in the RETURN
// type and blanket-implemented over the caller's own claims type, so
// `jwt::SignWithKey.sign_with_key#2` and `jwt::VerifyWithKey.verify_with_key#2`
// — both really emitted by the exported graph for the trait-path spelling the
// crate's own examples write — are deliberately NOT declared. There is no
// return type to state that would not be an invention.
func TestJwtUndeclaredTraitPathKeyShape(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []string{
		"jwt::SignWithKey.sign_with_key",
		"jwt::VerifyWithKey.verify_with_key",
	} {
		if len(kb.ContractsFor(m, 2)) != 0 {
			t.Errorf("%s#2 now resolves; update the note in jwt.yaml", m)
		}
	}
}
