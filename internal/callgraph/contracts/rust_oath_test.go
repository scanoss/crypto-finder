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

// oath (avacariu/rust-oath) implements HOTP, TOTP and OCRA. It exports no type
// with a method -- its only exported type is the bare `HashType` enum -- so
// EVERY entry point is a CRATE-ROOT FREE FUNCTION and every emitted key carries
// a single dot. rustAuthoredKey (contracts.go:267) moves the second-to-last dot
// to "::" only when a key has at least two dots and returns a shorter key
// unchanged, so for this family the authored key IS the emitted key.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does. It renders the
// `parameters:` block as well as method/arity/role/return/params/confidence,
// because a renamed contributed property loads cleanly through the schema's
// presence checks and would otherwise pass unnoticed while still feeding the
// served payload.
//
// IT ALSO RENDERS `Varargs`, WHICH THE REST OF THIS DIRECTORY DOES NOT. A
// `varargs: true` mutation on `oath.hotp_raw` was measured to SURVIVE an
// otherwise-exact render, and the field is live: `contracts.go` lets an
// arity-tolerant chain collapse a call onto a lower-arity contract only when
// that contract is explicitly marked varargs, so a stray `true` here would
// silently accept a 4-argument call as `hotp_raw#3`. No rust family in this
// directory renders it today; this one does.
//
// The family is spread over FOUR files with four ranges, so the render matches
// on the four library names rather than on one.
var oathLibraries = map[string]bool{
	"oath":          true,
	"oath-0.1":      true,
	"oath-0.10":     true,
	"oath-from-hex": true,
}

func renderOathParameters(c *contracts.Contract) string {
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

func renderOathContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !oathLibraries[c.SourceLibrary] {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/%s/%s/va=%v",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				c.SourceLibrary, renderOathParameters(c), c.Varargs))
		}
	}
	sort.Strings(got)
	return got
}

var wantOathContracts = []string{
	"oath.from_hex#1/output/core::result::Result<alloc::vec::Vec<u8>, &str>/core::result::Result<alloc::vec::Vec<u8>, &str>/[&str]/high/oath-from-hex/-/va=false",
	"oath.hotp#3/operation/core::result::Result<u64, &str>/core::result::Result<u64, &str>/[&str,u64,u32]/high/oath/2=digits/metadata-contributing/outputLength:argument_value/va=false",
	"oath.hotp_custom#4/operation/u64/u64/[&[u8],u64,u32,D]/high/oath-0.1/2=digits/metadata-contributing/outputLength:argument_value;3=hash/metadata-contributing/algorithm:argument_type/va=false",
	"oath.hotp_raw#3/operation/u64/u64/[&[u8],u64,u32]/high/oath/2=digits/metadata-contributing/outputLength:argument_value/va=false",
	"oath.ocra#7/operation/core::result::Result<u64, ()>/core::result::Result<u64, ()>/[&str,&[u8],u64,&str,&[u8],&[u8],u64]/high/oath-0.10/0=suite/metadata-contributing/parameterSet:argument_value/va=false",
	"oath.ocra_debug#7/operation/core::result::Result<u64, alloc::string::String>/core::result::Result<u64, alloc::string::String>/[&str,&[u8],u64,&str,&[u8],&[u8],u64]/high/oath-0.10/0=suite/metadata-contributing/parameterSet:argument_value/va=false",
	"oath.totp#4/operation/core::result::Result<u64, &str>/core::result::Result<u64, &str>/[&str,u32,u64,u64]/high/oath-0.1/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value/va=false",
	"oath.totp_custom#5/operation/u64/u64/[&[u8],u32,u64,u64,u64]/high/oath-0.10/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value/va=false",
	"oath.totp_custom#6/operation/u64/u64/[&[u8],u32,u64,u64,u64,D]/high/oath-0.1/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value;5=hash/metadata-contributing/algorithm:argument_type/va=false",
	"oath.totp_custom_time#6/operation/core::result::Result<u64, &str>/core::result::Result<u64, &str>/[&str,u32,u64,u64,u64,&oath::HashType]/high/oath-0.10/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value;5=hash/metadata-contributing/algorithm:argument_value/va=false",
	"oath.totp_now#5/operation/core::result::Result<u64, &str>/core::result::Result<u64, &str>/[&str,u32,u64,u64,&oath::HashType]/high/oath-0.10/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value;4=hash/metadata-contributing/algorithm:argument_value/va=false",
	"oath.totp_raw#4/operation/u64/u64/[&[u8],u32,u64,u64]/high/oath-0.1/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value/va=false",
	"oath.totp_raw_custom_time#6/operation/u64/u64/[&[u8],u32,u64,u64,u64,&oath::HashType]/high/oath-0.10/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value;5=hash/metadata-contributing/algorithm:argument_value/va=false",
	"oath.totp_raw_now#5/operation/u64/u64/[&[u8],u32,u64,u64,&oath::HashType]/high/oath-0.10/1=digits/metadata-contributing/outputLength:argument_value;3=time_step/metadata-contributing/interval:argument_value;4=hash/metadata-contributing/algorithm:argument_value/va=false",
}

func TestLoadEmbeddedRustOathContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderOathContracts(t)
	want := append([]string(nil), wantOathContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("oath contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected oath contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing oath contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that -- not the authored spelling -- is what the parser looks up. Every key
// below was read off an exported call graph of two probe consumers, one on the
// 0.10 API and one on the 0.1 API, before this contract existed; each came back
// as `oath.<fn>(?, ?, ...)` with empty parameter types, which is what an absent
// contract looks like.
func TestOathEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := []struct {
		method string
		arity  int
	}{
		{"oath.hotp", 3},
		{"oath.hotp_raw", 3},
		{"oath.hotp_custom", 4},
		{"oath.totp", 4},
		{"oath.totp_raw", 4},
		{"oath.totp_custom", 5},
		{"oath.totp_custom", 6},
		{"oath.totp_raw_now", 5},
		{"oath.totp_now", 5},
		{"oath.totp_raw_custom_time", 6},
		{"oath.totp_custom_time", 6},
		{"oath.ocra", 7},
		{"oath.ocra_debug", 7},
		{"oath.from_hex", 1},
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
		if !oathLibraries[got[0].SourceLibrary] {
			t.Errorf("%s: library = %q, want an oath file", e.method, got[0].SourceLibrary)
		}
		if len(got[0].ParameterTypes) != e.arity {
			t.Errorf("%s#%d: %d parameter_types, want %d -- an entry whose declared "+
				"parameters do not match its arity renders a signature the parser "+
				"cannot fill", e.method, e.arity, len(got[0].ParameterTypes), e.arity)
		}
	}
}

// A "::" SPELLING MUST NOT RESOLVE. This is the assertion that would have caught
// the mechanical application of the Rust key substitution: rustAuthoredKey moves
// the second-to-last dot only when the key has at least two dots, and these keys
// have one, so the "::" form is not an alias and must be absent.
func TestOathDoubleColonSpellingDoesNotResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"oath::hotp", 3},
		{"oath::hotp_raw", 3},
		{"oath::totp_raw", 4},
		{"oath::totp_raw_now", 5},
		{"oath::ocra", 7},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved to %d contracts; a crate-root free "+
				"function is keyed with a dot and this spelling must not exist",
				tc.method, tc.arity, len(got))
		}
	}
}

// THE TWO API ERAS ARE KEYED APART BY ARITY, and they must resolve to different
// files, because the ranges those files declare are disjoint. `totp_custom` is
// the only identifier that survives the 0.1 -> 0.10 break, and its shape changes
// with it: arity 6 with the digest as a VALUE argument before, arity 5 with the
// digest as a turbofish TYPE parameter after. Folding either into the other's
// file would silently over-claim a range.
func TestOathErasResolveToTheirOwnFile(t *testing.T) {
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
		{"oath.hotp_raw", 3, "oath"},
		{"oath.hotp", 3, "oath"},
		{"oath.totp_custom", 6, "oath-0.1"},
		{"oath.totp_raw", 4, "oath-0.1"},
		{"oath.totp_custom", 5, "oath-0.10"},
		{"oath.ocra", 7, "oath-0.10"},
		{"oath.from_hex", 1, "oath-from-hex"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d): got %d contracts, want 1", tc.method, tc.arity, len(got))
		}
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s#%d: library = %q, want %q", tc.method, tc.arity, got[0].SourceLibrary, tc.library)
		}
	}
}

// THE LEGACY DIGEST IS DERIVED FROM THE ARGUMENT'S TYPE, THE 0.10 ONE FROM ITS
// VALUE, and mixing them up is a silent wrong reading rather than a load error.
// In 0.0.3-0.1.4 the call site writes `Sha1::new()`, a constructed value whose
// TYPE names the digest; in 0.10.x it writes `&HashType::SHA256`, an enum
// variant whose VALUE names it. `totp_custom` at arity 5 declares no hash
// parameter at all, because there the digest is a type parameter and not an
// argument.
func TestOathDigestDerivationsMatchHowTheDigestIsPassed(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	hashDerivation := func(method string, arity int) (string, bool) {
		got := kb.ContractsFor(method, arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d): got %d contracts, want 1", method, arity, len(got))
		}
		for _, p := range got[0].Parameters {
			if p.Name == "hash" && p.Contributes != nil {
				return p.Contributes.Derivation, true
			}
		}
		return "", false
	}

	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		{"oath.hotp_custom", 4, "argument_type"},
		{"oath.totp_custom", 6, "argument_type"},
		{"oath.totp_raw_now", 5, "argument_value"},
		{"oath.totp_now", 5, "argument_value"},
		{"oath.totp_raw_custom_time", 6, "argument_value"},
		{"oath.totp_custom_time", 6, "argument_value"},
	} {
		got, ok := hashDerivation(tc.method, tc.arity)
		if !ok {
			t.Errorf("%s#%d declares no contributing `hash` parameter", tc.method, tc.arity)
			continue
		}
		if got != tc.want {
			t.Errorf("%s#%d: hash derivation = %q, want %q", tc.method, tc.arity, got, tc.want)
		}
	}

	if _, ok := hashDerivation("oath.totp_custom", 5); ok {
		t.Error("oath.totp_custom#5 declares a contributing `hash` parameter, but at " +
			"that arity the digest is a TYPE PARAMETER and not an argument")
	}
	if _, ok := hashDerivation("oath.hotp_raw", 3); ok {
		t.Error("oath.hotp_raw#3 declares a contributing `hash` parameter, but it " +
			"hardcodes SHA-1 in every published version and takes no hash argument")
	}
}

// NO ENTRY CONTRIBUTES `keyMaterial`, AND THAT IS THE FAMILY'S DELIBERATE
// CHOICE RATHER THAN AN OVERSIGHT. The Go OTP contract (go/gotp.yaml) declares
// the shared secret as `keyMaterial` with `argument_value`, which reads the
// argument's value into the served payload. Every oath entry point takes the
// secret as its first argument, and at a great many real call sites -- the
// crate's own tests, its README, and two of the three matched consumers -- that
// argument is a byte-string LITERAL. Contributing it would publish the secret.
func TestOathContributesNoKeyMaterial(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !oathLibraries[c.SourceLibrary] {
				continue
			}
			for _, p := range c.Parameters {
				if p.Contributes == nil {
					continue
				}
				if p.Contributes.Property == "keyMaterial" || p.Contributes.Property == "secret" {
					t.Errorf("%s#%d parameter %d (%s) contributes %q; the secret must "+
						"not be lifted into the served payload",
						c.Method, c.Arity, p.Index, p.Name, p.Contributes.Property)
				}
			}
		}
	}
}

// THE FOUR FILES DECLARE THEIR OWN ERA.
//
// BE CLEAR ABOUT WHAT THIS TEST IS, in the terms rust_biscuit_test.go sets: a
// tripwire, not a guard. It compares the YAML to a constant in this file, so
// editing both together passes and a wrong bound passes from the start. The
// bounds here were verified by enumerating `pub fn` in `src/` for ALL EIGHT
// published archives (0.0.3, 0.1.0-0.1.4, 0.10.1, 0.10.2): `hotp` and
// `hotp_raw` present in all eight; `hotp_custom`, `totp` and `totp_raw` present
// in the first six and absent from both 0.10 releases; `totp_raw_now`,
// `totp_now`, `totp_raw_custom_time`, `totp_custom_time`, `ocra` and
// `ocra_debug` present only in the two 0.10 releases; `from_hex` absent from
// 0.0.3, 0.1.0 and 0.1.1 and present from 0.1.2 on. This only stops them
// drifting unnoticed.
func TestOathFilesDeclareTheirOwnEra(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ file, name, wantRange, wantDesc string }{
		{
			"rust/oath.yaml", "oath", ">=0.0.3,<0.11.0",
			"HOTP over HMAC-SHA1 in the oath crate (avacariu/rust-oath), the two entry points every published version shares",
		},
		{
			"rust/oath-0.1.yaml", "oath-0.1", ">=0.0.3,<0.2.0",
			"oath's pre-0.10 TOTP surface and its caller-supplied-digest entry points, split out so oath.yaml's range stays true",
		},
		{
			"rust/oath-0.10.yaml", "oath-0.10", ">=0.10.1,<0.11.0",
			"oath 0.10's TOTP entry points with an explicit HashType selector, and its OCRA implementation",
		},
		{
			"rust/oath-from-hex.yaml", "oath-from-hex", ">=0.1.2,<0.11.0",
			"oath's hex-decoding helper, typed so a consumer's call to it carries a declared signature",
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
		if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != "oath" {
			t.Errorf("%s: coordinates = %v, want exactly [oath] -- the crate name and "+
				"the callgraph key spelling are the same here, so there is no second "+
				"form to declare", tc.file, kb.Library.Coordinates)
		}
		// Compared EXACTLY, not merely for non-emptiness. A corrupted
		// description is parsed and never consulted, so nothing else in this
		// package would notice it; 5.5 names description alongside
		// version_range, coordinates and name for that reason.
		if kb.Library.Description != tc.wantDesc {
			t.Errorf("%s: library.description = %q, want %q",
				tc.file, kb.Library.Description, tc.wantDesc)
		}
	}
}
