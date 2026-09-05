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

// otpauth (pkg:cargo/otpauth, messense/otpauth-rs) computes HOTP and TOTP codes
// over a hard-coded HMAC-SHA1. Its KB is keyed on what the Rust parser emits, so
// a parser identity change must fail here rather than leaving the contracts
// silently unmatched.
//
// FOUR FILES, FOUR RANGES, AND THE SPLIT IS THE POINT. `version_range` is
// declared per library and a file may only claim versions for which EVERY entry
// is true, so the family is split by the windows in which its identifiers
// actually compile:
//
//	otpauth.yaml              >=0.2.0,<0.6.0  crate-root HOTP/TOTP core API
//	otpauth-0.1.yaml          >=0.1.0,<0.2.0  the pre-rename `OtpAuth` type
//	otpauth-0.2-modules.yaml  >=0.2.0,<0.4.0  the PUBLIC `hotp`/`totp` modules
//	otpauth-0.4.1.yaml        >=0.4.1,<0.6.0  from_base32/from_bytes/base32_secret
//
// Two things here are easy to get wrong and both are pinned below. The module
// spelling `otpauth::hotp::HOTP.generate` is a DIFFERENT key from the crate-root
// `otpauth::HOTP.generate`, so both must exist or a 0.2.x-0.3.x consumer
// resolves nothing. And the combination `otpauth::hotp::HOTP::from_base32` is
// not compilable Rust in ANY published release -- the modules go private at
// 0.4.0 and `from_base32` arrives at 0.4.1 -- so it must NOT be declared.
const otpauthProbe = `use otpauth::HOTP;
use otpauth::TOTP;

fn hotp_flow() -> bool {
    let auth = HOTP::new("python");
    let code = auth.generate(4);
    let _uri = auth.to_uri("alice", "example.com", 4);
    auth.verify(code, 0, 100)
}

fn hotp_from_base32() -> u32 {
    let maybe = HOTP::from_base32("OB4XI2DPNY");
    let auth = maybe.unwrap();
    auth.generate(1)
}

fn hotp_from_bytes() -> u32 {
    let auth = otpauth::HOTP::from_bytes(b"python");
    let _b32 = auth.base32_secret();
    auth.generate(2)
}

fn totp_flow(ts: u64) -> bool {
    let auth = TOTP::new("python");
    let code = auth.generate(30, ts);
    let _uri = auth.to_uri("alice", "example.com");
    auth.verify(code, 30, ts)
}

fn totp_from_base32(ts: u64) -> u32 {
    let maybe = TOTP::from_base32("OB4XI2DPNY");
    let auth = maybe.unwrap();
    auth.generate(30, ts)
}

fn totp_from_bytes(ts: u64) -> u32 {
    let auth = otpauth::TOTP::from_bytes(b"python");
    let _b32 = auth.base32_secret();
    auth.generate(30, ts)
}

// 0.2.0-0.3.0 only: the modules are public there and private from 0.4.0.
//
// The constructor and the methods are exercised through DIFFERENT spellings on
// purpose. "let h = otpauth::hotp::HOTP::new(..)" types h as the crate-root
// otpauth::HOTP, which is correct -- it is the same type -- so every method
// called on it afterwards emits the crate-root key. The module-qualified METHOD
// keys are reached only when the receiver type is written out, which is what a
// struct field or a declared parameter does.
fn module_construct() -> u32 {
    let h = otpauth::hotp::HOTP::new("python");
    let t = otpauth::totp::TOTP::new("python");
    h.generate(1) + t.generate(30, 100)
}

fn module_methods(h: &otpauth::hotp::HOTP, t: &otpauth::totp::TOTP) -> bool {
    let a = h.generate(1);
    let b = t.generate(30, 100);
    let _hu = h.to_uri("alice", "example.com", 1);
    let _tu = t.to_uri("alice", "example.com");
    h.verify(a, 0, 10) && t.verify(b, 30, 100)
}

// 0.1.0 only: one type that does both protocols.
fn legacy(ts: usize) -> bool {
    let auth = otpauth::OtpAuth::new("python");
    let c = auth.hotp(4);
    let t = auth.totp(30, ts);
    auth.valid_hotp(c, 0, 100) && auth.valid_totp(t, 30, ts)
}

fn main() {
    println!("{} {} {} {} {} {} {} {}",
        hotp_flow(), hotp_from_base32(), hotp_from_bytes(), totp_flow(1),
        totp_from_base32(1), totp_from_bytes(1), module_construct(), legacy(1));
}
`

func TestOtpauthContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(otpauthProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// FOUR FIELDS PER IDENTITY. `role` and `ret` are the semantic pair the
	// resolver reads; `params` and `canon` are what the EXPORT reads --
	// the served canonical signature is built from ParameterTypes and
	// CanonicalReturnType and never consults `return.type` -- so a contract
	// that omits them renders `name(?)` however correct its semantics are.
	//
	// This table is written from the crate's own source at 0.1.0, 0.2.0, 0.3.0
	// and 0.5.1, not generated from the YAML under test.
	type want struct {
		role   string
		ret    string
		params []string
		canon  string
	}
	noParams := []string{}
	wants := map[string]want{
		"otpauth.HOTP.new":           {"factory", "otpauth::HOTP", []string{"S"}, "otpauth::HOTP"},
		"otpauth.HOTP.from_base32":   {"factory", "core::option::Option", []string{"S"}, "core::option::Option<otpauth::HOTP>"},
		"otpauth.HOTP.from_bytes":    {"factory", "otpauth::HOTP", []string{"&[u8]"}, "otpauth::HOTP"},
		"otpauth.HOTP.generate":      {"operation", "u32", []string{"u64"}, "u32"},
		"otpauth.HOTP.verify":        {"operation", "bool", []string{"u32", "u64", "u64"}, "bool"},
		"otpauth.HOTP.to_uri":        {"output", "alloc::string::String", []string{"S", "S", "u64"}, "alloc::string::String"},
		"otpauth.HOTP.base32_secret": {"output", "alloc::string::String", noParams, "alloc::string::String"},

		"otpauth.TOTP.new":           {"factory", "otpauth::TOTP", []string{"S"}, "otpauth::TOTP"},
		"otpauth.TOTP.from_base32":   {"factory", "core::option::Option", []string{"S"}, "core::option::Option<otpauth::TOTP>"},
		"otpauth.TOTP.from_bytes":    {"factory", "otpauth::TOTP", []string{"&[u8]"}, "otpauth::TOTP"},
		"otpauth.TOTP.generate":      {"operation", "u32", []string{"u64", "u64"}, "u32"},
		"otpauth.TOTP.verify":        {"operation", "bool", []string{"u32", "u64", "u64"}, "bool"},
		"otpauth.TOTP.to_uri":        {"output", "alloc::string::String", []string{"S", "S"}, "alloc::string::String"},
		"otpauth.TOTP.base32_secret": {"output", "alloc::string::String", noParams, "alloc::string::String"},

		"otpauth::hotp.HOTP.new":      {"factory", "otpauth::HOTP", []string{"S"}, "otpauth::HOTP"},
		"otpauth::hotp.HOTP.generate": {"operation", "u32", []string{"u64"}, "u32"},
		"otpauth::hotp.HOTP.verify":   {"operation", "bool", []string{"u32", "u64", "u64"}, "bool"},
		"otpauth::hotp.HOTP.to_uri":   {"output", "alloc::string::String", []string{"S", "S", "u64"}, "alloc::string::String"},
		"otpauth::totp.TOTP.new":      {"factory", "otpauth::TOTP", []string{"S"}, "otpauth::TOTP"},
		"otpauth::totp.TOTP.generate": {"operation", "u32", []string{"u64", "u64"}, "u32"},
		"otpauth::totp.TOTP.verify":   {"operation", "bool", []string{"u32", "u64", "u64"}, "bool"},
		"otpauth::totp.TOTP.to_uri":   {"output", "alloc::string::String", []string{"S", "S"}, "alloc::string::String"},

		"otpauth.OtpAuth.new":        {"factory", "otpauth::OtpAuth", []string{"&str"}, "otpauth::OtpAuth"},
		"otpauth.OtpAuth.hotp":       {"operation", "u32", []string{"usize"}, "u32"},
		"otpauth.OtpAuth.totp":       {"operation", "u32", []string{"usize", "usize"}, "u32"},
		"otpauth.OtpAuth.valid_hotp": {"operation", "bool", []string{"u32", "usize", "usize"}, "bool"},
		"otpauth.OtpAuth.valid_totp": {"operation", "bool", []string{"u32", "usize", "usize"}, "bool"},
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				w, ok := wants[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				c := got[0]
				if !strings.HasPrefix(c.SourceLibrary, "otpauth") {
					t.Fatalf("contract for %q resolved to library %q", method, c.SourceLibrary)
				}
				if c.Role != w.role {
					t.Fatalf("contract for %q has role %q, want %q", method, c.Role, w.role)
				}
				if c.Return.Type != w.ret {
					t.Fatalf("contract for %q returns %q, want %q", method, c.Return.Type, w.ret)
				}
				if c.CanonicalReturnType != w.canon {
					t.Fatalf("contract for %q has canonical_return_type %q, want %q",
						method, c.CanonicalReturnType, w.canon)
				}
				if !slices.Equal(c.ParameterTypes, w.params) {
					t.Fatalf("contract for %q has parameter_types %q, want %q",
						method, c.ParameterTypes, w.params)
				}
				seen[method] = true
			}
		}
	}

	for method := range wants {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// THE EXACT SET, not a per-key lookup. A per-key assertion cannot see an entry
// that should not be there, an entry that was dropped, or a field corrupted in
// a way no probe call reaches. Rendering every loaded otpauth contract as
// `method#arity/role/return/canonical/params/confidence/parameters` and
// comparing the whole thing against a literal can see all three -- and the last
// two fields matter because `canonical_return_type` is what the export renders
// and a renamed contributed property loads cleanly through the schema's
// presence checks.
func TestOtpauthContractSetsAreExactlyThis(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for library, want := range map[string][]string{
		// otpauth.yaml — every entry true from 0.2.0 through 0.5.1.
		"otpauth": {
			"otpauth::HOTP.generate#1/operation/u32/u32/[u64]/high/[]",
			"otpauth::HOTP.new#1/factory/otpauth::HOTP/otpauth::HOTP/[S]/high/[]",
			"otpauth::HOTP.to_uri#3/output/alloc::string::String/alloc::string::String/[S, S, u64]/high/[]",
			"otpauth::HOTP.verify#3/operation/bool/bool/[u32, u64, u64]/high/[]",
			"otpauth::TOTP.generate#2/operation/u32/u32/[u64, u64]/high/[]",
			"otpauth::TOTP.new#1/factory/otpauth::TOTP/otpauth::TOTP/[S]/high/[]",
			"otpauth::TOTP.to_uri#2/output/alloc::string::String/alloc::string::String/[S, S]/high/[]",
			"otpauth::TOTP.verify#3/operation/bool/bool/[u32, u64, u64]/high/[]",
		},
		// otpauth-0.1.yaml — the pre-rename type, true for 0.1.0 alone.
		"otpauth-0.1": {
			"otpauth::OtpAuth.hotp#1/operation/u32/u32/[usize]/high/[]",
			"otpauth::OtpAuth.new#1/factory/otpauth::OtpAuth/otpauth::OtpAuth/[&str]/high/[]",
			"otpauth::OtpAuth.totp#2/operation/u32/u32/[usize, usize]/high/[]",
			"otpauth::OtpAuth.valid_hotp#3/operation/bool/bool/[u32, usize, usize]/high/[]",
			"otpauth::OtpAuth.valid_totp#3/operation/bool/bool/[u32, usize, usize]/high/[]",
		},
		// otpauth-0.2-modules.yaml — the public module spelling, 0.2.0-0.3.0.
		// from_base32/from_bytes/base32_secret are ABSENT on purpose: they
		// arrive at 0.4.1, by which point the modules are already private.
		"otpauth-0.2-modules": {
			"otpauth::hotp::HOTP.generate#1/operation/u32/u32/[u64]/high/[]",
			"otpauth::hotp::HOTP.new#1/factory/otpauth::HOTP/otpauth::HOTP/[S]/high/[]",
			"otpauth::hotp::HOTP.to_uri#3/output/alloc::string::String/alloc::string::String/[S, S, u64]/high/[]",
			"otpauth::hotp::HOTP.verify#3/operation/bool/bool/[u32, u64, u64]/high/[]",
			"otpauth::totp::TOTP.generate#2/operation/u32/u32/[u64, u64]/high/[]",
			"otpauth::totp::TOTP.new#1/factory/otpauth::TOTP/otpauth::TOTP/[S]/high/[]",
			"otpauth::totp::TOTP.to_uri#2/output/alloc::string::String/alloc::string::String/[S, S]/high/[]",
			"otpauth::totp::TOTP.verify#3/operation/bool/bool/[u32, u64, u64]/high/[]",
		},
		// otpauth-0.4.1.yaml — the 0.4.1 additions.
		"otpauth-0.4.1": {
			"otpauth::HOTP.base32_secret#0/output/alloc::string::String/alloc::string::String/[]/high/[]",
			"otpauth::HOTP.from_base32#1/factory/core::option::Option/core::option::Option<otpauth::HOTP>/[S]/high/[]",
			"otpauth::HOTP.from_bytes#1/factory/otpauth::HOTP/otpauth::HOTP/[&[u8]]/high/[]",
			"otpauth::TOTP.base32_secret#0/output/alloc::string::String/alloc::string::String/[]/high/[]",
			"otpauth::TOTP.from_base32#1/factory/core::option::Option/core::option::Option<otpauth::TOTP>/[S]/high/[]",
			"otpauth::TOTP.from_bytes#1/factory/otpauth::TOTP/otpauth::TOTP/[&[u8]]/high/[]",
		},
	} {
		got := renderOtpauthContracts(kb, library)
		if !slices.Equal(got, want) {
			t.Errorf("%s contract set mismatch:\n got %v\nwant %v", library, got, want)
		}
	}
}

// `version_range` is parsed and NEVER consulted at lookup, so an over-claiming
// range is a silent false statement rather than a caught error, and a merged
// LoadEmbedded KB drops the per-library metadata entirely. This loads each file
// on its own and pins the fields -- which for this family is the whole reason
// there are four files instead of one.
func TestOtpauthVersionRangesAreDeclaredPerReachability(t *testing.T) {
	t.Parallel()

	for file, want := range map[string]struct{ library, versions string }{
		"rust/otpauth.yaml":             {"otpauth", ">=0.2.0,<0.6.0"},
		"rust/otpauth-0.1.yaml":         {"otpauth-0.1", ">=0.1.0,<0.2.0"},
		"rust/otpauth-0.2-modules.yaml": {"otpauth-0.2-modules", ">=0.2.0,<0.4.0"},
		"rust/otpauth-0.4.1.yaml":       {"otpauth-0.4.1", ">=0.4.1,<0.6.0"},
	} {
		data, err := os.ReadFile(filepath.Join("contracts", file))
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", file, err)
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Fatalf("Load(%q): %v", file, err)
		}
		if kb.Library == nil {
			t.Fatalf("%s: no library metadata", file)
		}
		if kb.Library.Name != want.library {
			t.Errorf("%s: library %q, want %q", file, kb.Library.Name, want.library)
		}
		if kb.Library.VersionRange != want.versions {
			t.Errorf("%s: version_range %q, want %q", file, kb.Library.VersionRange, want.versions)
		}
		// All four files describe the SAME crate, so all four must carry the
		// same coordinate or three of them attribute to nothing.
		if got := strings.Join(kb.Library.Coordinates, ","); got != "otpauth" {
			t.Errorf("%s: coordinates = %q, want otpauth", file, got)
		}
	}
}

// The module spelling is a DISTINCT KEY, not an alias. A consumer on 0.2.0-0.3.0
// writing `otpauth::hotp::HOTP::new(..)` emits `otpauth::hotp.HOTP.new`, which
// the crate-root entry does not answer. Dropping either file would leave one
// spelling resolving nothing while every other test still passed.
func TestOtpauthModuleSpellingIsItsOwnKey(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, key := range []string{"otpauth::HOTP.new", "otpauth.HOTP.new"} {
		got := kb.ContractsFor(key, 1)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 1) = %d, want 1", key, len(got))
		}
		if got[0].SourceLibrary != "otpauth" {
			t.Errorf("%s resolved to %q, want otpauth", key, got[0].SourceLibrary)
		}
	}
	for _, key := range []string{"otpauth::hotp::HOTP.new", "otpauth::hotp.HOTP.new"} {
		got := kb.ContractsFor(key, 1)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 1) = %d, want 1", key, len(got))
		}
		if got[0].SourceLibrary != "otpauth-0.2-modules" {
			t.Errorf("%s resolved to %q, want otpauth-0.2-modules", key, got[0].SourceLibrary)
		}
	}
}

// A COMBINATION THAT NEVER COMPILED MUST NOT BE DECLARED. The `hotp` and `totp`
// modules are public only through 0.3.0 and `from_base32` / `from_bytes` /
// `base32_secret` arrive at 0.4.1, so the module-qualified spellings of those
// three methods are not compilable Rust in any published release. A contract for
// them would load without error and describe an API that does not exist, which
// is the shape a sibling family shipped and only a reviewer caught.
func TestOtpauthDeclaresNoModuleQualified041Methods(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, key := range []string{
		"otpauth::hotp::HOTP.from_base32",
		"otpauth::hotp::HOTP.from_bytes",
		"otpauth::totp::TOTP.from_base32",
		"otpauth::totp::TOTP.from_bytes",
	} {
		if got := kb.ContractsFor(key, 1); len(got) != 0 {
			t.Errorf("%s resolved (%d contracts); that combination never compiled", key, len(got))
		}
	}
	for _, key := range []string{
		"otpauth::hotp::HOTP.base32_secret",
		"otpauth::totp::TOTP.base32_secret",
	} {
		if got := kb.ContractsFor(key, 0); len(got) != 0 {
			t.Errorf("%s resolved (%d contracts); that combination never compiled", key, len(got))
		}
	}
}

// Arity separates HOTP from TOTP at every shared method name, and it is the ONLY
// thing that does: `HOTP::generate(counter)` is one argument, `TOTP::generate(
// period, timestamp)` is two, and the rules rely on exactly that. This pins the
// over-match direction the exact-set test cannot: a neighboring arity resolves
// to nothing.
func TestOtpauthArityIsLoadBearing(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		method string
		good   int
		bad    []int
	}{
		{"otpauth.HOTP.generate", 1, []int{0, 2}},
		{"otpauth.TOTP.generate", 2, []int{1, 3}},
		{"otpauth.HOTP.verify", 3, []int{2, 4}},
		{"otpauth.HOTP.to_uri", 3, []int{2}},
		{"otpauth.TOTP.to_uri", 2, []int{3}},
		{"otpauth.OtpAuth.totp", 2, []int{1, 3}},
	} {
		if got := kb.ContractsFor(tc.method, tc.good); len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want 1", tc.method, tc.good, len(got))
		}
		for _, arity := range tc.bad {
			if got := kb.ContractsFor(tc.method, arity); len(got) != 0 {
				t.Errorf("ContractsFor(%q, %d) = %d, want 0", tc.method, arity, len(got))
			}
		}
	}
}

// Renders one library's whole contract set, including the two fields
// `renderLibraryContracts` omits: `canonical_return_type`, which is what the
// export actually renders, and the `parameters` block, whose contributed
// property name loads cleanly through the schema's presence checks and would
// otherwise be invisible to an exact-set comparison.
func renderOtpauthContracts(kb *contracts.KnowledgeBase, library string) []string {
	var out []string
	for key, list := range kb.Contracts {
		method := strings.SplitN(key, "#", 2)[0]
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != library {
				continue
			}
			var params []string
			for _, p := range c.Parameters {
				idx := "-"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contributes := "-"
				if p.Contributes != nil {
					contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
				}
				params = append(params, fmt.Sprintf("%s|%s|%s|%s", idx, p.Name, p.Role, contributes))
			}
			out = append(out, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/[%s]",
				method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ", "), c.Return.Confidence,
				strings.Join(params, " ")))
		}
	}
	sort.Strings(out)
	return out
}
