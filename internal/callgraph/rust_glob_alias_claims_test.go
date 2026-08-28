// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Neither a glob nor an alias may claim a name it does not own. Each case names
// the wrong key it prevents and the crate and version it came from.
func TestRustParser_NoGlobOrAliasClaimsAForeignName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		importPath string
		files      map[string]string
		want       []string
		absent     []string
	}{
		{
			// orion 0.17.7 src/hazardous/hash/sha2/mod.rs:36 writes
			// `use core::ops::*;` inside `pub(crate) mod sha2_core`, whose
			// `W: Word` at :85/:128 is a generic parameter. 11 edges came out as
			// `core::ops.(W).from | .default | .size_of | .from_be_bytes`.
			name:       "a glob does not claim a generic type parameter",
			importPath: "globgen",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"globgen\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `use aes::*;

pub trait Maker { fn build() -> u32; }

pub fn run<T: Maker>() -> u32 { T::build() }

pub fn on_recv<W: Maker>(w: W) -> u32 { let _ = w; W::build() }
`,
			},
			// The bound is the identity a call on a parameter resolves through
			// (Reference, Paths -> generic parameters resolve through bounds).
			want: []string{"globgen.(Maker).build"},
			absent: []string{
				"aes.(T).build",
				"aes.(W).build",
			},
		},
		{
			// An unbounded parameter has no identity at all: no type, rather
			// than the glob's crate or the letter.
			name:       "an unbounded generic parameter carries no type",
			importPath: "globgen2",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"globgen2\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `use aes::*;

pub fn run<T>() -> u32 { T::build() }
`,
			},
			want: []string{"globgen2.build"},
			absent: []string{
				"aes.(T).build",
				"globgen2.(T).build",
			},
		},
		{
			// A `let` shadows an item of the same name for the rest of the block
			// (Reference, Names -> Scopes). Without that, a call to a local
			// closure was reported as `scrypt.scrypt`, one of scrypt.yaml's four
			// keys — key derivation attributed to a no-op.
			name:       "a local binding shadows a renaming import",
			importPath: "renshadow",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"renshadow\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nscrypt = \"0.11\"\n",
				"src/lib.rs": `use scrypt::{scrypt as scrypt_inner, Params};

pub fn shadowed(p: &[u8], s: &[u8], out: &mut [u8]) {
    let scrypt_inner = |_a: &[u8], _b: &[u8], _c: &mut [u8]| {};
    scrypt_inner(p, s, out);
}

pub fn real(p: &[u8], s: &[u8], out: &mut [u8]) {
    let params = Params::new(15, 8, 1, 32).unwrap();
    scrypt_inner(p, s, &params, out).unwrap();
}
`,
			},
			// The real call through the rename still resolves; only the shadowed
			// one is local.
			want:   []string{"renshadow.scrypt_inner", "scrypt.scrypt"},
			absent: []string{
				// scrypt.scrypt must be emitted ONCE, from `real` — the count
				// check below pins that.
			},
		},
		{
			// sequoia-openpgp 1.21.2 src/cert/revoke.rs:1344 (also
			// :1366,1380,1404,1418,1442,1456,1485) writes `use crate as openpgp;`.
			// `crate` is a keyword node, so the alias was dropped and 21 edges
			// kept the local spelling as their package. `openpgp` is a real
			// crates.io crate, so that is a WRONG identity, not a missing one.
			name:       "`use crate as <name>` names this crate",
			importPath: "sequoia-openpgp",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"sequoia-openpgp\"\nversion = \"1.21.2\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub mod packet {
    pub mod signature {
        pub struct SignatureBuilder;
        impl SignatureBuilder {
            pub fn new() -> SignatureBuilder { SignatureBuilder }
        }
    }
}

pub mod cert {
    use crate as openpgp;

    pub fn revoke() {
        let _b = openpgp::packet::signature::SignatureBuilder::new();
    }
}
`,
			},
			want:   []string{"sequoia-openpgp::packet::signature.(SignatureBuilder).new"},
			absent: []string{"openpgp::packet::signature.(SignatureBuilder).new"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCrateCalleeKeyCounts(t, tc.files, tc.importPath)
			for _, want := range tc.want {
				if got[want] == 0 {
					t.Errorf("missing %q; got %v", want, sortedKeyList(got))
				}
			}
			for _, bad := range tc.absent {
				if got[bad] != 0 {
					t.Errorf("emitted the wrong key %q (%d times); got %v", bad, got[bad], sortedKeyList(got))
				}
			}
		})
	}
}

// The shadowed call must not merely resolve elsewhere: `scrypt.scrypt` may be
// emitted exactly once, by the call that really goes through the rename.
func TestRustParser_ShadowedRenameIsEmittedOnlyForTheRealCall(t *testing.T) {
	t.Parallel()

	got := parseRustCrateCalleeKeyCounts(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"renshadow\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nscrypt = \"0.11\"\n",
		"src/lib.rs": `use scrypt::{scrypt as scrypt_inner, Params};

pub fn shadowed(p: &[u8], s: &[u8], out: &mut [u8]) {
    let scrypt_inner = |_a: &[u8], _b: &[u8], _c: &mut [u8]| {};
    scrypt_inner(p, s, out);
}

pub fn real(p: &[u8], s: &[u8], out: &mut [u8]) {
    let params = Params::new(15, 8, 1, 32).unwrap();
    scrypt_inner(p, s, &params, out).unwrap();
}
`,
	}, "renshadow")

	if got["scrypt.scrypt"] != 1 {
		t.Errorf("scrypt.scrypt emitted %d times, want 1 (only the call that goes through the rename); got %v",
			got["scrypt.scrypt"], sortedKeyList(got))
	}
	if got["renshadow.scrypt_inner"] != 1 {
		t.Errorf("the shadowed call resolved to %v, want one renshadow.scrypt_inner", sortedKeyList(got))
	}
}
