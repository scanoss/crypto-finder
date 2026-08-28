// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// Each form below reached the callee key with something other than a module in
// its package field. They are all path spellings that appear in published
// crates, and each one silently cost a whole API surface.
func TestRustParser_PathSpellingsResolveToModules(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		src  string
		raw  string
		want string
	}{
		{
			// `use ring::digest::{self, SHA256};` binds the MODULE too. Dropping
			// it left a bare `digest` package — which is also the name of a
			// different crypto crate, so a ring hash was keyed against digest.
			// age 0.11.1 hits the same shape 63 times with `std::io::{self, ..}`.
			name: "self in a use list binds the module",
			src: `use ring::digest::{self, SHA256};

pub fn hash(data: &[u8]) -> digest::Digest { digest::digest(&SHA256, data) }
`,
			raw:  "digest::digest",
			want: "ring.digest.digest",
		},
		{
			// The edition-2018 disambiguator. chacha20poly1305 0.10.1 uses it.
			name: "leading double colon",
			src: `use ::cipher::StreamCipher;

pub fn run<C: StreamCipher>(c: &mut C, buf: &mut [u8]) { c.apply_keystream(buf); }
`,
			raw:  "c.apply_keystream",
			want: "cipher.StreamCipher.apply_keystream",
		},
		{
			// rustls 0.23.20 declares `type Test = super::LimitedCache<..>;`.
			name: "type alias to a relative path",
			src: `pub struct Cache;
impl Cache {
    pub fn new() -> Self { Cache }
    pub fn insert(&self) {}
}

pub mod tests {
    type Test = super::Cache;
    pub fn go() { let c = Test::new(); c.insert(); }
}
`,
			raw:  "Test::new",
			want: "app.Cache.new",
		},
		{
			// hkdf 0.12.4's `Hkdf::new` calls `Self::extract(..)`, which severed
			// the constructor-to-extract edge.
			name: "Self in an associated call",
			src: `pub struct Hkdf;
impl Hkdf {
    pub fn extract(ikm: &[u8]) -> Self { Hkdf }
    pub fn new(ikm: &[u8]) -> Self { Self::extract(ikm) }
}
`,
			raw:  "Self::extract",
			want: "app.Hkdf.extract",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCalleeFQNs(t, tc.src)
			if got[tc.raw] != tc.want {
				t.Errorf("%s resolved to %q, want %q", tc.raw, got[tc.raw], tc.want)
			}
			// No key may keep a relative path root or a leading separator.
			for raw, key := range got {
				for _, bad := range []string{"::", "crate.", "self.", "super.", "Self."} {
					if strings.HasPrefix(key, bad) {
						t.Errorf("key for %q starts with %q: %q", raw, bad, key)
					}
				}
			}
		})
	}
}

// rustls re-exports a whole crate under a local name in one file and reaches it
// from its sibling files: `pub(crate) use ring as ring_like;` in
// src/crypto/ring/mod.rs, then `use super::ring_like::aead;` in
// src/crypto/ring/tls12.rs. That is its entire ring-backed AEAD, ECDSA and
// CSPRNG surface — 147 call edges that named a module of rustls instead of ring.
//
// The alias belongs to the DIRECTORY, not to the crate: rustls declares
// `ring_like` twice, once per backend, so a crate-wide table has to call it
// ambiguous and drop both.
func TestRustParser_CrateReExportAliasResolvesFromSiblingFiles(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod strong;\npub mod weak;\n",
		// Two backend directories, each re-exporting a DIFFERENT crate under the
		// same local alias — the shape that makes a crate-wide table useless.
		"src/strong/mod.rs": `pub(crate) use aes as backend;
pub mod work;
`,
		"src/strong/work.rs": `use super::backend::cipher::{BlockEncrypt, KeyInit};
use super::backend::Aes128;

pub fn go(b: &mut [u8]) {
    let c = Aes128::new(&Default::default());
    c.encrypt_block(b.into());
}
`,
		"src/weak/mod.rs": `pub(crate) use des as backend;
pub mod work;
`,
		"src/weak/work.rs": `use super::backend::cipher::{BlockEncrypt, KeyInit};
use super::backend::Des;

pub fn go(b: &mut [u8]) {
    let c = Des::new(&Default::default());
    c.encrypt_block(b.into());
}
`,
	}, "app")

	// Both spellings resolve, and the two directories are not confused.
	if got["Aes128::new"] != "aes.Aes128.new" {
		t.Errorf("Aes128::new resolved to %q, want %q", got["Aes128::new"], "aes.Aes128.new")
	}
	if got["Des::new"] != "des.Des.new" {
		t.Errorf("Des::new resolved to %q, want %q", got["Des::new"], "des.Des.new")
	}
	// No key reached through the alias may name a module of the analyzed crate.
	for raw, key := range got {
		if raw == "Aes128::new" || raw == "Des::new" || raw == "c.encrypt_block" {
			if strings.HasPrefix(key, "app") {
				t.Errorf("key for %q kept a local module path through the alias: %q", raw, key)
			}
		}
	}
}

// An imported MODULE keeps its own segment in the package field. Resolution
// dropped it whenever the parent path already contained "::", which lost
// rustls's own `crypto::hmac` module in five files and would have lost
// `ring::aead::quic` the same way. A TYPE, by contrast, IS the leaf: its package
// is the path that imported it.
func TestRustParser_ImportedModuleKeepsItsSegment(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use ring::aead::quic;
use ring::aead::LessSafeKey;
use crate::crypto;

pub fn go() {
    let h = quic::HeaderProtectionKey::new();
    h.new_mask();
    let k = LessSafeKey::new();
    k.seal_in_place_separate_tag();
    let t = crypto::hmac::Tag::new();
    t.as_ref();
}
`)
	for raw, want := range map[string]string{
		// A module two levels down keeps both segments.
		"quic::HeaderProtectionKey::new": "ring::aead::quic.HeaderProtectionKey.new",
		"h.new_mask":                     "ring::aead::quic.HeaderProtectionKey.new_mask",
		// A type's package is the path that imported it, with no extra segment.
		"LessSafeKey::new": "ring::aead.LessSafeKey.new",
		// A module path rooted at an imported module keeps every segment.
		"crypto::hmac::Tag::new": "app::crypto::hmac.Tag.new",
		"t.as_ref":               "app::crypto::hmac.Tag.as_ref",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
}

// A module the crate declares shadows the extern prelude even when the manifest
// renames a dependency to that same name. The rename was substituted first, so a
// crate with a local `mod codec` AND `[dependencies.codec] package = "des"`
// reported its own type against the DES crate — a weak-cipher finding for a
// library the code does not call.
func TestRustParser_LocalModuleBeatsAManifestRename(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
aes = "0.8"

[dependencies.codec]
package = "des"
version = "0.8"
`,
		"src/lib.rs": `mod codec {
    pub struct Des { pub id: u8 }
    impl Des {
        pub fn new(id: u8) -> Self { Des { id } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
}

pub fn go() {
    let framer = codec::Des::new(4);
    framer.encrypt_block(&mut []);
}
`,
	}, "app")

	for raw, want := range map[string]string{
		"codec::Des::new":      "app::codec.Des.new",
		"framer.encrypt_block": "app::codec.Des.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — a local module shadows the renamed dependency", raw, got[raw], want)
		}
	}
}
