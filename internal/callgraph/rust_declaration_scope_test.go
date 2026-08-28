// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A file's declared-type facts were module-blind and had no conflict rule: a
// function return type was kept under its bare name with first-declaration
// wins, and a struct field with last-declaration wins. Two modules in one file
// declaring the same name differently therefore answered for each other, so an
// AES call site emitted `des.Des.encrypt_block`.
//
// The crate-wide index already dropped such names; the file's own facts did not,
// and the file's own facts are consulted first. They are now keyed by the module
// that declares them, and looked up by the path the SOURCE wrote.

func TestRustParser_SameNamedDeclarationsInSiblingModulesStaySeparate(t *testing.T) {
	t.Parallel()

	// One fixture, validated with `cargo check`, covering each declaration kind
	// the facts table records. Every pair is the same name in two modules with
	// two different ciphers behind it.
	const src = `use aes::cipher::BlockEncrypt;

mod legacy {
    use aes::cipher::KeyInit;
    pub fn build() -> des::Des { des::Des::new(&Default::default()) }
    pub struct Session { pub cipher: des::Des }
    pub enum Algo { Primary(des::Des) }
    pub struct Holder;
    impl Holder { pub fn cipher(&self) -> des::Des { des::Des::new(&Default::default()) } }
}

mod modern {
    use aes::cipher::KeyInit;
    pub fn build() -> aes::Aes128 { aes::Aes128::new(&Default::default()) }
    pub struct Session { pub cipher: aes::Aes128 }
    pub enum Algo { Primary(aes::Aes128) }
    pub struct Holder;
    impl Holder { pub fn cipher(&self) -> aes::Aes128 { aes::Aes128::new(&Default::default()) } }
}

pub fn return_modern(b: &mut [u8; 16]) { let c = modern::build(); c.encrypt_block(b.into()); }
pub fn return_legacy(b: &mut [u8; 8])  { let c = legacy::build(); c.encrypt_block(b.into()); }
pub fn field_modern(s: &modern::Session, b: &mut [u8; 16]) { s.cipher.encrypt_block(b.into()); }
pub fn field_legacy(s: &legacy::Session, b: &mut [u8; 8])  { s.cipher.encrypt_block(b.into()); }
pub fn method_modern(b: &mut [u8; 16]) { let c = modern::Holder.cipher(); c.encrypt_block(b.into()); }
pub fn method_legacy(b: &mut [u8; 8])  { let c = legacy::Holder.cipher(); c.encrypt_block(b.into()); }
pub fn variant_modern(a: modern::Algo, b: &mut [u8; 16]) { match a { modern::Algo::Primary(c) => c.encrypt_block(b.into()) } }
pub fn variant_legacy(a: legacy::Algo, b: &mut [u8; 8])  { match a { legacy::Algo::Primary(c) => c.encrypt_block(b.into()) } }
`

	keys := countRustKeys(parseRustCalleeKeys(t, src))
	// Four AES call sites and four DES call sites, each resolved to its own.
	for _, want := range []struct {
		key   string
		count int
	}{
		{"aes.Aes128.encrypt_block", 4},
		{"des.Des.encrypt_block", 4},
	} {
		if keys[want.key] != want.count {
			t.Errorf("want %d x %q, got %d; keys = %v", want.count, want.key, keys[want.key], keys)
		}
	}
}

// A trait's method signature is the declared return type of every implementation
// reached through that trait. Recording it with no owning type let the bare
// method name pick up an unrelated inherent method's return type from elsewhere
// in the file, so a `dyn Backend` whose trait returns an AES cipher resolved to
// the DES-returning inherent method of another struct.
func TestRustParser_TraitSignatureReturnTypeIsOwnedByTheTrait(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::cipher::{BlockEncrypt, KeyInit};

pub struct LegacyBackend;
impl LegacyBackend {
    pub fn cipher(&self) -> des::Des { <des::Des as KeyInit>::new(&Default::default()) }
}

pub trait Backend {
    fn cipher(&self) -> aes::Aes128;
}

pub fn seal(backend: &dyn Backend, b: &mut [u8]) {
    let c = backend.cipher();
    c.encrypt_block(b.into());
}
`)
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("c.encrypt_block resolved to %q, want %q — the trait's own signature owns the return type", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
}
