// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A receiver often arrives from a declaration rather than from a constructor:
// a struct field, an enum variant's payload, a helper's return type, a tuple
// struct's positional field. None of those were read at all — `field_declaration`
// never appeared in the walker — so `self.cipher.encrypt_block(..)`, one of the
// most common shapes in real crypto code, produced a callee with no type.
func TestRustParser_DeclaredTypesResolveReceivers(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

fn mk() -> Aes128 { Aes128::new(&Default::default()) }

struct Holder { cipher: Aes128 }
struct Wrap(Aes128);
enum Algo { Aes(Aes128) }

impl Holder {
    fn from_field(&self, b: &mut [u8]) { self.cipher.encrypt_block(b); }
    fn from_self_helper(&self, b: &mut [u8]) { let c = Self::build(); c.encrypt_block(b); }
    fn build() -> Aes128 { mk() }
}

fn from_tuple_struct(b: &mut [u8]) {
    let w = Wrap(mk());
    w.0.encrypt_block(b);
}

fn from_enum_payload(b: &mut [u8]) {
    if let Algo::Aes(c) = Algo::Aes(mk()) { c.encrypt_block(b); }
}

fn from_helper_return(b: &mut [u8]) {
    let c = mk();
    c.encrypt_block(b);
}

fn from_indexed_collection(v: &[Aes128], b: &mut [u8]) {
    v[0].encrypt_block(b);
}
`)
	for _, raw := range []string{
		"self.cipher.encrypt_block",
		"c.encrypt_block",
		"w.0.encrypt_block",
		"v[0].encrypt_block",
	} {
		if got[raw] != "aes.Aes128.encrypt_block" {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], "aes.Aes128.encrypt_block")
		}
	}
}

// A type alias chain is the documented idiom for the block-mode crates, and it
// has to be followed all the way to the identity a contract keys on. A single
// hop left the intermediate alias as the identity; a bare target
// (`type A2 = A1;`, both sides a type_identifier) was dropped entirely.
func TestRustParser_TypeAliasChainsResolveTransitively(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

type Level1 = Aes128;
type Level2 = Level1;
type Level3 = Level2;

fn go(b: &mut [u8]) {
    let c = Level3::new(&Default::default());
    c.encrypt_block(b);
}
`)
	if got["Level3::new"] != "aes.Aes128.new" {
		t.Errorf("Level3::new resolved to %q, want %q", got["Level3::new"], "aes.Aes128.new")
	}
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("c.encrypt_block resolved to %q, want %q", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
}

// An alias to something with no nameable path has no identity to forward to.
// aes 0.8.4 declares `type State = [u64; 8];`, and recording it put the array's
// text in the package field of every call written through the alias.
func TestRustParser_AliasToUnnameableTypeStaysLocal(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `type State = [u64; 8];

fn go() {
    let s = State::default();
    let _ = s;
}
`)
	if got["State::default"] != "app.State.default" {
		t.Errorf("State::default resolved to %q, want %q", got["State::default"], "app.State.default")
	}
}

// `impl Trait for Type` exposes the target and the trait as two separate
// grammar fields. Taking the first type-shaped child picked up the TRAIT, so
// every method of every trait impl — the dominant shape across the RustCrypto
// ecosystems — was declared under the trait's name, and every `self.x()` inside
// it was typed by the trait too.
func TestRustParser_TraitImplIsTypedByItsTargetNotItsTrait(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustTestFile(t, dir, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

pub trait Runner { fn run(&self, b: &mut [u8]); }

pub struct MyCipher { inner: Aes128 }

impl Runner for MyCipher {
    fn run(&self, b: &mut [u8]) { self.inner.encrypt_block(b); }
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			id := analysis.Functions[i].ID
			declared[id.Package+"."+id.Type+"."+id.Name] = true
		}
	}
	if !declared["app.MyCipher.run"] {
		t.Errorf("trait impl method not declared as app.MyCipher.run; got %v", keysOfBool(declared))
	}
	if declared["app.Runner.run"] {
		t.Error("trait impl method declared under the TRAIT name app.Runner.run; the impl target owns it")
	}
}
