// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Rust bindings are lexically scoped, and a flat map per function is not a safe
// approximation of that. Two sibling blocks that both bind `c` collapsed into
// one entry, so whichever was recorded last won for the WHOLE function —
// including the calls that appear before it.
//
// That is the most damaging failure this parser can have. It does not lose a
// finding, it reports the wrong one: the AES block operation below came back as
// `des.Des.encrypt_block`, so a weak-cipher rule fired twice — once against code
// that uses AES — carrying the DES crate's package identity.
func TestRustParser_SiblingScopesDoNotLeakBindings(t *testing.T) {
	t.Parallel()

	keys := parseRustCalleeKeys(t, `use aes::Aes128;
use des::Des;
use aes::cipher::{BlockEncrypt, KeyInit};

pub fn go(b: &mut [u8]) {
    {
        let c = Aes128::new(&Default::default());
        c.encrypt_block(b.into());
    }
    {
        let c = Des::new(&Default::default());
        c.encrypt_block(b.into());
    }
}
`)
	// Both calls are written identically, so each identity has to be counted
	// rather than looked up by its call text.
	counts := countRustKeys(keys)
	for _, want := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if counts[want] != 1 {
			t.Errorf("want exactly one %q, got %d; keys = %v", want, counts[want], keys)
		}
	}
}

// The same leak in the other direction: a binding introduced inside a block must
// not be visible after it.
func TestRustParser_InnerBindingDoesNotEscapeItsBlock(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

pub fn go(b: &mut [u8], outer: &Des) {
    {
        let c = Aes128::new(&Default::default());
        c.encrypt_block(b.into());
    }
    outer.encrypt_block(b.into());
}
`)
	if got["outer.encrypt_block"] == "aes.Aes128.encrypt_block" {
		t.Error("a binding from an inner block leaked out and typed a later receiver as aes.Aes128")
	}
}

// A shadowing `let` sees the OUTER binding in its own initializer and shadows it
// only afterwards.
func TestRustParser_ShadowingLetSeesTheOuterBindingInItsInitializer(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use des::Des;
use aes::cipher::{BlockEncrypt, KeyInit};

fn rewrap(_c: &Aes128) -> Des { Des::new(&Default::default()) }

pub fn go(b: &mut [u8]) {
    let c = Aes128::new(&Default::default());
    let c = rewrap(&c);
    c.encrypt_block(b.into());
}
`)
	if got["c.encrypt_block"] != "des.Des.encrypt_block" {
		t.Errorf("after shadowing, c.encrypt_block resolved to %q, want %q", got["c.encrypt_block"], "des.Des.encrypt_block")
	}
}

// An `if let` binding belongs to the taken branch only, and the `else` branch
// must not see it.
func TestRustParser_IfLetBindingIsScopedToItsBranch(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use des::Des;
use aes::cipher::{BlockEncrypt, KeyInit};

fn maybe() -> Option<Aes128> { Some(Aes128::new(&Default::default())) }

pub fn go(b: &mut [u8], fallback: &Des) {
    if let Some(c) = maybe() {
        c.encrypt_block(b.into());
    } else {
        fallback.encrypt_block(b.into());
    }
}
`)
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("if-let binding resolved to %q, want %q", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
	if got["fallback.encrypt_block"] != "des.Des.encrypt_block" {
		t.Errorf("else branch resolved to %q, want %q", got["fallback.encrypt_block"], "des.Des.encrypt_block")
	}
}

// Each match arm binds in its own scope, so two arms binding the same name to
// different types stay distinct.
func TestRustParser_MatchArmsBindIndependently(t *testing.T) {
	t.Parallel()

	keys := parseRustCalleeKeys(t, `use aes::Aes128;
use des::Des;
use aes::cipher::{BlockEncrypt, KeyInit};

pub enum Algo { Fast(Aes128), Legacy(Des) }

pub fn go(a: Algo, b: &mut [u8]) {
    match a {
        Algo::Fast(c) => c.encrypt_block(b.into()),
        Algo::Legacy(c) => c.encrypt_block(b.into()),
    }
}
`)
	counts := countRustKeys(keys)
	for _, want := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if counts[want] != 1 {
			t.Errorf("want exactly one %q from independent match arms, got %d; keys = %v", want, counts[want], keys)
		}
	}
}
