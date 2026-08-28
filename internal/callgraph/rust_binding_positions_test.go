// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// The Rust Reference puts every local binding in the VALUE namespace: `let`,
// `if let`, `while let`, `for`, `match` arms, function parameters and closure
// parameters. The parser used to type only `let`, and only by string-splitting
// its text, so a receiver bound in any other position was keyed by its own
// variable name.
//
// `if let Ok(cipher) = Aes256Gcm::new_from_slice(k)` is the fallible-constructor
// idiom RustCrypto's own documentation teaches, which is why these positions
// matter more than their rarity in a synthetic corpus suggests.
func TestRustParser_EveryBindingPositionCarriesItsType(t *testing.T) {
	t.Parallel()

	const header = `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

fn mk() -> Aes128 { Aes128::new(&Default::default()) }
fn mk_result() -> Result<Aes128, ()> { Ok(mk()) }
fn mk_option() -> Option<Aes128> { Some(mk()) }
fn mk_vec() -> Vec<Aes128> { vec![mk()] }
fn mk_pair() -> (Aes128, u8) { (mk(), 0) }
enum Algo { Aes(Aes128), None }
struct Named { cipher: Aes128 }
`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"if let with a fallible constructor", `if let Ok(c) = mk_result() { c.encrypt_block(b); }`},
		{"if let on an Option", `if let Some(c) = mk_option() { c.encrypt_block(b); }`},
		{"while let", `let mut it = mk_vec().into_iter(); while let Some(c) = it.next() { c.encrypt_block(b); }`},
		{"let else", `let Ok(c) = mk_result() else { return; }; c.encrypt_block(b);`},
		{"match arm on an enum variant", `match Algo::Aes(mk()) { Algo::Aes(c) => c.encrypt_block(b), Algo::None => {} }`},
		{"for loop over a collection", `for c in mk_vec() { c.encrypt_block(b); }`},
		{"closure parameter from an iterator", `mk_vec().iter().for_each(|c| c.encrypt_block(b));`},
		{"tuple pattern", `let (c, _n) = mk_pair(); c.encrypt_block(b);`},
		{"struct pattern shorthand", `let Named { cipher } = Named { cipher: mk() }; cipher.encrypt_block(b);`},
		{"mut binding", `let mut c = mk(); c.encrypt_block(b);`},
		{"shadowed binding takes the later type", `let c = 1u8; let _ = c; let c = mk(); c.encrypt_block(b);`},
		{"annotated binding beats inference", `let c: Aes128 = mk(); c.encrypt_block(b);`},
		{"parameter with a declared type", `run(&mk(), b);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := header + `
fn run(c: &Aes128, b: &mut [u8]) { c.encrypt_block(b); }

fn go(b: &mut [u8]) {
    ` + tc.body + `
}
`
			got := parseRustCalleeFQNs(t, src)
			asserted := 0
			for raw, key := range got {
				if !strings.HasSuffix(raw, "encrypt_block") {
					continue
				}
				asserted++
				if key != "aes.Aes128.encrypt_block" {
					t.Errorf("%s resolved to %q, want %q", raw, key, "aes.Aes128.encrypt_block")
				}
			}
			if asserted == 0 {
				t.Errorf("no encrypt_block call parsed; got %v", got)
			}
		})
	}
}

// A `match` arm wraps its pattern in a `match_pattern` node, which also carries
// the optional `if` guard. Missing that wrapper left every match-arm binding
// untyped, and the guard form is the one that hides it.
func TestRustParser_MatchArmGuardStillBinds(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

fn mk() -> Option<Aes128> { Some(Aes128::new(&Default::default())) }

fn go(b: &mut [u8], ready: bool) {
    match mk() {
        Some(c) if ready => c.encrypt_block(b),
        _ => {}
    }
}
`)
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("guarded match arm resolved to %q, want %q", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
}
