// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A receiver's type used to be inferred by cutting up the SOURCE TEXT of the
// `let` that bound it: split at the first ".", then at the first "(", then at
// the last "::". That reads correctly for `let c = Type::new(..)` and produces a
// wrong-but-valid key for every other way a value can reach a receiver. Measured
// against a 70-case binding x spelling x routing matrix, 11 of 70 receivers
// carried the right identity and 8 of the 10 routings scored 0 of 7.
//
// Each case below is one routing, and each asserts the EXACT key. The failure
// they guard against is not a missing key: it is `app.(c).encrypt_block`, the
// receiver variable's own name sitting in the type field, which looks exactly
// like a resolved identity and joins to no contract.
func TestRustParser_ReceiverTypeSurvivesEveryValueRouting(t *testing.T) {
	t.Parallel()

	const header = `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

fn mk() -> Aes128 { Aes128::new(&Default::default()) }
async fn mk_async() -> Aes128 { mk() }
fn mk_result() -> Result<Aes128, ()> { Ok(mk()) }
struct Holder { cipher: Aes128 }
`

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "direct let",
			body: `let c = mk(); c.encrypt_block(b);`,
		},
		{
			name: "question mark on a Result",
			body: `let c = mk_result()?; c.encrypt_block(b);`,
		},
		{
			name: "awaited",
			body: `let c = mk_async().await; c.encrypt_block(b);`,
		},
		{
			name: "block tail",
			body: `let c = { mk() }; c.encrypt_block(b);`,
		},
		{
			name: "unsafe block tail",
			body: `let c = unsafe { mk() }; c.encrypt_block(b);`,
		},
		{
			name: "reference then deref",
			body: `let c = mk(); let r = &c; (*r).encrypt_block(b);`,
		},
		{
			name: "double reference",
			body: `let c = mk(); let r = &c; let rr = &r; rr.encrypt_block(b);`,
		},
		{
			name: "struct field",
			body: `let h = Holder { cipher: mk() }; h.cipher.encrypt_block(b);`,
		},
		{
			name: "method on a temporary",
			body: `mk().encrypt_block(b);`,
		},
		{
			// Only the `then` branch resolves, so this case pins the
			// consequence field on its own. With both branches producing the
			// same type, breaking either one still passed through the other.
			name: "if expression consequence",
			body: `let c = if true { mk() } else { panic!() }; c.encrypt_block(b);`,
		},
		{
			// The mirror: only the `else` branch resolves, pinning the
			// alternative field.
			name: "if expression alternative",
			body: `let c = if true { panic!() } else { mk() }; c.encrypt_block(b);`,
		},
		{
			name: "match expression arm",
			body: `let c = match 1 { _ => mk() }; c.encrypt_block(b);`,
		},
		{
			// `vec![..]` holds raw tokens rather than expressions, so the
			// element type comes from reading the macro's own name and its
			// token tree.
			name: "vec macro element",
			body: `let v = vec![mk()]; v[0].encrypt_block(b);`,
		},
		{
			name: "vec macro through an iterator closure",
			body: `let v = vec![mk()]; v.iter().for_each(|c| c.encrypt_block(b));`,
		},
		{
			name: "cast",
			body: `let c = mk() as Aes128; c.encrypt_block(b);`,
		},
		{
			name: "parenthesized",
			body: `let c = (mk()); c.encrypt_block(b);`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCalleeFQNs(t, header+"\nasync fn go(b: &mut [u8]) -> Result<(), ()> {\n    "+tc.body+"\n    Ok(())\n}\n")
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
				t.Errorf("no encrypt_block call was parsed at all; got %v", got)
			}
		})
	}
}

// The value routings that cannot be resolved must produce an UNTYPED callee,
// never the receiver variable's name in the type field. This is the invariant
// that keeps "unresolved" distinguishable from "resolved", which is what makes
// coverage measurable at all.
func TestRustParser_UnresolvedReceiverIsUntypedNotNamed(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use helper::compute;

fn go(a: u32) {
    let x = compute(a);
    x.finish();
    let closure = || 1u8;
    let y = closure();
    y.finish();
}
`)
	for raw, key := range got {
		switch raw {
		case "x.finish", "y.finish":
			if key != "app.finish" {
				t.Errorf("%s resolved to %q, want the untyped %q — a receiver whose type is unknown must not be keyed by its own variable name", raw, key, "app.finish")
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("no calls parsed")
	}
}
