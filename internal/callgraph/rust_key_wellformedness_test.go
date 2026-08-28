// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"regexp"
	"strings"
	"testing"
)

// rustKeyTextLeak matches characters that can only have come from SOURCE TEXT
// rather than from a resolved name: braces, brackets, angle brackets, sigils,
// quotes, whitespace.
var rustKeyTextLeak = regexp.MustCompile(`[{}\[\]<>&*"'\s]`)

// The parser used to build identities by cutting up source text, and the text it
// could not cut cleanly ended up INSIDE the emitted key: `probe_pkg.({ Aes128).
// encrypt_block` from a block tail, `openssl.([u8]).len` from a slice receiver,
// `<Aes128 as KeyInit>.new` from a qualified path, `*mut ffi.(X509V3_CTX).cast`
// from a pointer type. Those keys look like data and join to nothing.
//
// This is a property test over a deliberately hostile snippet: whatever the
// parser makes of it, no key may contain source punctuation, and no key may be
// missing its package.
func TestRustParser_EmittedKeysAreWellFormed(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use std::sync::Arc;

type State = [u64; 8];

struct Ctx { buf: Vec<u8>, cipher: Aes128 }

enum Kind { Fast, Slow(Aes128) }

async fn build() -> Result<Aes128, ()> { Ok(Aes128::new(&Default::default())) }

async fn go(ctx: &mut Ctx, raw: &[u8], ptr: *mut u8) -> Result<(), ()> {
    let _ = raw.len();
    let _ = raw.as_ptr();
    let _ = State::default();
    let _ = <Aes128 as KeyInit>::new(&Default::default());
    let _ = <[u64; 8]>::default();
    let c = { build().await? };
    c.encrypt_block(ctx.buf.as_mut_slice().into());
    ctx.cipher.encrypt_block(ctx.buf.as_mut_slice().into());
    let boxed = Arc::new(build().await?);
    boxed.encrypt_block(ctx.buf.as_mut_slice().into());
    let k = Kind::Slow(build().await?);
    if let Kind::Slow(inner) = k { inner.encrypt_block(ctx.buf.as_mut_slice().into()); }
    let _ = unsafe { ptr.offset(1) };
    Ok(())
}
`)
	if len(got) == 0 {
		t.Fatal("no calls parsed at all")
	}
	for raw, key := range got {
		if rustKeyTextLeak.MatchString(key) {
			t.Errorf("key for %q leaked source text: %q", raw, key)
		}
		if strings.HasPrefix(key, ".") || key == "" {
			t.Errorf("key for %q has no package: %q", raw, key)
		}
		for _, root := range []string{"crate.", "self.", "super.", "Self."} {
			if strings.HasPrefix(key, root) {
				t.Errorf("key for %q kept an unresolved path root: %q", raw, key)
			}
		}
		// The spec forbids a leading or trailing `::` outright. The leak regex
		// above carries no `:`, so `::cipher.StreamCipher.apply_keystream` —
		// the edition-2018 disambiguator surviving an alias import — passed
		// every check here while being exactly the shape this test exists to
		// forbid.
		if strings.HasPrefix(key, "::") {
			t.Errorf("key for %q kept a leading separator: %q", raw, key)
		}
		if strings.HasSuffix(key, "::") || strings.Contains(key, "::::") {
			t.Errorf("key for %q has a malformed separator: %q", raw, key)
		}
	}
}

// The edition-2018 `::` disambiguator is written on purpose to say "the CRATE
// cipher, not a local item of that name". Every spelling of it must resolve to
// the same identity: `use ::cipher::X;`, the list form, the alias form and the
// glob form all reached the package field by different routes, and three of
// the four read the node's raw text.
func TestRustParser_LeadingSeparatorNeverReachesAKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
	}{
		{
			name: "plain",
			src: `use ::cipher::StreamCipher;
fn go(c: &mut StreamCipher, b: &mut [u8]) { c.apply_keystream(b); }`,
		},
		{
			name: "use list",
			src: `use ::cipher::{StreamCipher};
fn go(c: &mut StreamCipher, b: &mut [u8]) { c.apply_keystream(b); }`,
		},
		{
			name: "renaming import",
			src: `use ::cipher::StreamCipher as SC;
fn go(c: &mut SC, b: &mut [u8]) { c.apply_keystream(b); }`,
		},
		// No glob case: a glob may not claim a name without crate-wide
		// visibility, so in a manifest-less fixture it correctly resolves to
		// nothing and the assertion would pass vacuously. The wildcard route
		// reads the same node text as the three above and is fixed with them;
		// TestRustParser_GlobDoesNotClaimNamesWithoutCrateVisibility covers
		// the claim rule itself.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			joined := strings.Join(parseRustCalleeKeys(t, tc.src), "\n")
			if strings.Contains(joined, "::cipher.") {
				t.Errorf("the leading separator reached a key; got:\n%s", joined)
			}
			if !strings.Contains(joined, "cipher.StreamCipher.apply_keystream") {
				t.Errorf("want cipher.StreamCipher.apply_keystream; got:\n%s", joined)
			}
		})
	}
}

// An ownership wrapper must never be the identity in a key's type field: it is
// the thing the receiver is wrapped IN, not what the call is on.
func TestRustParser_WrapperNeverAppearsAsTheReceiverType(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use std::sync::{Arc, Mutex};

fn mk() -> Aes128 { Aes128::new(&Default::default()) }

fn go(b: &mut [u8]) {
    let a = Arc::new(Mutex::new(mk()));
    a.lock().unwrap().encrypt_block(b);
    let o = Some(mk());
    o.unwrap().encrypt_block(b);
}
`)
	for raw, key := range got {
		if !strings.HasSuffix(raw, "encrypt_block") {
			continue
		}
		for _, wrapper := range []string{".Arc.", ".Mutex.", ".Option.", ".Box.", ".Rc.", ".RefCell."} {
			if strings.Contains(key, wrapper) {
				t.Errorf("key for %q named the wrapper instead of the receiver: %q", raw, key)
			}
		}
	}
}

// The pinned grammar cannot parse a turbofish in a parameter's TYPE position:
// rustc accepts `fn f(dec: cbc::Decryptor::<Aes128>, buf: &mut [u8])`, and the
// grammar recovers with an ERROR node that merges the two parameters, so a
// structural read assigns the SECOND parameter's type to the FIRST one. Where
// the grammar gives no structure, parameter binding falls back to splitting the
// list's text — gated on the error, so it never runs on well-formed code.
func TestRustParser_ParameterTurbofishSurvivesGrammarErrorRecovery(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `fn parameterized(dec: cbc::Decryptor::<Aes128>, buf: &mut [u8]) {
    dec.decrypt_padded_mut(buf);
}
`)
	if got["dec.decrypt_padded_mut"] != "cbc.Decryptor.decrypt_padded_mut" {
		t.Errorf("dec.decrypt_padded_mut resolved to %q, want %q", got["dec.decrypt_padded_mut"], "cbc.Decryptor.decrypt_padded_mut")
	}
}

// A generic parameter is not a type. The Reference resolves a method on it
// through the trait BOUNDS on it, so a bounded parameter carries the bound's
// identity and an unbounded one carries none — emitting `C` itself invents a
// type that exists nowhere.
func TestRustParser_GenericReceiverResolvesThroughItsBound(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;

fn bounded<C: BlockEncrypt>(c: &C, b: &mut [u8]) { c.encrypt_block(b); }

fn via_where<C>(c: &C, b: &mut [u8]) where C: BlockEncrypt { c.wheresig(b); }

fn multi_bound<C: KeyInit + BlockEncrypt>(c: &C, b: &mut [u8]) { c.multibound(b); }

fn lifetime_first<'a, C: BlockEncrypt>(c: &'a C, b: &mut [u8]) { c.lifetimed(b); }

fn unbounded<T>(t: &T) { t.anything(); }

struct Holder<C>(C);
impl<C: BlockEncrypt> Holder<C> {
    fn go(&self, b: &mut [u8]) { self.0.through_impl(b); }
}
`)
	const bound = "aes::cipher.BlockEncrypt."
	for raw, want := range map[string]string{
		"c.encrypt_block":     bound + "encrypt_block",
		"c.wheresig":          bound + "wheresig",
		"c.lifetimed":         bound + "lifetimed",
		"self.0.through_impl": bound + "through_impl",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
	// A parameter with several bounds resolves through the FIRST one, which is
	// the one the language looks up first.
	if got["c.multibound"] != "aes::cipher.KeyInit.multibound" {
		t.Errorf("multi-bound generic resolved to %q, want %q", got["c.multibound"], "aes::cipher.KeyInit.multibound")
	}
	if got["t.anything"] != "app.anything" {
		t.Errorf("unbounded generic receiver resolved to %q, want the untyped %q", got["t.anything"], "app.anything")
	}
}
