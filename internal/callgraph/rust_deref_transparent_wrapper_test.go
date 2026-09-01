// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A third-party wrapper the crate's OWN source proves transparent, by
// declaring a real `impl<T> Deref for Wrapper<T> { type Target = T; }`, is
// seen through the same way the hardcoded Box/Arc/Rc table already is. This
// is the shape crates like `secrecy` (`SecretBox<T>`) and `zeroize` use to
// hold key material behind an ergonomic accessor -- exactly where crypto
// identity matters most and no hardcoded list can anticipate every crate.
func TestRustParser_ThirdPartyDerefWrapperSeesThroughToTheWrappedValue(t *testing.T) {
	t.Parallel()

	src := `struct SecretBox<T> { inner: T }
impl<T> std::ops::Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.inner }
}
struct Aes128;
impl Aes128 { fn encrypt_block(&self) {} }
fn go() {
    let cipher: SecretBox<Aes128> = SecretBox { inner: Aes128 };
    cipher.encrypt_block();
}
`
	got := parseRustCalleeFQNs(t, src)
	if fqn := got["cipher.encrypt_block"]; fqn != "app.Aes128.encrypt_block" {
		t.Errorf("cipher.encrypt_block -> %q, want %q", fqn, "app.Aes128.encrypt_block")
	}
}

// A wrapper with more than one type parameter is not recorded transparent,
// even though it declares Deref: with several parameters in play, which one
// Target actually names is exactly the kind of guess a wrong identity comes
// from, so this is left unrecorded rather than assumed.
func TestRustParser_MultiParameterDerefWrapperIsNotRecordedTransparent(t *testing.T) {
	t.Parallel()

	src := `struct Pair<A, B> { a: A, b: B }
impl<A, B> std::ops::Deref for Pair<A, B> {
    type Target = A;
    fn deref(&self) -> &A { &self.a }
}
struct Aes128;
impl Aes128 { fn encrypt_block(&self) {} }
fn go() {
    let cipher: Pair<Aes128, u32> = Pair { a: Aes128, b: 0 };
    cipher.encrypt_block();
}
`
	got := parseRustCalleeFQNs(t, src)
	if fqn := got["cipher.encrypt_block"]; fqn == "app.Aes128.encrypt_block" {
		t.Errorf("cipher.encrypt_block resolved through an unproven multi-parameter wrapper; got %q", fqn)
	}
}

// The hardcoded wrapper table (Box, Arc, Rc, ...) is unaffected by the
// structural detection running alongside it in the same crate.
func TestRustParser_HardcodedAndThirdPartyDerefWrappersCoexist(t *testing.T) {
	t.Parallel()

	src := `struct SecretBox<T> { inner: T }
impl<T> std::ops::Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.inner }
}
struct Aes128;
impl Aes128 { fn encrypt_block(&self) {} }
fn go() {
    let boxed = Box::new(Aes128);
    boxed.encrypt_block();
    let secret: SecretBox<Aes128> = SecretBox { inner: Aes128 };
    secret.encrypt_block();
}
`
	got := parseRustCalleeFQNs(t, src)
	if fqn := got["boxed.encrypt_block"]; fqn != "app.Aes128.encrypt_block" {
		t.Errorf("boxed.encrypt_block -> %q, want %q", fqn, "app.Aes128.encrypt_block")
	}
	if fqn := got["secret.encrypt_block"]; fqn != "app.Aes128.encrypt_block" {
		t.Errorf("secret.encrypt_block -> %q, want %q", fqn, "app.Aes128.encrypt_block")
	}
}
