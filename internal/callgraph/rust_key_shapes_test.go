// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A glob names the module it points at, and no key may put source text where a
// resolved package or type belongs. Each case names the wrong key it prevents
// and the crate and version it came from.
// The fixture spells a plain `mod tests` rather than `#[cfg(test)] mod tests`
// on purpose: a default scan skips a cfg(test) module, and what this test
// exercises is name resolution inside a nested module, not file selection.
// The cfg gate has its own tests in rust_cfg_test_modules_test.go.
func TestRustParser_KeyShapesCarryOnlyResolvedNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		importPath string
		files      map[string]string
		want       []string
		absent     []string
	}{
		{
			// openssl 0.10.81 src/rsa.rs: `Rsa` comes out of the
			// `foreign_type_and_impl_send_sync!` macro, so no declared-type fact
			// records it; `mod test` at :592 writes `use super::*;`. 33 edges came
			// out as `openssl::rsa::test.(Rsa).*` — a test module named as the
			// owner of a public type — and `openssl::rsa::Rsa.generate`, which
			// openssl.yaml keys, matched nothing. Same shape in boring 4.9.1
			// src/rsa.rs, ~20 edges. No macro is expanded here: the fix is that a
			// `use super::*` glob names the PARENT module.
			name:       "a `use super::*` glob names the parent module",
			importPath: "openssl",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"openssl\"\nversion = \"0.10.81\"\nedition = \"2021\"\n\n[dependencies]\nopenssl-sys = \"0.9\"\n",
				"src/lib.rs": "pub mod rsa;\n",
				// `Rsa` is deliberately NOT declared: the macro that would declare
				// it is out of scope, exactly as in the real crate.
				"src/rsa.rs": `pub fn build() {}

mod test {
    use super::*;

    #[test]
    fn generate_key() {
        let k = Rsa::generate(2048).unwrap();
        k.public_key_to_pem_pkcs1().unwrap();
    }
}
`,
			},
			want: []string{
				"openssl::rsa.(Rsa).generate",
				"openssl::rsa.(Rsa).public_key_to_pem_pkcs1",
			},
			absent: []string{
				"openssl::rsa::test.(Rsa).generate",
				"openssl::rsa::test.(Rsa).public_key_to_pem_pkcs1",
			},
		},
		{
			// sequoia-openpgp 1.21.2 src/packet/unknown.rs:209 writes
			// `Self::Error::InvalidOperation(..)` under `type Error = crate::Error;`.
			// `Self::Error` is an ASSOCIATED TYPE, so the middle segment is not
			// statically known — and the key put the concrete type's name in the
			// PACKAGE field.
			name:       "`Self::AssocType::item` puts no type name in the package field",
			importPath: "sequoia-openpgp",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"sequoia-openpgp\"\nversion = \"1.21.2\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub enum Error { InvalidOperation(String) }
pub struct Packet;
pub struct Unknown;

impl std::convert::TryFrom<Packet> for Unknown {
    type Error = crate::Error;

    fn try_from(_p: Packet) -> std::result::Result<Self, Self::Error> {
        Err(Self::Error::InvalidOperation("no".to_string()))
    }
}
`,
			},
			want:   []string{"sequoia-openpgp.InvalidOperation"},
			absent: []string{"Unknown.(Error).InvalidOperation"},
		},
		{
			// openssl 0.10.81 and boring 4.9.1 src/stack.rs write
			// `T::Ref::from_ptr(..)` where `T` is a generic parameter and `Ref` an
			// associated type. ecdsa 0.16.9 src/der.rs:279 writes
			// `C::FieldBytesSize::USIZE.saturating_sub(..)`, the same shape reached
			// as a value rather than a call.
			name:       "an associated item on a generic parameter has no identity",
			importPath: "openssl",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"openssl\"\nversion = \"0.10.81\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub trait ForeignType { type Ref; }

pub fn borrow<T: ForeignType>(p: *mut u8) {
    let _ = T::Ref::from_ptr(p);
}

pub trait Curve { type FieldBytesSize; }

pub fn sizes<C: Curve>(n: usize) -> usize {
    C::FieldBytesSize::USIZE.saturating_sub(n)
}
`,
			},
			want: []string{"openssl.from_ptr", "openssl.saturating_sub"},
			absent: []string{
				"T.(Ref).from_ptr",
				"C.(FieldBytesSize).saturating_sub",
			},
		},
		{
			// dryoc 0.6.2 src/dryocstream.rs:364 annotates
			// `let (mut push_stream, header): (_, Header) = ..`, and the inferred-type
			// placeholder was distributed to the binding and reached the key's type
			// field. 14 edges across dryoc, curve25519-dalek, sequoia-openpgp and rsa.
			name:       "the `_` inferred-type placeholder is not a type",
			importPath: "dryoc",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"dryoc\"\nversion = \"0.6.2\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub struct Header;
pub struct Stream;

impl Stream {
    pub fn init_push() -> (Stream, Header) { (Stream, Header) }
    pub fn push(&mut self, m: &[u8]) -> usize { m.len() }
}

pub fn go(m: &[u8]) {
    let (mut push_stream, _header): (_, Header) = Stream::init_push();
    let _ = push_stream.push(m);
}
`,
			},
			want:   []string{"dryoc.push"},
			absent: []string{"dryoc.(_).push"},
		},
		{
			// rsa 0.9.6 src/pkcs1v15.rs:697 and src/pss.rs:568,587. The crate
			// declares `-> signature::Result<Signature>` in
			// src/pkcs1v15/signing_key.rs, and that file also writes
			// `use crate::{.., Result, ..}`. rustQualifyFactType looked for a path
			// THROUGH the wrapper — `signature::Result<Signature>` unwraps to
			// `Signature`, whose head is bare — so the bare-name branch fired and
			// rewrote `Result` inside the outer path, giving
			// `signature::rsa::Result<Signature>`: a crate name concatenated with a
			// foreign module. The 18 sibling `signature.(Result).*` edges are
			// correct and must survive.
			name:       "a qualified outer name is not re-qualified through its wrapper",
			importPath: "rsa",
			files: map[string]string{
				"Cargo.toml":      "[package]\nname = \"rsa\"\nversion = \"0.9.6\"\nedition = \"2021\"\n\n[dependencies]\nsignature = \"2\"\n",
				"src/lib.rs":      "pub mod pkcs1v15;\npub type Result<T> = core::result::Result<T, ()>;\n",
				"src/pkcs1v15.rs": "pub mod signing_key;\npub use self::signing_key::SigningKey;\n",
				"src/pkcs1v15/signing_key.rs": `use crate::Result;
use signature::Signature;

pub struct SigningKey;

impl SigningKey {
    pub fn sign_prehash(&self, _p: &[u8]) -> signature::Result<Signature> {
        Err(())
    }
}

pub fn use_it(k: &SigningKey, p: &[u8]) {
    let _ = k.sign_prehash(p).expect("sign");
    let _: Result<u8> = Ok(0);
}
`,
			},
			want:   []string{"signature.(Result).expect"},
			absent: []string{"signature::rsa.(Result).expect"},
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
