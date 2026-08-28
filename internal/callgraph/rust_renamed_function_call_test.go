// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A bare call written through a renaming import resolves to the function it
// renames.
//
// The alias table was consulted when the local name was used as a path PREFIX
// (`kdf::inner()`) and not when it was CALLED (`kdf(..)`), so the whole point of
// the rename was lost and the call keyed a function that exists nowhere. It
// costs live contract keys, and it cost one on a real crate: age 0.11.1 and
// 0.12.1 write
//
//	use scrypt::{.., scrypt as scrypt_inner, ..};
//
// in src/primitives.rs and call `scrypt_inner(..)`, which came out as
// `age::primitives.scrypt_inner` instead of `scrypt.scrypt` — so age's scrypt
// key derivation matched no contract at all.
//
// Each case names the wrong key it prevents.
func TestRustParser_RenamedFunctionCallResolvesToItsTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		src    string
		want   map[string]int
		absent []string
	}{
		{
			// age 0.11.1 / 0.12.1, src/primitives.rs.
			name: "a renamed KDF call carries the crate that owns it",
			src: `use scrypt::{scrypt as scrypt_inner, Params as ScryptParams};
use pbkdf2::pbkdf2_hmac as kdf_hmac;

pub fn derive(pw: &[u8], salt: &[u8], out: &mut [u8]) {
    scrypt_inner(pw, salt, &ScryptParams::default(), out).unwrap();
    kdf_hmac::<Sha256>(pw, salt, 4096, out);
}
`,
			want: map[string]int{
				"scrypt.scrypt":      1,
				"pbkdf2.pbkdf2_hmac": 1,
			},
			absent: []string{"app.scrypt_inner", "app.kdf_hmac"},
		},
		{
			// boring 4.9.1 src/stack.rs renames its -sys FFI surface:
			// `use boring_sys::{sk_value as OPENSSL_sk_value, ..};`. Thirteen
			// calls named `boring::stack` rather than the crate that has them.
			name: "a renamed FFI call carries the -sys crate",
			src: `use boring_sys::{sk_value as OPENSSL_sk_value, sk_free as OPENSSL_sk_free};

pub fn walk(stack: *mut u8, i: usize) {
    OPENSSL_sk_value(stack, i);
    OPENSSL_sk_free(stack);
}
`,
			want: map[string]int{
				"boring_sys.sk_value": 1,
				"boring_sys.sk_free":  1,
			},
			absent: []string{"app.OPENSSL_sk_value", "app.OPENSSL_sk_free"},
		},
		{
			// The narrowness. A crate rename is a single identifier, and calling
			// one is not a function call; keying it as one would put a crate
			// where a function belongs.
			name: "a crate rename is not a renamed function",
			src: `use openssl_sys as ffi;

pub fn go() { ffi(); }
`,
			want:   map[string]int{"app.ffi": 1},
			absent: []string{"openssl_sys.", ".openssl_sys"},
		},
		{
			// An UpperCamelCase leaf is a TYPE. `Aes128CbcEnc(v)` is a tuple
			// struct's constructor, not a call to a function named
			// `cbc::Encryptor`, and the type routing already owns that shape.
			name: "a renamed type is not a renamed function",
			src: `use cbc::Encryptor as Enc;

pub fn go(v: u8) { let _e = Enc(v); }
`,
			absent: []string{"cbc.Encryptor"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := countRustKeys(parseRustCalleeKeys(t, tc.src))
			for key, count := range tc.want {
				if got[key] != count {
					t.Errorf("key %q emitted %d times, want %d; got %v", key, got[key], count, keysOfInt(got))
				}
			}
			for _, key := range tc.absent {
				if got[key] != 0 {
					t.Errorf("key %q emitted %d times; it names no function that exists", key, got[key])
				}
			}
		})
	}
}
