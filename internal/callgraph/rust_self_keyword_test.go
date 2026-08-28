// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// No key may carry the `Self` keyword, and a trait's default method is one
// declaration, not two. Each case names the wrong key it prevents and the crate
// and version it came from.
func TestRustParser_SelfKeywordNeverReachesAKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		importPath string
		files      map[string]string
		want       []string
		absent     []string
	}{
		{
			// rcgen 0.13.1 src/string_types.rs:442 `Ok(Self(vec.to_vec()))`
			// keyed a function literally named `Self`; orion 0.17.7
			// src/hazardous/hash/sha2/mod.rs:429,437,445 did the same.
			// 219 edges across 20 of 53 crates.
			name:       "`Self(..)` is the impl's own tuple-struct constructor",
			importPath: "rcgen",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"rcgen\"\nversion = \"0.13.1\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub struct Ia5String(String);

impl Ia5String {
    pub fn make(v: &str) -> Ia5String { Self(v.to_string()) }
}

// curve25519-dalek 4.1.3 src/backend/vector/packed_simd.rs:243 and rustls
// 0.23.20 src/msgs/codec.rs:176 name their tuple structs in lower case; the
// constructor is still keyed by the type's own name.
pub struct u24(u32);

impl u24 {
    pub fn zero() -> u24 { Self(0) }
}
`,
			},
			want:   []string{"rcgen.Ia5String", "rcgen.u24"},
			absent: []string{"rcgen.Self"},
		},
		{
			// p256 0.13.2 src/arithmetic/scalar.rs:367 binds `Self::ONE` and
			// calls `is_odd` on it; the keyword reached the key's TYPE field.
			// orion's `Self::KEM_ID.to_be_bytes()` is the same shape.
			name:       "`Self::SOME_CONST` has the impl's own type",
			importPath: "p256",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"p256\"\nversion = \"0.13.2\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub struct Scalar(u64);

impl Scalar {
    pub const ONE: Scalar = Scalar(1);
    pub fn is_odd(&self) -> bool { self.0 & 1 == 1 }
    pub fn invert_vartime(&self) -> bool {
        let a = Self::ONE;
        a.is_odd()
    }
}
`,
			},
			want:   []string{"p256.(Scalar).is_odd"},
			absent: []string{"p256.(Self).is_odd"},
		},
		{
			// An associated TYPE is the implementing type's choice and is not
			// statically known (Reference, Paths -> Self), so it gets NO type
			// rather than the keyword or a guess.
			// sequoia-openpgp 1.21.2 src/parse.rs:295,309,319 emitted
			// `sequoia-openpgp::parse.(Self).from_reader`; also rsa's pss.rs and
			// pkcs1v15.rs, curve25519-dalek's traits.rs, orion, dryoc, aws-lc-rs.
			// 73 edges.
			name:       "`Self::AssocType` gets no type at all",
			importPath: "assoc",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"assoc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub trait Signer {
    type VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey;
}

pub struct S;
pub struct V;
impl V { pub fn verify(&self) {} }

impl Signer for S {
    type VerifyingKey = V;
    fn verifying_key(&self) -> Self::VerifyingKey { V }
}

pub fn go(s: &S) {
    let k = s.verifying_key();
    k.verify();
}
`,
			},
			want:   []string{"assoc.verify"},
			absent: []string{"assoc.(Self).verify"},
		},
		{
			// magic-crypt 3.1.13 src/traits.rs:20. The trait body was walked
			// twice: once by extractDeclarations, whose function_item case has no
			// owning type, and once by processRustTraitDefaults. No free function
			// of that name exists in the crate. 523 duplicated edges across 15 of
			// 53 crates: russh 149, thrussh 133, sequoia 92, rustls 55.
			name:       "a trait default method is recorded once, owned by the trait",
			importPath: "magic-crypt",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"magic-crypt\"\nversion = \"3.1.13\"\nedition = \"2021\"\n",
				"src/lib.rs": "pub mod traits;\n",
				"src/traits.rs": `pub trait MagicCryptTrait {
    fn encrypt_to_base64(&self, data: &[u8]) -> String;

    fn encrypt_str_to_base64(&self, string: &str) -> String {
        self.encrypt_to_base64(string.as_bytes())
    }
}
`,
			},
			want:   []string{"magic-crypt::traits.(MagicCryptTrait).encrypt_to_base64"},
			absent: []string{"magic-crypt::traits.encrypt_to_base64"},
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
			for key := range got {
				if key == "" {
					continue
				}
				if hasRustKeywordSegment(key) {
					t.Errorf("key %q carries a keyword segment; no package, type or name field may", key)
				}
			}
		})
	}
}

// hasRustKeywordSegment reports whether a callee key puts a Rust keyword where a
// resolved package, type or name belongs.
func hasRustKeywordSegment(key string) bool {
	pkg, typ, name := splitRustCalleeKey(key)
	for _, field := range []string{typ, name} {
		switch field {
		case "Self", "self", "crate", "super", "dyn", "_":
			return true
		}
	}
	for _, segment := range splitOnDoubleColon(pkg) {
		switch segment {
		case "Self", "self", "crate", "super", "dyn":
			return true
		}
	}
	return false
}
