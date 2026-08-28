// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Whether the crate's own declaration of a bare name beats a glob is a LEXICAL
// question, and the guard answered it crate-wide.
//
// From /tmp/review3-rustcrypto/probeG. `mod a { use aes::*; Aes128::new(k) }`
// resolves to the aes crate — until an unrelated `pub struct Aes128` is added in
// another file, never imported into `a`, and every AES call in `a` moves onto
// that struct. Declaring a name in ANY file of a crate therefore suppressed the
// real cryptographic identity everywhere a glob supplied it: a one-line way to
// hide a finding, and the same defect module shadowing had before it was made
// lexical.
//
// The rule is narrow on purpose, and the second half of this table is what keeps
// it so. A glob only outranks the crate's own declaration when the manifest says
// it is a real third-party dependency and the declaration is genuinely out of
// scope; every other case keeps the crate's answer. Widening it by one step —
// letting any glob win, or letting an unknown declaring module lose — moved 413
// edges on the corpus and made openssl's own `Builder` into
// `std::io::prelude.(Builder).build`.
//
// Each case names the wrong key it prevents.
func TestRustParser_GlobClaimIsLexicalNotCrateWide(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		files      map[string]string
		importPath string
		want       map[string]int
		absent     []string
	}{
		{
			name:       "an unrelated same-named declaration elsewhere does not steal a glob's name",
			importPath: "probeg",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"probeg\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `pub mod local;

mod a {
    use aes::*;
    use aes::cipher::{KeyInit, BlockEncrypt};
    pub fn f(k: &[u8; 16], b: &mut [u8]) {
        let c = Aes128::new(k.into());
        c.encrypt_block(b.into());
    }
}
`,
				"src/local.rs": `pub struct Aes128;
impl Aes128 { pub fn tag(&self) -> u32 { 7 } }
`,
			},
			want: map[string]int{
				"aes.Aes128.new":           1,
				"aes.Aes128.encrypt_block": 1,
			},
			absent: []string{
				"probeg::local.Aes128.encrypt_block",
				"probeg::a.Aes128.encrypt_block",
			},
		},
		{
			// The declaration IS in scope here, so it wins. This is the rule
			// that stops a glob from claiming a type the module declares.
			name:       "a declaration in the same module still beats a glob",
			importPath: "samemod",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"samemod\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `mod a {
    use aes::*;
    pub struct Aes128;
    impl Aes128 { pub fn encrypt_block(&self, _b: &mut [u8]) {} }
    pub fn f(b: &mut [u8]) { let c = Aes128; c.encrypt_block(b); }
}
`,
			},
			want:   map[string]int{"samemod::a.Aes128.encrypt_block": 1},
			absent: []string{"aes.Aes128.encrypt_block"},
		},
		{
			// An intra-crate glob names the declaring module, so the crate's
			// declaration is in scope and wins even with an external glob
			// beside it. This is item 1's resolution coexisting with item 4's.
			name:       "an intra-crate glob keeps the declaring module against an external glob",
			importPath: "bothglobs",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"bothglobs\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `pub mod decls;

mod a {
    use crate::decls::*;
    use aes::*;
    pub fn f() { Widget::new().spin(); }
}
`,
				"src/decls.rs": `pub struct Widget;
impl Widget { pub fn new() -> Self { Widget } pub fn spin(&self) {} }
`,
			},
			want:   map[string]int{"bothglobs::decls.Widget.spin": 1},
			absent: []string{"aes.Widget.spin", "bothglobs::a.Widget.spin"},
		},
		{
			// openssl 0.10.81 and ssh2 0.9.4 write `use std::io::prelude::*;`
			// throughout. The standard library's preludes say nothing about a
			// name the crate declares itself, and letting one win attributed
			// openssl's own `Builder` and ssh2's own `Error` to std.
			name:       "a std prelude glob never outranks the crate's own declaration",
			importPath: "stdglob",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"stdglob\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod builder;
pub mod user;
`,
				"src/builder.rs": `pub struct Builder;
impl Builder { pub fn build(&self) {} }
`,
				"src/user.rs": `use std::io::prelude::*;
use crate::builder::*;
pub fn go() { let b = Builder; b.build(); }
`,
			},
			want:   map[string]int{"stdglob::builder.Builder.build": 1},
			absent: []string{"std::io::prelude.Builder.build"},
		},
		{
			// sequoia-openpgp 2.4.1 refers to ITSELF as `openpgp`, so
			// `use openpgp::cert::prelude::*;` is an intra-crate glob wearing
			// another name. The manifest declares no such dependency, which is
			// the evidence that it cannot be a third-party crate.
			name:       "a glob rooted at an undeclared dependency does not outrank the crate",
			importPath: "selfalias",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"selfalias\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod cert;
pub mod user;
`,
				"src/cert.rs": `pub struct Cert;
impl Cert { pub fn primary_key(&self) {} }
`,
				"src/user.rs": `use openpgp::cert::prelude::*;
use crate::cert::*;
pub fn go(c: &Cert) { c.primary_key(); }
`,
			},
			want:   map[string]int{"selfalias::cert.Cert.primary_key": 1},
			absent: []string{"openpgp::cert::prelude.Cert.primary_key"},
		},
		{
			// Two modules declaring the name leave no single declaring module.
			// That is imprecision, not absence, and the using module is where it
			// stays: handing the name to the glob's crate on the strength of not
			// knowing would name a foreign owner.
			name:       "an ambiguous declaring module keeps the using module, not the glob",
			importPath: "ambglob",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"ambglob\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": "pub mod one;\npub mod two;\npub mod user;\n",
				"src/one.rs": `pub struct Engine;
impl Engine { pub fn run(&self) {} }
`,
				"src/two.rs": `pub struct Engine;
impl Engine { pub fn run(&self) {} }
`,
				"src/user.rs": `use aes::*;
use crate::one::*;
pub fn go(e: &Engine) { e.run(); }
`,
			},
			want:   map[string]int{"ambglob::user.Engine.run": 1},
			absent: []string{"aes.Engine.run"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := countRustKeys(parseRustCrateAllKeys(t, tc.files, tc.importPath))
			for key, count := range tc.want {
				if got[key] != count {
					t.Errorf("key %q emitted %d times, want %d", key, got[key], count)
				}
			}
			for _, key := range tc.absent {
				if got[key] != 0 {
					t.Errorf("key %q emitted %d times; it names the wrong owner for this name", key, got[key])
				}
			}
		})
	}
}
