// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A type belongs to the module that DECLARES it, not to whichever module
// globbed the name into scope.
//
// This was the highest-count defect the crate sweeps found: ~5379 edges over 51
// published crates, 5.7% of them, split one declaration across as many keys as
// it had importers. `mod tests { use super::*; }` is in nearly every Rust file,
// so the split is not an edge case — quinn-proto 0.11.9 declares `Assembler`
// once in src/connection/assembler.rs and emitted 12 edges under
// `quinn_proto::connection::assembler`, 102 under `…::assembler::test` and 4
// under `quinn_proto::connection`: one file, one type, three keys, of which the
// contract KB can only ever match one.
//
// Each case names the wrong key it prevents.
// The fixture spells a plain `mod tests` rather than `#[cfg(test)] mod tests`
// on purpose: a default scan skips a cfg(test) module, and what this test
// exercises is name resolution inside a nested module, not file selection.
// The cfg gate has its own tests in rust_cfg_test_modules_test.go.
func TestRustParser_GlobResolvesToTheDeclaringModule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		files      map[string]string
		importPath string
		want       map[string]int
		absent     []string
	}{
		{
			// The decisive reproduction: the same cross-file declaration reached
			// three ways in one crate. The explicit `use` and the fully
			// qualified path always answered `globs2::decls`; the glob answered
			// with the importing module, so a contract keyed on the declaring
			// path matched two spellings out of three.
			name:       "intra-crate glob names the declaring module, not the importing one",
			importPath: "globs2",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"globs2\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod decls;

pub mod one_glob {
    use crate::decls::*;
    pub fn go() { Widget::new().spin(); }
}

pub mod explicit {
    use crate::decls::Widget;
    pub fn go() { Widget::new().spin(); }
}

pub mod fq {
    pub fn go() { crate::decls::Widget::new().spin(); }
}
`,
				"src/decls.rs": `pub struct Widget;
impl Widget {
    pub fn new() -> Self { Widget }
    pub fn spin(&self) {}
}
`,
			},
			want: map[string]int{
				"globs2::decls.Widget.new":  3,
				"globs2::decls.Widget.spin": 3,
			},
			absent: []string{
				"globs2::one_glob.Widget.new",
				"globs2::one_glob.Widget.spin",
			},
		},
		{
			// quinn-proto 0.11.9, src/connection/assembler.rs. The macro-free,
			// entirely ordinary shape: a test module beside the declaration
			// glob-imports its parent. 102 of the crate's 118 Assembler edges
			// were keyed on the test module.
			name:       "a test module's `use super::*` keys on the parent that declares the type",
			importPath: "quinn_proto",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"quinn-proto\"\nversion = \"0.11.9\"\n",
				"src/lib.rs": "pub mod connection;\n",
				"src/connection/mod.rs": `pub mod assembler;
`,
				"src/connection/assembler.rs": `pub struct Assembler;
impl Assembler {
    pub fn new() -> Self { Assembler }
    pub fn insert(&mut self) {}
}

pub fn build() { let mut a = Assembler::new(); a.insert(); }

mod test {
    use super::*;

    #[test]
    fn ordered() { let mut a = Assembler::new(); a.insert(); }
}
`,
			},
			want: map[string]int{
				"quinn_proto::connection::assembler.Assembler.new":    2,
				"quinn_proto::connection::assembler.Assembler.insert": 2,
			},
			absent: []string{
				"quinn_proto::connection::assembler::test.Assembler.new",
				"quinn_proto::connection::assembler::test.Assembler.insert",
			},
		},
		{
			// Two modules declaring the same name have no single declaring
			// module. Naming either one would attribute half the call sites to
			// a module that declares something else under that name, so the
			// name gets no declaring module and stays keyed where the source
			// resolved it — a lost precision, never a wrong one.
			name:       "a name two modules declare is left keyed on the using module",
			importPath: "amb",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"amb\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": "pub mod fast;\npub mod legacy;\npub mod user;\n",
				"src/fast.rs": `pub struct Engine;
impl Engine { pub fn run(&self) {} }
`,
				"src/legacy.rs": `pub struct Engine;
impl Engine { pub fn run(&self) {} }
`,
				"src/user.rs": `use crate::fast::*;
pub fn go(e: &Engine) { e.run(); }
`,
			},
			want: map[string]int{"amb::user.Engine.run": 1},
			absent: []string{
				"amb::fast.Engine.run",
				"amb::legacy.Engine.run",
			},
		},
		{
			// The glob-claim rule is a DIFFERENT question and must not move:
			// deciding whether a glob may claim a name at all is about crate
			// visibility, and an external glob still hands the name to the
			// crate it came from. Resolving the declaring module of the
			// crate's OWN declarations does not touch it.
			name:       "an external glob still resolves to the crate it globs",
			importPath: "ext",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"ext\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": "pub mod inner;\n",
				"src/inner.rs": `use aes::*;
use aes::cipher::{KeyInit, BlockEncrypt};
pub fn go(b: &mut [u8]) {
    let c = Aes128::new(&Default::default());
    c.encrypt_block(b.into());
}
`,
			},
			want: map[string]int{
				"aes.Aes128.new":           1,
				"aes.Aes128.encrypt_block": 1,
			},
			absent: []string{"ext::inner.Aes128.encrypt_block"},
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
					t.Errorf("key %q emitted %d times; it names a module that does not declare the type", key, got[key])
				}
			}
		})
	}
}
