// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// parseRustCrateCalleeKeyCounts tallies every callee key a crate fixture emits,
// in the `package.(Type).method` shape the contract KB is matched against, so a
// regression test can name the exact wrong key it forbids.
func parseRustCrateCalleeKeyCounts(t *testing.T, files map[string]string, importPath string) map[string]int {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writeRustFile(t, dir, name, content)
	}
	parser := NewRustParser()
	counts := map[string]int{}
	var walk func(string, string)
	walk = func(at, pkg string) {
		parsed, err := parser.ParseDirectory(at, pkg)
		if err != nil {
			t.Fatalf("ParseDirectory(%s): %v", at, err)
		}
		for _, analysis := range parsed {
			for i := range analysis.Functions {
				for j := range analysis.Functions[i].Calls {
					counts[analysis.Functions[i].Calls[j].Callee.String()]++
				}
			}
		}
		entries, err := os.ReadDir(at)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !parser.SkipDirs()[entry.Name()] {
				walk(filepath.Join(at, entry.Name()), parser.SubPackagePath(pkg, entry.Name()))
			}
		}
	}
	walk(filepath.Join(dir, "src"), importPath)
	return counts
}

// sortedKeyList lists a tally's keys for a failure message that shows what WAS
// emitted, not only what was not.
func sortedKeyList(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for key := range counts {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// An `impl` block's self type keeps the path the header wrote, and a name the
// crate's own facts supplied is never re-resolved through the observing scope's
// imports or globs.
//
// Both defects were found on real crates:
//
//   - quinn 0.11.6 src/recv_stream.rs:557,566,585 and src/send_stream.rs:468,495,
//     quinn-proto 0.11.9 src/connection/mod.rs:3652 and
//     src/connection/streams/mod.rs:523 write `impl .. for <path>::Type` and the
//     path was dropped, so the leaf was re-resolved through the file's imports.
//     On those files the colliding import is `thiserror`, so no contract fires;
//     with `use aes::Aes128;` in scope the same code path emits
//     `aes.(Aes128).new` and `aes.(Aes128).encrypt_block`, both keys in
//     aes.yaml, for a crate whose own `Aes128` is a record framer.
//   - aws-lc-rs 1.12.2 src/cipher/streaming.rs declares `BufferUpdate` at :29,
//     returns it at :169/:390 and its `mod tests` at :501 writes `use paste::*;`
//     without ever writing `BufferUpdate`: four `.written()` calls came out as
//     `paste.(BufferUpdate).written`, naming a macro-only crate as the owner of
//     the crate's own type.
//
// The fixture spells a plain `mod tests` rather than `#[cfg(test)] mod tests`
// on purpose: a default scan skips a cfg(test) module, and what this test
// exercises is name resolution inside a nested module, not file selection.
// The cfg gate has its own tests in rust_cfg_test_modules_test.go.
func TestRustParser_ImplSelfTypeKeepsItsPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		importPath string
		files      map[string]string
		want       []string
		absent     []string
	}{
		{
			// quinn 0.11.6 / quinn-proto 0.11.9 shape, written with a colliding
			// import that DOES carry contracts, which is what makes it severe.
			name:       "explicit path in the impl header beats a colliding import",
			importPath: "ns2",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"ns2\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\naes = \"0.8\"\n",
				"src/lib.rs": `pub mod local {
    pub struct Aes128 { pub n: u32 }
    impl Aes128 {
        pub fn new() -> Aes128 { Aes128 { n: 0 } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
}

use aes::Aes128;

pub struct Wire;

impl From<Wire> for crate::local::Aes128 {
    fn from(_w: Wire) -> Self {
        let x = Self::new();
        x.encrypt_block(&mut [0u8; 16]);
        x
    }
}
`,
			},
			want: []string{
				"ns2::local.(Aes128).new",
				"ns2::local.(Aes128).encrypt_block",
			},
			absent: []string{
				"aes.(Aes128).new",
				"aes.(Aes128).encrypt_block",
			},
		},
		{
			// russh 0.54.6 src/keys/mod.rs: `use thiserror::Error;` at :67 is the
			// derive MACRO; `pub enum Error` at :90 is the type. Rust keeps the
			// two namespaces apart, the flat import table did not.
			name:       "a derive-macro import does not claim the type of the same name",
			importPath: "nsprobe",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"nsprobe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nthiserror = \"1\"\n",
				"src/lib.rs": `use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("bad")]
    Bad,
}

impl Error {
    pub fn describe(&self) -> &'static str { "bad" }
}

pub fn a() -> &'static str {
    let e = Error::Bad;
    e.describe()
}
`,
			},
			want:   []string{"nsprobe.(Error).describe"},
			absent: []string{"thiserror.(Error).describe"},
		},
		{
			// The same code path with a FOREIGN self type: `impl From<Wire> for
			// io::Error` must resolve through the written path, not through the
			// import that happens to bind the leaf `Error`.
			name:       "a foreign self type keeps the path its header wrote",
			importPath: "nsprobe",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"nsprobe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nthiserror = \"1\"\n",
				"src/lib.rs": `use thiserror::Error;
use std::io;

#[derive(Debug, Error)]
pub enum Error { Bad }

pub struct Wire;
impl From<Wire> for io::Error {
    fn from(_w: Wire) -> Self { Self::new(io::ErrorKind::Other, "x") }
}
`,
			},
			want:   []string{"std::io.(Error).new"},
			absent: []string{"thiserror.(Error).new"},
		},
		{
			// aws-lc-rs 1.12.2 src/cipher/streaming.rs shape: the value's type
			// comes from the crate's own declared return, the observing scope has
			// only a glob, and the glob must not claim it. The crate name carries
			// hyphens, exactly as aws-lc-rs does — a hyphenated crate root used to
			// make the whole absolute path unusable.
			name:       "a glob does not claim a type the crate's own facts supplied",
			importPath: "glob-fab",
			files: map[string]string{
				"Cargo.toml":        "[package]\nname = \"glob-fab\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npaste = \"1\"\naes = \"0.8\"\n",
				"src/lib.rs":        "pub mod cipher;\n",
				"src/cipher/mod.rs": "pub mod streaming;\npub use streaming::{BufferUpdate, Key};\n",
				"src/cipher/streaming.rs": `pub struct BufferUpdate<'a> { written: &'a [u8] }

impl<'a> BufferUpdate<'a> {
    pub fn written(&self) -> &[u8] { self.written }
}

pub struct Key;

impl Key {
    pub fn new() -> Key { Key }
    pub fn update<'a>(&mut self, out: &'a mut [u8]) -> Result<BufferUpdate<'a>, ()> {
        Ok(BufferUpdate { written: out })
    }
    pub fn finish<'a>(self, out: &'a mut [u8]) -> Result<((), BufferUpdate<'a>), ()> {
        Ok(((), BufferUpdate { written: out }))
    }
}

mod tests {
    use crate::cipher::Key;
    use paste::*;

    #[test]
    fn t() {
        let mut k = Key::new();
        let out = k.update(&mut [0u8; 16]).unwrap();
        let _ = out.written().len();
        let (_c, out2) = k.finish(&mut [0u8; 16]).unwrap();
        let _ = out2.written().len();
    }
}
`,
			},
			want: []string{
				"glob-fab::cipher::streaming.(BufferUpdate).written",
			},
			absent: []string{
				"paste.(BufferUpdate).written",
			},
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
