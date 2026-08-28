// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A name two files of a crate declare with different types is dropped rather
// than guessed, because an ambiguous crate-wide answer reports an algorithm the
// code may not use. The drop has to be STICKY: the conflict marker was written
// and never read, so a third file repeating the first resurrected the fact and
// `filepath.WalkDir` order decided which cipher a struct field was reported as
// holding — a wrong identity on a live weak-cipher key.
func TestRustParser_AConflictingDeclarationStaysDropped(t *testing.T) {
	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"
[dependencies]
aes = "0.8"
des = "0.8"
`
	consumer := `use crate::a::Holder;

pub fn use_it(h: &Holder, b: &mut [u8; 8]) { h.cipher.encrypt_block(b); }
`

	t.Run("two declarations disagree, so the field is dropped", func(t *testing.T) {
		joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
			"Cargo.toml":     manifest,
			"src/a.rs":       "pub struct Holder { pub cipher: aes::Aes128 }",
			"src/b.rs":       "pub struct Holder { pub cipher: des::Des }",
			"src/consume.rs": consumer,
		}, "app"), "\n")
		for _, unwanted := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
			if strings.Contains(joined, unwanted) {
				t.Errorf("ambiguous field resolved to %q; got:\n%s", unwanted, joined)
			}
		}
	})

	t.Run("a third declaration repeating the first does not resurrect it", func(t *testing.T) {
		joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
			"Cargo.toml":     manifest,
			"src/a.rs":       "pub struct Holder { pub cipher: aes::Aes128 }",
			"src/b.rs":       "pub struct Holder { pub cipher: des::Des }",
			"src/c.rs":       "pub struct Holder { pub cipher: aes::Aes128 }",
			"src/consume.rs": consumer,
		}, "app"), "\n")
		for _, unwanted := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
			if strings.Contains(joined, unwanted) {
				t.Errorf("a third declaration resurrected a dropped field as %q; got:\n%s", unwanted, joined)
			}
		}
	})
}

// The crate-alias table drops a contradicted alias for the same reason, and its
// conflict marker had the same defect: written, never read.
func TestRustParser_AConflictingCrateAliasStaysDropped(t *testing.T) {
	const src = `mod one { pub use aes as k; }
mod two { pub use des as k; }
mod three { pub use aes as k; }

fn go(b: &mut [u8; 8]) { k::cipher::hazmat::encrypt(b); }
`
	joined := strings.Join(parseRustCalleeKeys(t, src), "\n")
	for _, unwanted := range []string{"aes::cipher::hazmat.encrypt", "des::cipher::hazmat.encrypt"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("a contradicted crate alias resolved to %q; got:\n%s", unwanted, joined)
		}
	}
}
