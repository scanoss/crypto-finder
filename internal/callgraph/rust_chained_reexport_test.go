// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A crate's public type commonly aliases its way through two or three modules
// before reaching the crate that implements it. Resolving only one hop of the
// chain left the intermediate module's own path as the identity — a wrong
// identity, not a missing one, because it looks resolved and matches no
// contract.
func TestRustParser_ChainedReExportResolvesToTheImplementingCrate(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
`
	body := `fn go(k: &[u8; 16], b: &mut [u8; 16]) {
    let c = %s::new_from_slice(k).unwrap();
    c.encrypt_block(b);
}
`

	tests := []struct {
		name  string
		files map[string]string
		call  string
	}{
		{
			name: "two hops, renamed at each step",
			files: map[string]string{
				"src/outer.rs": `pub use crate::inner::Cipher as MyCipher;
`,
				"src/inner.rs": `pub use aes::Aes128 as Cipher;
`,
			},
			call: "outer::MyCipher",
		},
		{
			name: "three hops, renamed at each step",
			files: map[string]string{
				"src/a.rs": `pub use crate::b::Mid as Top;
`,
				"src/b.rs": `pub use crate::c::Low as Mid;
`,
				"src/c.rs": `pub use aes::Aes128 as Low;
`,
			},
			call: "a::Top",
		},
		{
			name: "a hop with no rename keeps the item's own name",
			files: map[string]string{
				"src/outer.rs": `pub use crate::inner::Aes128;
`,
				"src/inner.rs": `pub use aes::Aes128;
`,
			},
			call: "outer::Aes128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"Cargo.toml": manifest,
				"src/lib.rs": rustChainedReExportEntryFile(tt.files) + strings.ReplaceAll(body, "%s", tt.call),
			}
			for name, content := range tt.files {
				files[name] = content
			}
			joined := strings.Join(parseRustCrateAllKeys(t, files, "app"), "\n")
			if !strings.Contains(joined, "aes.Aes128.encrypt_block") || !strings.Contains(joined, "aes.Aes128.new_from_slice") {
				t.Errorf("chain did not resolve to the aes crate; got:\n%s", joined)
			}
		})
	}
}

// rustChainedReExportEntryFile declares a `mod` for every intermediate file so
// lib.rs sees them, in the order their names sort -- the crate index result
// does not depend on it, but a fixed order keeps the test deterministic.
func rustChainedReExportEntryFile(files map[string]string) string {
	var b strings.Builder
	for name := range files {
		mod := strings.TrimSuffix(strings.TrimPrefix(name, "src/"), ".rs")
		b.WriteString("mod " + mod + ";\n")
	}
	return b.String()
}

// Two cfg-gated re-exports of the same name to different crates -- picking
// the implementation by feature flag is a normal way to write this -- are a
// genuine ambiguity, since this parser does not evaluate feature predicates.
// The name is dropped rather than guessed, exactly as a struct field two
// files disagree on is.
func TestRustParser_ConflictingReExportStaysDropped(t *testing.T) {
	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
des = "0.8"
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml": manifest,
		"src/lib.rs": `mod outer;

fn go(k: &[u8; 16], b: &mut [u8; 16]) {
    let c = outer::Cipher::new_from_slice(k).unwrap();
    c.encrypt_block(b);
}
`,
		"src/outer.rs": `#[cfg(feature = "aes-backend")]
pub use aes::Aes128 as Cipher;
#[cfg(not(feature = "aes-backend"))]
pub use des::Des as Cipher;
`,
	}, "app"), "\n")
	for _, unwanted := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("an ambiguous re-export resolved to %q; got:\n%s", unwanted, joined)
		}
	}
}
