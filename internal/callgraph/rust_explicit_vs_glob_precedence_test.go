// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// rustc/rust-analyzer resolve a name that is both glob-supplied and explicitly
// imported (or locally declared) to the explicit/local source, deterministically
// and regardless of source order — never as an ambiguity. The parser already
// gets this right because analysis.Imports is consulted before WildcardImports
// in resolveRustBareType, but no test pinned the invariant: these lock it in so
// a future refactor of that ordering fails loudly instead of silently
// resolving a conflicting import to the wrong crate.
func TestRustParser_ExplicitImportBeatsAConflictingGlob(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
des = "0.8"
`
	body := `fn go(k: &[u8; 16], b: &mut [u8; 16]) {
    let c = Aes128::new_from_slice(k).unwrap();
    c.encrypt_block(b);
}
`
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "explicit import written after the glob still wins",
			src:  "use des::*;\nuse aes::Aes128;\n\n" + body,
		},
		{
			name: "explicit import written before the glob still wins",
			src:  "use aes::Aes128;\nuse des::*;\n\n" + body,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
				"Cargo.toml":  manifest,
				"src/main.rs": tt.src,
			}, "app"), "\n")
			if !strings.Contains(joined, "aes.Aes128.encrypt_block") {
				t.Errorf("explicit import lost to the competing glob; got:\n%s", joined)
			}
			if strings.Contains(joined, "des.") {
				t.Errorf("the glob's crate leaked into the key; got:\n%s", joined)
			}
		})
	}
}

// A type this module declares itself beats a glob supplying the same name, with
// no ambiguity — the declaration is not merely another candidate, it is what
// the name means in this scope (Rust Reference, Names -> Scopes).
func TestRustParser_LocalDeclarationBeatsAConflictingGlob(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
`
	src := `use aes::*;

struct Aes128;

impl Aes128 {
    fn new_from_slice(k: &[u8]) -> Result<Self, ()> { Ok(Aes128) }
    fn encrypt_block(&self, b: &mut [u8; 16]) {}
}

fn go(k: &[u8; 16], b: &mut [u8; 16]) {
    let c = Aes128::new_from_slice(k).unwrap();
    c.encrypt_block(b);
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if !strings.Contains(joined, "app.Aes128.encrypt_block") {
		t.Errorf("local declaration lost to the competing glob; got:\n%s", joined)
	}
	if strings.Contains(joined, "aes.Aes128") {
		t.Errorf("the glob's crate leaked into the key over the local declaration; got:\n%s", joined)
	}
}
