// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A function declared `-> impl Trait` monomorphizes to exactly one hidden
// concrete type — Rust picks it at compile time from the body, never at
// runtime — so a binding assigned its result should carry that concrete
// type, not the trait the signature merely names as a bound.
func TestRustParser_ImplTraitReturnResolvesToTheConcreteConstructor(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
`
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "implicit tail expression",
			src: `use sha2::{Digest, Sha256};

fn make_hasher() -> impl Digest {
    Sha256::new()
}

fn go(data: &[u8]) {
    let mut h = make_hasher();
    h.update(data);
}
`,
		},
		{
			name: "explicit return statement",
			src: `use sha2::{Digest, Sha256};

fn make_hasher() -> impl Digest {
    return Sha256::new();
}

fn go(data: &[u8]) {
    let mut h = make_hasher();
    h.update(data);
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
				"Cargo.toml":  manifest,
				"src/main.rs": tt.src,
			}, "app"), "\n")
			if !strings.Contains(joined, "sha2.Sha256.update") {
				t.Errorf("h.update did not resolve to the concrete sha2.Sha256 hidden behind impl Digest; got:\n%s", joined)
			}
			if strings.Contains(joined, "Digest.update") {
				t.Errorf("the trait leaked into the key instead of the concrete type; got:\n%s", joined)
			}
		})
	}
}

// A function returning `impl Trait` from a bare identifier that is not a
// type-case name (a variable, not a unit struct) has no expression this
// parser can read a concrete type from, and must degrade to the trait text
// rather than guess.
func TestRustParser_ImplTraitReturnDegradesWhenBodyIsNotConstructorShaped(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
`
	src := `use sha2::Digest;

fn pass_through(hasher: impl Digest) -> impl Digest {
    hasher
}
`
	// This must not panic and must not fabricate a concrete type; the
	// absence of a `sha2.Sha256...` key IS the assertion.
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if strings.Contains(joined, "sha2.") {
		t.Errorf("a variable tail expression should not resolve to a concrete crate type; got:\n%s", joined)
	}
}
