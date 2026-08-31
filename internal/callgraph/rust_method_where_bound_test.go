// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A trait bound written in a METHOD's own `where` clause — not in the
// enclosing `impl<T>`'s parameter list, and not in the method's own generic
// parameter list either — still gives the type parameter its identity, the
// same way rustc resolves `T::describe()` inside such a method.
func TestRustParser_MethodWhereClauseBoundGivesGenericItsIdentity(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
`
	src := `use sha2::Digest;

struct Wrapper<T>(std::marker::PhantomData<T>);

impl<T> Wrapper<T> {
    fn hash(data: &[u8]) -> Vec<u8> where T: Digest {
        T::digest(data).to_vec()
    }
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if !strings.Contains(joined, "sha2.Digest.digest") {
		t.Errorf("a method-level where-clause bound did not give T its identity; got:\n%s", joined)
	}
}
