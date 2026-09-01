// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Tests in this file port real scenarios found in rust-analyzer's and rustc's
// own test suites (see RUST_ANALYZER_AUDIT.md for the audit that produced
// them), verified against those suites and, where the expected behavior was
// not obvious from reading the reference test alone, against a real rustc
// build. They exercise shapes distinct from the existing rust_*_test.go
// coverage rather than duplicating it.

package callgraph

import (
	"strings"
	"testing"
)

// Ported from rust-analyzer's glob_shadowed_def_dependencies
// (crates/hir-def/src/nameres/tests/globs.rs): an explicit import that wins
// over a competing glob is not just a leaf identity -- it is itself usable as
// a path prefix afterward. `TestRustParser_LocalDeclarationBeatsAConflictingGlob`
// and `TestRustParser_ExplicitImportBeatsAConflictingGlob` cover the leaf-name
// case; this covers the module-prefix case, which exercises a different code
// path (splitRustScopedCallee's path resolution, not a bare-name lookup).
func TestRustParser_ExplicitModuleImportBeatsGlobWhenUsedAsAPathPrefix(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"
`
	src := `mod a { pub mod foo { pub struct Aes128; impl Aes128 { pub fn tag() -> &'static str { "a" } } } }
mod b { pub use super::a::foo; }
mod c { pub mod foo { pub struct Aes128; impl Aes128 { pub fn tag() -> &'static str { "c" } } } }
mod d {
    use super::c::foo;
    use super::b::*;
    fn go() -> &'static str {
        foo::Aes128::tag()
    }
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if !strings.Contains(joined, "app::c::foo.Aes128.tag") {
		t.Errorf("explicit module import lost to the competing glob when used as a path prefix; got:\n%s", joined)
	}
	if strings.Contains(joined, "app::a::foo") {
		t.Errorf("the glob's module leaked into the key; got:\n%s", joined)
	}
}

// Ported from rustc's tests/ui/resolve/hidden_glob_reexports.rs (upstream_a):
// a private item declared in a module beats a glob re-export of the same name
// brought into that SAME module from a submodule, distinct from the
// sibling-file-vs-external-crate shape TestRustParser_LocalDeclarationBeatsAConflictingGlob
// already covers. rustc accepts this with only a lint warning ("private item
// shadows public glob re-export"), not an error -- the local item wins
// unambiguously.
func TestRustParser_PrivateModuleItemBeatsAGlobReexportFromItsOwnSubmodule(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"
`
	src := `mod upstream {
    mod inner {
        pub struct Aes128;
        impl Aes128 { pub fn tag() -> &'static str { "inner" } }
    }

    struct Aes128;
    impl Aes128 { fn tag() -> &'static str { "local" } }

    pub use self::inner::*;

    pub fn go() -> &'static str {
        Aes128::tag()
    }
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if !strings.Contains(joined, "app::upstream.Aes128.tag") {
		t.Errorf("the module's own private declaration lost to its submodule's glob re-export; got:\n%s", joined)
	}
	if strings.Contains(joined, "app::upstream::inner") {
		t.Errorf("the glob re-export's submodule leaked into the key; got:\n%s", joined)
	}
}

// Confirmed against a real rustc build (see RUST_ANALYZER_AUDIT.md) and
// against rust-analyzer's super_trait_method_resolution
// (crates/hir-ty/src/tests/method_resolution.rs): a method declared only on a
// SUPERTRAIT, called through a generic parameter bound to the SUBTRAIT
// (`trait Trait1: SuperTrait {}`, `fn test<T: Trait1>(x: T) { x.describe() }`),
// resolves correctly to the supertrait's method in real Rust.
//
// This is a KNOWN, UNFIXED GAP, not a regression this PR introduces:
// rustFirstTraitBound has no notion of supertrait relationships, and no
// existing fact table records which methods a trait declares (fnReturns is
// close but only records methods with an explicit return type, so a supertrait
// check built on it would silently mis-classify every void method -- exactly
// the crypto-relevant shape, since `update(&mut self, data: &[u8])` returns
// nothing). Fixing this needs a new trait-declares-method-name fact,
// independent of return-type tracking, plus a supertrait graph to walk when
// the directly bound trait doesn't own the called method -- out of scope for
// a quick patch. This test pins CURRENT behavior (the fabricated identity) so
// a future fix is a deliberate, tracked change to this test, not a silent
// diff. See RUST_ANALYZER_AUDIT.md for the full writeup.
func TestRustParser_SupertraitBoundMethodIsAKnownUnfixedGap(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"
`
	src := `mod foo {
    pub trait SuperTrait { fn describe(&self) -> &'static str { "super" } }
}
trait Trait1: foo::SuperTrait {}

struct Marker;
impl foo::SuperTrait for Marker {}
impl Trait1 for Marker {}

fn test<T: Trait1>(x: &T) -> &'static str {
    x.describe()
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	// KNOWN GAP: real Rust resolves x.describe() through foo::SuperTrait (the
	// only declarer of describe), not Trait1 (which declares no methods of its
	// own). If this assertion starts failing because the key changed, the gap
	// may have been fixed -- update this test's expectation and
	// RUST_ANALYZER_AUDIT.md together rather than treating it as a regression.
	if !strings.Contains(joined, "app.Trait1.describe") {
		t.Errorf("expected the known gap's current (fabricated) identity app.Trait1.describe; got:\n%s\nif this changed because the gap was fixed, update this test and RUST_ANALYZER_AUDIT.md", joined)
	}
}
