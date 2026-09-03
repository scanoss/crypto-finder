// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// blake3's rules are crate-qualified paths -- `blake3::hash(..)`,
// `blake3::Hasher::new()` -- rather than method calls on a metavariable
// receiver, so they reject a consumer's own `hash`, `keyed_hash`, `derive_key`
// and `Hasher` at the rule layer and need nothing from this filter for that.
//
// Two shapes they cannot reject, because opengrep's Rust engine unifies
// `a::b(x)` with `a.b(x)` and because Rust resolves an explicit item over a glob
// import:
//
//	1. a receiver literally named `blake3` -- `let blake3 = MyThing;
//	   blake3.hash(b"x")`, or a parameter of that name;
//	2. a file-level `use blake3::*;` plus the consumer's OWN `fn hash`, which
//	   shadows the glob so the call goes to the consumer's function.
//
// Both are matched at the rule layer on opengrep 1.12.1 and 1.28.0, and the
// rules repository pins them as residuals there. This filter is what keeps them
// out of the served report, and these tests are the other half of that claim:
// without them it rests on a one-off manual scan.
//
// A third shape -- a consumer's own `mod blake3 { pub fn hash(..) }` -- is now
// guarded in the rules themselves with `pattern-not-inside`, so it no longer
// reaches this layer. It is kept here as defense in depth, and because the
// filter should drop it on its own merits if the guard is ever relaxed.
//
// WHY THIS FILE IS HERE, stated accurately. It does not exercise the contract
// KB this change adds -- delete blake3.yaml and every test below still passes,
// because `FilterForeignReceiverAssets` never consults the KB. It is here
// because the detection rules for this family assert a SERVED zero for the two
// shapes above, and this is the only place in this repository that pins it;
// `foreign_receiver_filter_test.go` covers the equivalent shapes generically
// but not for a crate whose rules make that claim. Crate-specific test files
// are established practice in this package -- `bcprov_fragment_profile_test.go`,
// `commons_codec_blake3_e2e_integration_test.go`, `jose4j_e2e_integration_test.go`,
// `netty_tls_e2e_integration_test.go` and `password4j_dispatch_e2e_test.go` are
// all here already -- so the cost is one more of those, not a new pattern.

const blake3ModuleShadowSrc = `mod blake3 {
    pub struct Hasher;
    impl Hasher {
        pub fn new() -> Self { Hasher }
    }
    pub fn hash(_x: &[u8]) -> u32 { 0 }
}

fn shadowed_free() -> u32 { blake3::hash(b"x") }
fn shadowed_type() -> blake3::Hasher { blake3::Hasher::new() }

// The cost side lives in the same file: a genuine call on the real crate,
// reached through a path the local module cannot shadow.
fn genuine_call() -> ::blake3::Hash { ::blake3::Hasher::new().update(b"x").finalize() }
`

// Shape 1 and shape 2 in one file each, alongside a GENUINE blake3 call, so
// each test can show the filter discriminating within a single file rather than
// merely returning zero.
const blake3ReceiverShadowSrc = `use blake3::Hasher;

struct MyDigester;
impl MyDigester {
    fn hash(&self, _x: &[u8]) -> usize { 0 }
}

fn residual_receiver_named_blake3() -> usize {
    let blake3 = MyDigester;
    blake3.hash(b"x")
}

fn genuine_call() -> blake3::Hash {
    let mut h = Hasher::new();
    h.update(b"x");
    h.finalize()
}
`

const blake3GlobShadowSrc = `use blake3::*;

fn hash(x: &[u8]) -> usize { x.len() }

fn residual_own_hash() -> usize { hash(b"x") }

fn genuine_call() -> blake3::Hash { blake3::Hasher::new().update(b"x").finalize() }
`

const (
	blake3HashRule   = "rust.blake3.algorithm.hash.blake3"
	blake3HasherRule = "rust.blake3.algorithm.hash.blake3-hasher"
)

func TestRustBlake3LocalModuleShadowIsNotServed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, needle string }{
		{"free function", `blake3::hash(b"x")`},
		{"associated function", "blake3::Hasher::new()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildRustGraphForFilter(t, "app", blake3ModuleShadowSrc)
			line, sc, ec := lineOf(t, blake3ModuleShadowSrc, tc.needle)
			report := reportAt(blake3HashRule, line, sc, ec)

			if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
				t.Fatalf("dropped = %d, want 1 — the consumer's own mod blake3 is claimed by blake3's rule", got)
			}
			if got := assetCount(report); got != 0 {
				t.Fatalf("assets left = %d, want 0", got)
			}
		})
	}
}

// Shape 1. The receiver is a consumer-declared type reached through a variable
// that happens to be named `blake3`.
func TestRustBlake3ReceiverNamedBlake3IsNotServed(t *testing.T) {
	t.Parallel()

	graph := buildRustGraphForFilter(t, "app", blake3ReceiverShadowSrc)
	line, sc, ec := lineOf(t, blake3ReceiverShadowSrc, `blake3.hash(b"x")`)
	report := reportAt(blake3HashRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1 — the receiver is the consumer's own type", got)
	}
	if got := assetCount(report); got != 0 {
		t.Fatalf("assets left = %d, want 0", got)
	}
}

// Shape 2. The consumer's own free function shadows the glob import.
func TestRustBlake3GlobShadowedFreeFunctionIsNotServed(t *testing.T) {
	t.Parallel()

	graph := buildRustGraphForFilter(t, "app", blake3GlobShadowSrc)
	line, sc, ec := lineOf(t, blake3GlobShadowSrc, `fn residual_own_hash() -> usize { hash(b"x") }`)
	report := reportAt(blake3HashRule, line, sc, ec)

	if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 1 {
		t.Fatalf("dropped = %d, want 1 — the call resolves to the consumer's own fn hash", got)
	}
	if got := assetCount(report); got != 0 {
		t.Fatalf("assets left = %d, want 0", got)
	}
}

// The cost side, and the reason the three tests above are not enough on their
// own: a GENUINE blake3 call must survive. A filter that dropped everything
// would pass all of them while removing the family's detections entirely.
//
// `FilterForeignReceiverAssets` is deliberately one-sided -- it keeps any asset
// whose call it cannot resolve -- so "dropped == 0" alone would also pass when
// resolution simply failed, and these cases cannot by themselves tell the two
// apart. Resolution is per-CALL-SITE, so a sibling line dropping in the same
// file proves nothing about the line under test; an earlier version of this
// comment claimed otherwise and was wrong.
//
// What makes the zero meaningful is instrumenting the filter: each case below
// yields exactly one candidate with `candidateOwnerFQN = "blake3.Hasher"`,
// `judgeable = true` and `graphDeclaresMethod = false`, so the call IS resolved
// and IS kept as a third-party call. The assertions here are the regression
// guard on that outcome, not the proof of it -- and they still catch the defect
// that matters, a receiver-routing bug conflating `Hasher` with the local
// `MyDigester`.
func TestRustBlake3GenuineCallSurvivesTheFilter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, src, needle, rule string
	}{
		{
			name:   "receiver-shadow file",
			src:    blake3ReceiverShadowSrc,
			needle: "let mut h = Hasher::new();",
			rule:   blake3HasherRule,
		},
		{
			name:   "glob-shadow file",
			src:    blake3GlobShadowSrc,
			needle: `fn genuine_call() -> blake3::Hash { blake3::Hasher::new().update(b"x").finalize() }`,
			rule:   blake3HasherRule,
		},
		{
			name:   "module-shadow file",
			src:    blake3ModuleShadowSrc,
			needle: `::blake3::Hasher::new().update(b"x").finalize()`,
			rule:   blake3HasherRule,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildRustGraphForFilter(t, "app", tc.src)
			line, sc, ec := lineOf(t, tc.src, tc.needle)
			report := reportAt(tc.rule, line, sc, ec)

			if got := FilterForeignReceiverAssets(report, graph, "rust"); got != 0 {
				t.Fatalf("dropped = %d, want 0 — a genuine blake3 call must be served", got)
			}
			if got := assetCount(report); got != 1 {
				t.Fatalf("assets left = %d, want 1", got)
			}
		})
	}
}
