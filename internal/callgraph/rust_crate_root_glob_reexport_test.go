// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A crate root that writes `pub use crate::inner::*;` re-exports its child
// exactly as `pub use self::inner::*;` does, and the items must carry the crate
// path rather than the declaring module's.
//
// MEASURED ON A REAL CRATE. Four of rusoto_kms's 26 published versions —
// 0.39.0, 0.40.0, 0.41.0 and 0.42.0 — write `pub use crate::generated::*;` in
// lib.rs where every other version writes `pub use generated::*;`. Before this
// case, every item of those four kept a `rusoto_kms::generated` package, so the
// synthesized entry-point FQN read `rusoto_kms::generated.KmsClient.encrypt`,
// matched no rule `api`, and all four scanned as zero-finding while 0.38.0
// produced six entry points and 0.43.0 ten. The idiom is ordinary modern Rust.
func TestRustParser_CrateRootGlobReExportCarriesTheCratePath(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"rusoto_kms\"\nversion = \"0.41.0\"\n",
		"src/lib.rs": "mod generated;\nmod custom;\n\npub use crate::generated::*;\npub use crate::custom::*;\n",
		"src/generated.rs": `pub fn encrypt_op(_input: u8) -> u8 { 0 }

pub fn go() -> u8 { encrypt_op(1) }
`,
		"src/custom.rs": "pub fn helper() {}\npub fn call_it() { helper(); }\n",
	}, "rusoto_kms")

	if got["encrypt_op"] != "rusoto_kms.encrypt_op" {
		t.Errorf("encrypt_op resolved to %q, want %q — the crate root re-exports generated with a glob",
			got["encrypt_op"], "rusoto_kms.encrypt_op")
	}
	if got["helper"] != "rusoto_kms.helper" {
		t.Errorf("helper resolved to %q, want %q — custom is re-exported the same way",
			got["helper"], "rusoto_kms.helper")
	}
}

// The `crate::` form is accepted at the crate root and NOWHERE ELSE. From a
// nested `mod.rs`, `crate::x` names a top-level module rather than this
// directory's child, so treating it as a child re-export would strip a segment
// every item legitimately carries.
func TestRustParser_NestedModuleCrateGlobIsNotAChildReExport(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
		"src/lib.rs": "pub mod inner;\npub mod top;\n",
		// `crate::top` is NOT a child of `inner`; `inner::leaf` keeps its segment.
		"src/inner/mod.rs":  "pub use crate::top::*;\npub mod leaf;\n",
		"src/inner/leaf.rs": "pub fn thing() {}\npub fn go() { thing(); }\n",
		"src/top.rs":        "pub fn other() {}\npub fn run() { other(); }\n",
	}, "app")

	if got["thing"] != "app::inner::leaf.thing" {
		t.Errorf("thing resolved to %q, want %q — a nested `pub use crate::top::*;` does not re-export `leaf`",
			got["thing"], "app::inner::leaf.thing")
	}
}

// The pre-existing forms keep working: this is the case that cost four contract
// hits on sodiumoxide when it was got wrong, pinned here beside the new one.
func TestRustParser_SelfGlobReExportStillCarriesTheParentPath(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml":             "[package]\nname = \"sodium\"\nversion = \"0.2.7\"\n",
		"src/lib.rs":             "pub mod crypto;\n",
		"src/crypto/mod.rs":      "pub mod sign;\n",
		"src/crypto/sign/mod.rs": "pub use self::ed25519::*;\npub mod ed25519;\n",
		"src/crypto/sign/ed25519.rs": `pub fn sign_detached(_m: &[u8]) -> u8 { 0 }

pub fn helper(m: &[u8]) -> u8 { sign_detached(m) }
`,
	}, "sodium")

	if got["sign_detached"] != "sodium::crypto::sign.sign_detached" {
		t.Errorf("sign_detached resolved to %q, want %q", got["sign_detached"], "sodium::crypto::sign.sign_detached")
	}
}
