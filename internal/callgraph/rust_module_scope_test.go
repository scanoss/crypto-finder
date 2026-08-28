// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// Inline `mod x { ... }` was invisible: the declaration and import passes only
// looked at a file's top-level children. A crate that puts its code in inline
// modules, or any `#[cfg(test)] mod tests`, contributed nothing at all —
// walking them raised openssl 0.10.81 from 7875 to 11195 call edges.
func TestRustParser_InlineModulesContributeDeclarationsAndCalls(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustTestFile(t, dir, `pub mod inner {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};

    pub fn run(b: &mut [u8]) {
        let c = Aes128::new(&Default::default());
        c.encrypt_block(b);
    }

    pub mod deeper {
        use aes::Aes128;
        use aes::cipher::KeyInit;
        pub fn build() { let _ = Aes128::new(&Default::default()); }
    }
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	calls := map[string]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := analysis.Functions[i]
			declared[fn.ID.Package+"."+fn.ID.Name] = true
			for j := range fn.Calls {
				callee := fn.Calls[j].Callee
				fqn, _ := splitMethodArity(&callee)
				calls[fn.Calls[j].Raw] = fqn
			}
		}
	}
	if !declared["app::inner.run"] {
		t.Errorf("inline module function not declared as app::inner.run; got %v", keysOfBool(declared))
	}
	if !declared["app::inner::deeper.build"] {
		t.Errorf("nested inline module function not declared as app::inner::deeper.build; got %v", keysOfBool(declared))
	}
	if calls["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("call inside an inline module resolved to %q, want %q", calls["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
}

// A trait's default method body is real code with real calls, and the trait owns
// it. The declaration pass had no `trait_item` case at all.
func TestRustParser_TraitDefaultMethodBodiesAreWalked(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustTestFile(t, dir, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

pub trait Runner {
    fn cipher(&self) -> Aes128 { Aes128::new(&Default::default()) }
    fn go(&self, b: &mut [u8]) {
        let c = self.cipher();
        c.encrypt_block(b);
    }
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := analysis.Functions[i]
			if fn.ID.Type != "Runner" || fn.ID.Name != "go" {
				continue
			}
			found = true
			for j := range fn.Calls {
				callee := fn.Calls[j].Callee
				fqn, _ := splitMethodArity(&callee)
				if strings.HasSuffix(fn.Calls[j].Raw, "encrypt_block") && fqn != "aes.Aes128.encrypt_block" {
					t.Errorf("call in a trait default body resolved to %q, want %q", fqn, "aes.Aes128.encrypt_block")
				}
			}
		}
	}
	if !found {
		t.Error("trait default method Runner::go was not declared at all")
	}
}

// `crate::`, `self::` and `super::` are relative to the file's own position in
// the module tree. Keeping the keyword produced a package that names a path root
// instead of a module: 1108 such edges in openssl 0.10.81.
func TestRustParser_RelativePathRootsResolveToModules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustFile(t, dir, "lib.rs", `pub mod util;
pub mod consumer;
`)
	writeRustFile(t, dir, "consumer.rs", `use crate::util::helper;
use crate::{util, other};

pub fn go() {
    helper();
    crate::util::helper();
    self::local();
    let _ = util::helper();
    let _ = other::thing();
}

pub fn local() {}
pub mod nested {
    pub fn up() { super::local(); }
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				call := analysis.Functions[i].Calls[j]
				callee := call.Callee
				fqn, _ := splitMethodArity(&callee)
				got[call.Raw] = fqn
			}
		}
	}
	for raw, want := range map[string]string{
		"crate::util::helper": "app::util.helper",
		// consumer.rs is the module `consumer`, so `self::` resolves there.
		"self::local": "app::consumer.local",
		// A module-level function keeps the module in the key's TYPE field:
		// that is the shape the contract KB keys on
		// (`sodiumoxide::crypto.secretbox.gen_key`, `ring.digest.digest`).
		"util::helper": "app.util.helper",
		"other::thing": "app.other.thing",
		// `super::` from `mod nested` inside consumer.rs resolves to the
		// `consumer` module, which is what declares `local`.
		"super::local": "app::consumer.local",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
	for raw, key := range got {
		if strings.HasPrefix(key, "crate.") || strings.HasPrefix(key, "self.") || strings.HasPrefix(key, "super.") {
			t.Errorf("%s kept a relative path root in its package: %q", raw, key)
		}
		if strings.HasPrefix(key, ".") {
			t.Errorf("%s produced an empty package: %q", raw, key)
		}
	}
}

// A glob import binds every public item of a module. The wildcard's path was
// never recorded — the guard that read it could not be reached — so every call
// through `use aes::*` resolved to the local package.
func TestRustParser_GlobImportsResolveWhenUnambiguous(t *testing.T) {
	t.Parallel()

	// A crate layout, because a glob may only claim a name once the crate's own
	// declarations are visible — which takes a manifest to find them.
	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
		"src/lib.rs": `use aes::*;
use aes::cipher::*;

pub fn go(b: &mut [u8]) {
    let c = Aes128::new(&Default::default());
    c.encrypt_block(b.into());
}
`,
	}, "app")

	if got["Aes128::new"] != "aes.Aes128.new" && got["Aes128::new"] != "aes::cipher.Aes128.new" {
		t.Errorf("glob-imported constructor resolved to %q, want a resolved aes identity", got["Aes128::new"])
	}
}

// Without crate-wide visibility — a source tree with no Cargo.toml anywhere
// above it — "not declared here" means "not visible from here", not "not
// declared". A glob must not claim the name then: a `use des::*` beside the
// crate's OWN `Framer` produced `des.(Framer).encrypt_block`, a weak-cipher
// identity for a type the crate declares itself. Staying local loses a
// resolution; guessing invents a finding.
func TestRustParser_GlobDoesNotClaimNamesWithoutCrateVisibility(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustFile(t, dir, "lib.rs", `pub struct Framer;
impl Framer {
    pub fn new() -> Self { Framer }
    pub fn encrypt_block(&self, _b: &mut [u8]) {}
}
pub mod wire;
`)
	writeRustFile(t, dir, "wire.rs", `use super::*;
use des::*;

pub fn go(b: &mut [u8]) {
    let f = Framer::new();
    f.encrypt_block(b);
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "probe")
	if err != nil {
		t.Fatal(err)
	}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				callee := analysis.Functions[i].Calls[j].Callee
				if callee.Package == "des" {
					t.Errorf("a glob claimed the crate's own type without crate visibility: %s.(%s).%s",
						callee.Package, callee.Type, callee.Name)
				}
			}
		}
	}
}

// Two glob imports from different crates make a bare name genuinely ambiguous:
// a glob names no members, so the honest answer is an unresolved identity. The
// one thing the parser must never do is pick one and fabricate a third-party
// identity, which is the only failure mode that can produce a FALSE POSITIVE
// against a crate the code does not use that way.
func TestRustParser_AmbiguousGlobImportsStayUnresolved(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::*;
use des::*;

fn go(b: &mut [u8]) {
    let c = Unknown::new();
    c.encrypt_block(b);
}
`)
	for raw, key := range got {
		if strings.HasPrefix(key, "aes.") || strings.HasPrefix(key, "des.") {
			t.Errorf("%s was attributed to %q, but two competing glob imports make it ambiguous", raw, key)
		}
	}
}

// A `use` inside a function body or an inline module binds names for the code
// there. Only top-level `use` declarations were read.
func TestRustParser_ScopedUseDeclarationsAreRead(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `fn go(b: &mut [u8]) {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let c = Aes128::new(&Default::default());
    c.encrypt_block(b);
}
`)
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("function-scoped import resolved to %q, want %q", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
}

// A module this crate declares shadows a third-party crate of the same name.
// The Reference gives an item in the current module precedence over an
// extern-crate-prelude name of the same kind, and getting this wrong is the one
// failure mode that INVENTS a finding: a local `mod aes` holding a toy cipher
// was reported against the real aes crate, with its PURL, for code that never
// calls it.
func TestRustParser_LocalModuleShadowsACrateOfTheSameName(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `mod aes {
    pub struct Aes128;
    impl Aes128 {
        pub fn new(_k: &[u8]) -> Self { Aes128 }
        pub fn encrypt_block(&self, _b: &mut [u8; 16]) {}
    }
}

pub fn go(key: &[u8]) {
    let mut blk = [0u8; 16];
    let c = aes::Aes128::new(key);
    c.encrypt_block(&mut blk);
}
`)
	for raw, want := range map[string]string{
		"aes::Aes128::new": "app::aes.Aes128.new",
		"c.encrypt_block":  "app::aes.Aes128.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — a locally declared module shadows the crate", raw, got[raw], want)
		}
	}
}

// An explicit import is written on purpose and beats a local module of the same
// name, so the shadowing rule must not swallow real library usage sitting next
// to a same-named local module.
func TestRustParser_ExplicitImportBeatsALocalModuleName(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

mod aes_helpers {
    pub fn tweak() {}
}

pub fn go(key: &[u8], b: &mut [u8]) {
    let c = Aes128::new(&Default::default());
    c.encrypt_block(b);
    aes_helpers::tweak();
}
`)
	if got["c.encrypt_block"] != "aes.Aes128.encrypt_block" {
		t.Errorf("real aes usage resolved to %q, want %q", got["c.encrypt_block"], "aes.Aes128.encrypt_block")
	}
	if got["aes_helpers::tweak"] != "app::aes_helpers.tweak" {
		t.Errorf("local module call resolved to %q, want %q", got["aes_helpers::tweak"], "app::aes_helpers.tweak")
	}
}
