// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Every case in this file comes from an adversarial review that made the parser
// name a cryptographic library for code that does not use it that way. They are
// all the SAME defect in different clothes: the import and alias tables were
// per file rather than per scope, so a name bound anywhere in a file bound it
// everywhere in that file.
//
// The damage is not a missed finding, it is a wrong one. A weak-cipher rule
// keyed on `des.Des.encrypt_block` fired against AES-128 code, and in the worst
// case against a crate with no cryptographic dependency at all.

// Two functions in one module, each binding the same local name to a different
// crate. Before scoping, whichever `use` came last in the file won for both.
func TestRustParser_FunctionScopedImportsDoNotLeakToSiblings(t *testing.T) {
	t.Parallel()

	keys := countRustKeys(parseRustCalleeKeys(t, `use aes::cipher::{BlockEncrypt, KeyInit};

pub fn strong(key: &[u8], b: &mut [u8]) {
    use aes::Aes128 as Cipher;
    let c = Cipher::new(key);
    c.encrypt_block(b);
}

pub fn weak(key: &[u8], b: &mut [u8]) {
    use des::Des as Cipher;
    let c = Cipher::new(key);
    c.encrypt_block(b);
}
`))
	for _, want := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if keys[want] != 1 {
			t.Errorf("want exactly one %q, got %d; keys = %v", want, keys[want], keys)
		}
	}
}

// The same collision through `type` aliases, in sibling modules. This one was
// worse: module scoping was not respected at all, so the first alias in the file
// won everywhere.
func TestRustParser_TypeAliasesAreScopedToTheirModule(t *testing.T) {
	t.Parallel()

	keys := countRustKeys(parseRustCalleeKeys(t, `pub mod legacy {
    use aes::cipher::{BlockEncrypt, KeyInit};
    type Cipher = des::Des;
    pub fn run(key: &[u8], b: &mut [u8]) {
        let c = Cipher::new(key);
        c.encrypt_block(b);
    }
}

pub mod modern {
    use aes::cipher::{BlockEncrypt, KeyInit};
    type Cipher = aes::Aes128;
    pub fn run(key: &[u8], b: &mut [u8]) {
        let c = Cipher::new(key);
        c.encrypt_block(b);
    }
}
`))
	for _, want := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if keys[want] != 1 {
			t.Errorf("want exactly one %q, got %d; keys = %v", want, keys[want], keys)
		}
	}
}

// A `#[cfg(test)]` module's alias must not reach the production code above it.
// This shape appears in published crates: ecdsa 0.16.9 declares
// `type Signature = crate::Signature<MockCurve>;` inside its test module.
func TestRustParser_TestModuleAliasDoesNotHijackProductionCode(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

pub fn production(key: &[u8], b: &mut [u8]) {
    let c = Aes128::new(key);
    c.encrypt_block(b);
}

#[cfg(test)]
mod tests {
    type Aes128 = des::Des;
}
`)
	for raw, want := range map[string]string{
		"Aes128::new":     "aes.Aes128.new",
		"c.encrypt_block": "aes.Aes128.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — a test module's alias must not reach production code", raw, got[raw], want)
		}
	}
}

// A module this crate declares shadows the extern prelude on the `use` path too,
// not only on a call path. The reviewed failure had no cryptographic dependency
// at all: a `mod des` holding a record framer emitted `des.Des.encrypt_block`,
// matching the live weak-cipher contract.
func TestRustParser_UseOfALocalModuleIsNotACrate(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `mod des {
    pub struct Des { pub id: u8 }
    impl Des {
        pub fn new(id: u8) -> Self { Des { id } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
}

mod md5 {
    pub struct Md5;
    impl Md5 {
        pub fn new() -> Self { Md5 }
        pub fn update(&mut self, _d: &[u8]) {}
    }
}

use des::Des;
use md5::Md5;

pub fn go() {
    let f = Des::new(3);
    f.encrypt_block(&mut []);
    let mut m = Md5::new();
    m.update(b"x");
}
`)
	for raw, want := range map[string]string{
		"Des::new":        "app::des.Des.new",
		"f.encrypt_block": "app::des.Des.encrypt_block",
		"Md5::new":        "app::md5.Md5.new",
		"m.update":        "app::md5.Md5.update",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — this crate declares the module, so the item is its own", raw, got[raw], want)
		}
	}
}

// One module imports a third-party type; a sibling module declares its own type
// of the same name. Each must keep its own identity, in either file order.
func TestRustParser_SiblingModuleKeepsItsOwnTypeAgainstAnImportedName(t *testing.T) {
	t.Parallel()

	for _, order := range []struct {
		name string
		src  string
	}{
		{
			name: "importing module first",
			src: `mod transport {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use des::Des;
    pub fn wrap(b: &mut [u8]) { let c = Des::new(&[]); c.encrypt_block(b); }
}

mod store {
    pub struct Des { pub rows: u32 }
    impl Des {
        pub fn new(rows: u32) -> Self { Des { rows } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
    pub fn persist(b: &mut [u8]) { let d = Des::new(7); d.encrypt_block(b); }
}
`,
		},
		{
			name: "declaring module first",
			src: `mod store {
    pub struct Des { pub rows: u32 }
    impl Des {
        pub fn new(rows: u32) -> Self { Des { rows } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
    pub fn persist(b: &mut [u8]) { let d = Des::new(7); d.encrypt_block(b); }
}

mod transport {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use des::Des;
    pub fn wrap(b: &mut [u8]) { let c = Des::new(&[]); c.encrypt_block(b); }
}
`,
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			keys := countRustKeys(parseRustCalleeKeys(t, order.src))
			if keys["des.Des.encrypt_block"] != 1 {
				t.Errorf("want exactly one third-party des key, got %d; keys = %v", keys["des.Des.encrypt_block"], keys)
			}
			if keys["app::store.Des.encrypt_block"] != 1 {
				t.Errorf("the local Des was not kept local; keys = %v", keys)
			}
		})
	}
}

// A renaming import in one module must not type another module's own type. The
// reviewed failure emitted a type name that appears nowhere in the offended
// module's source.
func TestRustParser_RenamingImportDoesNotLeakAcrossModules(t *testing.T) {
	t.Parallel()

	keys := countRustKeys(parseRustCalleeKeys(t, `mod legacy {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use des::Des as Cipher;
    pub fn run(b: &mut [u8]) { let c = Cipher::new(&[]); c.encrypt_block(b); }
}

mod pipeline {
    pub struct Cipher { stage: u8 }
    impl Cipher {
        pub fn new(stage: u8) -> Self { Cipher { stage } }
        pub fn encrypt_block(&self, _b: &mut [u8]) {}
    }
    pub fn run(b: &mut [u8]) { let c = Cipher::new(0); c.encrypt_block(b); }
}
`))
	if keys["des.Des.encrypt_block"] != 1 {
		t.Errorf("want exactly one des key, got %d; keys = %v", keys["des.Des.encrypt_block"], keys)
	}
	if keys["app::pipeline.Cipher.encrypt_block"] != 1 {
		t.Errorf("pipeline's own Cipher was not kept local; keys = %v", keys)
	}
}

// A `use` inside a nested block binds only inside that block, and it must be
// seen at all: the reviewed failure dropped it entirely and attributed the
// third-party type to the local crate — a silent false negative.
func TestRustParser_NestedBlockImportsAreRead(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `pub fn nested(key: &[u8]) {
    use aes::cipher::KeyInit;
    {
        use aes::Aes128;
        let _c = Aes128::new(key);
    }
}
`)
	if got["Aes128::new"] != "aes.Aes128.new" {
		t.Errorf("Aes128::new resolved to %q, want %q", got["Aes128::new"], "aes.Aes128.new")
	}
}

// Module shadowing is lexical. A `mod des;` declared in lib.rs shadows the des
// crate in lib.rs — and nowhere else. Consulting a crate-wide module index
// instead meant an empty `mod des;` anywhere in a crate suppressed every real
// DES call in every other file: a one-line way to hide a weak-cipher finding.
func TestRustParser_ModuleShadowingDoesNotCrossFiles(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[dependencies]\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod des;\npub mod transport;\n",
		"src/des.rs": "pub fn frame() {}\n",
		"src/transport.rs": `use des::cipher::{BlockEncrypt, KeyInit};

pub fn go(b: &mut [u8]) {
    let c = des::Des::new(&[]);
    c.encrypt_block(b);
}
`,
	}, "probe")

	for raw, want := range map[string]string{
		"des::Des::new":   "des.Des.new",
		"c.encrypt_block": "des.Des.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — `mod des` in another file must not shadow the crate here", raw, got[raw], want)
		}
	}
}
