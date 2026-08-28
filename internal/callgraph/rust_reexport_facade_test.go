// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A module whose only item re-exports a whole crate of the same name is that
// crate's API under a local spelling, and the API's OWNER is what a callee key
// must name.
//
// tokio-native-tls 0.3.1 src/lib.rs:382 writes exactly that:
//
//	pub mod native_tls { pub use native_tls::*; }
//
// and seven edges came out as `tokio-native-tls::native_tls.(TlsStream).get_mut`
// and friends. tokio-native-tls contains no cryptography — it is an async
// adapter, and the handshake belongs to native-tls — so that key attributed a
// crypto operation to a package that does not implement it, and no contract
// keyed on the owning crate could ever match it. Caller keys are unchanged, so
// the call chain still records how the code got there.
//
// The discriminator is deliberately narrow, and the second half of this table
// is what keeps it so: a module that declares anything of its own is a module,
// and the local-module rule that stops a crate's own `mod des` from being
// reported against the DES crate must not move.
//
// Each case names the wrong key it prevents.
func TestRustParser_PureReExportModuleNamesTheOwningCrate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		files      map[string]string
		importPath string
		want       map[string]int
		absent     []string
	}{
		{
			// tokio-native-tls 0.3.1.
			name:       "a pure `pub use <crate>::*` facade names the crate it re-exports",
			importPath: "tokio_native_tls",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"tokio-native-tls\"\nversion = \"0.3.1\"\nedition = \"2018\"\n\n[dependencies]\nnative-tls = \"0.2\"\n",
				"src/lib.rs": `use crate::native_tls::{Error, MidHandshakeTlsStream};

pub mod native_tls {
    pub use native_tls::*;
}

pub struct Guard(u8);

impl Guard {
    pub fn take(s: MidHandshakeTlsStream) { s.handshake(); }
    pub fn peek(s: &native_tls::TlsStream<u8>) { s.get_mut(); }
}
`,
			},
			want: map[string]int{
				"native_tls.MidHandshakeTlsStream.handshake": 1,
				"native_tls.TlsStream.get_mut":               1,
			},
			absent: []string{
				"tokio_native_tls::native_tls.MidHandshakeTlsStream.handshake",
				"tokio_native_tls::native_tls.TlsStream.get_mut",
			},
		},
		{
			// The discriminator. One item of the module's own and it is a
			// module: a crate that wraps a dependency AND adds to it is not a
			// facade for it, and its own types are its own.
			name:       "a module that also declares something of its own stays local",
			importPath: "wrapper",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"wrapper\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n[dependencies]\nnative-tls = \"0.2\"\n",
				"src/lib.rs": `pub mod native_tls {
    pub use native_tls::*;
    pub struct Extra;
    impl Extra { pub fn helper(&self) {} }
}

pub fn go(e: &native_tls::Extra) { e.helper(); }
`,
			},
			want:   map[string]int{"wrapper::native_tls.Extra.helper": 1},
			absent: []string{"native_tls.Extra.helper"},
		},
		{
			// The name must match. `pub mod tls { pub use native_tls::*; }`
			// renames the surface, and renaming is a separate mechanism with
			// its own rule; this one claims only the identity case.
			name:       "a re-export under a different name is not a facade",
			importPath: "renamer",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"renamer\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n[dependencies]\nnative-tls = \"0.2\"\n",
				"src/lib.rs": `pub mod tls {
    pub use native_tls::*;
}

pub fn go(s: &tls::TlsStream<u8>) { s.get_mut(); }
`,
			},
			want:   map[string]int{"renamer::tls.TlsStream.get_mut": 1},
			absent: []string{"native_tls.TlsStream.get_mut"},
		},
		{
			// The rule this must not weaken. A crate with no cryptographic
			// dependency at all, whose own `mod des` holds a record framer,
			// must never be reported against the DES crate — that is a
			// weak-cipher finding for code that has no cryptography.
			name:       "a local module with its own content is never reported against a crypto crate",
			importPath: "framer",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"framer\"\nversion = \"0.1.0\"\n",
				"src/lib.rs": `pub mod des {
    pub struct Des;
    impl Des { pub fn encrypt_block(&self, _b: &mut [u8]) {} }
}

pub fn go(d: &des::Des, b: &mut [u8]) { d.encrypt_block(b); }
`,
			},
			want:   map[string]int{"framer::des.Des.encrypt_block": 1},
			absent: []string{"des.Des.encrypt_block"},
		},
		{
			// Edition 2015 is where the facade rule's own argument stops
			// holding. A `use` path there is CRATE-ROOT-RELATIVE, so
			// `pub use des::*;` inside `mod des_facade` names THIS crate's root
			// module `des` and compiles with no `des` dependency at all. This
			// crate declares none, and its `des` is a record framer: keying it
			// as the DES crate is a weak-cipher finding for code with no
			// cryptography. Verified to compile under 2015 and to be rejected
			// under 2021 (E0432).
			name:       "an edition-2015 crate-root-relative re-export is not a facade",
			importPath: "ed2015b",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"ed2015b\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
				"src/lib.rs": `pub mod des;

pub mod des_facade {
    pub use des::*;
}

pub fn frame(b: &mut [u8]) {
    let d = des::Des::new();
    d.encrypt(b);
}
`,
				"src/des.rs": `pub struct Des;
impl Des {
    pub fn new() -> Des { Des }
    pub fn encrypt(&self, _b: &mut [u8]) {}
}
`,
			},
			want: map[string]int{
				"ed2015b::des.Des.new":     1,
				"ed2015b::des.Des.encrypt": 1,
			},
			absent: []string{"des.Des.new", "des.Des.encrypt"},
		},
		{
			// The manifest is the other half of the evidence. A name it does not
			// declare as a dependency cannot be the crate a module is a facade
			// for, in any edition.
			name:       "a module named after a crate the manifest does not declare is not a facade",
			importPath: "undeclared",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"undeclared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
				"src/lib.rs": `pub mod des {
    pub use des::*;
}

pub fn go(d: &des::Des, b: &mut [u8]) { d.encrypt_block(b); }
`,
			},
			want:   map[string]int{"undeclared::des.Des.encrypt_block": 1},
			absent: []string{"des.Des.encrypt_block"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := countRustKeys(parseRustCrateAllKeys(t, tc.files, tc.importPath))
			for key, count := range tc.want {
				if got[key] != count {
					t.Errorf("key %q emitted %d times, want %d", key, got[key], count)
				}
			}
			for _, key := range tc.absent {
				if got[key] != 0 {
					t.Errorf("key %q emitted %d times; it names the wrong owner for this API", key, got[key])
				}
			}
		})
	}
}
