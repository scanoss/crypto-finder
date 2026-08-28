// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A parent module that glob-re-exports a child makes the child's items public
// at the PARENT's path, and that is the identity a contract keys on. sodiumoxide
// 0.2.7 writes `pub use self::ed25519::*;` in src/crypto/sign/mod.rs, and its
// contract reads `sodiumoxide::crypto::sign.sign_detached` — not the declaring
// file's `...::sign::ed25519`. Extending the path unconditionally cost four
// contract hits on that crate's own source.
func TestRustParser_GlobReExportedModuleCarriesTheParentPath(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml":        "[package]\nname = \"sodium\"\nversion = \"0.2.7\"\n",
		"src/lib.rs":        "pub mod crypto;\n",
		"src/crypto/mod.rs": "pub mod sign;\n",
		// The parent re-exports its child with a glob.
		"src/crypto/sign/mod.rs": "pub use self::ed25519::*;\npub mod ed25519;\n",
		"src/crypto/sign/ed25519.rs": `pub struct Signature;

pub fn sign_detached(_m: &[u8]) -> Signature { Signature }

pub fn helper(m: &[u8]) -> Signature { sign_detached(m) }
`,
		// A sibling module that is NOT re-exported keeps its own segment.
		"src/crypto/other.rs": "pub fn thing() {}\npub fn go() { thing(); }\n",
	}, "sodium")

	if got["sign_detached"] != "sodium::crypto::sign.sign_detached" {
		t.Errorf("sign_detached resolved to %q, want %q — the re-exporting module is the public identity",
			got["sign_detached"], "sodium::crypto::sign.sign_detached")
	}
	if got["thing"] != "sodium::crypto::other.thing" {
		t.Errorf("thing resolved to %q, want %q — a module that is not re-exported keeps its segment",
			got["thing"], "sodium::crypto::other.thing")
	}
}

// A member crate's own manifest wins over its workspace's. Letting the
// workspace overwrite it meant a member declaring `ali = { package = "log" }`
// resolved as the workspace's `ali = { package = "libc" }` — a misattribution
// to a real, different crate.
func TestRustParser_MemberRenameWinsOverTheWorkspaceRename(t *testing.T) {
	t.Parallel()

	// The call names one type through the alias; only the PACKAGE the alias
	// resolves to is under test, since the parser reports the type the source
	// wrote.
	const source = "pub fn go() { let _ = ali::Cipher::new(); }\n"

	for _, tc := range []struct {
		name    string
		member  string
		wantPkg string
	}{
		{
			name: "member declares its own rename",
			member: `[package]
name = "member"
version = "0.1.0"

[dependencies]
ali = { package = "des", version = "0.8" }
`,
			wantPkg: "des",
		},
		{
			name: "member inherits the workspace rename",
			member: `[package]
name = "member"
version = "0.1.0"

[dependencies]
ali = { workspace = true }
`,
			wantPkg: "aes",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCrateFiles(t, map[string]string{
				"Cargo.toml": `[workspace]
members = ["member"]

[workspace.dependencies]
ali = { package = "aes", version = "0.8" }
`,
				"member/Cargo.toml": tc.member,
				"member/src/lib.rs": source,
			}, "member")

			key := got["ali::Cipher::new"]
			if !strings.HasPrefix(key, tc.wantPkg+".") {
				t.Errorf("ali::Cipher::new resolved to %q, want the %q crate", key, tc.wantPkg)
			}
		})
	}
}

// An `extern crate y as x;` alias, and a manifest rename, apply to a path
// rooted at `crate::` too. Once `crate::ffi::EVP_MD_CTX_new` is expanded to
// `boring::ffi::EVP_MD_CTX_new` the alias is no longer the first segment and
// never applies: 97 edges in boring 4.9.1 named a `boring::ffi` module that does
// not exist, alongside 578 correct ones from the bare `use crate::ffi;` form.
func TestRustParser_CrateRootedPathResolvesAnExternAlias(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"boring\"\nversion = \"4.9.1\"\n\n[dependencies]\nboring-sys = \"4\"\n",
		"src/lib.rs": "extern crate boring_sys as ffi;\npub mod hash;\n",
		"src/hash.rs": `use crate::ffi;
use crate::ffi::EVP_MD_CTX_new;

pub fn module_form() { unsafe { ffi::EVP_sha256(); } }
pub fn item_form() { unsafe { EVP_MD_CTX_new(); } }
pub fn qualified_form() { unsafe { crate::ffi::EVP_sha512(); } }
`,
	}, "boring")

	for raw, want := range map[string]string{
		"ffi::EVP_sha256":        "boring_sys.EVP_sha256",
		"EVP_MD_CTX_new":         "boring_sys.EVP_MD_CTX_new",
		"crate::ffi::EVP_sha512": "boring_sys.EVP_sha512",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
}

// A plain `extern crate x;` brings the CRATE into that module's scope, and
// edition-2015 code reaches it as `self::x::..`. Without recording it, the
// relative root expanded to the current module path and the crate's own name
// was appended: `native_tls::imp::openssl::openssl`, a module that does not
// exist, on 170 edges — which left the whole openssl surface of a TLS wrapper
// invisible.
func TestRustParser_PlainExternCrateIsReachableThroughSelf(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml":     "[package]\nname = \"native_tls\"\nversion = \"0.2.14\"\n\n[dependencies]\nopenssl = \"0.10\"\n",
		"src/lib.rs":     "pub mod imp;\n",
		"src/imp/mod.rs": "pub mod openssl;\n",
		"src/imp/openssl.rs": `extern crate openssl;

use self::openssl::hash::MessageDigest;

pub fn through_use() { let _ = MessageDigest::sha256(); }
pub fn through_path() { let _ = self::openssl::hash::MessageDigest::sha512(); }
`,
	}, "native_tls")

	for raw, want := range map[string]string{
		"MessageDigest::sha256":                      "openssl::hash.MessageDigest.sha256",
		"self::openssl::hash::MessageDigest::sha512": "openssl::hash.MessageDigest.sha512",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
	for raw, key := range got {
		if strings.Contains(key, "openssl::openssl") {
			t.Errorf("key for %q doubled the crate segment: %q", raw, key)
		}
	}
}

// `dyn` is a keyword, not part of any name. `<dyn Encrypter>::invalid()` put
// "dyn Encrypter" — with a space — into the key's package field, and an
// `impl dyn Encrypter` block put it into the type field.
func TestRustParser_DynKeywordNeverReachesAKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustTestFile(t, dir, `pub trait Encrypter {
    fn encrypt(&self);
}

impl dyn Encrypter {
    pub fn invalid() -> Box<dyn Encrypter + 'static> { unimplemented!() }
}

pub fn go() {
    let _ = <dyn Encrypter>::invalid();
}
`)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			id := analysis.Functions[i].ID
			if strings.Contains(id.Package+id.Type, "dyn ") {
				t.Errorf("declaration key carries the dyn keyword: %s.(%s).%s", id.Package, id.Type, id.Name)
			}
			for j := range analysis.Functions[i].Calls {
				callee := analysis.Functions[i].Calls[j].Callee
				if strings.Contains(callee.Package+callee.Type, "dyn ") {
					t.Errorf("callee key carries the dyn keyword: %s.(%s).%s", callee.Package, callee.Type, callee.Name)
				}
			}
		}
	}
}

// A module does not shadow itself. Inside `mod pbkdf2 { use pbkdf2::pbkdf2; }`
// the path's first segment is the CRATE, because uniform paths look at the items
// of the current module and a module is not an item of itself. Recording module
// names file-wide made cocoon 0.5.0's only PBKDF2 call invisible to its live
// contract.
func TestRustParser_AModuleDoesNotShadowItself(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"cocoon\"\nversion = \"0.5.0\"\n\n[dependencies]\npbkdf2 = \"0.12\"\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod kdf;\n",
		"src/kdf.rs": `pub mod pbkdf2 {
    use pbkdf2::pbkdf2;

    pub fn derive(salt: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        pbkdf2::<hmac::Hmac<sha2::Sha256>>(b"pw", salt, 1000, &mut out);
        out
    }
}
`,
		// A sibling module that DOES shadow: `mod des` is an item of the file's
		// top level, so a `use des::..` there means the local one.
		"src/other.rs": `mod des {
    pub struct Des;
    impl Des { pub fn new() -> Self { Des } }
}
use des::Des;
pub fn go() { let _ = Des::new(); }
`,
	}, "cocoon")

	if got["pbkdf2::<hmac::Hmac<sha2::Sha256>>"] != "pbkdf2.pbkdf2" && got["pbkdf2"] != "pbkdf2.pbkdf2" {
		found := false
		for _, key := range got {
			if key == "pbkdf2.pbkdf2" {
				found = true
			}
		}
		if !found {
			t.Errorf("the crate's pbkdf2 function was not resolved; keys = %v", got)
		}
	}
}

// A path segment the manifest does not declare as a dependency cannot name a
// crate. russh 0.54.6 writes `use cipher::SealingKey;` for its OWN
// `pub(crate) trait SealingKey` and declares no `cipher` dependency, so
// `cipher` — a real crates.io name — could never be the answer. Without the
// manifest to check against, the segment became the package, in russh,
// sequoia-openpgp (`types`, `crypto`, `key`, `mpi`) and rsa (`errors`).
func TestRustParser_AnUndeclaredDependencyIsNotACrate(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		// `des` IS declared; `cipher` is not.
		"Cargo.toml": "[package]\nname = \"russh\"\nversion = \"0.54.6\"\n\n[dependencies]\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod cipher;\npub mod sshbuffer;\n",
		"src/cipher.rs": `pub trait SealingKey { fn write(&self, b: &[u8]); }
pub struct Key;
impl SealingKey for Key { fn write(&self, _b: &[u8]) {} }
`,
		"src/sshbuffer.rs": `use cipher::SealingKey;
use des::Des;

pub fn seal(k: &dyn SealingKey) { k.write(b"x"); }
pub fn legacy() { let _ = Des::new_from_slice(&[]); }
`,
	}, "russh")

	// The crate's own module, not the `cipher` crate.
	if got["k.write"] != "russh::cipher.SealingKey.write" {
		t.Errorf("k.write resolved to %q, want %q — the manifest declares no `cipher` dependency",
			got["k.write"], "russh::cipher.SealingKey.write")
	}
	// A DECLARED dependency of the same shape still resolves to the crate.
	if got["Des::new_from_slice"] != "des.Des.new_from_slice" {
		t.Errorf("Des::new_from_slice resolved to %q, want %q — des IS declared",
			got["Des::new_from_slice"], "des.Des.new_from_slice")
	}
}

// `unwrap` hands back the contents of a WRAPPER. Applying it unconditionally
// stripped a generic argument off a type that is not one: `Mutex<Archive<R>>`
// already yields `Archive<R>` from `.lock()`, and the `.unwrap()` after it
// peeled again, landing on `R` — a type from a different crate than the
// receiver. And `map_err` rewrites a Result's error and leaves its value alone,
// so a constructor followed by `.map_err(..)?` keeps its identity; not knowing
// that broke a chain a bare `?` resolved.
func TestRustParser_UnwrapAndMapErrKeepTheRightType(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use std::sync::{Arc, Mutex};

pub struct Holder { inner: Mutex<Wrapped> }
pub struct Wrapped { c: Aes128 }
impl Wrapped { pub fn go(&self, b: &mut [u8]) {} }

fn make() -> Result<Aes128, ()> { Ok(Aes128::new(&Default::default())) }

pub fn through_lock(h: &Holder, b: &mut [u8]) {
    let guard = h.inner.lock().unwrap();
    guard.go(b);
}

pub fn through_map_err(b: &mut [u8]) -> Result<(), ()> {
    let c = make().map_err(|_e| ())?;
    c.encrypt_block(b.into());
    Ok(())
}

pub fn deref_then_lock(b: &mut [u8]) {
    let shared: Arc<Mutex<Aes128>> = Arc::new(Mutex::new(Aes128::new(&Default::default())));
    let c = shared.lock().unwrap();
    c.encrypt_block(b.into());
}
`)
	for raw, want := range map[string]string{
		// `Mutex<Wrapped>` yields Wrapped; unwrap must not peel Wrapped's own
		// generic-looking shape further.
		"guard.go": "app.Wrapped.go",
		// A constructor's type survives `.map_err(..)?`.
		"c.encrypt_block": "aes.Aes128.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q", raw, got[raw], want)
		}
	}
}

// The edition-2018 disambiguator and a reference in a qualified path are
// punctuation, not names: `use ::cipher::{..}` kept its leading separator in the
// package field, and `<&SignatureBytes<C>>::try_from(..)` kept `&`, `<` and `>`.
func TestRustParser_PunctuationNeverReachesAKey(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use ::cipher::{StreamCipher, StreamCipherSeek};

pub struct Bytes;
impl Bytes { pub fn make() -> Self { Bytes } }

pub fn run<C: StreamCipher>(c: &mut C, buf: &mut [u8]) {
    c.apply_keystream(buf);
}

pub fn qualified() {
    let _ = <&Bytes>::make();
}
`)
	for raw, key := range got {
		for _, bad := range []string{"::", "&", "<", ">"} {
			if strings.HasPrefix(key, bad) || strings.Contains(key, bad) && bad != "::" {
				t.Errorf("key for %q carries %q: %q", raw, bad, key)
			}
		}
	}
	if got["c.apply_keystream"] != "cipher.StreamCipher.apply_keystream" {
		t.Errorf("c.apply_keystream resolved to %q, want %q", got["c.apply_keystream"], "cipher.StreamCipher.apply_keystream")
	}
}
