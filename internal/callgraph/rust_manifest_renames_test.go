// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// parseRustCrateCalleeFQNs parses a whole crate laid out on disk — manifest
// included — because the identity of a renamed dependency lives in Cargo.toml,
// not in the source.
func parseRustCrateCalleeFQNs(t *testing.T, files map[string]string, srcDir, importPath string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	analyses, err := NewRustParser().ParseDirectory(filepath.Join(dir, srcDir), importPath)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
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
	return got
}

// Cargo lets a manifest bind a dependency to a different name than the crate it
// resolves to. openssl 0.10.81 does exactly this — `[dependencies.ffi] package =
// "openssl-sys"` — and it accounted for 1108 of its call edges, every one of
// them emitting a package ("ffi") that names no crate anywhere and that no
// contract can match. The rename is also how a crate depends on two major
// versions of the same library at once, and how a fork is dropped in under the
// upstream name.
func TestRustParser_ManifestDependencyRenamesResolveToTheRealCrate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		manifest string
		source   string
		raw      string
		want     string
	}{
		{
			name: "dependency table form, as openssl writes it",
			manifest: `[package]
name = "openssl"
version = "0.10.81"

[dependencies.ffi]
version = "0.9.117"
package = "openssl-sys"
`,
			source: `pub fn go() { let _ = ffi::EVP_sha256(); }`,
			raw:    "ffi::EVP_sha256",
			want:   "openssl_sys.EVP_sha256",
		},
		{
			name: "inline table form",
			manifest: `[package]
name = "app"
version = "0.1.0"

[dependencies]
aes_alt = { package = "aes", version = "0.8" }
`,
			source: `use aes_alt::Aes128;
use aes_alt::cipher::KeyInit;
pub fn go() { let _ = Aes128::new(&Default::default()); }`,
			raw:  "Aes128::new",
			want: "aes.Aes128.new",
		},
		{
			name: "two major versions of the same crate side by side",
			manifest: `[package]
name = "app"
version = "0.1.0"

[dependencies]
aes_v2 = { package = "aes", version = "0.8" }
`,
			source: `pub fn go() { let _ = aes_v2::Aes128::new(&Default::default()); }`,
			raw:    "aes_v2::Aes128::new",
			want:   "aes.Aes128.new",
		},
		{
			name: "target-specific dependency table",
			manifest: `[package]
name = "app"
version = "0.1.0"

[target.'cfg(unix)'.dependencies]
sys = { package = "openssl-sys", version = "0.9" }
`,
			source: `pub fn go() { let _ = sys::EVP_sha256(); }`,
			raw:    "sys::EVP_sha256",
			want:   "openssl_sys.EVP_sha256",
		},
		{
			name: "dev-dependency rename",
			manifest: `[package]
name = "app"
version = "0.1.0"

[dev-dependencies]
hashes = { package = "sha2", version = "0.10" }
`,
			source: `pub fn go() { let _ = hashes::Sha256::new(); }`,
			raw:    "hashes::Sha256::new",
			want:   "sha2.Sha256.new",
		},
		{
			name: "no rename leaves the identity alone",
			manifest: `[package]
name = "app"
version = "0.1.0"

[dependencies]
aes = "0.8"
`,
			source: `pub fn go() { let _ = aes::Aes128::new(&Default::default()); }`,
			raw:    "aes::Aes128::new",
			want:   "aes.Aes128.new",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRustCrateCalleeFQNs(t, map[string]string{
				"Cargo.toml": tc.manifest,
				"src/lib.rs": tc.source,
			}, "src", "app")
			if got[tc.raw] != tc.want {
				t.Errorf("%s resolved to %q, want %q", tc.raw, got[tc.raw], tc.want)
			}
		})
	}
}

// A member crate can inherit a renamed dependency from its workspace with
// `dep = { workspace = true }`, which leaves the rename in the workspace root's
// manifest rather than the member's.
func TestRustParser_WorkspaceInheritedRenameResolves(t *testing.T) {
	t.Parallel()

	got := parseRustCrateCalleeFQNs(t, map[string]string{
		"Cargo.toml": `[workspace]
members = ["member"]
resolver = "2"

[workspace.dependencies]
aes_ws = { package = "aes", version = "0.8" }
`,
		"member/Cargo.toml": `[package]
name = "member"
version = "0.1.0"

[dependencies]
aes_ws = { workspace = true }
`,
		"member/src/lib.rs": `use aes_ws::Aes128;
use aes_ws::cipher::KeyInit;
pub fn go() { let _ = Aes128::new(&Default::default()); }`,
	}, "member/src", "member")

	if got["Aes128::new"] != "aes.Aes128.new" {
		t.Errorf("workspace-inherited rename resolved to %q, want %q", got["Aes128::new"], "aes.Aes128.new")
	}
}

// `extern crate y as x;` is a crate-ROOT item: the alias is in scope for every
// module of the crate. The per-file import model could not see it, so a sibling
// file's calls through the alias kept a package that names no crate.
func TestRustParser_CrateRootExternCrateAliasIsVisibleToSiblingFiles(t *testing.T) {
	t.Parallel()

	got := parseRustCrateCalleeFQNs(t, map[string]string{
		"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
openssl-sys = "0.9"
`,
		"src/lib.rs": `extern crate openssl_sys as ffi;
pub mod consumer;
`,
		"src/consumer.rs": `pub fn go() { let _ = ffi::EVP_sha256(); }`,
	}, "src", "app")

	if got["ffi::EVP_sha256"] != "openssl_sys.EVP_sha256" {
		t.Errorf("sibling file's call through a crate-root extern alias resolved to %q, want %q", got["ffi::EVP_sha256"], "openssl_sys.EVP_sha256")
	}
}

// A manifest name may carry dashes; a Rust path never does.
func TestRustCrateIdentifier(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"openssl-sys":   "openssl_sys",
		"aes":           "aes",
		"x509-parser":   "x509_parser",
		"cfb-mode":      "cfb_mode",
		"already_under": "already_under",
	} {
		if got := rustCrateIdentifier(in); got != want {
			t.Errorf("rustCrateIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}
