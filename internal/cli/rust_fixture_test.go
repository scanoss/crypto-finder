// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os/exec"
	"path/filepath"
	"testing"
)

const rustFixtureChecksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// writeRustProject writes an invented Rust project that cargo reads offline:
// app depends on acme-sign (production) and acme-dev (dev only); acme-sign
// depends on acme-pad. Cargo's source replacement points crates.io at the
// project's vendor/ directory, so no network or registry cache is needed.
// It skips the test when cargo is not installed.
func writeRustProject(t *testing.T, project string) {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	registry := "registry+https://github.com/rust-lang/crates.io-index"
	lock := "version = 3\n\n[[package]]\nname = \"acme-dev\"\nversion = \"0.5.0\"\nsource = \"" + registry + "\"\nchecksum = \"" + rustFixtureChecksum + "\"\n\n" +
		"[[package]]\nname = \"acme-pad\"\nversion = \"1.2.0\"\nsource = \"" + registry + "\"\nchecksum = \"" + rustFixtureChecksum + "\"\n\n" +
		"[[package]]\nname = \"acme-sign\"\nversion = \"2.0.1\"\nsource = \"" + registry + "\"\nchecksum = \"" + rustFixtureChecksum + "\"\ndependencies = [\n \"acme-pad\",\n]\n\n" +
		"[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"acme-dev\",\n \"acme-sign\",\n]\n"
	files := map[string]string{
		"Cargo.toml":         "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nacme-sign = \"2.0.1\"\n\n[dev-dependencies]\nacme-dev = \"0.5.0\"\n",
		"Cargo.lock":         lock,
		".cargo/config.toml": "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n",
	}
	vendor := map[string]struct{ version, deps, lib string }{
		"acme-sign": {"2.0.1", "acme-pad = \"1.2.0\"\n", "pub fn sign(x: &[u8]) -> Vec<u8> {\n    acme_hash::digest(x)\n}\n"},
		"acme-pad":  {"1.2.0", "", "pub fn pad(x: &[u8]) -> Vec<u8> {\n    x.to_vec()\n}\n"},
		"acme-dev":  {"0.5.0", "", "pub fn dev() {}\n"},
	}
	for name, v := range vendor {
		dir := filepath.Join("vendor", name)
		files[filepath.Join(dir, "Cargo.toml")] = "[package]\nname = \"" + name + "\"\nversion = \"" + v.version + "\"\nedition = \"2021\"\n\n[dependencies]\n" + v.deps
		files[filepath.Join(dir, "src", "lib.rs")] = v.lib
		files[filepath.Join(dir, ".cargo-checksum.json")] = `{"files":{},"package":"` + rustFixtureChecksum + `"}`
	}
	files["src/main.rs"] = "fn main() {\n    let _ = acme_sign::sign(b\"x\");\n    let _ = acme_hash::digest(b\"y\");\n}\n"
	for name, text := range files {
		writeAnnotateCardsFile(t, filepath.Join(project, name), text)
	}
}
