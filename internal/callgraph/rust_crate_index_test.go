// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// parseRustCrateFiles parses a crate laid out on disk and returns every callee
// key, so cross-file resolution can be asserted.
func parseRustCrateFiles(t *testing.T, files map[string]string, importPath string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writeRustFile(t, dir, name, content)
	}
	// Walk subdirectories the way the builder does, so a crate laid out in
	// module directories is covered.
	parser := NewRustParser()
	var analyses []*FileAnalysis
	var walk func(string, string)
	walk = func(at, pkg string) {
		parsed, err := parser.ParseDirectory(at, pkg)
		if err != nil {
			t.Fatalf("ParseDirectory(%s): %v", at, err)
		}
		analyses = append(analyses, parsed...)
		entries, err := os.ReadDir(at)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !skipCallgraphWalkDir(entry.Name()) {
				walk(filepath.Join(at, entry.Name()), parser.SubPackagePath(pkg, entry.Name()))
			}
		}
	}
	root := filepath.Join(dir, "src")
	if _, err := os.Stat(root); err != nil {
		// A workspace fixture keeps its sources under the member directory.
		root = filepath.Join(dir, importPath, "src")
	}
	walk(root, importPath)
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

// parseRustCrateAllKeys returns every callee key a crate emits, with
// duplicates, for the cases where two call sites are written identically.
func parseRustCrateAllKeys(t *testing.T, files map[string]string, importPath string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writeRustFile(t, dir, name, content)
	}
	parser := NewRustParser()
	var keys []string
	var walk func(string, string)
	walk = func(at, pkg string) {
		parsed, err := parser.ParseDirectory(at, pkg)
		if err != nil {
			t.Fatalf("ParseDirectory(%s): %v", at, err)
		}
		for _, analysis := range parsed {
			for i := range analysis.Functions {
				for j := range analysis.Functions[i].Calls {
					callee := analysis.Functions[i].Calls[j].Callee
					fqn, _ := splitMethodArity(&callee)
					keys = append(keys, fqn)
				}
			}
		}
		entries, err := os.ReadDir(at)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() && !skipCallgraphWalkDir(entry.Name()) {
				walk(filepath.Join(at, entry.Name()), parser.SubPackagePath(pkg, entry.Name()))
			}
		}
	}
	walk(filepath.Join(dir, "src"), importPath)
	sort.Strings(keys)
	return keys
}

// A crate's declarations are the crate's truth, not each file's. A factory in
// one file is what types the receiver in another, and the per-file view left
// that receiver unresolved — losing the finding for a shape as common as a
// builder or factory module.
func TestRustParser_CrateIndexResolvesAcrossFiles(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
		"src/lib.rs": "pub mod factory;\npub mod consumer;\n",
		"src/factory.rs": `use aes::Aes128;
use aes::cipher::KeyInit;
pub fn make() -> Aes128 { Aes128::new(&Default::default()) }
pub struct Holder { pub cipher: Aes128 }
`,
		"src/consumer.rs": `use aes::cipher::BlockEncrypt;
use crate::factory::{make, Holder};

pub fn from_factory(b: &mut [u8]) {
    let c = make();
    c.encrypt_block(b.into());
}

pub fn from_field(h: &Holder, b: &mut [u8]) {
    h.cipher.encrypt_block(b.into());
}
`,
	}, "app")

	for raw, want := range map[string]string{
		"c.encrypt_block":        "aes.Aes128.encrypt_block",
		"h.cipher.encrypt_block": "aes.Aes128.encrypt_block",
	} {
		if got[raw] != want {
			t.Errorf("%s resolved to %q, want %q — a declaration in a sibling file is still this crate's truth", raw, got[raw], want)
		}
	}
}

// The crate index merges declarations from every file, so a name two files
// declare with DIFFERENT types is ambiguous. It must resolve to nothing: naming
// one of the two would report an algorithm the code does not use, which is the
// failure this parser exists to avoid. Losing the receiver is the safe outcome.
func TestRustParser_CrateIndexDropsConflictingDeclarations(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod fast;\npub mod legacy;\npub mod consumer;\n",
		"src/fast.rs": `use aes::Aes128;
use aes::cipher::KeyInit;
pub fn build() -> Aes128 { Aes128::new(&Default::default()) }
`,
		"src/legacy.rs": `use des::Des;
use des::cipher::KeyInit;
pub fn build() -> Des { Des::new(&Default::default()) }
`,
		"src/consumer.rs": `use aes::cipher::BlockEncrypt;
use crate::fast::build;

pub fn go(b: &mut [u8]) {
    let c = build();
    c.encrypt_block(b.into());
}
`,
	}, "app")

	switch got["c.encrypt_block"] {
	case "app::consumer.encrypt_block":
		// Unresolved, in the consumer's own module: the honest answer for an
		// ambiguous crate-wide name.
	case "des.Des.encrypt_block":
		t.Error("an ambiguous crate-wide name resolved to the WRONG crate; this reports an algorithm the code does not use")
	case "aes.Aes128.encrypt_block":
		t.Log("resolved through the importing file's own view, which is more precise than the crate index")
	default:
		t.Errorf("unexpected resolution %q", got["c.encrypt_block"])
	}
}

// A file's own declarations take precedence over the crate index: two modules
// may each declare a `Cipher`, and inside one of them the local one is meant.
func TestRustParser_FileDeclarationsBeatTheCrateIndex(t *testing.T) {
	t.Parallel()

	got := parseRustCrateFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\n",
		"src/lib.rs": "pub mod local;\npub mod other;\n",
		"src/other.rs": `use aes::Aes128;
use aes::cipher::KeyInit;
pub fn spawn() -> Aes128 { Aes128::new(&Default::default()) }
`,
		"src/local.rs": `pub struct Toy;
impl Toy {
    pub fn encrypt_block(&self, _b: &mut [u8]) {}
}
pub fn spawn() -> Toy { Toy }

pub fn go(b: &mut [u8]) {
    let c = spawn();
    c.encrypt_block(b);
}
`,
	}, "app")

	// Toy is declared in src/local.rs, so it belongs to the module `local`.
	if got["c.encrypt_block"] != "app::local.Toy.encrypt_block" {
		t.Errorf("c.encrypt_block resolved to %q, want %q — this file's own declaration wins", got["c.encrypt_block"], "app::local.Toy.encrypt_block")
	}
}

// A single-file module names a module of its own, exactly as a directory one
// does, and the contract KB keys it that way: `openssl::rsa::Rsa.generate`,
// from openssl's src/rsa.rs.
//
// Without the segment, a call inside rsa.rs emitted `openssl.(Rsa).generate`
// while the identical call from pkcs12.rs emitted `openssl::rsa.(Rsa).generate`
// — one matched its contract and the other did not. Worse, two sibling files
// declaring the same function name collapsed onto ONE key and the graph dropped
// an entire file's declarations: recovering that added roughly a thousand call
// edges across the sampled crates.
func TestRustParser_FileModulesExtendThePackagePath(t *testing.T) {
	t.Parallel()

	keys := parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\naes = \"0.8\"\ndes = \"0.8\"\n",
		"src/lib.rs": "pub mod modern;\npub mod legacy;\n",
		// Two sibling files, each declaring `run` and its own local helper type.
		"src/modern.rs": `use aes::cipher::{BlockEncrypt, KeyInit};

pub struct Holder { cipher: aes::Aes128 }

pub fn run(b: &mut [u8]) {
    let h = Holder { cipher: aes::Aes128::new(&Default::default()) };
    h.cipher.encrypt_block(b.into());
}
`,
		"src/legacy.rs": `use aes::cipher::{BlockEncrypt, KeyInit};

pub struct Holder { cipher: des::Des }

pub fn run(b: &mut [u8]) {
    let h = Holder { cipher: des::Des::new(&Default::default()) };
    h.cipher.encrypt_block(b.into());
}
`,
	}, "app")

	// Both files' declarations survive, each with its own cipher. Before the
	// file module extended the path, one file's whole declaration set was
	// dropped on the key collision.
	counts := countRustKeys(keys)
	for _, want := range []string{"aes.Aes128.encrypt_block", "des.Des.encrypt_block"} {
		if counts[want] != 1 {
			t.Errorf("want exactly one %q, got %d; keys = %v", want, counts[want], keys)
		}
	}
}

// The declarations themselves carry the file's module, which is what a contract
// keyed on a dependency's public path matches against.
func TestRustParser_FileModuleAppearsInDeclarationKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRustFile(t, dir, "Cargo.toml", "[package]\nname = \"openssl\"\nversion = \"0.10.81\"\n")
	writeRustFile(t, dir, "src/rsa.rs", `pub struct Rsa;

impl Rsa {
    pub fn generate(bits: u32) -> Self { Rsa }
    pub fn helper(&self) {}
    pub fn go(&self) { self.helper(); }
}
`)
	analyses, err := NewRustParser().ParseDirectory(filepath.Join(dir, "src"), "openssl")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			id := analysis.Functions[i].ID
			declared[id.Package+"."+id.Type+"."+id.Name] = true
		}
	}
	if !declared["openssl::rsa.Rsa.generate"] {
		t.Errorf("declaration not keyed under its file module; got %v", keysOfBool(declared))
	}
}
