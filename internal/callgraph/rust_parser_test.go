package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRustParser_PackageSeparator(t *testing.T) {
	p := NewRustParser()
	if got := p.PackageSeparator(); got != "::" {
		t.Errorf("PackageSeparator() = %q, want %q", got, "::")
	}
}

func TestRustParser_SkipDirs(t *testing.T) {
	p := NewRustParser()
	skip := p.SkipDirs()
	expected := []string{"target", "tests", "benches", "examples"}
	for _, dir := range expected {
		if !skip[dir] {
			t.Errorf("SkipDirs() missing %q", dir)
		}
	}
}

func TestRustParser_SubPackagePath(t *testing.T) {
	p := NewRustParser()
	tests := []struct {
		parent, dir, want string
	}{
		{"ring", "aead", "ring::aead"},
		{"", "ring", "ring"},
		{"ring::aead", "gcm", "ring::aead::gcm"},
		// src/ is the crate root in Rust — transparent in module paths
		{"ring", "src", "ring"},
		{"", "src", ""},
	}
	for _, tt := range tests {
		got := p.SubPackagePath(tt.parent, tt.dir)
		if got != tt.want {
			t.Errorf("SubPackagePath(%q, %q) = %q, want %q", tt.parent, tt.dir, got, tt.want)
		}
	}
}

func TestRustParser_ParseFile(t *testing.T) {
	src := `use ring::aead::{Aead, UnboundKey};
use ring::aead;

fn encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
    let sealing_key = aead::LessSafeKey::new(unbound);
    sealing_key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut data.to_vec()).unwrap();
    data.to_vec()
}

struct MyCrypto {
    key: Vec<u8>,
}

impl MyCrypto {
    fn new(key: Vec<u8>) -> Self {
        MyCrypto { key }
    }

    fn do_encrypt(&self, data: &[u8]) -> Vec<u8> {
        encrypt(&self.key, data)
    }
}
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.rs")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewRustParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]

	// Check imports
	if analysis.Imports["Aead"] != "ring::aead" {
		t.Errorf("import Aead = %q, want %q", analysis.Imports["Aead"], "ring::aead")
	}
	if analysis.Imports["UnboundKey"] != "ring::aead" {
		t.Errorf("import UnboundKey = %q, want %q", analysis.Imports["UnboundKey"], "ring::aead")
	}

	// Check functions
	funcNames := make(map[string]bool)
	for _, fn := range analysis.Functions {
		key := fn.ID.Type + "." + fn.ID.Name
		funcNames[key] = true
	}

	if !funcNames[".encrypt"] {
		t.Error("missing function 'encrypt'")
	}
	if !funcNames["MyCrypto.new"] {
		t.Error("missing method 'MyCrypto.new'")
	}
	if !funcNames["MyCrypto.do_encrypt"] {
		t.Error("missing method 'MyCrypto.do_encrypt'")
	}

	// Check that encrypt has calls
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "encrypt" && fn.ID.Type == "" {
			if len(fn.Calls) == 0 {
				t.Error("encrypt function should have calls")
			}
			break
		}
	}
}

func TestRustParser_SkipTestFiles(t *testing.T) {
	dir := t.TempDir()

	// Regular file
	os.WriteFile(filepath.Join(dir, "lib.rs"), []byte("fn foo() {}"), 0o644)
	// Test file — should be skipped
	os.WriteFile(filepath.Join(dir, "lib_test.rs"), []byte("fn test_foo() {}"), 0o644)
	// Another test file
	os.WriteFile(filepath.Join(dir, "tests.rs"), []byte("fn test_bar() {}"), 0o644)

	p := NewRustParser()
	analyses, err := p.ParseDirectory(dir, "test_pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}

	if len(analyses) != 1 {
		t.Errorf("expected 1 analysis (only lib.rs), got %d", len(analyses))
	}
}
