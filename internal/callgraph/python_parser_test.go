package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonParser_PackageSeparator(t *testing.T) {
	p := NewPythonParser()
	if got := p.PackageSeparator(); got != "." {
		t.Errorf("PackageSeparator() = %q, want %q", got, ".")
	}
}

func TestPythonParser_SkipDirs(t *testing.T) {
	p := NewPythonParser()
	skip := p.SkipDirs()
	expected := []string{"__pycache__", ".venv", "venv", "test", "tests", ".tox"}
	for _, dir := range expected {
		if !skip[dir] {
			t.Errorf("SkipDirs() missing %q", dir)
		}
	}
}

func TestPythonParser_SubPackagePath(t *testing.T) {
	p := NewPythonParser()
	tests := []struct {
		parent, dir, want string
	}{
		{"cryptography", "hazmat", "cryptography.hazmat"},
		{"", "cryptography", "cryptography"},
		{"cryptography.hazmat", "primitives", "cryptography.hazmat.primitives"},
	}
	for _, tt := range tests {
		got := p.SubPackagePath(tt.parent, tt.dir)
		if got != tt.want {
			t.Errorf("SubPackagePath(%q, %q) = %q, want %q", tt.parent, tt.dir, got, tt.want)
		}
	}
}

func TestPythonParser_ParseFile(t *testing.T) {
	src := `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from os import urandom

def generate_key(size):
    return urandom(size)

def encrypt(key, data):
    algo = algorithms.AES(key)
    cipher = Cipher(algo, None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

class CryptoHelper:
    def __init__(self, key):
        self.key = key

    def hash_data(self, data):
        return hashlib.sha256(data).hexdigest()

    def encrypt_data(self, data):
        return encrypt(self.key, data)
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto_utils.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]

	// Check imports
	expectedImports := map[string]string{
		"hashlib":    "hashlib",
		"Cipher":     "cryptography.hazmat.primitives.ciphers",
		"algorithms": "cryptography.hazmat.primitives.ciphers",
		"urandom":    "os",
	}
	for name, pkg := range expectedImports {
		if analysis.Imports[name] != pkg {
			t.Errorf("import %q = %q, want %q", name, analysis.Imports[name], pkg)
		}
	}
	if !analysis.ImportedTypes["Cipher"] {
		t.Error("expected Cipher import to be classified as a type")
	}
	if analysis.ImportedTypes["urandom"] {
		t.Error("expected urandom import to remain classified as a function")
	}

	// Check functions
	funcNames := make(map[string]bool)
	for _, fn := range analysis.Functions {
		key := fn.ID.Type + "." + fn.ID.Name
		funcNames[key] = true
	}

	if !funcNames[".generate_key"] {
		t.Error("missing function 'generate_key'")
	}
	if !funcNames[".encrypt"] {
		t.Error("missing function 'encrypt'")
	}
	if !funcNames["CryptoHelper.<init>"] {
		t.Error("missing method 'CryptoHelper.__init__' (mapped to <init>)")
	}
	if !funcNames["CryptoHelper.hash_data"] {
		t.Error("missing method 'CryptoHelper.hash_data'")
	}
	if !funcNames["CryptoHelper.encrypt_data"] {
		t.Error("missing method 'CryptoHelper.encrypt_data'")
	}

	// Check that encrypt function has calls
	for _, fn := range analysis.Functions {
		if fn.ID.Name != "encrypt" || fn.ID.Type != "" {
			continue
		}
		if len(fn.Calls) == 0 {
			t.Error("encrypt function should have calls")
		}
		// Verify Cipher constructor call resolves through imports
		foundCipherCall := false
		for _, call := range fn.Calls {
			if call.Callee.Type == "Cipher" && call.Callee.Name == "<init>" {
				foundCipherCall = true
				if call.Callee.Package != "cryptography.hazmat.primitives.ciphers" {
					t.Errorf("Cipher call package = %q, want %q", call.Callee.Package, "cryptography.hazmat.primitives.ciphers")
				}
			}
		}
		if !foundCipherCall {
			t.Error("encrypt function should have a Cipher() constructor call")
		}
		break
	}

	// Check that hash_data method resolves hashlib.sha256
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "hash_data" {
			foundHashCall := false
			for _, call := range fn.Calls {
				if call.Callee.Package == "hashlib" && call.Callee.Name == "sha256" {
					foundHashCall = true
				}
			}
			if !foundHashCall {
				t.Error("hash_data should have a hashlib.sha256 call")
			}
			break
		}
	}
}

func TestPythonParser_ImportedFunctionCallIsNotConstructor(t *testing.T) {
	src := `from hashlib import sha256

def digest(data):
    return sha256(data)
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "digest.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}

	analysis := analyses[0]
	if analysis.ImportedTypes["sha256"] {
		t.Fatal("expected sha256 import not to be classified as a type")
	}

	for _, fn := range analysis.Functions {
		if fn.ID.Name != "digest" || fn.ID.Type != "" {
			continue
		}
		for _, call := range fn.Calls {
			if call.Callee.Package == "hashlib" && call.Callee.Name == "sha256" {
				if call.Callee.Type != "" {
					t.Fatalf("sha256 call type = %q, want empty", call.Callee.Type)
				}
				return
			}
		}
		t.Fatal("expected digest to contain hashlib.sha256 call")
	}

	t.Fatal("expected digest function analysis")
}

func TestPythonParser_IncludeTestsIncludesTestFilesAndDirs(t *testing.T) {
	p := NewPythonParser(WithIncludeTests(true))
	dir := t.TempDir()

	testDir := filepath.Join(dir, "tests")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "test_crypto.py"), []byte("def test_encrypt():\n    return None\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(testDir, "myproject.tests")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (test file included), got %d", len(analyses))
	}
	if p.SkipDirs()["tests"] {
		t.Fatal("expected tests dir not to be skipped when includeTests is enabled")
	}
}

func TestPythonParser_SkipTestFiles(t *testing.T) {
	dir := t.TempDir()

	// Regular file
	os.WriteFile(filepath.Join(dir, "crypto.py"), []byte("def foo(): pass"), 0o644)
	// Test files — should be skipped
	os.WriteFile(filepath.Join(dir, "test_crypto.py"), []byte("def test_foo(): pass"), 0o644)
	os.WriteFile(filepath.Join(dir, "crypto_test.py"), []byte("def test_bar(): pass"), 0o644)

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "test_pkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}

	if len(analyses) != 1 {
		t.Errorf("expected 1 analysis (only crypto.py), got %d", len(analyses))
	}
}

func TestPythonParser_DunderMethodSkip(t *testing.T) {
	src := `class MyClass:
    def __init__(self, x):
        self.x = x

    def __repr__(self):
        return f"MyClass({self.x})"

    def __str__(self):
        return str(self.x)

    def real_method(self):
        return self.x
`
	dir := t.TempDir()
	filePath := filepath.Join(dir, "myclass.py")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatalf("expected at least 1 analysis from ParseDirectory(%q), got 0", dir)
	}

	analysis := analyses[0]

	// Should have __init__ (as <init>) and real_method, but NOT __repr__ or __str__
	funcNames := make(map[string]bool)
	for _, fn := range analysis.Functions {
		funcNames[fn.ID.Name] = true
	}

	if !funcNames["<init>"] {
		t.Error("missing __init__ (mapped to <init>)")
	}
	if !funcNames["real_method"] {
		t.Error("missing real_method")
	}
	if funcNames["__repr__"] {
		t.Error("__repr__ should be skipped")
	}
	if funcNames["__str__"] {
		t.Error("__str__ should be skipped")
	}
}

// TestPythonParser_FunctionCallCarriesNonZeroColumns verifies that FunctionCall
// structs produced by the Python parser populate StartCol and EndCol (parity with
// the Java parser). Zero values indicate the column-aware path was skipped, which
// would cause column-based disambiguation in annotate_supporting.go to fall back
// to line-only matching.
func TestPythonParser_FunctionCallCarriesNonZeroColumns(t *testing.T) {
	src := `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher

def encrypt(key, data):
    digest = hashlib.sha256(key)
    cipher = Cipher(key, None)
    return cipher.encryptor()
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "col_check.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPythonParser()
	analyses, err := p.ParseDirectory(dir, "mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) == 0 {
		t.Fatal("expected at least one analysis")
	}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				if call.StartCol == 0 || call.EndCol == 0 {
					t.Errorf("call %s.%s at line %d has zero StartCol=%d or EndCol=%d; Python parser must populate column spans",
						call.Callee.Package, call.Callee.Name, call.Line, call.StartCol, call.EndCol)
				}
				if call.StartCol > call.EndCol {
					t.Errorf("call %s.%s at line %d: StartCol=%d > EndCol=%d (invalid span)",
						call.Callee.Package, call.Callee.Name, call.Line, call.StartCol, call.EndCol)
				}
			}
		}
	}
}
