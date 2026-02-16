package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoParser_Basics(t *testing.T) {
	p := NewGoParser()

	if got := p.PackageSeparator(); got != "/" {
		t.Fatalf("PackageSeparator() = %q, want /", got)
	}
	skip := p.SkipDirs()
	if !skip["vendor"] || !skip["testdata"] {
		t.Fatalf("unexpected SkipDirs map: %#v", skip)
	}
	if got := p.SubPackagePath("example.com/root", "sub"); got != "example.com/root/sub" {
		t.Fatalf("SubPackagePath() = %q", got)
	}
}

func TestGoParser_ParseDirectoryAndFile(t *testing.T) {
	p := NewGoParser()
	dir := t.TempDir()

	src := `package mypkg

import (
	"fmt"
	alias "crypto/aes"
	"crypto/cipher"
)

func helper() {
	fmt.Println("ok")
}

type S struct{}

func (s *S) Encrypt(data []byte) {
	_, _ = alias.NewCipher(data)
	var b cipher.Block
	_ = b
	helper()
	s.internal()
}

func (s *S) internal() {}
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crypto_test.go"), []byte("package mypkg\nfunc TestX(){}"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "example.com/project/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (non-test file), got %d", len(analyses))
	}

	analysis := analyses[0]
	if analysis.PackageName != "mypkg" {
		t.Fatalf("PackageName = %q, want mypkg", analysis.PackageName)
	}
	if analysis.Imports["fmt"] != "fmt" {
		t.Fatalf("fmt import not resolved correctly: %#v", analysis.Imports)
	}
	if analysis.Imports["alias"] != "crypto/aes" {
		t.Fatalf("alias import not resolved correctly: %#v", analysis.Imports)
	}
	if analysis.Imports["cipher"] != "crypto/cipher" {
		t.Fatalf("cipher import not resolved correctly: %#v", analysis.Imports)
	}

	if len(analysis.Functions) < 3 {
		t.Fatalf("expected at least 3 functions, got %d", len(analysis.Functions))
	}

	foundMethod := false
	foundHelperCall := false
	foundAliasCall := false
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "Encrypt" {
			foundMethod = true
			for _, c := range fn.Calls {
				if c.Callee.Package == "example.com/project/mypkg" && c.Callee.Name == "helper" {
					foundHelperCall = true
				}
				if c.Callee.Package == "crypto/aes" && c.Callee.Name == "NewCipher" {
					foundAliasCall = true
				}
			}
		}
	}
	if !foundMethod {
		t.Fatal("expected method declaration for (*S).Encrypt")
	}
	if !foundHelperCall {
		t.Fatal("expected helper() call resolution in method")
	}
	if !foundAliasCall {
		t.Fatal("expected alias.NewCipher() call resolution in method")
	}

	_, err = p.ParseFile(filepath.Join(dir, "missing.go"), "example.com/project/mypkg")
	if err == nil {
		t.Fatal("expected ParseFile error for missing file")
	}
}

func TestGoParser_ParseDirectoryErrors(t *testing.T) {
	p := NewGoParser()
	_, err := p.ParseDirectory(filepath.Join(t.TempDir(), "missing"), "pkg")
	if err == nil {
		t.Fatal("expected ParseDirectory error for missing directory")
	}
}
