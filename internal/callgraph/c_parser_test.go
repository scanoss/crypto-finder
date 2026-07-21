package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCParser_ParseDirectory(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.c")
	src := `#include <openssl/evp.h>
#include "local/crypto.h"

EVP_CIPHER_CTX *build_ctx(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    unknown_call(ctx);
    return ctx;
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewCParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}

	analysis := analyses[0]
	if analysis.Imports["openssl/evp.h"] != "openssl/evp.h" || analysis.Imports["local/crypto.h"] != "local/crypto.h" {
		t.Fatalf("imports = %#v, want both include paths", analysis.Imports)
	}
	if len(analysis.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(analysis.Functions))
	}
	fn := analysis.Functions[0]
	if fn.ID != (FunctionID{Package: "example/crypto", Name: "build_ctx"}) {
		t.Fatalf("function ID = %#v", fn.ID)
	}

	calls := make(map[string]FunctionCall, len(fn.Calls))
	for _, call := range fn.Calls {
		calls[call.Callee.Name] = call
	}
	for _, name := range []string{"EVP_CIPHER_CTX_new", "EVP_EncryptInit_ex", "EVP_aes_256_gcm", "unknown_call"} {
		if _, ok := calls[name]; !ok {
			t.Errorf("missing call %q in %#v", name, fn.Calls)
		}
	}
	if got := calls["EVP_CIPHER_CTX_new"].AssignedVar; got != "ctx" {
		t.Errorf("factory AssignedVar = %q, want ctx", got)
	}
	outer := calls["EVP_EncryptInit_ex"]
	if outer.Line != 6 || outer.StartCol != 5 || outer.EndCol != 65 {
		t.Errorf("EVP_EncryptInit_ex position = line %d, cols %d:%d, want 6, 5:65", outer.Line, outer.StartCol, outer.EndCol)
	}
}

func TestCParser_Basics(t *testing.T) {
	p := NewCParser(WithIncludeTests(true))
	if !p.includeTests {
		t.Fatal("WithIncludeTests option was not preserved")
	}
	if got := p.PackageSeparator(); got != "/" {
		t.Fatalf("PackageSeparator() = %q, want /", got)
	}
	if got := p.SubPackagePath("example", "crypto"); got != "example/crypto" {
		t.Fatalf("SubPackagePath() = %q, want example/crypto", got)
	}
	if !p.SkipDirs()["vendor"] || !p.SkipDirs()["build"] {
		t.Fatalf("SkipDirs() = %#v", p.SkipDirs())
	}
	if _, ok := p.CloneParser().(*CParser); !ok {
		t.Fatalf("CloneParser() = %T, want *CParser", p.CloneParser())
	}
}

func TestCParser_StaticFunctionsAreTranslationUnitScoped(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"one.c": "static void helper(void) {}\nvoid one(void) { helper(); }\n",
		"two.c": "static void helper(void) {}\nvoid two(void) { helper(); }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	analyses, err := NewCParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatal(err)
	}
	callPackages := make(map[string]string)
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			if fn.ID.Name != "helper" && len(fn.Calls) == 1 {
				callPackages[fn.ID.Name] = fn.Calls[0].Callee.Package
			}
		}
	}
	if callPackages["one"] == callPackages["two"] {
		t.Fatalf("static helper calls share package %q; want translation-unit-specific identities", callPackages["one"])
	}
}

func TestCParser_ReturnSources(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "returns.c")
	src := `void *direct(void *value) {
    return value;
}

EVP_CIPHER_CTX *factory(void) {
    return EVP_CIPHER_CTX_new();
}

int unknown(int value) {
    return value + 1;
}

void no_return(void) {
    return;
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := NewCParser().ParseDirectory(dir, "example/crypto")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}

	direct := findCFunction(t, analyses[0], "direct")
	if direct.ReturnType != "void*" {
		t.Fatalf("direct ReturnType = %q, want void*", direct.ReturnType)
	}
	if got := direct.ReturnSources; len(got) != 1 || got[0].Type != "VARIABLE" || got[0].Name != "value" {
		t.Fatalf("direct ReturnSources = %#v, want VARIABLE value", got)
	}

	factory := findCFunction(t, analyses[0], "factory")
	if factory.ReturnType != "EVP_CIPHER_CTX*" {
		t.Fatalf("factory ReturnType = %q, want EVP_CIPHER_CTX*", factory.ReturnType)
	}
	if got := factory.ReturnSources; len(got) != 1 || got[0].Type != "CALL_RESULT" || got[0].CallTarget == nil || got[0].CallTarget.Name != "EVP_CIPHER_CTX_new#0" || got[0].CallTarget.Package != "example/crypto" {
		t.Fatalf("factory ReturnSources = %#v, want CALL_RESULT example/crypto.EVP_CIPHER_CTX_new#0", got)
	}

	for _, name := range []string{"unknown", "no_return"} {
		if got := findCFunction(t, analyses[0], name).ReturnSources; len(got) != 0 {
			t.Errorf("%s ReturnSources = %#v, want none", name, got)
		}
	}
}

func findCFunction(t *testing.T, analysis *FileAnalysis, name string) *FunctionDecl {
	t.Helper()
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Name == name {
			return &analysis.Functions[i]
		}
	}
	t.Fatalf("function %q not found", name)
	return nil
}
