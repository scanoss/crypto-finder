package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRustParser_ParseFile_ModuleScopedFunctionUsesPackageNotType(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.rs")
	src := `fn use_crypto() {
    ring::aead::seal();
}
`
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := NewRustParser()
	analyses, err := p.ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 || len(analyses[0].Functions) != 1 || len(analyses[0].Functions[0].Calls) != 1 {
		t.Fatalf("unexpected analyses: %#v", analyses)
	}

	call := analyses[0].Functions[0].Calls[0]
	if call.Callee.Package != "ring::aead" || call.Callee.Type != "" || call.Callee.Name != "seal" {
		t.Fatalf("unexpected scoped call callee: %#v", call.Callee)
	}
}

func parseRustInline(t *testing.T, src string) []FunctionDecl {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "lib.rs")
	if err := os.WriteFile(filePath, []byte(src), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "mycrate")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(analyses))
	}
	return analyses[0].Functions
}

func rustFunctionByName(t *testing.T, fns []FunctionDecl, name string) *FunctionDecl {
	t.Helper()
	for i := range fns {
		if fns[i].ID.Name == name {
			return &fns[i]
		}
	}
	t.Fatalf("function %q not found in %#v", name, fns)
	return nil
}

func TestRustParser_ReturnIdentifier_PopulatesReturnSources(t *testing.T) {
	fns := parseRustInline(t, `fn direct(key: Key) -> Key { return key; }`)
	fn := rustFunctionByName(t, fns, "direct")
	if len(fn.ReturnSources) != 1 {
		t.Fatalf("expected 1 return source, got %#v", fn.ReturnSources)
	}
	rs := fn.ReturnSources[0]
	if rs.Type != "VARIABLE" || rs.Name != "key" || rs.DeclaredType != "Key" {
		t.Fatalf("unexpected return source: %#v", rs)
	}
}

func TestRustParser_ReturnFactory_PopulatesCallTarget(t *testing.T) {
	fns := parseRustInline(t, `fn factory(unbound: UnboundKey) -> LessSafeKey {
    ring::aead::LessSafeKey::new(unbound)
}`)
	fn := rustFunctionByName(t, fns, "factory")
	if len(fn.ReturnSources) != 1 {
		t.Fatalf("expected 1 return source, got %#v", fn.ReturnSources)
	}
	rs := fn.ReturnSources[0]
	if rs.Type != "CALL_RESULT" || rs.CallTarget == nil {
		t.Fatalf("expected call-result return source with target, got %#v", rs)
	}
	want := FunctionID{Package: "ring::aead", Type: "LessSafeKey", Name: "new"}
	if *rs.CallTarget != want {
		t.Fatalf("CallTarget = %#v, want %#v", *rs.CallTarget, want)
	}
}

func TestRustParser_Chacha20Poly1305CallsKeepConcreteTypeEvidence(t *testing.T) {
	fns := parseRustInline(t, `use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
fn seal(key: Key, nonce: Nonce, plaintext: &[u8], buffer: &mut [u8]) {
    let cipher = ChaCha20Poly1305::new(&key);
    cipher.encrypt(&nonce, plaintext);
    cipher.encrypt_inout_detached(&nonce, b"", buffer);
}`)

	fn := rustFunctionByName(t, fns, "seal")
	if len(fn.Calls) != 3 {
		t.Fatalf("calls = %#v, want constructor plus two operations", fn.Calls)
	}
	want := []FunctionID{
		{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "new"},
		{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "encrypt"},
		{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "encrypt_inout_detached"},
	}
	for i, expected := range want {
		if fn.Calls[i].Callee != expected {
			t.Fatalf("calls[%d] = %#v, want %#v", i, fn.Calls[i].Callee, expected)
		}
	}
}

func TestRustParser_UnknownAndBareReturn_NoReturnSources(t *testing.T) {
	fns := parseRustInline(t, `fn unknown(flag: bool) -> Key { if flag { key } else { other } }
fn bare() { return; }`)
	for _, name := range []string{"unknown", "bare"} {
		fn := rustFunctionByName(t, fns, name)
		if len(fn.ReturnSources) != 0 {
			t.Fatalf("%s: expected no return sources, got %#v", name, fn.ReturnSources)
		}
	}
}

func TestRustParser_ReturnSources_RespectFunctionScope(t *testing.T) {
	fns := parseRustInline(t, `fn mixed(flag: bool, early: Key, tail: Key) -> Key {
    if flag { return early; }
    tail
}
fn outer(real: Key, wrong: Key) -> Key {
    let closure = || { return wrong; };
    fn nested(wrong: Key) -> Key { return wrong; }
    let _ = closure;
    let _ = nested;
    return real;
}`)

	mixed := rustFunctionByName(t, fns, "mixed")
	if len(mixed.ReturnSources) != 2 || mixed.ReturnSources[0].Name != "early" || mixed.ReturnSources[1].Name != "tail" {
		t.Fatalf("mixed ReturnSources = %#v, want early and tail", mixed.ReturnSources)
	}

	outer := rustFunctionByName(t, fns, "outer")
	if len(outer.ReturnSources) != 1 || outer.ReturnSources[0].Name != "real" {
		t.Fatalf("outer ReturnSources = %#v, want only real", outer.ReturnSources)
	}
}
