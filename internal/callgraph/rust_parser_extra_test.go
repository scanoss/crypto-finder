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
