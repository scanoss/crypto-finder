package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoParser_PredeclaredIdentifiersAreNotCalls pins Go's universe scope: a
// predeclared identifier belongs to no package, so it must not be recorded as a
// call into the caller's own package. Attributing them there invented callees
// like `app.len` that match no declaration and reach no user code — 26% of all
// call sites on this repository's own source before the fix.
func TestGoParser_PredeclaredIdentifiersAreNotCalls(t *testing.T) {
	src := `package app

import "crypto/aes"

func encrypt(key []byte) error {
	buf := make([]byte, len(key))
	n := int(len(buf))
	copy(buf, key)
	block, err := aes.NewCipher(buf)
	if err != nil {
		panic(err)
	}
	_ = n
	_ = block
	return helper()
}

func helper() error { return nil }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	var keys []string
	for _, a := range analyses {
		for i := range a.Functions {
			for j := range a.Functions[i].Calls {
				keys = append(keys, a.Functions[i].Calls[j].Callee.String())
			}
		}
	}

	for _, predeclared := range []string{"make", "len", "int", "copy", "panic"} {
		for _, k := range keys {
			if strings.HasSuffix(k, "."+predeclared) {
				t.Errorf("predeclared %q recorded as a call to %q; it belongs to no package", predeclared, k)
			}
		}
	}

	// las llamadas reales siguen ahi
	wantAny := []string{"crypto/aes.NewCipher", "app.helper"}
	for _, want := range wantAny {
		found := false
		for _, k := range keys {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing real call %q; recorded: %v", want, keys)
		}
	}
}
