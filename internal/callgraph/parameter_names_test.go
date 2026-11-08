// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func parameterNames(fn *FunctionDecl) []string {
	names := make([]string, len(fn.Parameters))
	for i := range fn.Parameters {
		names[i] = fn.Parameters[i].Name
	}
	return names
}

// TestGoParser_RecordsParameterNames: a scan maps an argument a caller passes
// onto the callee parameter that receives it, which needs every parameter's
// name, also when one declaration names several (`key, nonce []byte`).
func TestGoParser_RecordsParameterNames(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `package app

type S struct{}

func seal(key, nonce []byte, n int) {}

func (s *S) helper(iv []byte) {}

func unnamed(int, string) {}
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "example.com/app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	want := map[string][]string{
		"seal":    {"key", "nonce", "n"},
		"helper":  {"iv"},
		"unnamed": {"", ""},
	}
	seen := 0
	for _, a := range analyses {
		for i := range a.Functions {
			fn := &a.Functions[i]
			names, ok := want[fn.ID.Name]
			if !ok {
				continue
			}
			seen++
			if got := parameterNames(fn); !slices.Equal(got, names) {
				t.Errorf("%s parameter names = %q, want %q", fn.ID.Name, got, names)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("saw %d of %d functions", seen, len(want))
	}
}

func TestRustParser_RecordsParameterNames(t *testing.T) {
	t.Parallel()

	fns := parseRustInline(t, `
struct S;

impl S {
    fn seal(&self, mut key: Vec<u8>, nonce: &[u8]) {}
}

fn derive(pw: &[u8], (a, b): (u8, u8), salt: &[u8]) {}
`)
	for name, want := range map[string][]string{
		"seal":   {"self", "key", "nonce"},
		"derive": {"pw", "", "salt"},
	} {
		if got := parameterNames(rustFunctionByName(t, fns, name)); !slices.Equal(got, want) {
			t.Errorf("%s parameter names = %q, want %q", name, got, want)
		}
	}
}
