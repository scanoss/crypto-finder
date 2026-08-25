// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A library that opens its namespace with a macro leaves its declarations as
// siblings of the macro call, not children, so scope has to carry forward. Without
// that, every type in such a library resolves unqualified and no rule or contract
// anchored on the qualified name matches the library's own sources.
func TestCPPParserResolvesMacroOpenedNamespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, src, wantType string
	}{
		{
			name: "macro opened",
			src: `NAMESPACE_BEGIN(CryptoPP)
void SHA256::InitState(int *state) { (void)state; }
NAMESPACE_END`,
			wantType: "CryptoPP::SHA256",
		},
		{
			name: "nested macro namespaces",
			src: `NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Weak1)
void MD5::Init(int *state) { (void)state; }
NAMESPACE_END
NAMESPACE_END`,
			wantType: "CryptoPP::Weak1::MD5",
		},
		{
			name: "closed before the definition",
			src: `NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_END
void Local::Init(int *state) { (void)state; }`,
			wantType: "Local",
		},
		{
			name: "literal namespace still resolves",
			src: `namespace CryptoPP {
void SHA256::InitState(int *state) { (void)state; }
}`,
			wantType: "CryptoPP::SHA256",
		},
		{
			name: "already qualified is not doubled",
			src: `NAMESPACE_BEGIN(CryptoPP)
void CryptoPP::SHA256::InitState(int *state) { (void)state; }
NAMESPACE_END`,
			wantType: "CryptoPP::SHA256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "lib.cpp"), []byte(tt.src+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewCPPParser().ParseDirectory(dir, "lib")
			if err != nil {
				t.Fatal(err)
			}
			if len(analyses) != 1 || len(analyses[0].Functions) != 1 {
				t.Fatalf("analyses = %#v, want one function", analyses)
			}
			if got := analyses[0].Functions[0].ID.Type; got != tt.wantType {
				t.Fatalf("Type = %q, want %q", got, tt.wantType)
			}
		})
	}
}
