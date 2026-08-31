// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"path/filepath"
	"strings"
	"testing"
)

// findRustCallByName parses a one-file crate and returns the first call whose
// callee name matches, so ReceiverVar — which parseRustCrateAllKeys discards —
// can be asserted directly.
func findRustCallByName(t *testing.T, files map[string]string, importPath, calleeName string) *FunctionCall {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writeRustFile(t, dir, name, content)
	}
	parser := NewRustParser()
	analyses, err := parser.ParseDirectory(filepath.Join(dir, "src"), importPath)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				if analysis.Functions[i].Calls[j].Callee.Name == calleeName {
					return &analysis.Functions[i].Calls[j]
				}
			}
		}
	}
	return nil
}

// `Trait::method(&mut recv, args)` / `Type::method(recv, args)` are exactly
// equivalent to `recv.method(args)` (Rust's fully-qualified syntax) and must
// carry the same ReceiverVar, so a caller that mixes both spellings for the
// same object is recognized as touching the same object — the mechanism
// AGENTS.md documents supporting-call derivation on.
func TestRustParser_UFCSCallResolvesLikeAMethodCall(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
`
	tests := []struct {
		name            string
		src             string
		wantReceiverVar string
		wantCalleePkg   string
		wantCalleeType  string
	}{
		{
			name: "trait-qualified UFCS on a generic parameter bound to the trait",
			src: `use sha2::Digest;

fn generic_hash<D: Digest>(d: &mut D, data: &[u8]) {
    Digest::update(d, data);
}
`,
			wantReceiverVar: "d",
			wantCalleePkg:   "sha2",
			wantCalleeType:  "Digest",
		},
		{
			name: "type-qualified UFCS on a concrete binding",
			src: `use sha2::{Digest, Sha256};

fn go(data: &[u8]) {
    let mut h = Sha256::new();
    Sha256::update(&mut h, data);
}
`,
			wantReceiverVar: "h",
			wantCalleePkg:   "sha2",
			wantCalleeType:  "Sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := findRustCallByName(t, map[string]string{
				"Cargo.toml":  manifest,
				"src/main.rs": tt.src,
			}, "app", "update")
			if call == nil {
				t.Fatal("no call to `update` found")
			}
			if call.ReceiverVar != tt.wantReceiverVar {
				t.Errorf("ReceiverVar = %q, want %q — the UFCS form lost the receiver a dotted call would have kept", call.ReceiverVar, tt.wantReceiverVar)
			}
			if call.Callee.Package != tt.wantCalleePkg || call.Callee.Type != tt.wantCalleeType {
				t.Errorf("Callee = %s.%s.%s, want %s.%s.update", call.Callee.Package, call.Callee.Type, call.Callee.Name, tt.wantCalleePkg, tt.wantCalleeType)
			}
		})
	}
}

// A genuine receiverless call must not be rewritten just because its first
// argument happens to have a known, unrelated type.
func TestRustParser_UFCSRewriteDoesNotFireOnAGenuineStaticCall(t *testing.T) {
	t.Parallel()

	manifest := `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
`
	src := `use aes::Aes128;

fn go(key: &[u8; 16]) {
    let _c = Aes128::new_from_slice(key);
}
`
	joined := strings.Join(parseRustCrateAllKeys(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app"), "\n")
	if !strings.Contains(joined, "aes.Aes128.new_from_slice") {
		t.Errorf("a genuine associated-function call must still resolve normally; got:\n%s", joined)
	}
	call := findRustCallByName(t, map[string]string{
		"Cargo.toml":  manifest,
		"src/main.rs": src,
	}, "app", "new_from_slice")
	if call == nil {
		t.Fatal("no call to `new_from_slice` found")
	}
	if call.ReceiverVar != "" {
		t.Errorf("a genuine static call must not gain a ReceiverVar; got %q", call.ReceiverVar)
	}
}
