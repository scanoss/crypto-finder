// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rustEncryptBlockKeys returns, per function name, the resolved FQN of every
// call whose raw text contains "encrypt_block" -- the terminal call each
// scenario below routes an Option/Result-wrapped cipher through.
func rustEncryptBlockKeys(t *testing.T, src string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	got := map[string]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				if !strings.Contains(call.Raw, "encrypt_block") {
					continue
				}
				fqn, _ := splitMethodArity(&call.Callee)
				got[fn.ID.Name] = fqn
			}
		}
	}
	return got
}

// A cipher built behind a fallible constructor (`Result<Aes128, _>`) is a
// documented RustCrypto idiom (`Aes128::new_from_slice`), and code reaches the
// cipher itself in several equally common ways. None of these Deref through
// the wrapper -- Option and Result deliberately do not -- so each shape needs
// its own extraction: `.unwrap()`/`.expect()` (an explicit accessor), `?` (a
// transparent expression), and a tuple-struct pattern (`Ok(c)`/`Some(c)`) in
// an `if let` or a `match` arm. All resolve today; this pins that they keep
// doing so.
func TestRustParser_OptionResultExtractionFormsResolveTheInnerType(t *testing.T) {
	t.Parallel()

	const body = `
use aes::Aes128;
use aes::cipher::KeyInit;
`
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "unwrap on a Result",
			src: body + `
fn via_unwrap(k: &[u8; 16]) {
    let c = Aes128::new_from_slice(k).unwrap();
    c.encrypt_block(&mut [0u8; 16]);
}
`,
		},
		{
			name: "expect on a Result",
			src: body + `
fn via_expect(k: &[u8; 16]) {
    let c = Aes128::new_from_slice(k).expect("bad key");
    c.encrypt_block(&mut [0u8; 16]);
}
`,
		},
		{
			name: "bare try operator on a Result",
			src: body + `
fn via_try(k: &[u8; 16]) -> Result<(), aes::cipher::InvalidLength> {
    let c = Aes128::new_from_slice(k)?;
    c.encrypt_block(&mut [0u8; 16]);
    Ok(())
}
`,
		},
		{
			name: "try operator chained through map_err on a Result",
			src: body + `
fn via_try_map_err(k: &[u8; 16]) -> Result<(), ()> {
    let c = Aes128::new_from_slice(k).map_err(|_| ())?;
    c.encrypt_block(&mut [0u8; 16]);
    Ok(())
}
`,
		},
		{
			name: "if-let Ok pattern on a Result",
			src: body + `
fn via_if_let(k: &[u8; 16]) {
    if let Ok(c) = Aes128::new_from_slice(k) {
        c.encrypt_block(&mut [0u8; 16]);
    }
}
`,
		},
		{
			name: "match Ok arm on a Result",
			src: body + `
fn via_match(k: &[u8; 16]) {
    match Aes128::new_from_slice(k) {
        Ok(c) => c.encrypt_block(&mut [0u8; 16]),
        Err(_) => {}
    }
}
`,
		},
		{
			name: "unwrap on an Option",
			src: body + `
fn make(k: &[u8; 16]) -> Option<Aes128> { Aes128::new_from_slice(k).ok() }
fn via_option_unwrap(k: &[u8; 16]) {
    let c = make(k).unwrap();
    c.encrypt_block(&mut [0u8; 16]);
}
`,
		},
		{
			name: "if-let Some pattern on an Option",
			src: body + `
fn make(k: &[u8; 16]) -> Option<Aes128> { Aes128::new_from_slice(k).ok() }
fn via_option_if_let(k: &[u8; 16]) {
    if let Some(c) = make(k) {
        c.encrypt_block(&mut [0u8; 16]);
    }
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rustEncryptBlockKeys(t, tt.src)
			for fn, fqn := range got {
				if !strings.Contains(fqn, "aes.Aes128.encrypt_block") {
					t.Errorf("%s: encrypt_block resolved to %q, want it to name aes.Aes128", fn, fqn)
				}
			}
			if len(got) == 0 {
				t.Fatal("no encrypt_block call found in fixture")
			}
		})
	}
}

// When the wrapped value's own type cannot be inferred at all (an external
// function this file never declares), extraction must carry that absence
// through rather than inventing an identity for the value it unwraps.
func TestRustParser_OptionResultExtractionOfAnUnresolvableInnerDegradesSafely(t *testing.T) {
	t.Parallel()

	got := rustEncryptBlockKeys(t, `
fn go() {
    let c = some_external_fn().unwrap();
    c.encrypt_block(&mut [0u8; 16]);
}
`)
	fqn, ok := got["go"]
	if !ok {
		t.Fatal("no encrypt_block call found in fixture")
	}
	if strings.Contains(fqn, ".(") || strings.Count(fqn, ".") > 1 {
		t.Errorf("unresolvable inner type produced a typed key: %q, want no type segment", fqn)
	}
}
