// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A turbofish on a constructor belongs to the type, not to the identity of the
// variable it produces. Before the fix this pinned, `Blowfish::<LE>::new(..)`
// left the variable typed "Blowfish::" — a name no import resolves — so every
// later call on that variable was emitted under the local package as
// "app.Blowfish::.encrypt_block" instead of "blowfish.Blowfish.encrypt_block".
// A wrong key is worse than a missing one: it looks like data and joins to
// nothing, so both spellings are asserted exactly and against each other.
func TestRustParser_TurbofishConstructorKeepsReceiverIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "turbofish on an imported type",
			src: `use blowfish::Blowfish;
use byteorder::LE;
fn go(k: &[u8], block: &mut [u8; 8]) {
    let c = Blowfish::<LE>::new_from_slice(k).unwrap();
    c.encrypt_block(block.into());
    c.decrypt_block(block.into());
}`,
			want: []string{
				"blowfish.Blowfish.new_from_slice",
				"blowfish.Blowfish.encrypt_block",
				"blowfish.Blowfish.decrypt_block",
			},
		},
		{
			name: "no turbofish, same identities",
			src: `use blowfish::Blowfish;
fn go(k: &[u8], block: &mut [u8; 8]) {
    let c = Blowfish::new_from_slice(k).unwrap();
    c.encrypt_block(block.into());
    c.decrypt_block(block.into());
}`,
			want: []string{
				"blowfish.Blowfish.new_from_slice",
				"blowfish.Blowfish.encrypt_block",
				"blowfish.Blowfish.decrypt_block",
			},
		},
		{
			name: "turbofish on a fully qualified path",
			src: `use byteorder::LE;
fn go(k: &[u8], block: &mut [u8; 8]) {
    let c = blowfish::Blowfish::<LE>::new_from_slice(k).unwrap();
    c.encrypt_block(block.into());
}`,
			want: []string{
				"blowfish.Blowfish.new_from_slice",
				"blowfish.Blowfish.encrypt_block",
			},
		},
		{
			// A nested module keeps its "::" in the package segment, which is
			// correct and must survive: the identity is `ring::digest` /
			// `Context` / `update`, not a mangled receiver type.
			name: "turbofish under a nested module import",
			src: `use ring::digest;
fn go(data: &[u8]) {
    let mut ctx = digest::Context::<u8>::new(&digest::SHA256);
    ctx.update(data);
}`,
			want: []string{
				"ring::digest.Context.new",
				"ring::digest.Context.update",
			},
		},
		{
			// Not a constructor: a generic free function bound with `let`. The
			// turbofish spelling now agrees with the plain spelling, which
			// already resolved no receiver type for this shape.
			name: "generic free function agrees with the plain spelling",
			src: `use helper::compute;
fn go(a: u32) {
    let x = compute::<u8>(a);
    x.finish();
    let y = compute(a);
    y.finish();
}`,
			want: []string{"app.x.finish", "app.y.finish"},
		},
		{
			name: "turbofish carrying a generic argument",
			src: `use aes::Aes256;
use cipher::Key;
fn go(bytes: &[u8], block: &mut [u8; 16]) {
    let key = Key::<Aes256>::from_slice(bytes);
    let c = Aes256::new(key);
    c.encrypt_block(block.into());
}`,
			want: []string{
				"cipher.Key.from_slice",
				"aes.Aes256.new",
				"aes.Aes256.encrypt_block",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			analyses, err := NewRustParser().ParseDirectory(dir, "app")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, analysis := range analyses {
				for _, fn := range analysis.Functions {
					for _, call := range fn.Calls {
						callee := call.Callee
						method, _ := splitMethodArity(&callee)
						got[method] = true
					}
				}
			}
			for _, key := range tc.want {
				if !got[key] {
					t.Errorf("missing callee key %q; got %v", key, keysOf(got))
				}
			}
			// A legitimate key may carry "::" inside its package segment
			// (`ring::digest.Context.update`), so only a segment left ending
			// in "::" indicates the unnormalized receiver type this fix is
			// about.
			for key := range got {
				for _, segment := range strings.Split(key, ".") {
					if strings.HasSuffix(segment, "::") {
						t.Errorf("callee key %q has a segment ending in \"::\"; "+
							"the receiver type was not normalized", key)
					}
				}
			}
		})
	}
}
