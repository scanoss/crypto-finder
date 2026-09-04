// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The KB is asserted as a SET, not as a sample.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Comparing the whole
// rendered set means no entry can be added, removed or altered without this
// test saying so, which is what makes a short mutation check sufficient.
//
// The render covers canonical_return_type because the fragment export reads it,
// and the PARAMETERS block because that is what feeds key and nonce sizes into
// the served answer: renaming a contributed property (keySize -> nonceSize) or
// swapping a derivation loads cleanly through the schema's presence checks, so
// only an exact comparison catches it.
func TestChacha20ContractSetIsExact(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method string
		arity  int
		role   string
		ret    string
		canon  string
		params []string
		pblock []string
	}
	want := []row{
		{"chacha20::ChaCha20.new", 2, "factory", "chacha20::ChaCha20", "chacha20::ChaCha20", []string{"&chacha20::Key", "&chacha20::Nonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20.new_from_slices", 2, "factory", "chacha20::ChaCha20", "core::result::Result<chacha20::ChaCha20, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20.new_var", 2, "factory", "chacha20::ChaCha20", "core::result::Result", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha20.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha20.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::ChaCha20.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::ChaCha20.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::ChaCha8.new", 2, "factory", "chacha20::ChaCha8", "chacha20::ChaCha8", []string{"&chacha20::Key", "&chacha20::Nonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha8.new_from_slices", 2, "factory", "chacha20::ChaCha8", "core::result::Result<chacha20::ChaCha8, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha8.new_var", 2, "factory", "chacha20::ChaCha8", "core::result::Result", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha8.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha8.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha8.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::ChaCha8.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::ChaCha8.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::ChaCha12.new", 2, "factory", "chacha20::ChaCha12", "chacha20::ChaCha12", []string{"&chacha20::Key", "&chacha20::Nonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha12.new_from_slices", 2, "factory", "chacha20::ChaCha12", "core::result::Result<chacha20::ChaCha12, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha12.new_var", 2, "factory", "chacha20::ChaCha12", "core::result::Result", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha12.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha12.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha12.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::ChaCha12.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::ChaCha12.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::XChaCha20.new", 2, "factory", "chacha20::XChaCha20", "chacha20::XChaCha20", []string{"&chacha20::Key", "&chacha20::XNonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha20.new_from_slices", 2, "factory", "chacha20::XChaCha20", "core::result::Result<chacha20::XChaCha20, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha20.new_var", 2, "factory", "chacha20::XChaCha20", "core::result::Result", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha20.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha20.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha20.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::XChaCha20.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::XChaCha20.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::XChaCha8.new", 2, "factory", "chacha20::XChaCha8", "chacha20::XChaCha8", []string{"&chacha20::Key", "&chacha20::XNonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha8.new_from_slices", 2, "factory", "chacha20::XChaCha8", "core::result::Result<chacha20::XChaCha8, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha8.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha8.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha8.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::XChaCha8.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::XChaCha8.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::XChaCha12.new", 2, "factory", "chacha20::XChaCha12", "chacha20::XChaCha12", []string{"&chacha20::Key", "&chacha20::XNonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha12.new_from_slices", 2, "factory", "chacha20::XChaCha12", "core::result::Result<chacha20::XChaCha12, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XChaCha12.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha12.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::XChaCha12.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::XChaCha12.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::XChaCha12.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::ChaCha20Legacy.new", 2, "factory", "chacha20::ChaCha20Legacy", "chacha20::ChaCha20Legacy", []string{"&chacha20::Key", "&chacha20::LegacyNonce"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20Legacy.new_from_slices", 2, "factory", "chacha20::ChaCha20Legacy", "core::result::Result<chacha20::ChaCha20Legacy, cipher::InvalidLength>", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20Legacy.new_var", 2, "factory", "chacha20::ChaCha20Legacy", "core::result::Result", []string{"&[u8]", "&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length", "1:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::ChaCha20Legacy.apply_keystream", 1, "operation", "()", "()", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha20Legacy.try_apply_keystream", 1, "operation", "()", "core::result::Result", []string{"&mut [u8]"}, []string{"0:data:metadata-contributing:plaintext:argument_value"}},
		{"chacha20::ChaCha20Legacy.apply_keystream_b2b", 2, "operation", "()", "", []string{"&[u8]", "&mut [u8]"}, []string{"0:input:metadata-contributing:plaintext:argument_value", "1:output:metadata-contributing:ciphertext:argument_value"}},
		{"chacha20::ChaCha20Legacy.seek", 1, "config", "()", "()", []string{}, []string{}},
		{"chacha20::ChaCha20Legacy.try_seek", 1, "config", "()", "core::result::Result", []string{}, []string{}},
		{"chacha20::ChaCha8Rng.from_seed", 1, "factory", "chacha20::ChaCha8Rng", "chacha20::ChaCha8Rng", []string{"[u8; 32]"}, []string{"0:seed:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::ChaCha8Rng.seed_from_u64", 1, "factory", "chacha20::ChaCha8Rng", "chacha20::ChaCha8Rng", []string{"u64"}, []string{}},
		{"chacha20::ChaCha8Rng.from_entropy", 0, "factory", "chacha20::ChaCha8Rng", "chacha20::ChaCha8Rng", []string{}, []string{}},
		{"chacha20::ChaCha8Rng.from_os_rng", 0, "factory", "chacha20::ChaCha8Rng", "chacha20::ChaCha8Rng", []string{}, []string{}},
		{"chacha20::ChaCha8Rng.from_rng", 1, "factory", "chacha20::ChaCha8Rng", "", []string{}, []string{}},
		{"chacha20::ChaCha8Rng.deserialize_state", 1, "factory", "chacha20::ChaCha8Rng", "chacha20::ChaCha8Rng", []string{"&chacha20::SerializedRngState"}, []string{}},
		{"chacha20::ChaCha12Rng.from_seed", 1, "factory", "chacha20::ChaCha12Rng", "chacha20::ChaCha12Rng", []string{"[u8; 32]"}, []string{"0:seed:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::ChaCha12Rng.seed_from_u64", 1, "factory", "chacha20::ChaCha12Rng", "chacha20::ChaCha12Rng", []string{"u64"}, []string{}},
		{"chacha20::ChaCha12Rng.from_entropy", 0, "factory", "chacha20::ChaCha12Rng", "chacha20::ChaCha12Rng", []string{}, []string{}},
		{"chacha20::ChaCha12Rng.from_os_rng", 0, "factory", "chacha20::ChaCha12Rng", "chacha20::ChaCha12Rng", []string{}, []string{}},
		{"chacha20::ChaCha12Rng.from_rng", 1, "factory", "chacha20::ChaCha12Rng", "", []string{}, []string{}},
		{"chacha20::ChaCha12Rng.deserialize_state", 1, "factory", "chacha20::ChaCha12Rng", "chacha20::ChaCha12Rng", []string{"&chacha20::SerializedRngState"}, []string{}},
		{"chacha20::ChaCha20Rng.from_seed", 1, "factory", "chacha20::ChaCha20Rng", "chacha20::ChaCha20Rng", []string{"[u8; 32]"}, []string{"0:seed:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::ChaCha20Rng.seed_from_u64", 1, "factory", "chacha20::ChaCha20Rng", "chacha20::ChaCha20Rng", []string{"u64"}, []string{}},
		{"chacha20::ChaCha20Rng.from_entropy", 0, "factory", "chacha20::ChaCha20Rng", "chacha20::ChaCha20Rng", []string{}, []string{}},
		{"chacha20::ChaCha20Rng.from_os_rng", 0, "factory", "chacha20::ChaCha20Rng", "chacha20::ChaCha20Rng", []string{}, []string{}},
		{"chacha20::ChaCha20Rng.from_rng", 1, "factory", "chacha20::ChaCha20Rng", "", []string{}, []string{}},
		{"chacha20::ChaCha20Rng.deserialize_state", 1, "factory", "chacha20::ChaCha20Rng", "chacha20::ChaCha20Rng", []string{"&chacha20::SerializedRngState"}, []string{}},
		{"chacha20.hchacha", 2, "operation", "chacha20::Key", "chacha20::Key", []string{}, []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::Key.from_slice", 1, "factory", "chacha20::Key", "&chacha20::Key", []string{"&[u8]"}, []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::Key.from", 1, "factory", "chacha20::Key", "chacha20::Key", []string{}, []string{"0:key:metadata-contributing:keySize:argument_bit_length"}},
		{"chacha20::Nonce.from_slice", 1, "factory", "chacha20::Nonce", "&chacha20::Nonce", []string{"&[u8]"}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::Nonce.from", 1, "factory", "chacha20::Nonce", "chacha20::Nonce", []string{}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XNonce.from_slice", 1, "factory", "chacha20::XNonce", "&chacha20::XNonce", []string{"&[u8]"}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::XNonce.from", 1, "factory", "chacha20::XNonce", "chacha20::XNonce", []string{}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::LegacyNonce.from_slice", 1, "factory", "chacha20::LegacyNonce", "&chacha20::LegacyNonce", []string{"&[u8]"}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
		{"chacha20::LegacyNonce.from", 1, "factory", "chacha20::LegacyNonce", "chacha20::LegacyNonce", []string{}, []string{"0:nonce:metadata-contributing:nonceSize:argument_bit_length"}},
	}

	render := func(method string, arity int, role, ret, canon string, params, pblock []string) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s canon=%s params=[%s] contributes=[%s] conf=high",
			method, arity, role, ret, canon, strings.Join(params, ","), strings.Join(pblock, ","))
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r.method, r.arity, r.role, r.ret, r.canon, r.params, r.pblock)] = true
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "chacha20" {
				continue
			}
			var pblock []string
			for _, p := range c.Parameters {
				var prop, deriv string
				if p.Contributes != nil {
					prop, deriv = p.Contributes.Property, p.Contributes.Derivation
				}
				idx := -1
				if p.Index != nil {
					idx = *p.Index
				}
				pblock = append(pblock, fmt.Sprintf("%d:%s:%s:%s:%s",
					idx, p.Name, p.Role, prop, deriv))
			}
			gotSet[fmt.Sprintf("%s#%d role=%s ret=%s canon=%s params=[%s] contributes=[%s] conf=%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), strings.Join(pblock, ","),
				c.Return.Confidence)] = true
		}
	}

	var missing, unexpected []string
	for k := range wantSet {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !wantSet[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	for _, m := range missing {
		t.Errorf("missing from the KB: %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("present in the KB but not declared here: %s", u)
	}
}

// Keys are authored in the CONVENTION shape `chacha20::Type.method`, not in
// the shape the call graph emits (`chacha20.Type.method`). rustAuthoredKey
// bridges the emitted form onto this one; authoring the emitted form leaves
// the entry loadable but unreachable, which looks exactly like having no
// contract.
//
// The free function `chacha20.hchacha` is the deliberate exception: it has no
// receiver type, so there is no module/type separator to move, and
// rustAuthoredKey returns a key with fewer than two dots unchanged.
func TestChacha20KeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "chacha20" {
				continue
			}
			if c.Method == "chacha20.hchacha" {
				continue
			}
			head := c.Method
			if i := strings.LastIndex(head, "."); i > 0 {
				head = head[:i]
			}
			if strings.Contains(head, ".") {
				t.Errorf("%s: module path uses '.', want '::' (the authored shape)", c.Method)
			}
		}
	}
}

// A receiver bound from `new_from_slices(..).unwrap()` must be typed as the
// constructed cipher, so the keystream call that follows resolves to the
// chacha20 contract. This pins the unwrap-passthrough type semantics for the
// crate's fallible constructor era (cipher 0.3+), which is the spelling real
// consumers write.
func TestChacha20UnwrappedConstructorTypesTheReceiver(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
fn f(key: &[u8], nonce: &[u8], data: &mut [u8]) {
    let mut cipher = ChaCha20::new_from_slices(key, nonce).unwrap();
    cipher.apply_keystream(data);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for ai := range analyses {
		fns := analyses[ai].Functions
		for fi := range fns {
			calls := fns[fi].Calls
			for ci := range calls {
				callee := calls[ci].Callee
				m, _ := splitMethodArity(&callee)
				seen[m] = true
			}
		}
	}
	if !seen["chacha20.ChaCha20.new_from_slices"] {
		t.Errorf("new_from_slices not keyed on chacha20.ChaCha20; seen = %v", seen)
	}
	if !seen["chacha20.ChaCha20.apply_keystream"] {
		t.Errorf("apply_keystream after unwrap() not keyed on chacha20.ChaCha20; seen = %v", seen)
	}
}

// What stays out, and why it must stay out. Every name here was read from the
// source rather than guessed: the cipher 0.5 keystream writers and the rng
// state accessors are real API that carries no crypto asset of its own -- a
// position getter or a raw keystream buffer write is bookkeeping -- and
// rand_chacha's same-named types belong to a different crate whose callee
// identities carry its own path.
func TestChacha20ExcludedSurfaceIsAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		// cipher 0.5.0 src/stream.rs:211 and :158 -- keystream writers, new in
		// the 0.10.x era. (An earlier revision of this test named
		// `write_keystream_block`, which no cipher release declares.)
		{"chacha20::ChaCha20.write_keystream", 1},
		{"chacha20::ChaCha20.try_write_keystream", 1},
		// rng bookkeeping, 0.10.1 src/rng.rs:202-297
		{"chacha20::ChaCha20Rng.get_seed", 0},
		{"chacha20::ChaCha20Rng.get_word_pos", 0},
		{"chacha20::ChaCha20Rng.set_word_pos", 1},
		{"chacha20::ChaCha20Rng.get_block_pos", 0},
		{"chacha20::ChaCha20Rng.set_block_pos", 1},
		{"chacha20::ChaCha20Rng.get_stream", 0},
		{"chacha20::ChaCha20Rng.set_stream", 1},
		{"chacha20::ChaCha20Rng.serialize_state", 0},
		// stream position readers on the ciphers themselves
		{"chacha20::ChaCha20.current_pos", 0},
		{"chacha20::ChaCha20.try_current_pos", 0},
		// the internal core is not the consumer-facing type
		{"chacha20::ChaChaCore.new", 2},
		// a different crate entirely
		{"rand_chacha::ChaCha20Rng.from_seed", 1},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; it must stay absent", tc.method, tc.arity, len(got))
		}
	}
}
