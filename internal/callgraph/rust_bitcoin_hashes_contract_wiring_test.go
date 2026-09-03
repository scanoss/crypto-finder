// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bitcoin_hashes emits TWO key shapes at once, and keying either one like the
// other loads cleanly and resolves nothing. Read off an exported call graph:
//
//	bitcoin_hashes::sha256.Hash.hash     — one module per algorithm, `::` kept
//	bitcoin_hashes.HmacEngine.new        — crate-root re-export, flat
func TestBitcoinHashesContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use bitcoin_hashes::{sha256, sha512, ripemd160, hash160, siphash24, Hash, HashEngine, Hmac, HmacEngine};

fn one_shot(d: &[u8]) {
    let _a = bitcoin_hashes::sha256::Hash::hash(d);
    let _b = bitcoin_hashes::sha512::Hash::hash(d);
    let _c = bitcoin_hashes::ripemd160::Hash::hash(d);
    let _e = bitcoin_hashes::hash160::Hash::hash(d);
    let _f = bitcoin_hashes::sha256d::Hash::hash(d);
}

fn streaming(d: &[u8]) {
    let mut e = bitcoin_hashes::sha256::Hash::engine();
    e.input(d);
    let _h = bitcoin_hashes::sha256::Hash::from_engine(e);
}

fn keyed(k: &[u8], d: &[u8]) {
    let _s = bitcoin_hashes::siphash24::Hash::hash_with_keys(1, 2, d);
    let mut m = HmacEngine::<sha256::Hash>::new(k);
    let _t = Hmac::<sha256::Hash>::from_engine(m);
}

fn derive(salt: &[u8], ikm: &[u8], info: &[u8]) {
    let h = bitcoin_hashes::HkdfSha256::new(salt, ikm);
    let _o = h.expand_to_len(info, 32);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	type key struct {
		method string
		arity  int
	}
	want := map[key]string{
		{"bitcoin_hashes::sha256.Hash.hash", 1}:    "operation",
		{"bitcoin_hashes::sha512.Hash.hash", 1}:    "operation",
		{"bitcoin_hashes::ripemd160.Hash.hash", 1}: "operation",
		{"bitcoin_hashes::hash160.Hash.hash", 1}:   "operation",
		{"bitcoin_hashes::sha256d.Hash.hash", 1}:   "operation",
		{"bitcoin_hashes::sha256.Hash.engine", 0}:  "factory",
		// from_engine emits at arity 0: the engine argument is taken as the
		// receiver, so the explicit argument is not counted.
		{"bitcoin_hashes::sha256.Hash.from_engine", 0}: "operation",
		// input is keyed on Hash, not HashEngine, though it is declared on
		// the engine.
		{"bitcoin_hashes::sha256.Hash.input", 1}:             "operation",
		{"bitcoin_hashes::siphash24.Hash.hash_with_keys", 3}: "operation",
		{"bitcoin_hashes.HmacEngine.new", 1}:                 "factory",
		{"bitcoin_hashes.Hmac.from_engine", 1}:               "operation",
		{"bitcoin_hashes.HkdfSha256.new", 2}:                 "factory",
	}
	seen := map[key]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				k := key{method, len(call.Arguments)}
				wantRole, ok := want[k]
				if !ok {
					continue
				}
				got := kb.ContractsFor(k.method, k.arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", k.method, k.arity, len(got))
				}
				if got[0].SourceLibrary != "bitcoin_hashes" {
					t.Fatalf("%s came from %q, want bitcoin_hashes", k.method, got[0].SourceLibrary)
				}
				if got[0].Role != wantRole {
					t.Fatalf("%s/%d role = %q, want %q", k.method, k.arity, got[0].Role, wantRole)
				}
				seen[k] = true
			}
		}
	}
	for k := range want {
		if !seen[k] {
			t.Fatalf("parsed calls did not cover %q at arity %d; seen = %v", k.method, k.arity, seen)
		}
	}
}

// Every algorithm module carries the same four entries, and each declares its
// own return types. A missing module is a whole algorithm going untyped.
func TestBitcoinHashesEveryAlgorithmModuleIsTyped(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, algo := range []string{
		"sha1", "sha256", "sha256d", "sha256t", "sha384", "sha512",
		"sha512_256", "sha3_256", "ripemd160", "hash160", "muhash", "siphash24",
	} {
		for _, tc := range []struct {
			method string
			arity  int
			role   string
			ret    string
		}{
			{"Hash.hash", 1, "operation", "bitcoin_hashes::" + algo + "::Hash"},
			{"Hash.engine", 0, "factory", "bitcoin_hashes::" + algo + "::HashEngine"},
			{"Hash.from_engine", 0, "operation", "bitcoin_hashes::" + algo + "::Hash"},
			{"Hash.input", 1, "operation", "()"},
		} {
			key := "bitcoin_hashes::" + algo + "." + tc.method
			got := kb.ContractsFor(key, tc.arity)
			if len(got) != 1 {
				t.Errorf("ContractsFor(%q, %d) = %d, want one", key, tc.arity, len(got))
				continue
			}
			c := got[0]
			if c.SourceLibrary != "bitcoin_hashes" {
				t.Errorf("%s came from %q", key, c.SourceLibrary)
			}
			if c.Role != tc.role {
				t.Errorf("%s role = %q, want %q", key, c.Role, tc.role)
			}
			if c.Return.Type != tc.ret {
				t.Errorf("%s return = %q, want %q", key, c.Return.Type, tc.ret)
			}
			if c.Return.Confidence != "high" {
				t.Errorf("%s confidence = %q, want high", key, c.Return.Confidence)
			}
			if len(c.ParameterTypes) != tc.arity {
				t.Errorf("%s has %d parameter types, want %d", key, len(c.ParameterTypes), tc.arity)
			}
		}
	}
}

// The encoding surface must stay out: those calls move a digest between
// representations and perform no hashing. `from_slice` and `from_byte_array`
// return a Hash value, so typing them would route deserialisation through the
// crypto call graph.
func TestBitcoinHashesEncodingSurfaceIsAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"bitcoin_hashes::sha256.Hash.from_slice", 1},
		{"bitcoin_hashes::sha256.Hash.from_byte_array", 1},
		{"bitcoin_hashes::sha256.Hash.to_byte_array", 0},
		{"bitcoin_hashes::sha256.Hash.as_byte_array", 0},
		{"bitcoin_hashes::sha256.Hash.from_str", 1},
		{"bitcoin_hashes::sha256.Hash.to_engine", 0},
		{"bitcoin_hashes::sha256.HashEngine.midstate", 0},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; the encoding surface must stay absent",
				tc.method, tc.arity, len(got))
		}
	}
}
