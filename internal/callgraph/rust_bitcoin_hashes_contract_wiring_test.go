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
// An earlier revision listed a handful of keys and checked them one by one. A
// review's mutation sweep put 164 of 496 mutations through it — 17 entries were
// asserted by nothing at all, and every entry's parameter-type STRINGS and
// confidence were free to change. Comparing the whole set means an entry cannot
// be added, removed or altered without this test saying so.
func TestBitcoinHashesContractSetIsExact(t *testing.T) {
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
		params []string
	}
	want := []row{
		{"bitcoin_hashes::Hash160.finalize", 0, "output", "bitcoin_hashes::hash160::Hash", []string{}},
		{"bitcoin_hashes::Hash160.hash", 1, "output", "bitcoin_hashes::hash160::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::HkdfSha256.expand", 2, "operation", "core::result::Result", []string{"&[u8]", "&mut [u8]"}},
		{"bitcoin_hashes::HkdfSha256.expand_to_len", 2, "output", "core::result::Result", []string{"&[u8]", "usize"}},
		{"bitcoin_hashes::HkdfSha256.new", 2, "factory", "bitcoin_hashes::hkdf::Hkdf", []string{"&[u8]", "&[u8]"}},
		{"bitcoin_hashes::HkdfSha512.expand", 2, "operation", "core::result::Result", []string{"&[u8]", "&mut [u8]"}},
		{"bitcoin_hashes::HkdfSha512.expand_to_len", 2, "output", "core::result::Result", []string{"&[u8]", "usize"}},
		{"bitcoin_hashes::HkdfSha512.new", 2, "factory", "bitcoin_hashes::hkdf::Hkdf", []string{"&[u8]", "&[u8]"}},
		{"bitcoin_hashes::Ripemd160.finalize", 0, "output", "bitcoin_hashes::ripemd160::Hash", []string{}},
		{"bitcoin_hashes::Ripemd160.hash", 1, "output", "bitcoin_hashes::ripemd160::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha1.finalize", 0, "output", "bitcoin_hashes::sha1::Hash", []string{}},
		{"bitcoin_hashes::Sha1.hash", 1, "output", "bitcoin_hashes::sha1::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha256.finalize", 0, "output", "bitcoin_hashes::sha256::Hash", []string{}},
		{"bitcoin_hashes::Sha256.hash", 1, "output", "bitcoin_hashes::sha256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha256d.finalize", 0, "output", "bitcoin_hashes::sha256d::Hash", []string{}},
		{"bitcoin_hashes::Sha256d.hash", 1, "output", "bitcoin_hashes::sha256d::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha384.finalize", 0, "output", "bitcoin_hashes::sha384::Hash", []string{}},
		{"bitcoin_hashes::Sha384.hash", 1, "output", "bitcoin_hashes::sha384::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha3_256.finalize", 0, "output", "bitcoin_hashes::sha3_256::Hash", []string{}},
		{"bitcoin_hashes::Sha3_256.hash", 1, "output", "bitcoin_hashes::sha3_256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha512.finalize", 0, "output", "bitcoin_hashes::sha512::Hash", []string{}},
		{"bitcoin_hashes::Sha512.hash", 1, "output", "bitcoin_hashes::sha512::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Sha512_256.finalize", 0, "output", "bitcoin_hashes::sha512_256::Hash", []string{}},
		{"bitcoin_hashes::Sha512_256.hash", 1, "output", "bitcoin_hashes::sha512_256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::Siphash24.finalize", 0, "output", "bitcoin_hashes::siphash24::Hash", []string{}},
		{"bitcoin_hashes::Siphash24.hash", 1, "output", "bitcoin_hashes::siphash24::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::hash160::Hash.engine", 0, "factory", "bitcoin_hashes::sha256::HashEngine", []string{}},
		{"bitcoin_hashes::hash160::Hash.finalize", 0, "output", "bitcoin_hashes::hash160::Hash", []string{}},
		{"bitcoin_hashes::hash160::Hash.from_engine", 1, "output", "bitcoin_hashes::hash160::Hash", []string{"bitcoin_hashes::sha256::HashEngine"}},
		{"bitcoin_hashes::hash160::Hash.hash", 1, "output", "bitcoin_hashes::hash160::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::hash160::HashEngine.finalize", 0, "output", "bitcoin_hashes::hash160::Hash", []string{}},
		{"bitcoin_hashes::hash160::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::hkdf::Hkdf.expand", 2, "operation", "core::result::Result", []string{"&[u8]", "&mut [u8]"}},
		{"bitcoin_hashes::hkdf::Hkdf.expand_to_len", 2, "output", "core::result::Result", []string{"&[u8]", "usize"}},
		{"bitcoin_hashes::hkdf::Hkdf.new", 2, "factory", "bitcoin_hashes::hkdf::Hkdf", []string{"&[u8]", "&[u8]"}},
		{"bitcoin_hashes::hmac::Hmac.engine", 0, "factory", "bitcoin_hashes::hmac::HmacEngine", []string{}},
		{"bitcoin_hashes::hmac::Hmac.from_engine", 1, "output", "bitcoin_hashes::hmac::Hmac", []string{"bitcoin_hashes::hmac::HmacEngine"}},
		{"bitcoin_hashes::hmac::HmacEngine.from_inner_engines", 2, "factory", "bitcoin_hashes::hmac::HmacEngine", []string{"T::Engine", "T::Engine"}},
		{"bitcoin_hashes::hmac::HmacEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::hmac::HmacEngine.new", 1, "factory", "bitcoin_hashes::hmac::HmacEngine", []string{"&[u8]"}},
		{"bitcoin_hashes::ripemd160::Hash.engine", 0, "factory", "bitcoin_hashes::ripemd160::HashEngine", []string{}},
		{"bitcoin_hashes::ripemd160::Hash.finalize", 0, "output", "bitcoin_hashes::ripemd160::Hash", []string{}},
		{"bitcoin_hashes::ripemd160::Hash.from_engine", 1, "output", "bitcoin_hashes::ripemd160::Hash", []string{"bitcoin_hashes::ripemd160::HashEngine"}},
		{"bitcoin_hashes::ripemd160::Hash.hash", 1, "output", "bitcoin_hashes::ripemd160::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::ripemd160::HashEngine.finalize", 0, "output", "bitcoin_hashes::ripemd160::Hash", []string{}},
		{"bitcoin_hashes::ripemd160::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha1::Hash.engine", 0, "factory", "bitcoin_hashes::sha1::HashEngine", []string{}},
		{"bitcoin_hashes::sha1::Hash.finalize", 0, "output", "bitcoin_hashes::sha1::Hash", []string{}},
		{"bitcoin_hashes::sha1::Hash.from_engine", 1, "output", "bitcoin_hashes::sha1::Hash", []string{"bitcoin_hashes::sha1::HashEngine"}},
		{"bitcoin_hashes::sha1::Hash.hash", 1, "output", "bitcoin_hashes::sha1::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha1::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha1::Hash", []string{}},
		{"bitcoin_hashes::sha1::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256::Hash.engine", 0, "factory", "bitcoin_hashes::sha256::HashEngine", []string{}},
		{"bitcoin_hashes::sha256::Hash.finalize", 0, "output", "bitcoin_hashes::sha256::Hash", []string{}},
		{"bitcoin_hashes::sha256::Hash.from_engine", 1, "output", "bitcoin_hashes::sha256::Hash", []string{"bitcoin_hashes::sha256::HashEngine"}},
		{"bitcoin_hashes::sha256::Hash.hash", 1, "output", "bitcoin_hashes::sha256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha256::Hash", []string{}},
		{"bitcoin_hashes::sha256::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256d::Hash.engine", 0, "factory", "bitcoin_hashes::sha256::HashEngine", []string{}},
		{"bitcoin_hashes::sha256d::Hash.finalize", 0, "output", "bitcoin_hashes::sha256d::Hash", []string{}},
		{"bitcoin_hashes::sha256d::Hash.from_engine", 1, "output", "bitcoin_hashes::sha256d::Hash", []string{"bitcoin_hashes::sha256::HashEngine"}},
		{"bitcoin_hashes::sha256d::Hash.hash", 1, "output", "bitcoin_hashes::sha256d::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256d::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha256d::Hash", []string{}},
		{"bitcoin_hashes::sha256d::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256t::Hash.engine", 0, "factory", "bitcoin_hashes::sha256::HashEngine", []string{}},
		{"bitcoin_hashes::sha256t::Hash.finalize", 0, "output", "bitcoin_hashes::sha256t::Hash", []string{}},
		{"bitcoin_hashes::sha256t::Hash.from_engine", 1, "output", "bitcoin_hashes::sha256t::Hash", []string{"bitcoin_hashes::sha256::HashEngine"}},
		{"bitcoin_hashes::sha256t::Hash.hash", 1, "output", "bitcoin_hashes::sha256t::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha256t::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha256t::Hash", []string{}},
		{"bitcoin_hashes::sha256t::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha384::Hash.engine", 0, "factory", "bitcoin_hashes::sha384::HashEngine", []string{}},
		{"bitcoin_hashes::sha384::Hash.finalize", 0, "output", "bitcoin_hashes::sha384::Hash", []string{}},
		{"bitcoin_hashes::sha384::Hash.from_engine", 1, "output", "bitcoin_hashes::sha384::Hash", []string{"bitcoin_hashes::sha384::HashEngine"}},
		{"bitcoin_hashes::sha384::Hash.hash", 1, "output", "bitcoin_hashes::sha384::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha384::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha384::Hash", []string{}},
		{"bitcoin_hashes::sha384::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha3_256::Hash.engine", 0, "factory", "bitcoin_hashes::sha3_256::HashEngine", []string{}},
		{"bitcoin_hashes::sha3_256::Hash.finalize", 0, "output", "bitcoin_hashes::sha3_256::Hash", []string{}},
		{"bitcoin_hashes::sha3_256::Hash.hash", 1, "output", "bitcoin_hashes::sha3_256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha3_256::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha3_256::Hash", []string{}},
		{"bitcoin_hashes::sha3_256::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha512::Hash.engine", 0, "factory", "bitcoin_hashes::sha512::HashEngine", []string{}},
		{"bitcoin_hashes::sha512::Hash.finalize", 0, "output", "bitcoin_hashes::sha512::Hash", []string{}},
		{"bitcoin_hashes::sha512::Hash.from_engine", 1, "output", "bitcoin_hashes::sha512::Hash", []string{"bitcoin_hashes::sha512::HashEngine"}},
		{"bitcoin_hashes::sha512::Hash.hash", 1, "output", "bitcoin_hashes::sha512::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha512::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha512::Hash", []string{}},
		{"bitcoin_hashes::sha512::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::sha512_256::Hash.engine", 0, "factory", "bitcoin_hashes::sha512_256::HashEngine", []string{}},
		{"bitcoin_hashes::sha512_256::Hash.finalize", 0, "output", "bitcoin_hashes::sha512_256::Hash", []string{}},
		{"bitcoin_hashes::sha512_256::Hash.from_engine", 1, "output", "bitcoin_hashes::sha512_256::Hash", []string{"bitcoin_hashes::sha512_256::HashEngine"}},
		{"bitcoin_hashes::sha512_256::Hash.hash", 1, "output", "bitcoin_hashes::sha512_256::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::sha512_256::HashEngine.finalize", 0, "output", "bitcoin_hashes::sha512_256::Hash", []string{}},
		{"bitcoin_hashes::sha512_256::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::siphash24::Hash.engine", 0, "factory", "bitcoin_hashes::siphash24::HashEngine", []string{}},
		{"bitcoin_hashes::siphash24::Hash.engine", 2, "factory", "bitcoin_hashes::siphash24::HashEngine", []string{"u64", "u64"}},
		{"bitcoin_hashes::siphash24::Hash.from_engine", 1, "output", "bitcoin_hashes::siphash24::Hash", []string{"bitcoin_hashes::siphash24::HashEngine"}},
		{"bitcoin_hashes::siphash24::Hash.hash", 1, "output", "bitcoin_hashes::siphash24::Hash", []string{"&[u8]"}},
		{"bitcoin_hashes::siphash24::Hash.hash_with_keys", 3, "output", "bitcoin_hashes::siphash24::Hash", []string{"u64", "u64", "&[u8]"}},
		{"bitcoin_hashes::siphash24::HashEngine.input", 1, "operation", "()", []string{"&[u8]"}},
		{"bitcoin_hashes::siphash24::HashEngine.with_keys", 2, "factory", "bitcoin_hashes::siphash24::HashEngine", []string{"u64", "u64"}},
	}

	render := func(r row) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=high",
			r.method, r.arity, r.role, r.ret, strings.Join(r.params, ","))
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r)] = true
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "bitcoin_hashes" {
				continue
			}
			gotSet[fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=%s",
				c.Method, c.Arity, c.Role, c.Return.Type,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence)] = true
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

// The keys must be authored in the CONVENTION shape
// `bitcoin_hashes::<module>::Type.method`, not in the shape the call graph
// emits. rustAuthoredKey bridges the emitted form onto this one; authoring the
// emitted form leaves the entry unreachable from the parser's own lookup, and
// the graph then misreports both the engine's type and from_engine's arity.
func TestBitcoinHashesKeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "bitcoin_hashes" {
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

// With the authored key shape the parser types the engine, so `input` is keyed
// on HashEngine and `from_engine` takes its argument. This pins both, because an
// earlier revision recorded the opposite as facts about the analyzer when they
// were artifacts of a wrong key.
func TestBitcoinHashesStreamingIdentitiesAreTyped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use bitcoin_hashes::{sha256, Hash, HashEngine};
fn f(d: &[u8]) {
    let mut e = bitcoin_hashes::sha256::Hash::engine();
    e.input(d);
    let _h = bitcoin_hashes::sha256::Hash::from_engine(e);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, a := range analyses {
		for _, fn := range a.Functions {
			for _, c := range fn.Calls {
				callee := c.Callee
				m, _ := splitMethodArity(&callee)
				seen[m] = len(c.Arguments)
			}
		}
	}
	if _, ok := seen["bitcoin_hashes::sha256.HashEngine.input"]; !ok {
		t.Errorf("engine.input is not keyed on HashEngine; seen = %v", seen)
	}
	if n, ok := seen["bitcoin_hashes::sha256.Hash.from_engine"]; !ok || n != 1 {
		t.Errorf("from_engine emitted at arity %d (present=%v), want 1; seen = %v", n, ok, seen)
	}
}

// The encoding surface must stay out: those calls move a digest between
// representations and perform no hashing.
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
		{"bitcoin_hashes::muhash.Hash.hash", 1},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; it must stay absent", tc.method, tc.arity, len(got))
		}
	}
}
