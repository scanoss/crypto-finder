// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// alloy-primitives ships its crypto surface in NINE KB files because
// `version_range` is declared per library and may claim only versions for which
// every entry in the file holds -- the crate's surface arrives in eight disjoint
// waves across the 75 committed rows. `library.name` must therefore differ per
// file: a repeated name is a HARD LOAD ERROR ("duplicate library name ... in
// files"), measured here while authoring, so the names are per-file labels and
// `coordinates` is what ties them back to the one crate.
//
// The keys were read off an exported call graph rather than written from the
// API, and then converted per rustAuthoredKey (contracts.go:267), which moves
// the SECOND-TO-LAST dot to "::" -- and ONLY when the key carries at least two
// dots. THREE shapes are present here and they convert differently:
//
//	crate-root free function   ONE dot    `alloy_primitives.keccak256`
//	                                      authored VERBATIM
//	module free function       ONE dot    `alloy_primitives::utils.keccak256`
//	                                      authored VERBATIM
//	type method                TWO dots   graph emits
//	                                      `alloy_primitives.Signature.to_k256`,
//	                                      file holds
//	                                      `alloy_primitives::Signature.to_k256`
//
// Both free-function shapes would be BROKEN by mechanically applying the
// substitution -- it would produce `alloy::primitives.keccak256` and
// `alloy_primitives::utils::keccak256`, each of which loads without error and
// joins nothing. TestAlloyPrimitivesEmittedCallSiteKeysResolve pins every
// spelling the parser actually looks up.
//
// THE MODULE SEGMENT FOLLOWS THE CONSUMER'S IMPORT and this crate re-exports
// selectively, so the same function and the same type emit two keys each.
// Measured on two probe consumers: `use alloy_primitives::keccak256;` emits
// `alloy_primitives.keccak256` while `alloy_primitives::utils::keccak256(..)`
// emits `alloy_primitives::utils.keccak256`. `keccak256_cached` is the exception
// that proves the rule -- it is re-exported at the crate root in NO release, so
// only its `utils` key exists.
//
// The set is compared EXACTLY. A per-key assertion cannot see an entry that
// should not be there, an entry that was dropped, or a field that was corrupted;
// only a whole-set comparison does. The rendering deliberately includes the
// source library, the arity, `parameter_types`, both return fields, the
// confidence, the `parameters` block AND `Varargs`, because a renamed
// contributed property, a changed derivation or a flipped varargs flag all load
// cleanly through the schema's presence checks and would otherwise pass an
// "exact" test unchanged.
//
// AND AN EXACT-SET TEST PROVES ONLY THAT THE TEST DETECTS CHANGES TO WHAT WAS
// WRITTEN, NOT THAT WHAT WAS WRITTEN IS TRUE. The baseline below is traced to
// crate source per symbol and then CONFIRMED BY COMPILING a probe against the
// exact published version -- see the per-file headers for the version windows
// and their negative controls.
func renderAlloyPrimitivesContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !strings.HasPrefix(c.SourceLibrary, "alloy-primitives") {
				continue
			}
			var params strings.Builder
			for _, p := range c.Parameters {
				idx := -1
				if p.Index != nil {
					idx = *p.Index
				}
				prop, der := "", ""
				if p.Contributes != nil {
					prop, der = p.Contributes.Property, p.Contributes.Derivation
				}
				fmt.Fprintf(&params, "{%d:%s:%s:%s:%s}", idx, p.Name, p.Role, prop, der)
			}
			got = append(got, fmt.Sprintf("%s|%s#%d/%s/%s/%s/[%s]/%s/%s",
				c.SourceLibrary, c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence, params.String()))
		}
	}
	sort.Strings(got)
	return got
}

// `parameter_types` IS EMPTY ON EVERY `_prehash` ENTRY AND ON EVERY FREE
// FUNCTION, and both omissions are deliberate version facts rather than
// oversights.
//
//   - the free functions are generic over `T: AsRef<[u8]>` throughout, and their
//     RETURN is spelled `FixedBytes<32>` in 0.1.0-0.5.x and `B256` from 0.6.0.
//     Those are the same type (`pub type B256 = FixedBytes<32>`, 0.1.0
//     src/bits/mod.rs:27), so `canonical_return_type` names the alias, which is
//     true of every release.
//   - `recover_address_from_prehash` and `recover_from_prehash` take
//     `prehash: B256` BY VALUE at 0.6.0 and `&B256` from 0.6.1. Found by
//     COMPILING, not by reading `pub fn`: the by-reference call against 0.6.0
//     fails with E0308 `expected FixedBytes<32>, found &FixedBytes<32>`. Arity is
//     unchanged and a KB entry holds ONE value per method and arity, so either
//     spelling would be false for part of the range.
//
// `update` RETURNS `void` RATHER THAN `()`: this is a digest hasher whose
// `update(&mut self, bytes)` genuinely returns unit, which is the one case `void`
// is reserved for in this directory, and it matches the merged sha3, sha2 and
// blake2 KBs for the identical shape. `()` is reserved for the Ok half of a
// `Result<(), E>`, which no entry here has.
var wantAlloyPrimitivesContracts = []string{
	"alloy-primitives-eip191|alloy_primitives.eip191_hash_message#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:message:operation-determining:digestLength:argument_type}",
	"alloy-primitives-keccak-cache|alloy_primitives.keccak256_uncached#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives-keccak-cache|alloy_primitives::utils.keccak256_cached#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives-keccak-cache|alloy_primitives::utils.keccak256_uncached#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.default#0/factory/alloy_primitives::Keccak256/alloy_primitives::Keccak256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.finalize#0/output/alloy_primitives::B256/alloy_primitives::B256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.finalize_into#1/output/void/void/[&mut [u8]]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.finalize_into_array#1/output/void/void/[&mut [u8; 32]]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.new#0/factory/alloy_primitives::Keccak256/alloy_primitives::Keccak256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::Keccak256.update#1/operation/void/void/[impl AsRef<[u8]>]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.default#0/factory/alloy_primitives::utils::Keccak256/alloy_primitives::utils::Keccak256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.finalize#0/output/alloy_primitives::B256/alloy_primitives::B256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.finalize_into#1/output/void/void/[&mut [u8]]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.finalize_into_array#1/output/void/void/[&mut [u8; 32]]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.new#0/factory/alloy_primitives::utils::Keccak256/alloy_primitives::utils::Keccak256/[]/high/",
	"alloy-primitives-keccak-hasher|alloy_primitives::utils::Keccak256.update#1/operation/void/void/[impl AsRef<[u8]>]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives-primitive-signature|alloy_primitives::PrimitiveSignature.recover_address_from_msg#1/operation/alloy_primitives::Address/core::result::Result<alloy_primitives::Address, alloy_primitives::SignatureError>/[T]/high/{0:msg:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-primitive-signature|alloy_primitives::PrimitiveSignature.recover_address_from_prehash#1/operation/alloy_primitives::Address/core::result::Result<alloy_primitives::Address, alloy_primitives::SignatureError>/[]/high/{0:prehash:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-primitive-signature|alloy_primitives::PrimitiveSignature.recover_from_msg#1/operation/k256::ecdsa::VerifyingKey/core::result::Result<k256::ecdsa::VerifyingKey, alloy_primitives::SignatureError>/[T]/high/{0:msg:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-primitive-signature|alloy_primitives::PrimitiveSignature.recover_from_prehash#1/operation/k256::ecdsa::VerifyingKey/core::result::Result<k256::ecdsa::VerifyingKey, alloy_primitives::SignatureError>/[]/high/{0:prehash:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-primitive-signature|alloy_primitives::PrimitiveSignature.to_k256#0/operation/k256::ecdsa::Signature/core::result::Result<k256::ecdsa::Signature, k256::ecdsa::Error>/[]/high/",
	"alloy-primitives-secp256k1|alloy_primitives::Signature.recover_from_msg_secp256k1#1/operation/secp256k1::PublicKey/core::result::Result<secp256k1::PublicKey, alloy_primitives::SignatureError>/[T]/high/{0:msg:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-secp256k1|alloy_primitives::Signature.recover_from_prehash_secp256k1#1/operation/secp256k1::PublicKey/core::result::Result<secp256k1::PublicKey, alloy_primitives::SignatureError>/[]/high/{0:prehash:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-secp256k1|alloy_primitives::Signature.to_secp256k1#0/operation/secp256k1::ecdsa::RecoverableSignature/core::result::Result<secp256k1::ecdsa::RecoverableSignature, secp256k1::Error>/[]/high/",
	"alloy-primitives-signature-k256|alloy_primitives::Signature.to_k256#0/operation/k256::ecdsa::Signature/core::result::Result<k256::ecdsa::Signature, k256::ecdsa::Error>/[]/high/",
	"alloy-primitives-signature|alloy_primitives::Signature.recover_address_from_msg#1/operation/alloy_primitives::Address/core::result::Result<alloy_primitives::Address, alloy_primitives::SignatureError>/[T]/high/{0:msg:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-signature|alloy_primitives::Signature.recover_address_from_prehash#1/operation/alloy_primitives::Address/core::result::Result<alloy_primitives::Address, alloy_primitives::SignatureError>/[]/high/{0:prehash:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-signature|alloy_primitives::Signature.recover_from_msg#1/operation/k256::ecdsa::VerifyingKey/core::result::Result<k256::ecdsa::VerifyingKey, alloy_primitives::SignatureError>/[T]/high/{0:msg:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-signature|alloy_primitives::Signature.recover_from_prehash#1/operation/k256::ecdsa::VerifyingKey/core::result::Result<k256::ecdsa::VerifyingKey, alloy_primitives::SignatureError>/[]/high/{0:prehash:operation-determining:signatureAlgorithm:argument_type}",
	"alloy-primitives-utils|alloy_primitives::utils.eip191_hash_message#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:message:operation-determining:digestLength:argument_type}",
	"alloy-primitives-utils|alloy_primitives::utils.keccak256#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
	"alloy-primitives|alloy_primitives.keccak256#1/operation/alloy_primitives::B256/alloy_primitives::B256/[]/high/{0:bytes:operation-determining:digestLength:argument_type}",
}

func TestLoadEmbeddedRustAlloyPrimitivesContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderAlloyPrimitivesContracts(t)
	want := append([]string(nil), wantAlloyPrimitivesContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("alloy-primitives contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected alloy-primitives contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing alloy-primitives contract:    %s", w)
		}
	}
}

// NO ENTRY IN THIS FAMILY USES `varargs`, and that is asserted rather than
// assumed. `Contract.Varargs` is rendered by no other rust exact-set test in
// this directory, so a `varargs: true` mutation survives every one of them; if a
// later change to these files needs the field, this assertion is what fails and
// forces the render above to carry it.
func TestAlloyPrimitivesNoVarargs(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	n := 0
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !strings.HasPrefix(c.SourceLibrary, "alloy-primitives") {
				continue
			}
			n++
			if c.Varargs {
				t.Errorf("%s declares varargs; the exact-set render does not carry the field", c.Method)
			}
		}
	}
	if n == 0 {
		t.Fatal("no alloy-primitives contracts loaded, so this assertion is vacuous")
	}
}

// THE `library:` BLOCK IS PARSED AND THEN NEVER CONSULTED BY ANY OTHER
// ASSERTION, so corrupting a name, a coordinate, a version range or a
// description leaves an otherwise-exact contract test green. Measured on other
// families and true here too. Pin all four fields of all nine files by loading
// each YAML directly -- LoadEmbedded merges every rust KB and drops Library to
// nil, so the merged knowledge base cannot see them.
//
// THE VERSION RANGES ARE THE FAMILY'S ACTUAL CLAIM and every bound below was
// established by compiling a probe against the adjacent published versions:
//
//	>=0.1.0-0  crate-root `keccak256`, present in all 75 rows. The `-0`
//	           prerelease floor admits the matrix's `1.0.0-rc.1` row under
//	           strict semver, where a prerelease sorts below its release.
//	>=0.4.0    `eip191_hash_message`; absent at 0.3.3 (E0425).
//	>=0.5.0    the `utils` module goes from `mod utils;` to `pub mod utils;`
//	           (0.4.2 src/lib.rs:53 vs 0.5.0:47), so no `utils`-qualified key is
//	           reachable before it.
//	>=0.6.0    the incremental `Keccak256` (absent at 0.5.4, E0433) and the
//	           `Signature` recovery surface with the `k256` Cargo feature that
//	           gates it, which 0.6.0's Cargo.toml is the first to declare.
//	>=0.8.1    `Signature::to_k256`; absent at 0.8.0. An earlier reading of this
//	           family put it at 1.0.0 and was wrong.
//	>=0.8.10,<1.5.0  `PrimitiveSignature`, which first appears in
//	           src/signature/mod.rs at 0.8.10 and is REMOVED at 1.5.0
//	           (compiling it against 1.5.7 fails).
//	>=1.5.0    `keccak256_cached` / `keccak256_uncached`; absent at 1.4.1. An
//	           earlier reading put them at 1.6.0 and was wrong.
//	>=1.6.0    the `secp256k1` Cargo feature, declared in no earlier release.
//
// Every upper bound is <1.7.0 except the PrimitiveSignature file, because 1.6.0
// is the newest row in the committed matrix.
func TestAlloyPrimitivesLibraryBlocks(t *testing.T) {
	t.Parallel()

	cases := []struct {
		file    string
		name    string
		vrange  string
		mustSay string
		mustNot string
	}{
		{"alloy-primitives.yaml", "alloy-primitives", ">=0.1.0-0,<1.7.0", "Keccak-256", "SHA3"},
		{"alloy-primitives-eip191.yaml", "alloy-primitives-eip191", ">=0.4.0,<1.7.0", "EIP-191", "SHA3"},
		{"alloy-primitives-utils.yaml", "alloy-primitives-utils", ">=0.5.0,<1.7.0", "utils", "SHA3"},
		{"alloy-primitives-keccak-hasher.yaml", "alloy-primitives-keccak-hasher", ">=0.6.0,<1.7.0", "Keccak-256", "SHA3"},
		{"alloy-primitives-signature.yaml", "alloy-primitives-signature", ">=0.6.0,<1.7.0", "secp256k1", "SHA3"},
		{"alloy-primitives-signature-k256.yaml", "alloy-primitives-signature-k256", ">=0.8.1,<1.7.0", "k256", "SHA3"},
		{"alloy-primitives-primitive-signature.yaml", "alloy-primitives-primitive-signature", ">=0.8.10,<1.5.0", "PrimitiveSignature", "SHA3"},
		{"alloy-primitives-keccak-cache.yaml", "alloy-primitives-keccak-cache", ">=1.5.0,<1.7.0", "Keccak-256", "SHA3"},
		{"alloy-primitives-secp256k1.yaml", "alloy-primitives-secp256k1", ">=1.6.0,<1.7.0", "secp256k1", "SHA3"},
	}

	for _, tc := range cases {
		data, err := os.ReadFile(filepath.Join("rust", tc.file))
		if err != nil {
			t.Errorf("read %s: %v", tc.file, err)
			continue
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Errorf("Load(%s): %v", tc.file, err)
			continue
		}
		if kb.SchemaVersion != "2" {
			t.Errorf("%s: schema_version = %q, want 2", tc.file, kb.SchemaVersion)
		}
		if kb.Ecosystem != "rust" {
			t.Errorf("%s: ecosystem = %q, want rust", tc.file, kb.Ecosystem)
		}
		if kb.Library == nil {
			t.Errorf("%s: library block did not load", tc.file)
			continue
		}
		if kb.Library.Name != tc.name {
			t.Errorf("%s: library.name = %q, want %q", tc.file, kb.Library.Name, tc.name)
		}
		if got := strings.Join(kb.Library.Coordinates, ","); got != "alloy-primitives,alloy_primitives" {
			t.Errorf("%s: library.coordinates = %q, want alloy-primitives,alloy_primitives", tc.file, got)
		}
		if kb.Library.VersionRange != tc.vrange {
			t.Errorf("%s: library.version_range = %q, want %q", tc.file, kb.Library.VersionRange, tc.vrange)
		}
		if !strings.Contains(kb.Library.Description, tc.mustSay) {
			t.Errorf("%s: description must name %q; got %q", tc.file, tc.mustSay, kb.Library.Description)
		}
		// The algorithm is Keccak-256 with ORIGINAL padding. No description in
		// this family may claim SHA-3, which is a different padding and
		// therefore a different digest.
		if strings.Contains(kb.Library.Description, tc.mustNot) {
			t.Errorf("%s: description must not claim %q; got %q", tc.file, tc.mustNot, kb.Library.Description)
		}
		if len(kb.Contracts) == 0 {
			t.Errorf("%s: no contracts loaded", tc.file)
		}
	}
}

// THE DOT-JOINED SPELLING THE CALL GRAPH EMITS MUST RESOLVE, because that -- not
// the authored spelling -- is what the parser looks up. Every key below was read
// off the exported call graph of a probe consumer that calls the API the way a
// real consumer does, and every one of the 32 declared entries is covered by one
// of the two probes.
//
// Arities exclude the receiver: `Signature::recover_address_from_msg(&self, msg)`
// is 1, `Keccak256::finalize(self)` is 0, `Keccak256::update(&mut self, bytes)`
// is 1.
//
// THE THREE SPELLINGS THAT MUST **NOT** RESOLVE ARE ASSERTED TOO, because a
// contract that joins something it should not is as wrong as one that joins
// nothing:
//   - the mechanical `::` substitution applied to a one-dot free-function key;
//   - a `PrimitiveSignature` x `_secp256k1` pairing, whose windows are disjoint;
//   - anything under `alloy_primitives::signature`, a PRIVATE module in every
//     release (E0603).
func TestAlloyPrimitivesEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := map[string]int{
		// free functions -- ONE dot, no separator to move
		"alloy_primitives.keccak256":                  1,
		"alloy_primitives.eip191_hash_message":        1,
		"alloy_primitives.keccak256_uncached":         1,
		"alloy_primitives::utils.keccak256":           1,
		"alloy_primitives::utils.eip191_hash_message": 1,
		"alloy_primitives::utils.keccak256_cached":    1,
		"alloy_primitives::utils.keccak256_uncached":  1,
		// the incremental hasher -- TWO dots, both import spellings
		"alloy_primitives.Keccak256.new":                        0,
		"alloy_primitives.Keccak256.default":                    0,
		"alloy_primitives.Keccak256.update":                     1,
		"alloy_primitives.Keccak256.finalize":                   0,
		"alloy_primitives.Keccak256.finalize_into":              1,
		"alloy_primitives.Keccak256.finalize_into_array":        1,
		"alloy_primitives::utils.Keccak256.new":                 0,
		"alloy_primitives::utils.Keccak256.default":             0,
		"alloy_primitives::utils.Keccak256.update":              1,
		"alloy_primitives::utils.Keccak256.finalize":            0,
		"alloy_primitives::utils.Keccak256.finalize_into":       1,
		"alloy_primitives::utils.Keccak256.finalize_into_array": 1,
		// the recovery surface -- TWO dots
		"alloy_primitives.Signature.recover_address_from_msg":       1,
		"alloy_primitives.Signature.recover_address_from_prehash":   1,
		"alloy_primitives.Signature.recover_from_msg":               1,
		"alloy_primitives.Signature.recover_from_prehash":           1,
		"alloy_primitives.Signature.to_k256":                        0,
		"alloy_primitives.Signature.to_secp256k1":                   0,
		"alloy_primitives.Signature.recover_from_msg_secp256k1":     1,
		"alloy_primitives.Signature.recover_from_prehash_secp256k1": 1,
		// the 0.8.10 - 1.4.1 type name
		"alloy_primitives.PrimitiveSignature.recover_address_from_msg":     1,
		"alloy_primitives.PrimitiveSignature.recover_address_from_prehash": 1,
		"alloy_primitives.PrimitiveSignature.recover_from_msg":             1,
		"alloy_primitives.PrimitiveSignature.recover_from_prehash":         1,
		"alloy_primitives.PrimitiveSignature.to_k256":                      0,
	}
	if len(emitted) != len(wantAlloyPrimitivesContracts) {
		t.Fatalf("this test covers %d emitted keys but the family declares %d contracts",
			len(emitted), len(wantAlloyPrimitivesContracts))
	}
	for key, arity := range emitted {
		if got := kb.ContractsFor(key, arity); len(got) == 0 {
			t.Errorf("emitted key %q at arity %d resolves to nothing", key, arity)
		}
	}

	mustNotResolve := map[string]int{
		// the mechanical substitution applied to a one-dot free function
		"alloy::primitives.keccak256":           1,
		"alloy_primitives::utils::keccak256":    1,
		"alloy_primitives::eip191_hash_message": 1,
		// disjoint windows: PrimitiveSignature ends at 1.4.1, the secp256k1
		// feature begins at 1.6.0
		"alloy_primitives.PrimitiveSignature.to_secp256k1":                   0,
		"alloy_primitives.PrimitiveSignature.recover_from_msg_secp256k1":     1,
		"alloy_primitives.PrimitiveSignature.recover_from_prehash_secp256k1": 1,
		// `mod signature;` is private in every release
		"alloy_primitives::signature.Signature.recover_address_from_msg": 1,
		"alloy_primitives::signature.Signature.to_k256":                  0,
	}
	for key, arity := range mustNotResolve {
		if got := kb.ContractsFor(key, arity); len(got) != 0 {
			t.Errorf("key %q at arity %d must not resolve, got %d contracts", key, arity, len(got))
		}
	}
}
