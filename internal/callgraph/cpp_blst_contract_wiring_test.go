// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The blst contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestBLSTWrapperContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include <blst.hpp>

void flows(blst::SecretKey& sk, blst::P1& p1, blst::P2& p2, blst::P1_Affine& a1, blst::P2_Affine& a2, blst::PT& pt, blst::Pairing& ctx, int x) {
    sk.keygen(x);
    sk.keygen(x, x);
    sk.keygen(x, x, x);
    sk.keygen_v3(x);
    sk.keygen_v3(x, x);
    sk.keygen_v3(x, x, x);
    sk.keygen_v4_5(x, x);
    sk.keygen_v4_5(x, x, x);
    sk.keygen_v4_5(x, x, x, x);
    sk.keygen_v4_5(x, x, x, x, x);
    sk.keygen_v5(x, x);
    sk.keygen_v5(x, x, x);
    sk.keygen_v5(x, x, x, x);
    sk.keygen_v5(x, x, x, x, x);
    sk.derive_master_eip2333(x, x);
    sk.derive_child_eip2333(x, x);
    p1.hash_to(x);
    p1.hash_to(x, x);
    p1.hash_to(x, x, x);
    p1.hash_to(x, x, x, x);
    p1.hash_to(x, x, x, x, x);
    p1.encode_to(x);
    p1.encode_to(x, x);
    p1.encode_to(x, x, x);
    p1.encode_to(x, x, x, x);
    p1.encode_to(x, x, x, x, x);
    p1.sign_with(x);
    p1.aggregate(x);
    p1.to_affine();
    p1.serialize(x);
    p1.compress(x);
    a1.core_verify(x, x, x);
    a1.core_verify(x, x, x, x);
    a1.core_verify(x, x, x, x, x);
    a1.core_verify(x, x, x, x, x, x);
    a1.core_verify(x, x, x, x, x, x, x);
    a1.serialize(x);
    a1.compress(x);
    p2.hash_to(x);
    p2.hash_to(x, x);
    p2.hash_to(x, x, x);
    p2.hash_to(x, x, x, x);
    p2.hash_to(x, x, x, x, x);
    p2.encode_to(x);
    p2.encode_to(x, x);
    p2.encode_to(x, x, x);
    p2.encode_to(x, x, x, x);
    p2.encode_to(x, x, x, x, x);
    p2.sign_with(x);
    p2.aggregate(x);
    p2.to_affine();
    p2.serialize(x);
    p2.compress(x);
    a2.core_verify(x, x, x);
    a2.core_verify(x, x, x, x);
    a2.core_verify(x, x, x, x, x);
    a2.core_verify(x, x, x, x, x, x);
    a2.core_verify(x, x, x, x, x, x, x);
    a2.serialize(x);
    a2.compress(x);
    pt.final_exp();
    blst::PT::finalverify(x, x);
    ctx.init(x, x, x);
    ctx.aggregate(x, x, x);
    ctx.aggregate(x, x, x, x);
    ctx.aggregate(x, x, x, x, x);
    ctx.aggregate(x, x, x, x, x, x);
    ctx.mul_n_aggregate(x, x, x, x, x);
    ctx.mul_n_aggregate(x, x, x, x, x, x);
    ctx.mul_n_aggregate(x, x, x, x, x, x, x);
    ctx.mul_n_aggregate(x, x, x, x, x, x, x, x);
    ctx.commit();
    ctx.merge(x);
    ctx.finalverify();
    ctx.finalverify(x);
    a1.is_equal(x);
    p1.dup();
}
`
	if err := os.WriteFile(filepath.Join(dir, "bls.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"blst::SecretKey.keygen#1":                "operation",
		"blst::SecretKey.keygen#2":                "operation",
		"blst::SecretKey.keygen#3":                "operation",
		"blst::SecretKey.keygen_v3#1":             "operation",
		"blst::SecretKey.keygen_v3#2":             "operation",
		"blst::SecretKey.keygen_v3#3":             "operation",
		"blst::SecretKey.keygen_v4_5#2":           "operation",
		"blst::SecretKey.keygen_v4_5#3":           "operation",
		"blst::SecretKey.keygen_v4_5#4":           "operation",
		"blst::SecretKey.keygen_v4_5#5":           "operation",
		"blst::SecretKey.keygen_v5#2":             "operation",
		"blst::SecretKey.keygen_v5#3":             "operation",
		"blst::SecretKey.keygen_v5#4":             "operation",
		"blst::SecretKey.keygen_v5#5":             "operation",
		"blst::SecretKey.derive_master_eip2333#2": "operation",
		"blst::SecretKey.derive_child_eip2333#2":  "operation",
		"blst::P1.hash_to#1":                      "operation",
		"blst::P1.hash_to#2":                      "operation",
		"blst::P1.hash_to#3":                      "operation",
		"blst::P1.hash_to#4":                      "operation",
		"blst::P1.hash_to#5":                      "operation",
		"blst::P1.encode_to#1":                    "operation",
		"blst::P1.encode_to#2":                    "operation",
		"blst::P1.encode_to#3":                    "operation",
		"blst::P1.encode_to#4":                    "operation",
		"blst::P1.encode_to#5":                    "operation",
		"blst::P1.sign_with#1":                    "operation",
		"blst::P1.aggregate#1":                    "operation",
		"blst::P1.to_affine#0":                    "output",
		"blst::P1.serialize#1":                    "output",
		"blst::P1.compress#1":                     "output",
		"blst::P1_Affine.core_verify#3":           "operation",
		"blst::P1_Affine.core_verify#4":           "operation",
		"blst::P1_Affine.core_verify#5":           "operation",
		"blst::P1_Affine.core_verify#6":           "operation",
		"blst::P1_Affine.core_verify#7":           "operation",
		"blst::P1_Affine.serialize#1":             "output",
		"blst::P1_Affine.compress#1":              "output",
		"blst::P2.hash_to#1":                      "operation",
		"blst::P2.hash_to#2":                      "operation",
		"blst::P2.hash_to#3":                      "operation",
		"blst::P2.hash_to#4":                      "operation",
		"blst::P2.hash_to#5":                      "operation",
		"blst::P2.encode_to#1":                    "operation",
		"blst::P2.encode_to#2":                    "operation",
		"blst::P2.encode_to#3":                    "operation",
		"blst::P2.encode_to#4":                    "operation",
		"blst::P2.encode_to#5":                    "operation",
		"blst::P2.sign_with#1":                    "operation",
		"blst::P2.aggregate#1":                    "operation",
		"blst::P2.to_affine#0":                    "output",
		"blst::P2.serialize#1":                    "output",
		"blst::P2.compress#1":                     "output",
		"blst::P2_Affine.core_verify#3":           "operation",
		"blst::P2_Affine.core_verify#4":           "operation",
		"blst::P2_Affine.core_verify#5":           "operation",
		"blst::P2_Affine.core_verify#6":           "operation",
		"blst::P2_Affine.core_verify#7":           "operation",
		"blst::P2_Affine.serialize#1":             "output",
		"blst::P2_Affine.compress#1":              "output",
		"blst::PT.final_exp#0":                    "operation",
		"blst::PT.finalverify#2":                  "operation",
		"blst::Pairing.init#3":                    "config",
		"blst::Pairing.aggregate#3":               "operation",
		"blst::Pairing.aggregate#4":               "operation",
		"blst::Pairing.aggregate#5":               "operation",
		"blst::Pairing.aggregate#6":               "operation",
		"blst::Pairing.mul_n_aggregate#5":         "operation",
		"blst::Pairing.mul_n_aggregate#6":         "operation",
		"blst::Pairing.mul_n_aggregate#7":         "operation",
		"blst::Pairing.mul_n_aggregate#8":         "operation",
		"blst::Pairing.commit#0":                  "operation",
		"blst::Pairing.merge#1":                   "operation",
		"blst::Pairing.finalverify#0":             "operation",
		"blst::Pairing.finalverify#1":             "operation",
	}
	negative := map[string]bool{}
	for _, key := range []string{"blst::P1_Affine.is_equal#1", "blst::P1.dup#0"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one blst contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "blst" {
					t.Fatalf("contract for %q = role %q library %q, want blst %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}
