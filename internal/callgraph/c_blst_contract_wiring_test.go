// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The blst contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestBLSTContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <blst.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) {
    blst_keygen(a0, a1, a2, a3, a4);
    blst_keygen_v3(a0, a1, a2, a3, a4);
    blst_keygen_v4_5(a0, a1, a2, a3, a4, a5, a6);
    blst_keygen_v5(a0, a1, a2, a3, a4, a5, a6);
    blst_derive_master_eip2333(a0, a1, a2);
    blst_derive_child_eip2333(a0, a1, a2);
    blst_sk_to_pk_in_g1(a0, a1);
    blst_sk_to_pk_in_g2(a0, a1);
    blst_hash_to_g1(a0, a1, a2, a3, a4, a5, a6);
    blst_hash_to_g2(a0, a1, a2, a3, a4, a5, a6);
    blst_encode_to_g1(a0, a1, a2, a3, a4, a5, a6);
    blst_encode_to_g2(a0, a1, a2, a3, a4, a5, a6);
    blst_sign_pk_in_g1(a0, a1, a2);
    blst_sign_pk_in_g2(a0, a1, a2);
    blst_core_verify_pk_in_g1(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    blst_core_verify_pk_in_g2(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    blst_miller_loop(a0, a1, a2);
    blst_miller_loop_n(a0, a1, a2, a3);
    blst_miller_loop_lines(a0, a1, a2);
    blst_final_exp(a0, a1);
    blst_fp12_finalverify(a0, a1);
    blst_pairing_init(a0, a1, a2, a3);
    blst_pairing_aggregate_pk_in_g1(a0, a1, a2, a3, a4, a5, a6);
    blst_pairing_aggregate_pk_in_g2(a0, a1, a2, a3, a4, a5, a6);
    blst_pairing_mul_n_aggregate_pk_in_g1(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    blst_pairing_mul_n_aggregate_pk_in_g2(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    blst_pairing_commit(a0);
    blst_pairing_merge(a0, a1);
    blst_pairing_finalverify(a0, a1);
    blst_p1_to_affine(a0, a1);
    blst_p2_to_affine(a0, a1);
    blst_p1_from_affine(a0, a1);
    blst_p2_from_affine(a0, a1);
    blst_p1_uncompress(a0, a1);
    blst_p2_uncompress(a0, a1);
    blst_p1_deserialize(a0, a1);
    blst_p2_deserialize(a0, a1);
    blst_p1_compress(a0, a1);
    blst_p2_compress(a0, a1);
    blst_p1_affine_compress(a0, a1);
    blst_p2_affine_compress(a0, a1);
    blst_p1_serialize(a0, a1);
    blst_p2_serialize(a0, a1);
    blst_p1_affine_serialize(a0, a1);
    blst_p2_affine_serialize(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) {
    blst_p1_affine_is_equal(a0, a1);
    blst_p2_affine_in_g2(a0);
    blst_pairing_sizeof();
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"blst_keygen":                           {5, "operation"},
		"blst_keygen_v3":                        {5, "operation"},
		"blst_keygen_v4_5":                      {7, "operation"},
		"blst_keygen_v5":                        {7, "operation"},
		"blst_derive_master_eip2333":            {3, "operation"},
		"blst_derive_child_eip2333":             {3, "operation"},
		"blst_sk_to_pk_in_g1":                   {2, "operation"},
		"blst_sk_to_pk_in_g2":                   {2, "operation"},
		"blst_hash_to_g1":                       {7, "operation"},
		"blst_hash_to_g2":                       {7, "operation"},
		"blst_encode_to_g1":                     {7, "operation"},
		"blst_encode_to_g2":                     {7, "operation"},
		"blst_sign_pk_in_g1":                    {3, "operation"},
		"blst_sign_pk_in_g2":                    {3, "operation"},
		"blst_core_verify_pk_in_g1":             {9, "operation"},
		"blst_core_verify_pk_in_g2":             {9, "operation"},
		"blst_miller_loop":                      {3, "operation"},
		"blst_miller_loop_n":                    {4, "operation"},
		"blst_miller_loop_lines":                {3, "operation"},
		"blst_final_exp":                        {2, "operation"},
		"blst_fp12_finalverify":                 {2, "operation"},
		"blst_pairing_init":                     {4, "config"},
		"blst_pairing_aggregate_pk_in_g1":       {7, "operation"},
		"blst_pairing_aggregate_pk_in_g2":       {7, "operation"},
		"blst_pairing_mul_n_aggregate_pk_in_g1": {9, "operation"},
		"blst_pairing_mul_n_aggregate_pk_in_g2": {9, "operation"},
		"blst_pairing_commit":                   {1, "operation"},
		"blst_pairing_merge":                    {2, "operation"},
		"blst_pairing_finalverify":              {2, "operation"},
		"blst_p1_to_affine":                     {2, "factory"},
		"blst_p2_to_affine":                     {2, "factory"},
		"blst_p1_from_affine":                   {2, "factory"},
		"blst_p2_from_affine":                   {2, "factory"},
		"blst_p1_uncompress":                    {2, "factory"},
		"blst_p2_uncompress":                    {2, "factory"},
		"blst_p1_deserialize":                   {2, "factory"},
		"blst_p2_deserialize":                   {2, "factory"},
		"blst_p1_compress":                      {2, "output"},
		"blst_p2_compress":                      {2, "output"},
		"blst_p1_affine_compress":               {2, "output"},
		"blst_p2_affine_compress":               {2, "output"},
		"blst_p1_serialize":                     {2, "output"},
		"blst_p2_serialize":                     {2, "output"},
		"blst_p1_affine_serialize":              {2, "output"},
		"blst_p2_affine_serialize":              {2, "output"},
	}
	negative := []string{"blst_p1_affine_is_equal", "blst_p2_affine_in_g2", "blst_pairing_sizeof"}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)

				bare := method
				if idx := strings.LastIndex(bare, "."); idx >= 0 {
					bare = bare[idx+1:]
				}

				for _, n := range negative {
					if bare == n {
						if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
							t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
						}
						seen[bare] = true
					}
				}

				expect, ok := want[bare]
				if !ok {
					continue
				}
				if len(call.Arguments) != expect.arity {
					t.Fatalf("%s: parsed arity %d, want %d", bare, len(call.Arguments), expect.arity)
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract", method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", bare, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "blst" {
					t.Fatalf("%s: library = %q, want blst", bare, got[0].SourceLibrary)
				}
				seen[bare] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q", method)
		}
	}
	for _, n := range negative {
		if !seen[n] {
			t.Fatalf("parsed calls did not cover negative %q", n)
		}
	}
}
