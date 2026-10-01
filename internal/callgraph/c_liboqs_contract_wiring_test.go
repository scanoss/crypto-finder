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

// The liboqs contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestLibOQSContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <oqs/oqs.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) {
    OQS_KEM_new(a0);
    OQS_KEM_keypair(a0, a1, a2);
    OQS_KEM_keypair_derand(a0, a1, a2, a3);
    OQS_KEM_encaps(a0, a1, a2, a3);
    OQS_KEM_encaps_derand(a0, a1, a2, a3, a4);
    OQS_KEM_decaps(a0, a1, a2, a3);
    OQS_SIG_new(a0);
    OQS_SIG_keypair(a0, a1, a2);
    OQS_SIG_sign(a0, a1, a2, a3, a4, a5);
    OQS_SIG_sign_with_ctx_str(a0, a1, a2, a3, a4, a5, a6, a7);
    OQS_SIG_verify(a0, a1, a2, a3, a4, a5);
    OQS_SIG_verify_with_ctx_str(a0, a1, a2, a3, a4, a5, a6, a7);
    OQS_KEM_ml_kem_512_keypair(a0, a1);
    OQS_KEM_ml_kem_512_keypair_derand(a0, a1, a2);
    OQS_KEM_ml_kem_512_encaps(a0, a1, a2);
    OQS_KEM_ml_kem_512_encaps_derand(a0, a1, a2, a3);
    OQS_KEM_ml_kem_512_decaps(a0, a1, a2);
    OQS_KEM_ml_kem_768_keypair(a0, a1);
    OQS_KEM_ml_kem_768_keypair_derand(a0, a1, a2);
    OQS_KEM_ml_kem_768_encaps(a0, a1, a2);
    OQS_KEM_ml_kem_768_encaps_derand(a0, a1, a2, a3);
    OQS_KEM_ml_kem_768_decaps(a0, a1, a2);
    OQS_KEM_ml_kem_1024_keypair(a0, a1);
    OQS_KEM_ml_kem_1024_keypair_derand(a0, a1, a2);
    OQS_KEM_ml_kem_1024_encaps(a0, a1, a2);
    OQS_KEM_ml_kem_1024_encaps_derand(a0, a1, a2, a3);
    OQS_KEM_ml_kem_1024_decaps(a0, a1, a2);
    OQS_SIG_ml_dsa_44_keypair(a0, a1);
    OQS_SIG_ml_dsa_44_sign(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_44_sign_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
    OQS_SIG_ml_dsa_44_verify(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_44_verify_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
    OQS_SIG_ml_dsa_65_keypair(a0, a1);
    OQS_SIG_ml_dsa_65_sign(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_65_sign_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
    OQS_SIG_ml_dsa_65_verify(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_65_verify_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
    OQS_SIG_ml_dsa_87_keypair(a0, a1);
    OQS_SIG_ml_dsa_87_sign(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_87_sign_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
    OQS_SIG_ml_dsa_87_verify(a0, a1, a2, a3, a4);
    OQS_SIG_ml_dsa_87_verify_with_ctx_str(a0, a1, a2, a3, a4, a5, a6);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) {
    OQS_KEM_free(a0);
    OQS_SIG_free(a0);
    OQS_KEM_alg_is_enabled(a0);
    OQS_SIG_supports_ctx_str(a0);
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
		"OQS_KEM_new":                           {1, "factory"},
		"OQS_KEM_keypair":                       {3, "operation"},
		"OQS_KEM_keypair_derand":                {4, "operation"},
		"OQS_KEM_encaps":                        {4, "operation"},
		"OQS_KEM_encaps_derand":                 {5, "operation"},
		"OQS_KEM_decaps":                        {4, "operation"},
		"OQS_SIG_new":                           {1, "factory"},
		"OQS_SIG_keypair":                       {3, "operation"},
		"OQS_SIG_sign":                          {6, "operation"},
		"OQS_SIG_sign_with_ctx_str":             {8, "operation"},
		"OQS_SIG_verify":                        {6, "operation"},
		"OQS_SIG_verify_with_ctx_str":           {8, "operation"},
		"OQS_KEM_ml_kem_512_keypair":            {2, "operation"},
		"OQS_KEM_ml_kem_512_keypair_derand":     {3, "operation"},
		"OQS_KEM_ml_kem_512_encaps":             {3, "operation"},
		"OQS_KEM_ml_kem_512_encaps_derand":      {4, "operation"},
		"OQS_KEM_ml_kem_512_decaps":             {3, "operation"},
		"OQS_KEM_ml_kem_768_keypair":            {2, "operation"},
		"OQS_KEM_ml_kem_768_keypair_derand":     {3, "operation"},
		"OQS_KEM_ml_kem_768_encaps":             {3, "operation"},
		"OQS_KEM_ml_kem_768_encaps_derand":      {4, "operation"},
		"OQS_KEM_ml_kem_768_decaps":             {3, "operation"},
		"OQS_KEM_ml_kem_1024_keypair":           {2, "operation"},
		"OQS_KEM_ml_kem_1024_keypair_derand":    {3, "operation"},
		"OQS_KEM_ml_kem_1024_encaps":            {3, "operation"},
		"OQS_KEM_ml_kem_1024_encaps_derand":     {4, "operation"},
		"OQS_KEM_ml_kem_1024_decaps":            {3, "operation"},
		"OQS_SIG_ml_dsa_44_keypair":             {2, "operation"},
		"OQS_SIG_ml_dsa_44_sign":                {5, "operation"},
		"OQS_SIG_ml_dsa_44_sign_with_ctx_str":   {7, "operation"},
		"OQS_SIG_ml_dsa_44_verify":              {5, "operation"},
		"OQS_SIG_ml_dsa_44_verify_with_ctx_str": {7, "operation"},
		"OQS_SIG_ml_dsa_65_keypair":             {2, "operation"},
		"OQS_SIG_ml_dsa_65_sign":                {5, "operation"},
		"OQS_SIG_ml_dsa_65_sign_with_ctx_str":   {7, "operation"},
		"OQS_SIG_ml_dsa_65_verify":              {5, "operation"},
		"OQS_SIG_ml_dsa_65_verify_with_ctx_str": {7, "operation"},
		"OQS_SIG_ml_dsa_87_keypair":             {2, "operation"},
		"OQS_SIG_ml_dsa_87_sign":                {5, "operation"},
		"OQS_SIG_ml_dsa_87_sign_with_ctx_str":   {7, "operation"},
		"OQS_SIG_ml_dsa_87_verify":              {5, "operation"},
		"OQS_SIG_ml_dsa_87_verify_with_ctx_str": {7, "operation"},
	}
	negative := []string{"OQS_KEM_free", "OQS_SIG_free", "OQS_KEM_alg_is_enabled", "OQS_SIG_supports_ctx_str"}

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
				if got[0].SourceLibrary != "liboqs" {
					t.Fatalf("%s: library = %q, want liboqs", bare, got[0].SourceLibrary)
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

// The consumer names the algorithm, parameter set or mode at the call site. Each
// call that takes that selector must carry it as operation-determining at the
// right index, or the identity of the finding it supports is unattributed.
func TestLibOQSContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"OQS_KEM_new": {1, 0, "algorithm"},
		"OQS_SIG_new": {1, 0, "algorithm"},
	}

	for method, want := range selector {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != want.index {
				continue
			}
			found = true
			if p.Role != "operation-determining" {
				t.Errorf("%s: parameters[%d].role = %q, want operation-determining", method, want.index, p.Role)
			}
			if p.Contributes == nil || p.Contributes.Property != want.property {
				t.Errorf("%s: parameters[%d] contributes %#v, want property %s", method, want.index, p.Contributes, want.property)
			}
		}
		if !found {
			t.Errorf("%s: no parameter entry at index %d", method, want.index)
		}
	}
}
