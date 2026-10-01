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

// The mcl contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestMCLContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <mcl/she.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5) {
    mclBn_init(a0, a1);
    sheInit(a0, a1);
    sheSetRangeForDLP(a0);
    ecdsaInit();
    mclBnG1_hashAndMapTo(a0, a1, a2);
    mclBnG1_hashAndMapToWithDst(a0, a1, a2, a3, a4);
    mclBnG2_hashAndMapTo(a0, a1, a2);
    mclBnG2_hashAndMapToWithDst(a0, a1, a2, a3, a4);
    mclBn_pairing(a0, a1, a2);
    mclBn_millerLoop(a0, a1, a2);
    mclBn_millerLoopVec(a0, a1, a2, a3);
    mclBn_millerLoopVecMT(a0, a1, a2, a3, a4);
    mclBn_precomputedMillerLoop(a0, a1, a2);
    mclBn_precomputedMillerLoop2(a0, a1, a2, a3, a4);
    mclBn_precomputedMillerLoop2mixed(a0, a1, a2, a3, a4);
    mclBn_finalExp(a0, a1);
    ecdsaSecretKeySetByCSPRNG(a0);
    ecdsaGetPublicKey(a0, a1);
    ecdsaSign(a0, a1, a2, a3);
    ecdsaVerify(a0, a1, a2, a3);
    ecdsaVerifyPrecomputed(a0, a1, a2, a3);
    ecdsaSignatureSerialize(a0, a1, a2);
    sheSecretKeySetByCSPRNG(a0);
    sheGetPublicKey(a0, a1);
    sheEncG1(a0, a1, a2);
    sheEncG2(a0, a1, a2);
    sheEncGT(a0, a1, a2);
    sheEncIntVecG1(a0, a1, a2, a3);
    sheEncIntVecG2(a0, a1, a2, a3);
    sheEncIntVecGT(a0, a1, a2, a3);
    sheEncWithZkpBinG1(a0, a1, a2, a3);
    sheEncWithZkpBinG2(a0, a1, a2, a3);
    sheEncWithZkpBinEq(a0, a1, a2, a3, a4);
    sheEncWithZkpEq(a0, a1, a2, a3, a4);
    sheEncWithZkpSetG1(a0, a1, a2, a3, a4, a5);
    shePrecomputedPublicKeyEncG1(a0, a1, a2);
    shePrecomputedPublicKeyEncG2(a0, a1, a2);
    shePrecomputedPublicKeyEncGT(a0, a1, a2);
    shePrecomputedPublicKeyEncIntVecG1(a0, a1, a2, a3);
    shePrecomputedPublicKeyEncIntVecG2(a0, a1, a2, a3);
    shePrecomputedPublicKeyEncIntVecGT(a0, a1, a2, a3);
    shePrecomputedPublicKeyEncWithZkpBinG1(a0, a1, a2, a3);
    shePrecomputedPublicKeyEncWithZkpBinG2(a0, a1, a2, a3);
    shePrecomputedPublicKeyEncWithZkpBinEq(a0, a1, a2, a3, a4);
    shePrecomputedPublicKeyEncWithZkpEq(a0, a1, a2, a3, a4);
    shePrecomputedPublicKeyEncWithZkpSetG1(a0, a1, a2, a3, a4, a5);
    sheDecG1(a0, a1, a2);
    sheDecG2(a0, a1, a2);
    sheDecGT(a0, a1, a2);
    sheDecG1ViaGT(a0, a1, a2);
    sheDecG2ViaGT(a0, a1, a2);
    sheDecWithZkpDecG1(a0, a1, a2, a3, a4);
    sheDecWithZkpDecGT(a0, a1, a2, a3, a4);
    sheAddG1(a0, a1, a2);
    sheAddG2(a0, a1, a2);
    sheAddGT(a0, a1, a2);
    sheSubG1(a0, a1, a2);
    sheSubG2(a0, a1, a2);
    sheSubGT(a0, a1, a2);
    sheMulG1(a0, a1, a2);
    sheMulG2(a0, a1, a2);
    sheMulGT(a0, a1, a2);
    sheMul(a0, a1, a2);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5) {
    mclBnGT_isEqual(a0, a1);
    mclBnG1_mul(a0, a1, a2);
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
		"mclBn_init":                             {2, "config"},
		"sheInit":                                {2, "config"},
		"sheSetRangeForDLP":                      {1, "config"},
		"ecdsaInit":                              {0, "config"},
		"mclBnG1_hashAndMapTo":                   {3, "operation"},
		"mclBnG1_hashAndMapToWithDst":            {5, "operation"},
		"mclBnG2_hashAndMapTo":                   {3, "operation"},
		"mclBnG2_hashAndMapToWithDst":            {5, "operation"},
		"mclBn_pairing":                          {3, "operation"},
		"mclBn_millerLoop":                       {3, "operation"},
		"mclBn_millerLoopVec":                    {4, "operation"},
		"mclBn_millerLoopVecMT":                  {5, "operation"},
		"mclBn_precomputedMillerLoop":            {3, "operation"},
		"mclBn_precomputedMillerLoop2":           {5, "operation"},
		"mclBn_precomputedMillerLoop2mixed":      {5, "operation"},
		"mclBn_finalExp":                         {2, "operation"},
		"ecdsaSecretKeySetByCSPRNG":              {1, "operation"},
		"ecdsaGetPublicKey":                      {2, "operation"},
		"ecdsaSign":                              {4, "operation"},
		"ecdsaVerify":                            {4, "operation"},
		"ecdsaVerifyPrecomputed":                 {4, "operation"},
		"ecdsaSignatureSerialize":                {3, "output"},
		"sheSecretKeySetByCSPRNG":                {1, "operation"},
		"sheGetPublicKey":                        {2, "operation"},
		"sheEncG1":                               {3, "operation"},
		"sheEncG2":                               {3, "operation"},
		"sheEncGT":                               {3, "operation"},
		"sheEncIntVecG1":                         {4, "operation"},
		"sheEncIntVecG2":                         {4, "operation"},
		"sheEncIntVecGT":                         {4, "operation"},
		"sheEncWithZkpBinG1":                     {4, "operation"},
		"sheEncWithZkpBinG2":                     {4, "operation"},
		"sheEncWithZkpBinEq":                     {5, "operation"},
		"sheEncWithZkpEq":                        {5, "operation"},
		"sheEncWithZkpSetG1":                     {6, "operation"},
		"shePrecomputedPublicKeyEncG1":           {3, "operation"},
		"shePrecomputedPublicKeyEncG2":           {3, "operation"},
		"shePrecomputedPublicKeyEncGT":           {3, "operation"},
		"shePrecomputedPublicKeyEncIntVecG1":     {4, "operation"},
		"shePrecomputedPublicKeyEncIntVecG2":     {4, "operation"},
		"shePrecomputedPublicKeyEncIntVecGT":     {4, "operation"},
		"shePrecomputedPublicKeyEncWithZkpBinG1": {4, "operation"},
		"shePrecomputedPublicKeyEncWithZkpBinG2": {4, "operation"},
		"shePrecomputedPublicKeyEncWithZkpBinEq": {5, "operation"},
		"shePrecomputedPublicKeyEncWithZkpEq":    {5, "operation"},
		"shePrecomputedPublicKeyEncWithZkpSetG1": {6, "operation"},
		"sheDecG1":                               {3, "operation"},
		"sheDecG2":                               {3, "operation"},
		"sheDecGT":                               {3, "operation"},
		"sheDecG1ViaGT":                          {3, "operation"},
		"sheDecG2ViaGT":                          {3, "operation"},
		"sheDecWithZkpDecG1":                     {5, "operation"},
		"sheDecWithZkpDecGT":                     {5, "operation"},
		"sheAddG1":                               {3, "operation"},
		"sheAddG2":                               {3, "operation"},
		"sheAddGT":                               {3, "operation"},
		"sheSubG1":                               {3, "operation"},
		"sheSubG2":                               {3, "operation"},
		"sheSubGT":                               {3, "operation"},
		"sheMulG1":                               {3, "operation"},
		"sheMulG2":                               {3, "operation"},
		"sheMulGT":                               {3, "operation"},
		"sheMul":                                 {3, "operation"},
	}
	negative := []string{"mclBnGT_isEqual", "mclBnG1_mul"}

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
				if got[0].SourceLibrary != "mcl" {
					t.Fatalf("%s: library = %q, want mcl", bare, got[0].SourceLibrary)
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
func TestMCLContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"mclBn_init": {2, 0, "algorithm"},
		"sheInit":    {2, 0, "algorithm"},
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
