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

// The cotp contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestCOTPContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "cotp.h"

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5) {
    totp_new(a0, a1, a2, a3, a4, a5);
    hotp_new(a0, a1, a2, a3, a4);
    otp_new(a0, a1, a2, a3);
    totp_now(a0, a1);
    totp_at(a0, a1, a2, a3);
    hotp_at(a0, a1, a2);
    hotp_next(a0, a1);
    otp_generate(a0, a1, a2);
    totp_verify(a0, a1, a2, a3);
    totp_compare(a0, a1, a2, a3);
    hotp_compare(a0, a1, a2);
    otp_random_base32(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5) {
    otp_free(a0);
    totp_timecode(a0, a1);
    totp_valid_until(a0, a1, a2);
    otp_byte_secret(a0, a1);
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
		"totp_new":          {6, "factory"},
		"hotp_new":          {5, "factory"},
		"otp_new":           {4, "factory"},
		"totp_now":          {2, "operation"},
		"totp_at":           {4, "operation"},
		"hotp_at":           {3, "operation"},
		"hotp_next":         {2, "operation"},
		"otp_generate":      {3, "operation"},
		"totp_verify":       {4, "operation"},
		"totp_compare":      {4, "operation"},
		"hotp_compare":      {3, "operation"},
		"otp_random_base32": {2, "operation"},
	}
	negative := []string{"otp_free", "totp_timecode", "totp_valid_until", "otp_byte_secret"}

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
				if got[0].SourceLibrary != "cotp" {
					t.Fatalf("%s: library = %q, want cotp", bare, got[0].SourceLibrary)
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
func TestCOTPContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"totp_new": {6, 2, "algorithm"},
		"hotp_new": {5, 2, "algorithm"},
		"otp_new":  {4, 2, "algorithm"},
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

// otp_random_base32 took a character set until v1.1.1 dropped it, so both
// arities are contracted and must resolve to the same operation.
func TestCOTPContractsCoverBothRandomBase32Arities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, arity := range []int{2, 3} {
		got := kb.ContractsForCFunction("otp_random_base32", arity, true)
		if len(got) != 1 || got[0].Role != "operation" || got[0].SourceLibrary != "cotp" {
			t.Fatalf("otp_random_base32/%d = %#v, want one cotp operation", arity, got)
		}
	}
}
