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

// The rnp contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: calls outside the contracted surface resolve to nothing.
func TestRNPContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <rnp/rnp.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    rnp_op_encrypt_create(a0, a1, a2, a3);
    rnp_op_encrypt_add_recipient(a0, a1);
    rnp_op_encrypt_add_password(a0, a1, a2, a3, a4);
    rnp_op_encrypt_add_signature(a0, a1, a2);
    rnp_op_encrypt_set_cipher(a0, a1);
    rnp_op_encrypt_set_aead(a0, a1);
    rnp_op_encrypt_set_aead_bits(a0, a1);
    rnp_op_encrypt_set_hash(a0, a1);
    rnp_op_encrypt_set_armor(a0, a1);
    rnp_op_encrypt_set_flags(a0, a1);
    rnp_op_encrypt_execute(a0);
    rnp_op_sign_create(a0, a1, a2, a3);
    rnp_op_sign_cleartext_create(a0, a1, a2, a3);
    rnp_op_sign_detached_create(a0, a1, a2, a3);
    rnp_op_sign_add_signature(a0, a1, a2);
    rnp_op_sign_set_hash(a0, a1);
    rnp_op_sign_signature_set_hash(a0, a1);
    rnp_op_sign_set_armor(a0, a1);
    rnp_op_sign_execute(a0);
    rnp_op_verify_create(a0, a1, a2, a3);
    rnp_op_verify_detached_create(a0, a1, a2, a3);
    rnp_op_verify_set_flags(a0, a1);
    rnp_op_verify_execute(a0);
    rnp_op_verify_get_signature_at(a0, a1, a2);
    rnp_op_verify_signature_get_status(a0);
    rnp_op_verify_signature_get_hash(a0, a1);
    rnp_op_verify_signature_get_key(a0, a1);
    rnp_op_verify_get_used_recipient(a0, a1);
    rnp_op_verify_get_used_symenc(a0, a1);
    rnp_decrypt(a0, a1, a2);
    rnp_signature_is_valid(a0, a1);
    rnp_op_generate_create(a0, a1, a2);
    rnp_op_generate_subkey_create(a0, a1, a2, a3);
    rnp_op_generate_set_bits(a0, a1);
    rnp_op_generate_set_curve(a0, a1);
    rnp_op_generate_set_hash(a0, a1);
    rnp_op_generate_set_dsa_qbits(a0, a1);
    rnp_op_generate_set_protection_cipher(a0, a1);
    rnp_op_generate_set_protection_hash(a0, a1);
    rnp_op_generate_set_protection_mode(a0, a1);
    rnp_op_generate_set_protection_iterations(a0, a1);
    rnp_op_generate_set_protection_password(a0, a1);
    rnp_op_generate_set_userid(a0, a1);
    rnp_op_generate_set_expiration(a0, a1);
    rnp_op_generate_add_usage(a0, a1);
    rnp_op_generate_add_pref_hash(a0, a1);
    rnp_op_generate_add_pref_cipher(a0, a1);
    rnp_op_generate_execute(a0);
    rnp_op_generate_get_key(a0, a1);
    rnp_generate_key_rsa(a0, a1, a2, a3, a4, a5);
    rnp_generate_key_dsa_eg(a0, a1, a2, a3, a4, a5);
    rnp_generate_key_ec(a0, a1, a2, a3, a4);
    rnp_generate_key_25519(a0, a1, a2, a3);
    rnp_generate_key_sm2(a0, a1, a2, a3);
    rnp_generate_key_ex(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    rnp_key_protect(a0, a1, a2, a3, a4, a5);
    rnp_key_unprotect(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    rnp_op_encrypt_destroy(a0);
    rnp_op_sign_destroy(a0);
    rnp_op_generate_destroy(a0);
    rnp_op_encrypt_set_file_name(a0, a1);
    rnp_buffer_destroy(a0);
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
		"rnp_op_encrypt_create":                     {4, "factory"},
		"rnp_op_encrypt_add_recipient":              {2, "config"},
		"rnp_op_encrypt_add_password":               {5, "config"},
		"rnp_op_encrypt_add_signature":              {3, "config"},
		"rnp_op_encrypt_set_cipher":                 {2, "config"},
		"rnp_op_encrypt_set_aead":                   {2, "config"},
		"rnp_op_encrypt_set_aead_bits":              {2, "config"},
		"rnp_op_encrypt_set_hash":                   {2, "config"},
		"rnp_op_encrypt_set_armor":                  {2, "config"},
		"rnp_op_encrypt_set_flags":                  {2, "config"},
		"rnp_op_encrypt_execute":                    {1, "operation"},
		"rnp_op_sign_create":                        {4, "factory"},
		"rnp_op_sign_cleartext_create":              {4, "factory"},
		"rnp_op_sign_detached_create":               {4, "factory"},
		"rnp_op_sign_add_signature":                 {3, "config"},
		"rnp_op_sign_set_hash":                      {2, "config"},
		"rnp_op_sign_signature_set_hash":            {2, "config"},
		"rnp_op_sign_set_armor":                     {2, "config"},
		"rnp_op_sign_execute":                       {1, "operation"},
		"rnp_op_verify_create":                      {4, "factory"},
		"rnp_op_verify_detached_create":             {4, "factory"},
		"rnp_op_verify_set_flags":                   {2, "config"},
		"rnp_op_verify_execute":                     {1, "operation"},
		"rnp_op_verify_get_signature_at":            {3, "output"},
		"rnp_op_verify_signature_get_status":        {1, "output"},
		"rnp_op_verify_signature_get_hash":          {2, "output"},
		"rnp_op_verify_signature_get_key":           {2, "output"},
		"rnp_op_verify_get_used_recipient":          {2, "output"},
		"rnp_op_verify_get_used_symenc":             {2, "output"},
		"rnp_decrypt":                               {3, "operation"},
		"rnp_signature_is_valid":                    {2, "operation"},
		"rnp_op_generate_create":                    {3, "factory"},
		"rnp_op_generate_subkey_create":             {4, "factory"},
		"rnp_op_generate_set_bits":                  {2, "config"},
		"rnp_op_generate_set_curve":                 {2, "config"},
		"rnp_op_generate_set_hash":                  {2, "config"},
		"rnp_op_generate_set_dsa_qbits":             {2, "config"},
		"rnp_op_generate_set_protection_cipher":     {2, "config"},
		"rnp_op_generate_set_protection_hash":       {2, "config"},
		"rnp_op_generate_set_protection_mode":       {2, "config"},
		"rnp_op_generate_set_protection_iterations": {2, "config"},
		"rnp_op_generate_set_protection_password":   {2, "config"},
		"rnp_op_generate_set_userid":                {2, "config"},
		"rnp_op_generate_set_expiration":            {2, "config"},
		"rnp_op_generate_add_usage":                 {2, "config"},
		"rnp_op_generate_add_pref_hash":             {2, "config"},
		"rnp_op_generate_add_pref_cipher":           {2, "config"},
		"rnp_op_generate_execute":                   {1, "operation"},
		"rnp_op_generate_get_key":                   {2, "output"},
		"rnp_generate_key_rsa":                      {6, "operation"},
		"rnp_generate_key_dsa_eg":                   {6, "operation"},
		"rnp_generate_key_ec":                       {5, "operation"},
		"rnp_generate_key_25519":                    {4, "operation"},
		"rnp_generate_key_sm2":                      {4, "operation"},
		"rnp_generate_key_ex":                       {10, "operation"},
		"rnp_key_protect":                           {6, "operation"},
		"rnp_key_unprotect":                         {2, "operation"},
	}
	negative := []string{"rnp_op_encrypt_destroy", "rnp_op_sign_destroy", "rnp_op_generate_destroy", "rnp_op_encrypt_set_file_name", "rnp_buffer_destroy"}

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
				if got[0].SourceLibrary != "rnp" {
					t.Fatalf("%s: library = %q, want rnp", bare, got[0].SourceLibrary)
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
func TestRNPContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"rnp_op_encrypt_set_cipher": {2, 1, "algorithm"},
		"rnp_op_sign_set_hash":      {2, 1, "algorithm"},
		"rnp_op_generate_create":    {3, 2, "algorithm"},
		"rnp_op_generate_set_curve": {2, 1, "parameterSet"},
		"rnp_op_encrypt_set_aead":   {2, 1, "algorithm"},
		"rnp_key_protect":           {6, 2, "algorithm"},
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
