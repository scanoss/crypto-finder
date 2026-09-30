package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The gpgme contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestGPGMEContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <gpgme.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {
    gpgme_new(a0);
    gpgme_set_protocol(a0, a1);
    gpgme_get_protocol(a0);
    gpgme_set_armor(a0, a1);
    gpgme_set_textmode(a0, a1);
    gpgme_signers_add(a0, a1);
    gpgme_signers_clear(a0);
    gpgme_set_pinentry_mode(a0, a1);
    gpgme_set_passphrase_cb(a0, a1, a2);
    gpgme_op_encrypt(a0, a1, a2, a3, a4);
    gpgme_op_encrypt_start(a0, a1, a2, a3, a4);
    gpgme_op_encrypt_ext(a0, a1, a2, a3, a4, a5);
    gpgme_op_encrypt_ext_start(a0, a1, a2, a3, a4, a5);
    gpgme_op_encrypt_sign(a0, a1, a2, a3, a4);
    gpgme_op_encrypt_sign_start(a0, a1, a2, a3, a4);
    gpgme_op_encrypt_sign_ext(a0, a1, a2, a3, a4, a5);
    gpgme_op_encrypt_sign_ext_start(a0, a1, a2, a3, a4, a5);
    gpgme_op_encrypt_result(a0);
    gpgme_op_decrypt(a0, a1, a2);
    gpgme_op_decrypt_start(a0, a1, a2);
    gpgme_op_decrypt_ext(a0, a1, a2, a3);
    gpgme_op_decrypt_ext_start(a0, a1, a2, a3);
    gpgme_op_decrypt_verify(a0, a1, a2);
    gpgme_op_decrypt_verify_start(a0, a1, a2);
    gpgme_op_decrypt_result(a0);
    gpgme_op_sign(a0, a1, a2, a3);
    gpgme_op_sign_start(a0, a1, a2, a3);
    gpgme_op_sign_result(a0);
    gpgme_op_verify(a0, a1, a2, a3);
    gpgme_op_verify_start(a0, a1, a2, a3);
    gpgme_op_verify_ext(a0, a1, a2, a3, a4);
    gpgme_op_verify_ext_start(a0, a1, a2, a3, a4);
    gpgme_op_verify_result(a0);
    gpgme_op_keysign(a0, a1, a2, a3, a4);
    gpgme_op_keysign_start(a0, a1, a2, a3, a4);
    gpgme_op_createkey(a0, a1, a2, a3, a4, a5, a6);
    gpgme_op_createkey_start(a0, a1, a2, a3, a4, a5, a6);
    gpgme_op_createsubkey(a0, a1, a2, a3, a4, a5);
    gpgme_op_createsubkey_start(a0, a1, a2, a3, a4, a5);
    gpgme_op_genkey(a0, a1, a2, a3);
    gpgme_op_genkey_start(a0, a1, a2, a3);
    gpgme_op_genkey_result(a0);
    gpgme_op_import(a0, a1);
    gpgme_op_import_start(a0, a1);
    gpgme_op_import_ext(a0, a1, a2);
    gpgme_op_import_keys(a0, a1);
    gpgme_op_import_keys_start(a0, a1);
    gpgme_op_import_result(a0);
    gpgme_op_export(a0, a1, a2, a3);
    gpgme_op_export_start(a0, a1, a2, a3);
    gpgme_op_export_ext(a0, a1, a2, a3);
    gpgme_op_export_ext_start(a0, a1, a2, a3);
    gpgme_op_export_keys(a0, a1, a2, a3);
    gpgme_op_export_keys_start(a0, a1, a2, a3);
    gpgme_get_key(a0, a1, a2, a3);
    gpgme_op_keylist_start(a0, a1, a2);
    gpgme_op_keylist_ext_start(a0, a1, a2, a3);
    gpgme_op_keylist_next(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    gpgme_release(a0);
    gpgme_key_release(a0);
    gpgme_set_engine_info(a0, a1, a2);
    gpgme_op_keylist_end(a0);
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
		"gpgme_new":                       {1, "factory"},
		"gpgme_set_protocol":              {2, "config"},
		"gpgme_get_protocol":              {1, "output"},
		"gpgme_set_armor":                 {2, "config"},
		"gpgme_set_textmode":              {2, "config"},
		"gpgme_signers_add":               {2, "config"},
		"gpgme_signers_clear":             {1, "config"},
		"gpgme_set_pinentry_mode":         {2, "config"},
		"gpgme_set_passphrase_cb":         {3, "config"},
		"gpgme_op_encrypt":                {5, "operation"},
		"gpgme_op_encrypt_start":          {5, "operation"},
		"gpgme_op_encrypt_ext":            {6, "operation"},
		"gpgme_op_encrypt_ext_start":      {6, "operation"},
		"gpgme_op_encrypt_sign":           {5, "operation"},
		"gpgme_op_encrypt_sign_start":     {5, "operation"},
		"gpgme_op_encrypt_sign_ext":       {6, "operation"},
		"gpgme_op_encrypt_sign_ext_start": {6, "operation"},
		"gpgme_op_encrypt_result":         {1, "output"},
		"gpgme_op_decrypt":                {3, "operation"},
		"gpgme_op_decrypt_start":          {3, "operation"},
		"gpgme_op_decrypt_ext":            {4, "operation"},
		"gpgme_op_decrypt_ext_start":      {4, "operation"},
		"gpgme_op_decrypt_verify":         {3, "operation"},
		"gpgme_op_decrypt_verify_start":   {3, "operation"},
		"gpgme_op_decrypt_result":         {1, "output"},
		"gpgme_op_sign":                   {4, "operation"},
		"gpgme_op_sign_start":             {4, "operation"},
		"gpgme_op_sign_result":            {1, "output"},
		"gpgme_op_verify":                 {4, "operation"},
		"gpgme_op_verify_start":           {4, "operation"},
		"gpgme_op_verify_ext":             {5, "operation"},
		"gpgme_op_verify_ext_start":       {5, "operation"},
		"gpgme_op_verify_result":          {1, "output"},
		"gpgme_op_keysign":                {5, "operation"},
		"gpgme_op_keysign_start":          {5, "operation"},
		"gpgme_op_createkey":              {7, "operation"},
		"gpgme_op_createkey_start":        {7, "operation"},
		"gpgme_op_createsubkey":           {6, "operation"},
		"gpgme_op_createsubkey_start":     {6, "operation"},
		"gpgme_op_genkey":                 {4, "operation"},
		"gpgme_op_genkey_start":           {4, "operation"},
		"gpgme_op_genkey_result":          {1, "output"},
		"gpgme_op_import":                 {2, "operation"},
		"gpgme_op_import_start":           {2, "operation"},
		"gpgme_op_import_ext":             {3, "operation"},
		"gpgme_op_import_keys":            {2, "operation"},
		"gpgme_op_import_keys_start":      {2, "operation"},
		"gpgme_op_import_result":          {1, "output"},
		"gpgme_op_export":                 {4, "operation"},
		"gpgme_op_export_start":           {4, "operation"},
		"gpgme_op_export_ext":             {4, "operation"},
		"gpgme_op_export_ext_start":       {4, "operation"},
		"gpgme_op_export_keys":            {4, "operation"},
		"gpgme_op_export_keys_start":      {4, "operation"},
		"gpgme_get_key":                   {4, "factory"},
		"gpgme_op_keylist_start":          {3, "factory"},
		"gpgme_op_keylist_ext_start":      {4, "factory"},
		"gpgme_op_keylist_next":           {2, "output"},
	}
	negative := []string{"gpgme_release", "gpgme_key_release", "gpgme_set_engine_info", "gpgme_op_keylist_end"}

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
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", bare, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "gpgme" {
					t.Fatalf("%s: library = %q, want gpgme", bare, got[0].SourceLibrary)
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
func TestGPGMEContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"gpgme_set_protocol":          {2, 1, "protocol"},
		"gpgme_op_createkey":          {7, 2, "algorithm"},
		"gpgme_op_createkey_start":    {7, 2, "algorithm"},
		"gpgme_op_createsubkey":       {6, 2, "algorithm"},
		"gpgme_op_createsubkey_start": {6, 2, "algorithm"},
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
