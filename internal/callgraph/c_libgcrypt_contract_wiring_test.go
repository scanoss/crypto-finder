package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libgcrypt contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestLibgcryptContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <gcrypt.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10, void *a11, void *a12) {
    gcry_cipher_open(a0, a1, a2, a3);
    gcry_cipher_setkey(a0, a1, a2);
    gcry_cipher_setiv(a0, a1, a2);
    gcry_cipher_setctr(a0, a1, a2);
    gcry_cipher_authenticate(a0, a1, a2);
    gcry_cipher_final(a0);
    gcry_cipher_encrypt(a0, a1, a2, a3, a4);
    gcry_cipher_decrypt(a0, a1, a2, a3, a4);
    gcry_cipher_gettag(a0, a1, a2);
    gcry_cipher_checktag(a0, a1, a2);
    gcry_md_open(a0, a1, a2);
    gcry_md_enable(a0, a1);
    gcry_md_setkey(a0, a1, a2);
    gcry_md_write(a0, a1, a2);
    gcry_md_final(a0);
    gcry_md_read(a0, a1);
    gcry_md_extract(a0, a1, a2, a3);
    gcry_md_hash_buffer(a0, a1, a2, a3);
    gcry_md_hash_buffers(a0, a1, a2, a3, a4);
    gcry_mac_open(a0, a1, a2, a3);
    gcry_mac_setkey(a0, a1, a2);
    gcry_mac_setiv(a0, a1, a2);
    gcry_mac_write(a0, a1, a2);
    gcry_mac_read(a0, a1, a2);
    gcry_mac_verify(a0, a1, a2);
    gcry_kdf_derive(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    gcry_kdf_open(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
    gcry_kdf_compute(a0, a1);
    gcry_kdf_final(a0, a1, a2);
    gcry_sexp_build(a0, a1, a2);
    gcry_sexp_build(a0, a1, a2, a3);
    gcry_sexp_build(a0, a1, a2, a3, a4);
    gcry_sexp_build(a0, a1, a2, a3, a4, a5);
    gcry_sexp_new(a0, a1, a2, a3);
    gcry_sexp_sscan(a0, a1, a2, a3);
    gcry_pk_genkey(a0, a1);
    gcry_pk_testkey(a0);
    gcry_pk_sign(a0, a1, a2);
    gcry_pk_verify(a0, a1, a2);
    gcry_pk_encrypt(a0, a1, a2);
    gcry_pk_decrypt(a0, a1, a2);
    gcry_pk_hash_sign(a0, a1, a2, a3, a4);
    gcry_pk_hash_verify(a0, a1, a2, a3, a4);
    gcry_pk_get_nbits(a0);
    gcry_pk_get_keygrip(a0, a1);
    gcry_randomize(a0, a1, a2);
    gcry_random_bytes(a0, a1);
    gcry_random_bytes_secure(a0, a1);
    gcry_create_nonce(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    gcry_cipher_close(a0);
    gcry_md_close(a0);
    gcry_mpi_powm(a0, a1, a2, a3);
    gcry_check_version(a0);
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
		"gcry_cipher_open/4":         {4, "factory"},
		"gcry_cipher_setkey/3":       {3, "config"},
		"gcry_cipher_setiv/3":        {3, "config"},
		"gcry_cipher_setctr/3":       {3, "config"},
		"gcry_cipher_authenticate/3": {3, "config"},
		"gcry_cipher_final/1":        {1, "config"},
		"gcry_cipher_encrypt/5":      {5, "operation"},
		"gcry_cipher_decrypt/5":      {5, "operation"},
		"gcry_cipher_gettag/3":       {3, "output"},
		"gcry_cipher_checktag/3":     {3, "operation"},
		"gcry_md_open/3":             {3, "factory"},
		"gcry_md_enable/2":           {2, "config"},
		"gcry_md_setkey/3":           {3, "config"},
		"gcry_md_write/3":            {3, "operation"},
		"gcry_md_final/1":            {1, "operation"},
		"gcry_md_read/2":             {2, "output"},
		"gcry_md_extract/4":          {4, "output"},
		"gcry_md_hash_buffer/4":      {4, "operation"},
		"gcry_md_hash_buffers/5":     {5, "operation"},
		"gcry_mac_open/4":            {4, "factory"},
		"gcry_mac_setkey/3":          {3, "config"},
		"gcry_mac_setiv/3":           {3, "config"},
		"gcry_mac_write/3":           {3, "operation"},
		"gcry_mac_read/3":            {3, "output"},
		"gcry_mac_verify/3":          {3, "operation"},
		"gcry_kdf_derive/9":          {9, "operation"},
		"gcry_kdf_open/13":           {13, "factory"},
		"gcry_kdf_compute/2":         {2, "operation"},
		"gcry_kdf_final/3":           {3, "output"},
		"gcry_sexp_build/3":          {3, "factory"},
		"gcry_sexp_build/4":          {4, "factory"},
		"gcry_sexp_build/5":          {5, "factory"},
		"gcry_sexp_build/6":          {6, "factory"},
		"gcry_sexp_new/4":            {4, "factory"},
		"gcry_sexp_sscan/4":          {4, "factory"},
		"gcry_pk_genkey/2":           {2, "operation"},
		"gcry_pk_testkey/1":          {1, "operation"},
		"gcry_pk_sign/3":             {3, "operation"},
		"gcry_pk_verify/3":           {3, "operation"},
		"gcry_pk_encrypt/3":          {3, "operation"},
		"gcry_pk_decrypt/3":          {3, "operation"},
		"gcry_pk_hash_sign/5":        {5, "operation"},
		"gcry_pk_hash_verify/5":      {5, "operation"},
		"gcry_pk_get_nbits/1":        {1, "output"},
		"gcry_pk_get_keygrip/2":      {2, "output"},
		"gcry_randomize/3":           {3, "operation"},
		"gcry_random_bytes/2":        {2, "operation"},
		"gcry_random_bytes_secure/2": {2, "operation"},
		"gcry_create_nonce/2":        {2, "operation"},
	}
	negative := []string{"gcry_cipher_close", "gcry_md_close", "gcry_mpi_powm", "gcry_check_version"}

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

				key := fmt.Sprintf("%s/%d", bare, len(call.Arguments))
				expect, ok := want[key]
				if !ok {
					continue
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "libgcrypt" {
					t.Fatalf("%s: library = %q, want libgcrypt", bare, got[0].SourceLibrary)
				}
				seen[key] = true
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
func TestLibgcryptContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := []struct {
		method       string
		arity, index int
		property     string
	}{
		{"gcry_cipher_open", 4, 1, "algorithm"},
		{"gcry_cipher_open", 4, 2, "mode"},
		{"gcry_md_open", 3, 1, "algorithm"},
		{"gcry_md_enable", 2, 1, "algorithm"},
		{"gcry_md_read", 2, 1, "algorithm"},
		{"gcry_md_hash_buffer", 4, 0, "algorithm"},
		{"gcry_md_hash_buffers", 5, 0, "algorithm"},
		{"gcry_mac_open", 4, 1, "algorithm"},
		{"gcry_kdf_derive", 9, 2, "algorithm"},
		{"gcry_kdf_derive", 9, 3, "hashFunction"},
		{"gcry_kdf_open", 13, 1, "algorithm"},
		{"gcry_kdf_open", 13, 2, "variant"},
	}

	for _, want := range selector {
		method := want.method
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
