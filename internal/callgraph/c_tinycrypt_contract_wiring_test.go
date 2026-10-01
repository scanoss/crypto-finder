package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The tinycrypt contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestTinyCryptContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <tinycrypt/aes.h>
#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/ctr_mode.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/cmac_mode.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/ctr_prng.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_dsa.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {
    tc_aes128_set_encrypt_key(a0, a1);
    tc_aes128_set_decrypt_key(a0, a1);
    tc_aes_encrypt(a0, a1, a2);
    tc_aes_decrypt(a0, a1, a2);
    tc_cbc_mode_encrypt(a0, a1, a2, a3, a4, a5);
    tc_cbc_mode_decrypt(a0, a1, a2, a3, a4, a5);
    tc_ctr_mode(a0, a1, a2, a3, a4, a5);
    tc_ccm_config(a0, a1, a2, a3, a4);
    tc_ccm_generation_encryption(a0, a1, a2, a3, a4, a5);
    tc_ccm_generation_encryption(a0, a1, a2, a3, a4, a5, a6);
    tc_ccm_decryption_verification(a0, a1, a2, a3, a4, a5);
    tc_ccm_decryption_verification(a0, a1, a2, a3, a4, a5, a6);
    tc_cmac_setup(a0, a1, a2);
    tc_cmac_init(a0);
    tc_cmac_update(a0, a1, a2);
    tc_cmac_final(a0, a1);
    tc_hmac_set_key(a0, a1, a2);
    tc_hmac_init(a0);
    tc_hmac_update(a0, a1, a2);
    tc_hmac_final(a0, a1, a2);
    tc_sha256_init(a0);
    tc_sha256_update(a0, a1, a2);
    tc_sha256_final(a0, a1);
    tc_hmac_prng_init(a0, a1, a2);
    tc_hmac_prng_reseed(a0, a1, a2, a3, a4);
    tc_hmac_prng_generate(a0, a1, a2);
    tc_ctr_prng_init(a0, a1, a2, a3, a4);
    tc_ctr_prng_reseed(a0, a1, a2, a3, a4);
    tc_ctr_prng_generate(a0, a1, a2, a3, a4);
    ecc_make_key(a0, a1, a2);
    ecdh_shared_secret(a0, a1, a2);
    ecdsa_sign(a0, a1, a2, a3, a4);
    ecdsa_verify(a0, a1, a2, a3);
    uECC_make_key_with_d(a0, a1, a2, a3);
    uECC_sign_with_k(a0, a1, a2, a3, a4, a5);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    tc_cmac_erase(a0);
    tc_ctr_prng_uninstantiate(a0);
    ecc_bytes2native(a0, a1);
    uECC_vli_clear(a0, 8);
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
		"tc_aes128_set_encrypt_key/2":      {2, "config"},
		"tc_aes128_set_decrypt_key/2":      {2, "config"},
		"tc_aes_encrypt/3":                 {3, "operation"},
		"tc_aes_decrypt/3":                 {3, "operation"},
		"tc_cbc_mode_encrypt/6":            {6, "operation"},
		"tc_cbc_mode_decrypt/6":            {6, "operation"},
		"tc_ctr_mode/6":                    {6, "operation"},
		"tc_ccm_config/5":                  {5, "config"},
		"tc_ccm_generation_encryption/6":   {6, "operation"},
		"tc_ccm_generation_encryption/7":   {7, "operation"},
		"tc_ccm_decryption_verification/6": {6, "operation"},
		"tc_ccm_decryption_verification/7": {7, "operation"},
		"tc_cmac_setup/3":                  {3, "config"},
		"tc_cmac_init/1":                   {1, "config"},
		"tc_cmac_update/3":                 {3, "operation"},
		"tc_cmac_final/2":                  {2, "operation"},
		"tc_hmac_set_key/3":                {3, "config"},
		"tc_hmac_init/1":                   {1, "config"},
		"tc_hmac_update/3":                 {3, "operation"},
		"tc_hmac_final/3":                  {3, "operation"},
		"tc_sha256_init/1":                 {1, "config"},
		"tc_sha256_update/3":               {3, "operation"},
		"tc_sha256_final/2":                {2, "operation"},
		"tc_hmac_prng_init/3":              {3, "config"},
		"tc_hmac_prng_reseed/5":            {5, "config"},
		"tc_hmac_prng_generate/3":          {3, "operation"},
		"tc_ctr_prng_init/5":               {5, "config"},
		"tc_ctr_prng_reseed/5":             {5, "config"},
		"tc_ctr_prng_generate/5":           {5, "operation"},
		"ecc_make_key/3":                   {3, "operation"},
		"ecdh_shared_secret/3":             {3, "operation"},
		"ecdsa_sign/5":                     {5, "operation"},
		"ecdsa_verify/4":                   {4, "operation"},
		"uECC_make_key_with_d/4":           {4, "operation"},
		"uECC_sign_with_k/6":               {6, "operation"},
	}
	negative := []string{"tc_cmac_erase", "tc_ctr_prng_uninstantiate", "ecc_bytes2native", "uECC_vli_clear"}

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
				wantLib := "tinycrypt"
				if key == "ecdsa_verify/4" {
					// Same symbol, arity and role as the Nettle contract, which owns it.
					wantLib = "nettle"
				}
				if got[0].SourceLibrary != wantLib {
					t.Fatalf("%s: library = %q, want %s", bare, got[0].SourceLibrary, wantLib)
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
