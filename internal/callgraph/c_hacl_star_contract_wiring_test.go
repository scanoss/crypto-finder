package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The HACL* and EverCrypt contracts key on bare C function names. This pins, against
// what the C parser emits, that agile AEAD and hash state creation and use, one-shot
// AEAD, hashing, HMAC, HKDF, DRBG, X25519, P-256 and Ed25519 calls each resolve to
// exactly one hacl-star contract, and that verified internals, CPU detection and
// teardown resolve to nothing.
func TestHaclStarContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "EverCrypt_AEAD.h"
#include "EverCrypt_Hash.h"
#include "Hacl_Hash_SHA2.h"

void flows(uint8_t *key, uint8_t *iv, uint8_t *ad, uint8_t *pt, uint8_t *ct, uint8_t *tag, uint8_t *out,
           uint8_t *sk, uint8_t *pk, uint8_t *sig, uint8_t *ss, uint8_t *seed, uint64_t *f) {
    EverCrypt_AEAD_state_s *st = NULL;
    EverCrypt_AEAD_create_in(Spec_Agile_AEAD_AES128_GCM, &st, key);
    EverCrypt_AEAD_encrypt(st, iv, 12, ad, 16, pt, 64, ct, tag);
    EverCrypt_AEAD_decrypt(st, iv, 12, ad, 16, ct, 64, tag, pt);
    Hacl_Chacha20Poly1305_32_aead_encrypt(key, iv, 16, ad, 64, pt, ct, tag);
    EverCrypt_Hash_Incremental_state_t *h = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_256);
    EverCrypt_Hash_Incremental_init(h);
    EverCrypt_Hash_Incremental_update(h, pt, 64);
    EverCrypt_Hash_Incremental_finish(h, out);
    Hacl_Hash_SHA2_hash_256(pt, 64, out);
    Hacl_HMAC_compute_sha2_256(out, key, 32, pt, 64);
    Hacl_HKDF_extract_sha2_256(out, seed, 16, key, 32);
    EverCrypt_DRBG_state_s *d = EverCrypt_DRBG_create(Spec_Hash_Definitions_SHA2_256);
    EverCrypt_DRBG_instantiate(d, seed, 32);
    EverCrypt_DRBG_generate(out, d, 64, NULL, 0);
    Hacl_Curve25519_51_secret_to_public(pk, sk);
    Hacl_Curve25519_51_ecdh(ss, sk, pk);
    Hacl_Ed25519_sign(sig, sk, 64, pt);
    Hacl_Ed25519_verify(pk, 64, pt, sig);

    /* Internals, CPU detection, teardown. None may resolve to a contract. */
    Hacl_Impl_Curve25519_Field51_fadd(f, f, f);
    EverCrypt_AutoConfig2_init();
    EverCrypt_AEAD_free(st);
    EverCrypt_Hash_Incremental_free(h);
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
		"EverCrypt_AEAD_create_in":              {3, "factory"},
		"EverCrypt_AEAD_encrypt":                {9, "operation"},
		"EverCrypt_AEAD_decrypt":                {9, "operation"},
		"Hacl_Chacha20Poly1305_32_aead_encrypt": {8, "operation"},
		"EverCrypt_Hash_Incremental_create_in":  {1, "factory"},
		"EverCrypt_Hash_Incremental_init":       {1, "config"},
		"EverCrypt_Hash_Incremental_update":     {3, "operation"},
		"EverCrypt_Hash_Incremental_finish":     {2, "operation"},
		"Hacl_Hash_SHA2_hash_256":               {3, "operation"},
		"Hacl_HMAC_compute_sha2_256":            {5, "operation"},
		"Hacl_HKDF_extract_sha2_256":            {5, "operation"},
		"EverCrypt_DRBG_create":                 {1, "factory"},
		"EverCrypt_DRBG_instantiate":            {3, "config"},
		"EverCrypt_DRBG_generate":               {5, "operation"},
		"Hacl_Curve25519_51_secret_to_public":   {2, "factory"},
		"Hacl_Curve25519_51_ecdh":               {3, "operation"},
		"Hacl_Ed25519_sign":                     {4, "operation"},
		"Hacl_Ed25519_verify":                   {4, "operation"},
	}
	negative := map[string]bool{
		"Hacl_Impl_Curve25519_Field51_fadd": true,
		"EverCrypt_AutoConfig2_init":        true,
		"EverCrypt_AEAD_free":               true,
		"EverCrypt_Hash_Incremental_free":   true,
	}

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
				if negative[bare] {
					if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
						t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
					}
					seen[bare] = true
					continue
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
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one", method, expect.arity, len(got))
				}
				if got[0].Role != expect.role || got[0].SourceLibrary != "hacl-star" {
					t.Fatalf("%s: role %q library %q, want %q hacl-star", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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
	for method := range negative {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover negative %q", method)
		}
	}
}

// The Spec_ algorithm constant passed to the EverCrypt agile entry points selects the
// algorithm, so it must be operation-determining.
func TestHaclStarContractsMarkSelectors(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, tc := range []struct {
		method         string
		arity, index   int
		property, role string
	}{
		{"EverCrypt_AEAD_create_in", 3, 0, "algorithm", "operation-determining"},
		{"EverCrypt_Hash_Incremental_create_in", 1, 0, "algorithm", "operation-determining"},
		{"EverCrypt_DRBG_create", 1, 0, "algorithm", "operation-determining"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		var ok bool
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == tc.index && p.Role == tc.role && p.Contributes != nil &&
				p.Contributes.Property == tc.property {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s/%d: parameter %d is not %s %s", tc.method, tc.arity, tc.index, tc.role, tc.property)
		}
	}
}
