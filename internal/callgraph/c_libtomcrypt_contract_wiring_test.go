package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The LibTomCrypt contracts key on bare C function names, including the macro
// spellings consumers write (aes_setup, rsa_sign_hash, sha224_process). This
// pins, against what the C parser emits, that descriptor selection, cipher, AEAD,
// hash, MAC, KDF, PRNG and public-key calls each resolve to exactly one
// libtomcrypt contract with the expected role, and that registry management,
// encoding, math and teardown resolve to nothing.
func TestLibTomCryptContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <tomcrypt.h>

int flows(prng_state *prng, rsa_key *rsa, ecc_key *ecc, unsigned char *key, unsigned char *iv,
          unsigned char *pt, unsigned char *ct, unsigned char *tag, unsigned char *out, unsigned long *outlen) {
    symmetric_key skey;
    symmetric_CBC cbc;
    gcm_state gcm;
    hash_state md;
    hmac_state hmac;
    unsigned long taglen = 16;
    int stat = 0;
    register_cipher(&aes_desc);
    int cipher = find_cipher("aes");
    int hash = find_hash("sha256");
    int wprng = find_prng("fortuna");
    aes_setup(key, 16, 0, &skey);
    aes_ecb_encrypt(pt, ct, &skey);
    cbc_start(cipher, iv, key, 16, 0, &cbc);
    cbc_encrypt(pt, ct, 64, &cbc);
    cbc_done(&cbc);
    gcm_init(&gcm, cipher, key, 16);
    gcm_add_iv(&gcm, iv, 12);
    gcm_add_aad(&gcm, NULL, 0);
    gcm_process(&gcm, pt, 64, ct, GCM_ENCRYPT);
    gcm_done(&gcm, tag, &taglen);
    gcm_memory(cipher, key, 16, iv, 12, NULL, 0, pt, 64, ct, tag, &taglen, GCM_ENCRYPT);
    sha256_init(&md);
    sha224_process(&md, pt, 64);
    sha256_done(&md, out);
    hmac_init(&hmac, hash, key, 32);
    hmac_process(&hmac, pt, 64);
    hmac_done(&hmac, out, outlen);
    pkcs_5_alg2(key, 32, iv, 16, 10000, hash, out, outlen);
    fortuna_start(prng);
    fortuna_add_entropy(key, 32, prng);
    fortuna_ready(prng);
    fortuna_read(out, 32, prng);
    rsa_make_key(prng, wprng, 256, 65537, rsa);
    rsa_encrypt_key(pt, 32, ct, outlen, NULL, 0, prng, wprng, hash, rsa);
    rsa_sign_hash_ex(pt, 32, out, outlen, LTC_PKCS_1_PSS, prng, wprng, hash, 32, rsa);
    rsa_export(out, outlen, PK_PUBLIC, rsa);
    ecc_make_key(prng, wprng, 32, ecc);
    ecc_sign_hash(pt, 32, out, outlen, prng, wprng, ecc);
    ecc_verify_hash(out, 64, pt, 32, &stat, ecc);

    /* Registry management, encoding, teardown. None may resolve to a contract. */
    unregister_cipher(&aes_desc);
    cipher_is_valid(cipher);
    base64_encode(pt, 32, out, outlen);
    zeromem(key, 32);
    rsa_free(rsa);
    ecc_free(ecc);
    return stat;
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
		"register_cipher": {1, "factory"}, "find_cipher": {1, "factory"}, "find_hash": {1, "factory"},
		"find_prng": {1, "factory"}, "aes_setup": {4, "config"}, "aes_ecb_encrypt": {3, "operation"},
		"cbc_start": {6, "config"}, "cbc_encrypt": {4, "operation"}, "cbc_done": {1, "operation"},
		"gcm_init": {4, "config"}, "gcm_add_iv": {3, "config"}, "gcm_add_aad": {3, "config"},
		"gcm_process": {5, "operation"}, "gcm_done": {3, "operation"}, "gcm_memory": {13, "operation"},
		"sha256_init": {1, "config"}, "sha224_process": {3, "operation"}, "sha256_done": {2, "operation"},
		"hmac_init": {4, "config"}, "hmac_process": {3, "operation"}, "hmac_done": {3, "operation"},
		"pkcs_5_alg2": {8, "operation"}, "fortuna_start": {1, "config"}, "fortuna_add_entropy": {3, "config"},
		"fortuna_ready": {1, "config"}, "fortuna_read": {3, "operation"}, "rsa_make_key": {5, "factory"},
		"rsa_encrypt_key": {10, "operation"}, "rsa_sign_hash_ex": {10, "operation"}, "rsa_export": {4, "output"},
		"ecc_make_key": {4, "factory"}, "ecc_sign_hash": {7, "operation"}, "ecc_verify_hash": {6, "operation"},
	}
	negative := map[string]bool{
		"unregister_cipher": true, "cipher_is_valid": true, "base64_encode": true, "zeromem": true,
		"rsa_free": true, "ecc_free": true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "libtomcrypt" {
					t.Fatalf("%s: role %q library %q, want %q libtomcrypt", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The descriptor index, the AEAD direction flag and the RSA padding flag select
// what a LibTomCrypt call does, so each must be operation-determining at its index.
func TestLibTomCryptContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"find_cipher":        {1, 0, "algorithm"},
		"register_hash":      {1, 0, "algorithm"},
		"cbc_start":          {6, 0, "algorithm"},
		"gcm_init":           {4, 1, "algorithm"},
		"gcm_memory":         {13, 12, "operation"},
		"gcm_process":        {5, 4, "operation"},
		"ccm_memory":         {14, 13, "operation"},
		"hmac_memory":        {7, 0, "algorithm"},
		"pkcs_5_alg2":        {8, 5, "algorithm"},
		"hkdf":               {9, 0, "algorithm"},
		"rsa_encrypt_key_ex": {11, 9, "padding"},
		"rsa_sign_hash_ex":   {10, 4, "padding"},
		"rsa_verify_hash_ex": {9, 4, "padding"},
	}
	for method, want := range selector {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var ok bool
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == want.index && p.Role == "operation-determining" &&
				p.Contributes != nil && p.Contributes.Property == want.property {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: parameter %d is not operation-determining %s", method, want.index, want.property)
		}
	}
}
