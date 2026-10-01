package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The PQClean contracts key on the PQCLEAN_<SCHEME>_<IMPLEMENTATION>_ function names.
// This pins, against what the C parser emits, that keypair, KEM and signature calls of
// several schemes and implementations each resolve to exactly one pqclean contract,
// and that a scheme's internal functions, the common helpers and the bare NIST names
// resolve to nothing.
func TestPQCleanContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "api.h"

int flows(uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss, uint8_t *sig, size_t *siglen,
          const uint8_t *m, size_t mlen, uint8_t *sm, size_t *smlen, polyvec *v) {
    PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_KYBER768_AVX2_crypto_kem_enc(ct, ss, pk);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
    PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, *siglen, m, mlen, pk);
    PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign(sm, smlen, m, mlen, sk);
    PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);

    /* Internals, helpers and bare NIST names. None may resolve to a contract. */
    PQCLEAN_KYBER768_CLEAN_polyvec_ntt(v);
    randombytes(ss, 32);
    crypto_kem_keypair(pk, sk);
    return 0;
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
		"PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair":           {2, "factory"},
		"PQCLEAN_KYBER768_AVX2_crypto_kem_enc":                {3, "operation"},
		"PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec":               {3, "operation"},
		"PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair":        {2, "factory"},
		"PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature":      {5, "operation"},
		"PQCLEAN_FALCON512_CLEAN_crypto_sign_verify":          {5, "operation"},
		"PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CLEAN_crypto_sign": {5, "operation"},
		"PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc":         {3, "operation"},
	}
	negative := map[string]bool{
		"PQCLEAN_KYBER768_CLEAN_polyvec_ntt": true,
		"randombytes":                        true,
		"crypto_kem_keypair":                 true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "pqclean" {
					t.Fatalf("%s: role %q library %q, want %q pqclean", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The scheme and parameter set live in the function name, so every PQClean
// contract must be argument-free and keyed to a PQCLEAN_ prefixed NIST API.
func TestPQCleanContractsCarryNoArgumentRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	var n int
	for _, candidates := range kb.Contracts {
		for _, c := range candidates {
			if c.SourceLibrary != "pqclean" {
				continue
			}
			n++
			if !strings.HasPrefix(c.Method, "PQCLEAN_") || !strings.Contains(c.Method, "_crypto_") {
				t.Errorf("%s is not a PQCLEAN_ NIST API", c.Method)
			}
			if len(c.Parameters) != 0 {
				t.Errorf("%s carries %d parameter roles, want none", c.Method, len(c.Parameters))
			}
		}
	}
	if n != 1228 {
		t.Fatalf("pqclean contracts = %d, want 1228", n)
	}
}
