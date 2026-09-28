package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The Monocypher contracts key on bare C function names across the 4.x API and
// the 1.x-3.x names it replaced. This pins, against what the C parser emits,
// that AEAD, incremental AEAD, BLAKE2b, SHA-512, HMAC, HKDF, Argon2, X25519 and
// EdDSA calls each resolve to exactly one monocypher contract with the expected
// role, and that crypto_wipe and the constant-time comparisons resolve to nothing.
func TestMonocypherContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "monocypher.h"
#include "monocypher-ed25519.h"

void flows(uint8_t *key, uint8_t *nonce, uint8_t *mac, uint8_t *pt, uint8_t *ct, uint8_t *hash,
           uint8_t *sk, uint8_t *pk, uint8_t *sig, uint8_t *shared, void *work,
           crypto_argon2_config config, crypto_argon2_inputs inputs, crypto_argon2_extras extras) {
    crypto_aead_ctx actx;
    crypto_blake2b_ctx bctx;
    crypto_sha512_hmac_ctx hctx;
    crypto_aead_lock(ct, mac, key, nonce, NULL, 0, pt, 64);
    crypto_aead_unlock(pt, mac, key, nonce, NULL, 0, ct, 64);
    crypto_aead_init_x(&actx, key, nonce);
    crypto_aead_write(&actx, ct, mac, NULL, 0, pt, 64);
    crypto_aead_read(&actx, pt, mac, NULL, 0, ct, 64);
    crypto_lock(mac, ct, key, nonce, pt, 64);
    crypto_blake2b_init(&bctx, 64);
    crypto_blake2b_update(&bctx, pt, 64);
    crypto_blake2b_final(&bctx, hash);
    crypto_blake2b(hash, 64, pt, 64);
    crypto_sha512(hash, pt, 64);
    crypto_sha512_hmac_init(&hctx, key, 32);
    crypto_sha512_hmac_update(&hctx, pt, 64);
    crypto_sha512_hmac_final(&hctx, hash);
    crypto_sha512_hkdf(hash, 64, key, 32, NULL, 0, NULL, 0);
    crypto_argon2(hash, 32, work, config, inputs, extras);
    crypto_x25519_public_key(pk, sk);
    crypto_x25519(shared, sk, pk);
    crypto_eddsa_key_pair(sk, pk, key);
    crypto_eddsa_sign(sig, sk, pt, 64);
    crypto_eddsa_check(sig, pk, pt, 64);
    crypto_ed25519_sign(sig, sk, pt, 64);

    /* Wiping and constant-time comparison. None may resolve to a contract. */
    crypto_verify32(pk, sk);
    crypto_wipe(key, 32);
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
		"crypto_aead_lock": {8, "operation"}, "crypto_aead_unlock": {8, "operation"},
		"crypto_aead_init_x": {3, "config"}, "crypto_aead_write": {7, "operation"},
		"crypto_aead_read": {7, "operation"}, "crypto_lock": {6, "operation"},
		"crypto_blake2b_init": {2, "config"}, "crypto_blake2b_update": {3, "operation"},
		"crypto_blake2b_final": {2, "operation"}, "crypto_blake2b": {4, "operation"},
		"crypto_sha512": {3, "operation"}, "crypto_sha512_hmac_init": {3, "config"},
		"crypto_sha512_hmac_update": {3, "operation"}, "crypto_sha512_hmac_final": {2, "operation"},
		"crypto_sha512_hkdf": {8, "operation"}, "crypto_argon2": {6, "operation"},
		"crypto_x25519_public_key": {2, "factory"}, "crypto_x25519": {3, "operation"},
		"crypto_eddsa_key_pair": {3, "factory"}, "crypto_eddsa_sign": {4, "operation"},
		"crypto_eddsa_check": {4, "operation"}, "crypto_ed25519_sign": {4, "operation"},
	}
	negative := map[string]bool{"crypto_verify32": true, "crypto_wipe": true}

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
				if got[0].Role != expect.role || got[0].SourceLibrary != "monocypher" {
					t.Fatalf("%s: role %q library %q, want %q monocypher", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// crypto_blake2b changed arity between 3.x and 4.x; both spellings must resolve,
// and the 4.x Argon2 config struct must select the variant.
func TestMonocypherContractsCoverBothMajorsAndTheArgon2Variant(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, arity := range []int{3, 4} {
		if got := kb.ContractsFor("crypto_blake2b", arity); len(got) != 1 || got[0].SourceLibrary != "monocypher" {
			t.Fatalf("crypto_blake2b/%d = %#v, want one monocypher contract", arity, got)
		}
	}
	got := kb.ContractsFor("crypto_argon2", 6)
	if len(got) != 1 {
		t.Fatalf("crypto_argon2/6 = %d contracts, want one", len(got))
	}
	var ok bool
	for _, p := range got[0].Parameters {
		if p.Index != nil && *p.Index == 3 && p.Role == "operation-determining" && p.Contributes != nil &&
			p.Contributes.Property == "variant" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("crypto_argon2: config argument 3 is not operation-determining variant: %#v", got[0].Parameters)
	}
}
