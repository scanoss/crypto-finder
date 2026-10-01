package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The Nettle contracts key on the unprefixed C names consumers write. This pins,
// against what the C parser emits, that cipher, mode, AEAD, hash, MAC, KDF, DRBG and
// public-key calls each resolve to exactly one nettle contract with the expected role,
// and that encoding, the non-cryptographic LFIB generator and memory helpers resolve
// to nothing.
func TestNettleContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <nettle/nettle-meta.h>

void flows(struct aes128_ctx *aes, struct gcm_aes128_ctx *gcm, struct sha256_ctx *sha, struct hmac_sha256_ctx *hmac,
           struct rsa_public_key *pub, struct rsa_private_key *priv, struct yarrow256_ctx *yarrow,
           struct knuth_lfib_ctx *lfib, uint8_t *key, uint8_t *iv, uint8_t *pt, uint8_t *ct, uint8_t *out, char *text) {
    aes128_set_encrypt_key(aes, key);
    aes128_encrypt(aes, 64, ct, pt);
    cbc_encrypt(aes, (nettle_cipher_func *) aes128_encrypt, 16, iv, 64, ct, pt);
    gcm_aes128_set_key(gcm, key);
    gcm_aes128_set_iv(gcm, 12, iv);
    gcm_aes128_encrypt(gcm, 64, ct, pt);
    gcm_aes128_digest(gcm, 16, out);
    sha256_update(sha, 64, pt);
    sha256_digest(sha, 32, out);
    sha256_digest(sha, out);
    hmac_sha256_set_key(hmac, 32, key);
    hmac_sha256_digest(hmac, 32, out);
    pbkdf2_hmac_sha256(32, key, 10000, 16, iv, 32, out);
    yarrow256_random(yarrow, 32, out);
    rsa_generate_keypair(pub, priv, NULL, NULL, NULL, NULL, 2048, 0);

    /* Encoding, LFIB and memory helpers. None may resolve to a contract. */
    base64_encode_raw(text, 32, pt);
    knuth_lfib_random(lfib, 32, out);
    memeql_sec(pt, ct, 16);
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
		"aes128_set_encrypt_key": {2, "config"},
		"aes128_encrypt":         {4, "operation"},
		"cbc_encrypt":            {7, "operation"},
		"gcm_aes128_set_key":     {2, "config"},
		"gcm_aes128_set_iv":      {3, "config"},
		"gcm_aes128_encrypt":     {4, "operation"},
		"gcm_aes128_digest":      {3, "operation"},
		"sha256_update":          {3, "operation"},
		"hmac_sha256_set_key":    {3, "config"},
		"hmac_sha256_digest":     {3, "operation"},
		"pbkdf2_hmac_sha256":     {7, "operation"},
		"yarrow256_random":       {3, "operation"},
		"rsa_generate_keypair":   {8, "factory"},
	}
	negative := map[string]bool{
		"base64_encode_raw": true,
		"knuth_lfib_random": true,
		"memeql_sec":        true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "nettle" {
					t.Fatalf("%s: role %q library %q, want %q nettle", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The cipher function passed to a generic mode selects the block cipher, and the
// RSA modulus size and PBKDF2 iteration count describe the operation.
func TestNettleContractsMarkSelectors(t *testing.T) {
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
		{"cbc_encrypt", 7, 1, "algorithm", "operation-determining"},
		{"ctr_crypt", 7, 1, "algorithm", "operation-determining"},
		{"gcm_encrypt", 7, 3, "algorithm", "operation-determining"},
		{"rsa_generate_keypair", 8, 6, "keySize", "metadata-contributing"},
		{"pbkdf2_hmac_sha256", 7, 2, "iterations", "metadata-contributing"},
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

// Nettle 4.0 dropped the length argument of the digest functions, so both
// spellings must resolve to a nettle operation.
func TestNettleDigestArityOfBothMajors(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, method := range []string{"sha256_digest", "hmac_sha256_digest", "gcm_aes128_digest"} {
		for _, arity := range []int{2, 3} {
			got := kb.ContractsFor(method, arity)
			if len(got) != 1 || got[0].SourceLibrary != "nettle" || got[0].Role != "operation" {
				t.Fatalf("%s/%d = %#v, want one nettle operation", method, arity, got)
			}
		}
	}
}
