package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libp11 contracts key on bare C function names. This pins, against what the
// C parser emits, that module loading, slot and token lookup, session, key and
// certificate objects, and the sign, verify and RSA private-key operations each
// resolve to exactly one libp11 contract with the expected role, and that
// teardown, logout and PIN management resolve to nothing.
func TestLibp11ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <libp11.h>

int flows(const char *module, unsigned char *m, unsigned char *sig, unsigned char *to, X509 *x509) {
    PKCS11_SLOT *slots, *slot;
    PKCS11_KEY *keys;
    PKCS11_CERT *certs;
    unsigned int nslots, nkeys, ncerts, siglen = 0;
    PKCS11_CTX *ctx = PKCS11_CTX_new();
    PKCS11_CTX_load(ctx, module);
    PKCS11_enumerate_slots(ctx, &slots, &nslots);
    slot = PKCS11_find_token(ctx, slots, nslots);
    PKCS11_TOKEN *token = slot->token;
    PKCS11_open_session(slot, 1);
    PKCS11_login(slot, 0, "1234");
    PKCS11_enumerate_keys(token, &keys, &nkeys);
    PKCS11_enumerate_certs(token, &certs, &ncerts);
    PKCS11_generate_key(token, EVP_PKEY_RSA, 2048, "label", NULL, 0);
    PKCS11_store_certificate(token, x509, "label", NULL, 0, NULL);
    EVP_PKEY *pkey = PKCS11_get_private_key(keys);
    PKCS11_sign(NID_sha256, m, 32, sig, &siglen, keys);
    PKCS11_verify(NID_sha256, m, 32, sig, siglen, keys);
    PKCS11_ecdsa_sign(m, 32, sig, &siglen, keys);
    PKCS11_private_decrypt(256, sig, to, keys, RSA_PKCS1_OAEP_PADDING);

    /* Teardown, logout and PIN management. None may resolve to a contract. */
    PKCS11_change_pin(slot, "1234", "5678");
    PKCS11_logout(slot);
    PKCS11_release_all_slots(ctx, slots, nslots);
    PKCS11_CTX_unload(ctx);
    return pkey != NULL;
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
		"PKCS11_CTX_new": {0, "factory"}, "PKCS11_CTX_load": {2, "config"},
		"PKCS11_enumerate_slots": {3, "factory"}, "PKCS11_find_token": {3, "factory"},
		"PKCS11_open_session": {2, "config"}, "PKCS11_login": {3, "config"},
		"PKCS11_enumerate_keys": {3, "factory"}, "PKCS11_enumerate_certs": {3, "factory"},
		"PKCS11_generate_key": {6, "factory"}, "PKCS11_store_certificate": {6, "config"},
		"PKCS11_get_private_key": {1, "factory"}, "PKCS11_sign": {6, "operation"},
		"PKCS11_verify": {6, "operation"}, "PKCS11_ecdsa_sign": {5, "operation"},
		"PKCS11_private_decrypt": {5, "operation"},
	}
	negative := map[string]bool{
		"PKCS11_change_pin": true, "PKCS11_logout": true, "PKCS11_release_all_slots": true, "PKCS11_CTX_unload": true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "libp11" {
					t.Fatalf("%s: role %q library %q, want %q libp11", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The digest NID, the RSA padding and the generated key algorithm select what a
// libp11 call does, so each must be operation-determining at its index.
func TestLibp11ContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"PKCS11_sign":            {6, 0, "hashAlgorithm"},
		"PKCS11_verify":          {6, 0, "hashAlgorithm"},
		"PKCS11_private_encrypt": {5, 4, "padding"},
		"PKCS11_private_decrypt": {5, 4, "padding"},
		"PKCS11_generate_key":    {6, 1, "algorithm"},
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
