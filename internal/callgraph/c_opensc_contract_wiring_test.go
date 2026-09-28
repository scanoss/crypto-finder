package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The OpenSC contracts key on bare C function names. This pins, against what the
// C parser emits, that the PKCS#15 and card sign, decipher and derive calls, the
// security environment, binding and the key and certificate object calls each
// resolve to exactly one opensc contract with the expected role, and that PIN
// verification, APDU transport and teardown resolve to nothing.
func TestOpenSCContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "pkcs15init/pkcs15-init.h"

int flows(sc_card_t *card, sc_security_env_t *env, struct sc_pkcs15_id *id, struct sc_apdu *apdu,
          u8 *in, u8 *out, unsigned long *outlen, struct sc_pkcs15_cert_info *info, struct sc_pkcs15_object *pin) {
    struct sc_pkcs15_card *p15card;
    struct sc_pkcs15_object *key, *cert_obj;
    struct sc_pkcs15_pubkey *pubkey;
    struct sc_pkcs15_cert *cert;
    sc_pkcs15_bind(card, NULL, &p15card);
    sc_pkcs15_find_prkey_by_id(p15card, id, &key);
    sc_pkcs15_compute_signature(p15card, key, SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256, in, 32, out, 256);
    sc_pkcs15_decipher(p15card, key, SC_ALGORITHM_RSA_PAD_PKCS1, in, 256, out, 256);
    sc_pkcs15_derive(p15card, key, 0, in, 65, out, outlen);
    sc_pkcs15_read_pubkey(p15card, key, &pubkey);
    sc_pkcs15_find_cert_by_id(p15card, id, &cert_obj);
    sc_pkcs15_read_certificate(p15card, info, &cert);
    sc_set_security_env(card, env, 0);
    sc_compute_signature(card, in, 32, out, 256);
    sc_decipher(card, in, 256, out, 256);

    /* PIN verification, transport and teardown. None may resolve to a contract. */
    sc_pkcs15_verify_pin(p15card, pin, in, 4);
    sc_transmit_apdu(card, apdu);
    sc_pkcs15_free_certificate(cert);
    return sc_pkcs15_unbind(p15card);
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
		"sc_pkcs15_bind": {3, "factory"}, "sc_pkcs15_find_prkey_by_id": {3, "factory"},
		"sc_pkcs15_compute_signature": {7, "operation"}, "sc_pkcs15_decipher": {7, "operation"},
		"sc_pkcs15_derive": {7, "operation"}, "sc_pkcs15_read_pubkey": {3, "factory"},
		"sc_pkcs15_find_cert_by_id": {3, "factory"}, "sc_pkcs15_read_certificate": {3, "factory"},
		"sc_set_security_env": {3, "config"}, "sc_compute_signature": {5, "operation"},
		"sc_decipher": {5, "operation"},
	}
	negative := map[string]bool{
		"sc_pkcs15_verify_pin": true, "sc_transmit_apdu": true, "sc_pkcs15_free_certificate": true,
		"sc_pkcs15_unbind": true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "opensc" {
					t.Fatalf("%s: role %q library %q, want %q opensc", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The flags argument selects the padding or signature scheme in every release,
// including the later arities that add a mechanism argument.
func TestOpenSCContractsMarkFlagsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"sc_pkcs15_compute_signature", 7},
		{"sc_pkcs15_compute_signature", 8},
		{"sc_pkcs15_decipher", 7},
		{"sc_pkcs15_decipher", 8},
		{"sc_pkcs15_derive", 7},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		var ok bool
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == 2 && p.Role == "operation-determining" {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s/%d: flags argument 2 is not operation-determining", tc.method, tc.arity)
		}
	}
}
