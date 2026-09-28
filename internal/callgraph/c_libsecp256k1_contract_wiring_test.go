package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libsecp256k1 contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestLibSecp256k1ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_musig.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) {
    secp256k1_context_create(a0);
    secp256k1_context_randomize(a0, a1);
    secp256k1_ec_seckey_verify(a0, a1);
    secp256k1_ec_pubkey_create(a0, a1, a2);
    secp256k1_ecdsa_sign(a0, a1, a2, a3, a4, a5);
    secp256k1_ecdsa_verify(a0, a1, a2, a3);
    secp256k1_ecdsa_signature_normalize(a0, a1, a2);
    secp256k1_ecdsa_sign_recoverable(a0, a1, a2, a3, a4, a5);
    secp256k1_ecdsa_recover(a0, a1, a2, a3);
    secp256k1_keypair_create(a0, a1, a2);
    secp256k1_keypair_pub(a0, a1, a2);
    secp256k1_keypair_sec(a0, a1, a2);
    secp256k1_keypair_xonly_pub(a0, a1, a2, a3);
    secp256k1_schnorrsig_sign32(a0, a1, a2, a3, a4);
    secp256k1_schnorrsig_sign(a0, a1, a2, a3, a4);
    secp256k1_schnorrsig_sign_custom(a0, a1, a2, a3, a4, a5);
    secp256k1_schnorrsig_verify(a0, a1, a2, a3, a4);
    secp256k1_musig_pubkey_agg(a0, a1, a2, a3, a4);
    secp256k1_musig_partial_sign(a0, a1, a2, a3, a4, a5);
    secp256k1_musig_partial_sig_verify(a0, a1, a2, a3, a4, a5);
    secp256k1_ecdh(a0, a1, a2, a3, a4, a5);
    secp256k1_ellswift_xdh(a0, a1, a2, a3, a4, a5, a6, a7);
    secp256k1_ellswift_create(a0, a1, a2, a3);
    secp256k1_ellswift_encode(a0, a1, a2, a3);
    secp256k1_ellswift_decode(a0, a1, a2);
    secp256k1_tagged_sha256(a0, a1, a2, a3, a4, a5);
    secp256k1_ec_pubkey_parse(a0, a1, a2, a3);
    secp256k1_ec_pubkey_serialize(a0, a1, a2, a3, a4);
    secp256k1_xonly_pubkey_parse(a0, a1, a2);
    secp256k1_xonly_pubkey_serialize(a0, a1, a2);
    secp256k1_xonly_pubkey_from_pubkey(a0, a1, a2, a3);
    secp256k1_ecdsa_signature_parse_der(a0, a1, a2, a3);
    secp256k1_ecdsa_signature_parse_compact(a0, a1, a2);
    secp256k1_ecdsa_signature_serialize_der(a0, a1, a2, a3);
    secp256k1_ecdsa_signature_serialize_compact(a0, a1, a2);
    secp256k1_ecdsa_recoverable_signature_parse_compact(a0, a1, a2, a3);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(a0, a1, a2, a3);
    secp256k1_ecdsa_recoverable_signature_convert(a0, a1, a2);
    secp256k1_ec_seckey_negate(a0, a1);
    secp256k1_ec_seckey_tweak_add(a0, a1, a2);
    secp256k1_ec_seckey_tweak_mul(a0, a1, a2);
    secp256k1_ec_pubkey_negate(a0, a1);
    secp256k1_ec_pubkey_tweak_add(a0, a1, a2);
    secp256k1_ec_pubkey_tweak_mul(a0, a1, a2);
    secp256k1_ec_pubkey_combine(a0, a1, a2, a3);
    secp256k1_xonly_pubkey_tweak_add(a0, a1, a2, a3);
    secp256k1_xonly_pubkey_tweak_add_check(a0, a1, a2, a3, a4);
    secp256k1_keypair_xonly_tweak_add(a0, a1, a2);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    secp256k1_context_destroy(a0);
    secp256k1_selftest();
    secp256k1_ec_pubkey_cmp(a0, a1, a2);
    secp256k1_ec_privkey_negate(a0, a1);
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
		"secp256k1_context_create":                                {1, "factory"},
		"secp256k1_context_randomize":                             {2, "config"},
		"secp256k1_ec_seckey_verify":                              {2, "operation"},
		"secp256k1_ec_pubkey_create":                              {3, "operation"},
		"secp256k1_ecdsa_sign":                                    {6, "operation"},
		"secp256k1_ecdsa_verify":                                  {4, "operation"},
		"secp256k1_ecdsa_signature_normalize":                     {3, "operation"},
		"secp256k1_ecdsa_sign_recoverable":                        {6, "operation"},
		"secp256k1_ecdsa_recover":                                 {4, "operation"},
		"secp256k1_keypair_create":                                {3, "factory"},
		"secp256k1_keypair_pub":                                   {3, "output"},
		"secp256k1_keypair_sec":                                   {3, "output"},
		"secp256k1_keypair_xonly_pub":                             {4, "output"},
		"secp256k1_schnorrsig_sign32":                             {5, "operation"},
		"secp256k1_schnorrsig_sign":                               {5, "operation"},
		"secp256k1_schnorrsig_sign_custom":                        {6, "operation"},
		"secp256k1_schnorrsig_verify":                             {5, "operation"},
		"secp256k1_musig_pubkey_agg":                              {5, "operation"},
		"secp256k1_musig_partial_sign":                            {6, "operation"},
		"secp256k1_musig_partial_sig_verify":                      {6, "operation"},
		"secp256k1_ecdh":                                          {6, "operation"},
		"secp256k1_ellswift_xdh":                                  {8, "operation"},
		"secp256k1_ellswift_create":                               {4, "operation"},
		"secp256k1_ellswift_encode":                               {4, "output"},
		"secp256k1_ellswift_decode":                               {3, "factory"},
		"secp256k1_tagged_sha256":                                 {6, "operation"},
		"secp256k1_ec_pubkey_parse":                               {4, "factory"},
		"secp256k1_ec_pubkey_serialize":                           {5, "output"},
		"secp256k1_xonly_pubkey_parse":                            {3, "factory"},
		"secp256k1_xonly_pubkey_serialize":                        {3, "output"},
		"secp256k1_xonly_pubkey_from_pubkey":                      {4, "factory"},
		"secp256k1_ecdsa_signature_parse_der":                     {4, "factory"},
		"secp256k1_ecdsa_signature_parse_compact":                 {3, "factory"},
		"secp256k1_ecdsa_signature_serialize_der":                 {4, "output"},
		"secp256k1_ecdsa_signature_serialize_compact":             {3, "output"},
		"secp256k1_ecdsa_recoverable_signature_parse_compact":     {4, "factory"},
		"secp256k1_ecdsa_recoverable_signature_serialize_compact": {4, "output"},
		"secp256k1_ecdsa_recoverable_signature_convert":           {3, "factory"},
		"secp256k1_ec_seckey_negate":                              {2, "operation"},
		"secp256k1_ec_seckey_tweak_add":                           {3, "operation"},
		"secp256k1_ec_seckey_tweak_mul":                           {3, "operation"},
		"secp256k1_ec_pubkey_negate":                              {2, "operation"},
		"secp256k1_ec_pubkey_tweak_add":                           {3, "operation"},
		"secp256k1_ec_pubkey_tweak_mul":                           {3, "operation"},
		"secp256k1_ec_pubkey_combine":                             {4, "operation"},
		"secp256k1_xonly_pubkey_tweak_add":                        {4, "operation"},
		"secp256k1_xonly_pubkey_tweak_add_check":                  {5, "operation"},
		"secp256k1_keypair_xonly_tweak_add":                       {3, "operation"},
	}
	negative := []string{"secp256k1_context_destroy", "secp256k1_selftest", "secp256k1_ec_pubkey_cmp", "secp256k1_ec_privkey_negate"}

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
				if got[0].SourceLibrary != "libsecp256k1" {
					t.Fatalf("%s: library = %q, want libsecp256k1", bare, got[0].SourceLibrary)
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
func TestLibSecp256k1ContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"secp256k1_ecdh":         {6, 4, "hashFunction"},
		"secp256k1_ellswift_xdh": {8, 6, "hashFunction"},
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
