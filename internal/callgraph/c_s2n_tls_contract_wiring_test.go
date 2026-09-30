package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The s2n-tls contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestS2NTLSContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <s2n.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5) {
    s2n_config_new();
    s2n_config_set_cipher_preferences(a0, a1);
    s2n_config_add_dhparams(a0, a1);
    s2n_config_add_ticket_crypto_key(a0, a1, a2, a3, a4, a5);
    s2n_config_set_session_tickets_onoff(a0, a1);
    s2n_config_disable_x509_verification(a0);
    s2n_cert_chain_and_key_new();
    s2n_cert_chain_and_key_load_pem(a0, a1, a2);
    s2n_cert_chain_and_key_load_pem_bytes(a0, a1, a2, a3, a4);
    s2n_cert_chain_and_key_load_public_pem_bytes(a0, a1, a2);
    s2n_config_add_cert_chain_and_key(a0, a1, a2);
    s2n_config_add_cert_chain_and_key_to_store(a0, a1);
    s2n_config_add_pem_to_trust_store(a0, a1);
    s2n_config_set_verification_ca_location(a0, a1, a2);
    s2n_crl_new();
    s2n_crl_load_pem(a0, a1, a2);
    s2n_connection_new(a0);
    s2n_connection_set_config(a0, a1);
    s2n_connection_set_cipher_preferences(a0, a1);
    s2n_negotiate(a0, a1);
    s2n_send(a0, a1, a2, a3);
    s2n_recv(a0, a1, a2, a3);
    s2n_shutdown(a0, a1);
    s2n_connection_get_actual_protocol_version(a0);
    s2n_connection_get_cipher(a0);
    s2n_connection_get_curve(a0);
    s2n_connection_get_kem_name(a0);
    s2n_connection_get_kem_group_name(a0);
    s2n_connection_get_selected_signature_algorithm(a0, a1);
    s2n_connection_get_selected_digest_algorithm(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    s2n_connection_free(a0);
    s2n_config_free(a0);
    s2n_connection_set_fd(a0, 3);
    s2n_init();
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
		"s2n_config_new":                               {0, "factory"},
		"s2n_config_set_cipher_preferences":            {2, "config"},
		"s2n_config_add_dhparams":                      {2, "config"},
		"s2n_config_add_ticket_crypto_key":             {6, "config"},
		"s2n_config_set_session_tickets_onoff":         {2, "config"},
		"s2n_config_disable_x509_verification":         {1, "config"},
		"s2n_cert_chain_and_key_new":                   {0, "factory"},
		"s2n_cert_chain_and_key_load_pem":              {3, "config"},
		"s2n_cert_chain_and_key_load_pem_bytes":        {5, "config"},
		"s2n_cert_chain_and_key_load_public_pem_bytes": {3, "config"},
		"s2n_config_add_cert_chain_and_key":            {3, "config"},
		"s2n_config_add_cert_chain_and_key_to_store":   {2, "config"},
		"s2n_config_add_pem_to_trust_store":            {2, "config"},
		"s2n_config_set_verification_ca_location":      {3, "config"},
		"s2n_crl_new":                           {0, "factory"},
		"s2n_crl_load_pem":                      {3, "config"},
		"s2n_connection_new":                    {1, "factory"},
		"s2n_connection_set_config":             {2, "config"},
		"s2n_connection_set_cipher_preferences": {2, "config"},
		"s2n_negotiate":                         {2, "operation"},
		"s2n_send":                              {4, "operation"},
		"s2n_recv":                              {4, "operation"},
		"s2n_shutdown":                          {2, "operation"},
		"s2n_connection_get_actual_protocol_version":      {1, "output"},
		"s2n_connection_get_cipher":                       {1, "output"},
		"s2n_connection_get_curve":                        {1, "output"},
		"s2n_connection_get_kem_name":                     {1, "output"},
		"s2n_connection_get_kem_group_name":               {1, "output"},
		"s2n_connection_get_selected_signature_algorithm": {2, "output"},
		"s2n_connection_get_selected_digest_algorithm":    {2, "output"},
	}
	negative := []string{"s2n_connection_free", "s2n_config_free", "s2n_connection_set_fd", "s2n_init"}

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
				if got[0].SourceLibrary != "s2n-tls" {
					t.Fatalf("%s: library = %q, want s2n-tls", bare, got[0].SourceLibrary)
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
func TestS2NTLSContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"s2n_connection_new": {1, 0, "mode"},
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
