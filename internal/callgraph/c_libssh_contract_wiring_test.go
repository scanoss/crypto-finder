package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libssh contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestLibSSHContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/legacy.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4) {
    ssh_new();
    ssh_options_set(a0, a1, a2);
    ssh_options_parse_config(a0, a1);
    ssh_connect(a0);
    ssh_disconnect(a0);
    ssh_is_server_known(a0);
    ssh_session_is_known_server(a0);
    ssh_get_server_publickey(a0, a1);
    ssh_get_publickey_hash(a0, a1, a2, a3);
    ssh_get_cipher_in(a0);
    ssh_get_cipher_out(a0);
    ssh_get_hmac_in(a0);
    ssh_get_hmac_out(a0);
    ssh_get_kex_algo(a0);
    ssh_userauth_publickey(a0, a1, a2);
    ssh_userauth_publickey_auto(a0, a1, a2);
    ssh_userauth_try_publickey(a0, a1, a2);
    ssh_userauth_agent(a0, a1);
    ssh_userauth_pubkey(a0, a1, a2, a3);
    ssh_userauth_autopubkey(a0, a1);
    ssh_userauth_password(a0, a1, a2);
    ssh_key_new();
    ssh_pki_generate(a0, a1, a2);
    ssh_pki_import_privkey_file(a0, a1, a2, a3, a4);
    ssh_pki_import_privkey_base64(a0, a1, a2, a3, a4);
    ssh_pki_import_pubkey_file(a0, a1);
    ssh_pki_import_pubkey_base64(a0, a1, a2);
    ssh_pki_import_cert_file(a0, a1);
    ssh_pki_import_cert_base64(a0, a1, a2);
    ssh_pki_export_privkey_file(a0, a1, a2, a3, a4);
    ssh_pki_export_privkey_base64(a0, a1, a2, a3, a4);
    ssh_pki_export_privkey_to_pubkey(a0, a1);
    ssh_pki_export_pubkey_file(a0, a1);
    ssh_pki_export_pubkey_base64(a0, a1);
    ssh_pki_copy_cert_to_privkey(a0, a1);
    ssh_key_type(a0);
    privatekey_from_file(a0, a1, a2, a3);
    publickey_from_file(a0, a1, a2);
    publickey_from_privatekey(a0);
    ssh_channel_new(a0);
    ssh_channel_open_session(a0);
    ssh_channel_request_exec(a0, a1);
    ssh_channel_read(a0, a1, a2, a3);
    ssh_channel_write(a0, a1, a2);
    ssh_channel_send_eof(a0);
    ssh_channel_close(a0);
    ssh_bind_new();
    ssh_bind_options_set(a0, a1, a2);
    ssh_bind_listen(a0);
    ssh_bind_accept(a0, a1);
    ssh_bind_accept_fd(a0, a1, a2);
    ssh_handle_key_exchange(a0);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    ssh_free(a0);
    ssh_key_free(a0);
    ssh_channel_free(a0);
    ssh_get_version(a0);
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
		"ssh_new":                          {0, "factory"},
		"ssh_options_set":                  {3, "config"},
		"ssh_options_parse_config":         {2, "config"},
		"ssh_connect":                      {1, "operation"},
		"ssh_disconnect":                   {1, "operation"},
		"ssh_is_server_known":              {1, "operation"},
		"ssh_session_is_known_server":      {1, "operation"},
		"ssh_get_server_publickey":         {2, "output"},
		"ssh_get_publickey_hash":           {4, "operation"},
		"ssh_get_cipher_in":                {1, "output"},
		"ssh_get_cipher_out":               {1, "output"},
		"ssh_get_hmac_in":                  {1, "output"},
		"ssh_get_hmac_out":                 {1, "output"},
		"ssh_get_kex_algo":                 {1, "output"},
		"ssh_userauth_publickey":           {3, "operation"},
		"ssh_userauth_publickey_auto":      {3, "operation"},
		"ssh_userauth_try_publickey":       {3, "operation"},
		"ssh_userauth_agent":               {2, "operation"},
		"ssh_userauth_pubkey":              {4, "operation"},
		"ssh_userauth_autopubkey":          {2, "operation"},
		"ssh_userauth_password":            {3, "operation"},
		"ssh_key_new":                      {0, "factory"},
		"ssh_pki_generate":                 {3, "operation"},
		"ssh_pki_import_privkey_file":      {5, "factory"},
		"ssh_pki_import_privkey_base64":    {5, "factory"},
		"ssh_pki_import_pubkey_file":       {2, "factory"},
		"ssh_pki_import_pubkey_base64":     {3, "factory"},
		"ssh_pki_import_cert_file":         {2, "factory"},
		"ssh_pki_import_cert_base64":       {3, "factory"},
		"ssh_pki_export_privkey_file":      {5, "output"},
		"ssh_pki_export_privkey_base64":    {5, "output"},
		"ssh_pki_export_privkey_to_pubkey": {2, "output"},
		"ssh_pki_export_pubkey_file":       {2, "output"},
		"ssh_pki_export_pubkey_base64":     {2, "output"},
		"ssh_pki_copy_cert_to_privkey":     {2, "config"},
		"ssh_key_type":                     {1, "output"},
		"privatekey_from_file":             {4, "factory"},
		"publickey_from_file":              {3, "factory"},
		"publickey_from_privatekey":        {1, "factory"},
		"ssh_channel_new":                  {1, "factory"},
		"ssh_channel_open_session":         {1, "operation"},
		"ssh_channel_request_exec":         {2, "operation"},
		"ssh_channel_read":                 {4, "operation"},
		"ssh_channel_write":                {3, "operation"},
		"ssh_channel_send_eof":             {1, "operation"},
		"ssh_channel_close":                {1, "operation"},
		"ssh_bind_new":                     {0, "factory"},
		"ssh_bind_options_set":             {3, "config"},
		"ssh_bind_listen":                  {1, "operation"},
		"ssh_bind_accept":                  {2, "operation"},
		"ssh_bind_accept_fd":               {3, "operation"},
		"ssh_handle_key_exchange":          {1, "operation"},
	}
	negative := []string{"ssh_free", "ssh_key_free", "ssh_channel_free", "ssh_get_version"}

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
				if got[0].SourceLibrary != "libssh" {
					t.Fatalf("%s: library = %q, want libssh", bare, got[0].SourceLibrary)
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
func TestLibSSHContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"ssh_get_publickey_hash":       {4, 1, "algorithm"},
		"ssh_pki_generate":             {3, 0, "algorithm"},
		"ssh_pki_import_pubkey_base64": {3, 1, "algorithm"},
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
