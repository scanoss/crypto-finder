package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libssh2 contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestLibSSH2ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <libssh2.h>
#include <libssh2_publickey.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9) {
    libssh2_session_init_ex(a0, a1, a2, a3);
    libssh2_session_init();
    libssh2_session_method_pref(a0, a1, a2);
    libssh2_session_handshake(a0, a1);
    libssh2_session_startup(a0, a1);
    libssh2_session_disconnect_ex(a0, a1, a2, a3);
    libssh2_session_disconnect(a0, a1);
    libssh2_session_methods(a0, a1);
    libssh2_session_hostkey(a0, a1, a2);
    libssh2_hostkey_hash(a0, a1);
    libssh2_knownhost_init(a0);
    libssh2_knownhost_readfile(a0, a1, a2);
    libssh2_knownhost_check(a0, a1, a2, a3, a4, a5);
    libssh2_knownhost_checkp(a0, a1, a2, a3, a4, a5, a6);
    libssh2_userauth_list(a0, a1, a2);
    libssh2_userauth_authenticated(a0);
    libssh2_userauth_password_ex(a0, a1, a2, a3, a4, a5);
    libssh2_userauth_password(a0, a1, a2);
    libssh2_userauth_publickey_fromfile_ex(a0, a1, a2, a3, a4, a5);
    libssh2_userauth_publickey_fromfile(a0, a1, a2, a3, a4);
    libssh2_userauth_publickey_frommemory(a0, a1, a2, a3, a4, a5, a6, a7);
    libssh2_userauth_publickey(a0, a1, a2, a3, a4, a5);
    libssh2_userauth_hostbased_fromfile_ex(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    libssh2_userauth_hostbased_fromfile(a0, a1, a2, a3, a4, a5);
    libssh2_userauth_keyboard_interactive_ex(a0, a1, a2, a3);
    libssh2_userauth_keyboard_interactive(a0, a1, a2);
    libssh2_agent_init(a0);
    libssh2_agent_connect(a0);
    libssh2_agent_list_identities(a0);
    libssh2_agent_get_identity(a0, a1, a2);
    libssh2_agent_userauth(a0, a1, a2);
    libssh2_channel_open_ex(a0, a1, a2, a3, a4, a5, a6);
    libssh2_channel_open_session(a0);
    libssh2_channel_process_startup(a0, a1, a2, a3, a4);
    libssh2_channel_exec(a0, a1);
    libssh2_channel_shell(a0);
    libssh2_channel_read_ex(a0, a1, a2, a3);
    libssh2_channel_read(a0, a1, a2);
    libssh2_channel_write_ex(a0, a1, a2, a3);
    libssh2_channel_write(a0, a1, a2);
    libssh2_channel_send_eof(a0);
    libssh2_channel_close(a0);
    libssh2_publickey_init(a0);
    libssh2_publickey_add_ex(a0, a1, a2, a3, a4, a5, a6, a7);
    libssh2_publickey_remove_ex(a0, a1, a2, a3, a4);
    libssh2_publickey_list_fetch(a0, a1, a2);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    libssh2_session_free(a0);
    libssh2_channel_free(a0);
    libssh2_exit();
    libssh2_session_set_blocking(a0, 1);
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
		"libssh2_session_init_ex/4":                  {4, "factory"},
		"libssh2_session_init/0":                     {0, "factory"},
		"libssh2_session_method_pref/3":              {3, "config"},
		"libssh2_session_handshake/2":                {2, "operation"},
		"libssh2_session_startup/2":                  {2, "operation"},
		"libssh2_session_disconnect_ex/4":            {4, "operation"},
		"libssh2_session_disconnect/2":               {2, "operation"},
		"libssh2_session_methods/2":                  {2, "output"},
		"libssh2_session_hostkey/3":                  {3, "output"},
		"libssh2_hostkey_hash/2":                     {2, "output"},
		"libssh2_knownhost_init/1":                   {1, "factory"},
		"libssh2_knownhost_readfile/3":               {3, "config"},
		"libssh2_knownhost_check/6":                  {6, "operation"},
		"libssh2_knownhost_checkp/7":                 {7, "operation"},
		"libssh2_userauth_list/3":                    {3, "output"},
		"libssh2_userauth_authenticated/1":           {1, "output"},
		"libssh2_userauth_password_ex/6":             {6, "operation"},
		"libssh2_userauth_password/3":                {3, "operation"},
		"libssh2_userauth_publickey_fromfile_ex/6":   {6, "operation"},
		"libssh2_userauth_publickey_fromfile/5":      {5, "operation"},
		"libssh2_userauth_publickey_frommemory/8":    {8, "operation"},
		"libssh2_userauth_publickey/6":               {6, "operation"},
		"libssh2_userauth_hostbased_fromfile_ex/10":  {10, "operation"},
		"libssh2_userauth_hostbased_fromfile/6":      {6, "operation"},
		"libssh2_userauth_keyboard_interactive_ex/4": {4, "operation"},
		"libssh2_userauth_keyboard_interactive/3":    {3, "operation"},
		"libssh2_agent_init/1":                       {1, "factory"},
		"libssh2_agent_connect/1":                    {1, "config"},
		"libssh2_agent_list_identities/1":            {1, "config"},
		"libssh2_agent_get_identity/3":               {3, "output"},
		"libssh2_agent_userauth/3":                   {3, "operation"},
		"libssh2_channel_open_ex/7":                  {7, "factory"},
		"libssh2_channel_open_session/1":             {1, "factory"},
		"libssh2_channel_process_startup/5":          {5, "operation"},
		"libssh2_channel_exec/2":                     {2, "operation"},
		"libssh2_channel_shell/1":                    {1, "operation"},
		"libssh2_channel_read_ex/4":                  {4, "operation"},
		"libssh2_channel_read/3":                     {3, "operation"},
		"libssh2_channel_write_ex/4":                 {4, "operation"},
		"libssh2_channel_write/3":                    {3, "operation"},
		"libssh2_channel_send_eof/1":                 {1, "operation"},
		"libssh2_channel_close/1":                    {1, "operation"},
		"libssh2_publickey_init/1":                   {1, "factory"},
		"libssh2_publickey_add_ex/8":                 {8, "operation"},
		"libssh2_publickey_remove_ex/5":              {5, "operation"},
		"libssh2_publickey_list_fetch/3":             {3, "output"},
	}
	negative := []string{"libssh2_session_free", "libssh2_channel_free", "libssh2_exit", "libssh2_session_set_blocking"}

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

				key := fmt.Sprintf("%s/%d", bare, len(call.Arguments))
				expect, ok := want[key]
				if !ok {
					continue
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "libssh2" {
					t.Fatalf("%s: library = %q, want libssh2", bare, got[0].SourceLibrary)
				}
				seen[key] = true
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
func TestLibSSH2ContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"libssh2_session_method_pref": {3, 1, "methodType"},
		"libssh2_session_methods":     {2, 1, "methodType"},
		"libssh2_hostkey_hash":        {2, 1, "algorithm"},
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
