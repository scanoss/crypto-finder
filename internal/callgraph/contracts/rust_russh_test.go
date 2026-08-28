package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// russh-keys was folded into russh at 0.50.0, so the same loader is reached as
// `russh_keys::load_secret_key` on older pins and `russh::keys::load_secret_key`
// on newer ones. Both roots must resolve, each to its own crate, or a consumer
// on one side of the merge goes untyped.
func TestLoadEmbeddedRustIncludesRusshContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
	}{
		{"russh::client.connect", 3, "russh", "factory"},
		{"russh::client::Handle.authenticate_publickey", 2, "russh", "operation"},
		{"russh::client::Handle.authenticate_publickey_with", 4, "russh", "operation"},
		{"russh::client::Handle.authenticate_openssh_cert", 3, "russh", "operation"},
		{"russh::client::Handle.authenticate_certificate_with", 3, "russh", "operation"},
		{"russh::client::Handle.authenticate_password", 2, "russh", "operation"},
		{"russh::client::Handle.authenticate_none", 1, "russh", "operation"},
		// removed at 0.49.2, still reachable on the older half of the range
		{"russh::client::Handle.authenticate_future", 2, "russh", "operation"},
		// the post-0.50.0 keys module
		{"russh::keys.load_secret_key", 2, "russh", "factory"},
		{"russh::keys.load_openssh_certificate", 1, "russh", "factory"},
		// the pre-0.50.0 standalone crate
		{"russh_keys.load_secret_key", 2, "russh-keys", "factory"},
		{"russh_keys.load_public_key", 1, "russh-keys", "factory"},
		{"russh_keys.parse_public_key_base64", 1, "russh-keys", "factory"},
		{"russh_keys.load_openssh_certificate", 1, "russh-keys", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want role %q from %s", tt.method, tt.arity, got[0], tt.role, tt.lib)
			}
		})
	}
}

// The crate merge means one function name lives under two roots at once. A
// contract keyed on only one of them leaves half the committed range untyped,
// and the miss is silent: the export just carries "(?)" parameter types.
func TestRusshKeyLoadersResolveUnderBothRoots(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct{ key, lib string }{
		{"russh_keys.load_secret_key", "russh-keys"}, // pre-0.50.0
		{"russh::keys.load_secret_key", "russh"},     // post-0.50.0
		{"russh_keys.parse_public_key_base64", "russh-keys"},
		{"russh::keys.parse_public_key_base64", "russh"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			// -1 is the arity a Rust call site carries when the callee name
			// encodes none, which is the common case.
			got := kb.ContractsFor(tc.key, -1)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", tc.key, len(got))
			}
			if got[0].SourceLibrary != tc.lib {
				t.Fatalf("%s resolved to %q, want %q — the crate merge must not blur attribution",
					tc.key, got[0].SourceLibrary, tc.lib)
			}
		})
	}
}
