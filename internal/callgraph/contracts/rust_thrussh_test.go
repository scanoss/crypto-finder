package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// thrussh carries two shapes a KB keyed on one spelling silently fails to
// resolve: a callable whose ARITY changed inside the committed range, and an
// authentication receiver that is a different TYPE before and after 0.22.0.
func TestLoadEmbeddedRustIncludesThrusshContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tt := range []struct {
		method string
		arity  int
		role   string
	}{
		{"thrussh::client::Connection.new", 4, "factory"}, // the 0.1.0-0.21.x entry point
		{"thrussh::client.connect", 3, "factory"},
		{"thrussh::client.connect_stream", 3, "factory"},
		{"thrussh::server.run", 3, "factory"},
		{"thrussh::server.run_stream", 3, "factory"},
		// 0.22.0 onwards: the receiver is client::Handle.
		{"thrussh::client::Handle.authenticate_password", 2, "operation"},
		{"thrussh::client::Handle.authenticate_publickey", 2, "operation"},
		{"thrussh::client::Handle.authenticate_future", 3, "operation"},
		// Up to 0.21.x: the same operations on client::Connection, and the
		// pre-rename authenticate_key spelling.
		{"thrussh::client::Connection.authenticate_password", 2, "operation"},
		{"thrussh::client::Connection.authenticate_key", 2, "operation"},
		{"thrussh::client::Connection.authenticate_key_future", 2, "operation"},
		// The in-crate key surface, which leaves for thrussh-keys at 0.18.0.
		{"thrussh.load_public_key", 1, "factory"},
		{"thrussh::key::PublicKey.parse", 2, "factory"},
		{"thrussh::key::Algorithm.clone_public_key", 0, "output"},
		{"thrussh::sodium.generate_keypair", 0, "factory"},
	} {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "thrussh" || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want role %q from thrussh", tt.method, tt.arity, got[0], tt.role)
			}
		})
	}
}

// `load_secret_key` takes one path up to 0.10.1 and two from 0.10.2, and
// `generate_keypair` takes an rng at 0.10.2 but not from 0.17.0. Both are
// declared at both arities: assert each resolves and that neither era is
// answered by a contract that does not exist.
func TestThrusshAritiesSpanTheSignatureChanges(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"thrussh.load_secret_key", 1},
		{"thrussh.load_secret_key", 2},
		{"thrussh::key::Algorithm.generate_keypair", 1},
		{"thrussh::key::Algorithm.generate_keypair", 2},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("%s#%d contracts = %d, want 1", tc.method, tc.arity, len(got))
		}
	}

	// An arity neither era ships must resolve to nothing rather than to the
	// nearest declaration.
	if got := kb.ContractsFor("thrussh.load_secret_key", 3); len(got) != 0 {
		t.Fatalf("thrussh.load_secret_key#3 resolved to %#v, want nothing", got)
	}
}

// The fork and the original must not answer for each other: russh has its own
// KB with the same method names, and a consumer of one is not a consumer of the
// other.
func TestThrusshAndRusshKbsStaySeparate(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for method, wantLib := range map[string]string{
		"thrussh::client::Handle.authenticate_password": "thrussh",
		"russh::client::Handle.authenticate_password":   "russh",
	} {
		got := kb.ContractsFor(method, 2)
		if len(got) != 1 {
			t.Fatalf("%s#2 contracts = %d, want 1", method, len(got))
		}
		if got[0].SourceLibrary != wantLib {
			t.Fatalf("%s#2 SourceLibrary = %q, want %q", method, got[0].SourceLibrary, wantLib)
		}
	}
}
