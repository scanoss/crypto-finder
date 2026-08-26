package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The parser emits dot-joined keys ("scrypt.Params.new") while the KB is
// authored with "::". Both forms must resolve to the same contract.
func TestLoadEmbeddedRustIncludesPasswordHashContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		authored string
		callSite string
		arity    int
		library  string
		role     string
		ret      string
	}{
		{"scrypt::Params.new", "scrypt.Params.new", 3, "scrypt", "config", "core::result::Result"},
		{"scrypt::Params.new_with_output_len", "scrypt.Params.new_with_output_len", 4, "scrypt", "config", "core::result::Result"},
		{"scrypt::Scrypt.default", "scrypt.Scrypt.default", 0, "scrypt", "factory", "scrypt::Scrypt"},
		{"scrypt.scrypt", "scrypt.scrypt", 4, "scrypt", "operation", "core::result::Result"},
		{"pbkdf2::Pbkdf2.default", "pbkdf2.Pbkdf2.default", 0, "pbkdf2", "factory", "pbkdf2::Pbkdf2"},
		// The parser fix made these resolvable; contract them so it has a
		// consumer. `Generate::generate()` takes no arguments (crypto-common
		// 0.2.0 src/generate.rs:43) and these were authored at arity 1, which
		// the export path's exact-arity lookup never matched; the
		// rng-taking spelling is `generate_from_rng(rng)` (src/generate.rs:17).
		{"chacha20poly1305::Key.generate", "chacha20poly1305.Key.generate", 0, "chacha20poly1305", "factory", "chacha20poly1305::Key"},
		{"chacha20poly1305::Nonce.generate", "chacha20poly1305.Nonce.generate", 0, "chacha20poly1305", "factory", "chacha20poly1305::Nonce"},
		{"chacha20poly1305::XNonce.generate", "chacha20poly1305.XNonce.generate", 0, "chacha20poly1305", "factory", "chacha20poly1305::XNonce"},
		{"chacha20poly1305::Key.generate_from_rng", "chacha20poly1305.Key.generate_from_rng", 1, "chacha20poly1305", "factory", "chacha20poly1305::Key"},
		{"chacha20poly1305::Nonce.generate_from_rng", "chacha20poly1305.Nonce.generate_from_rng", 1, "chacha20poly1305", "factory", "chacha20poly1305::Nonce"},
		{"pbkdf2.pbkdf2", "pbkdf2.pbkdf2", 4, "pbkdf2", "operation", "core::result::Result"},
		{"pbkdf2.pbkdf2_array", "pbkdf2.pbkdf2_array", 3, "pbkdf2", "operation", "core::result::Result"},
		{"pbkdf2.pbkdf2_hmac", "pbkdf2.pbkdf2_hmac", 4, "pbkdf2", "operation", "()"},
		{"pbkdf2.pbkdf2_hmac_array", "pbkdf2.pbkdf2_hmac_array", 3, "pbkdf2", "operation", "[u8; N]"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.authored, tt.arity), func(t *testing.T) {
			for _, key := range []string{tt.authored, tt.callSite} {
				got := kb.ContractsFor(key, tt.arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", key, tt.arity, len(got))
				}
				if got[0].SourceLibrary != tt.library || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
					t.Fatalf("ContractsFor(%q, %d) = %#v, want role %q return %q from %q",
						key, tt.arity, got[0], tt.role, tt.ret, tt.library)
				}
			}
		})
	}
}

// Params::new argument positions carry the cost, block-size and parallelism
// values a consumer reads back from the call site.
func TestRustScryptParamsNewParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := kb.ContractsFor("scrypt.Params.new", 3)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(scrypt.Params.new, 3) = %d contracts, want 1", len(got))
	}

	want := map[int]string{0: "logN", 1: "blockSize", 2: "parallelism"}
	if len(got[0].Parameters) != len(want) {
		t.Fatalf("parameters = %d, want %d", len(got[0].Parameters), len(want))
	}
	for _, p := range got[0].Parameters {
		if p.Index == nil {
			t.Fatalf("parameter %#v has no index", p)
		}
		prop, ok := want[*p.Index]
		if !ok {
			t.Fatalf("unexpected parameter index %d", *p.Index)
		}
		if p.Role != "metadata-contributing" || p.Contributes == nil || p.Contributes.Property != prop {
			t.Fatalf("parameter %d = %#v, want metadata-contributing property %q", *p.Index, p, prop)
		}
		if p.Contributes.Derivation != "argument_value" {
			t.Fatalf("parameter %d derivation = %q, want argument_value", *p.Index, p.Contributes.Derivation)
		}
	}
}
