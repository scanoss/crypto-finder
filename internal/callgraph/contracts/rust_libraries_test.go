package contracts_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedRustIncludesChacha20Poly1305Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		role   string
		ret    string
	}{
		{"chacha20poly1305::Key.from_slice", 1, "factory", "chacha20poly1305::Key"},
		{"chacha20poly1305::Nonce.from_slice", 1, "factory", "chacha20poly1305::Nonce"},
		{"chacha20poly1305::XNonce.from_slice", 1, "factory", "chacha20poly1305::XNonce"},
		{"chacha20poly1305::ChaCha20Poly1305.new", 1, "factory", "chacha20poly1305::ChaCha20Poly1305"},
		{"chacha20poly1305::XChaCha20Poly1305.new", 1, "factory", "chacha20poly1305::XChaCha20Poly1305"},
		{"chacha20poly1305::ChaCha20Poly1305.encrypt", 2, "operation", "alloc::vec::Vec"},
		{"chacha20poly1305::ChaCha20Poly1305.decrypt", 2, "operation", "alloc::vec::Vec"},
		{"chacha20poly1305::XChaCha20Poly1305.encrypt", 2, "operation", "alloc::vec::Vec"},
		{"chacha20poly1305::XChaCha20Poly1305.decrypt", 2, "operation", "alloc::vec::Vec"},
		{"chacha20poly1305::ChaCha20Poly1305.encrypt_in_place", 3, "operation", "()"},
		{"chacha20poly1305::ChaCha20Poly1305.decrypt_in_place", 3, "operation", "()"},
		{"chacha20poly1305::XChaCha20Poly1305.encrypt_in_place", 3, "operation", "()"},
		{"chacha20poly1305::XChaCha20Poly1305.decrypt_in_place", 3, "operation", "()"},
		{"chacha20poly1305::ChaCha20Poly1305.encrypt_inout_detached", 3, "operation", "chacha20poly1305::Tag"},
		{"chacha20poly1305::ChaCha20Poly1305.decrypt_inout_detached", 4, "operation", "()"},
		{"chacha20poly1305::XChaCha20Poly1305.encrypt_inout_detached", 3, "operation", "chacha20poly1305::Tag"},
		{"chacha20poly1305::XChaCha20Poly1305.decrypt_inout_detached", 4, "operation", "()"},
		{"chacha20poly1305::ChaCha20Poly1305.encrypt_in_place_detached", 3, "operation", "chacha20poly1305::Tag"},
		{"chacha20poly1305::ChaCha20Poly1305.decrypt_in_place_detached", 4, "operation", "()"},
		{"chacha20poly1305::XChaCha20Poly1305.encrypt_in_place_detached", 3, "operation", "chacha20poly1305::Tag"},
		{"chacha20poly1305::XChaCha20Poly1305.decrypt_in_place_detached", 4, "operation", "()"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "chacha20poly1305" || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = %#v, want role %q and return %q from chacha20poly1305", tt.method, tt.arity, got[0], tt.role, tt.ret)
			}
			assertChacha20Poly1305ParameterRoles(t, tt.method, got[0].Parameters)
		})
	}
}

func assertChacha20Poly1305ParameterRoles(t *testing.T, method string, parameters []contracts.ParameterContract) {
	t.Helper()

	var want []struct{ property, derivation string }
	switch {
	case strings.HasSuffix(method, ".from_slice"):
		property := "nonceSize"
		if strings.Contains(method, "::Key.") {
			property = "keySize"
		}
		want = []struct{ property, derivation string }{{property, "argument_bit_length"}}
	case strings.HasSuffix(method, ".new"):
		want = []struct{ property, derivation string }{{"keySize", "argument_bit_length"}}
	case strings.Contains(method, "decrypt_in_place_detached") || strings.Contains(method, "decrypt_inout_detached"):
		want = []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"associatedData", "argument_value"}, {"ciphertext", "argument_value"}, {"authenticationTag", "argument_value"}}
	case strings.Contains(method, "encrypt_in_place") || strings.Contains(method, "encrypt_inout_detached"):
		want = []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"associatedData", "argument_value"}, {"plaintext", "argument_value"}}
	case strings.Contains(method, "decrypt_in_place"):
		want = []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"associatedData", "argument_value"}, {"ciphertext", "argument_value"}}
	case strings.HasSuffix(method, ".encrypt"):
		want = []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"plaintext", "argument_value"}}
	case strings.HasSuffix(method, ".decrypt"):
		want = []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"ciphertext", "argument_value"}}
	}

	if len(parameters) != len(want) {
		t.Fatalf("%s parameters = %#v, want %d metadata contributions", method, parameters, len(want))
	}
	for i, expected := range want {
		parameter := parameters[i]
		if parameter.Index == nil || *parameter.Index != i || parameter.Role != "metadata-contributing" || parameter.Contributes == nil ||
			parameter.Contributes.Property != expected.property || parameter.Contributes.Derivation != expected.derivation {
			t.Fatalf("%s parameters[%d] = %#v, want metadata contribution %s/%s", method, i, parameter, expected.property, expected.derivation)
		}
	}
}
