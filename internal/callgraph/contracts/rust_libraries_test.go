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

func TestLoadEmbeddedRustIncludesRingContracts(t *testing.T) {
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
		{"ring::aead::UnboundKey.new", 2, "factory", "ring::aead::UnboundKey"},
		{"ring::aead::LessSafeKey.new", 1, "factory", "ring::aead::LessSafeKey"},
		{"ring::aead::Nonce.assume_unique_for_key", 1, "factory", "ring::aead::Nonce"},
		{"ring::aead::LessSafeKey.seal_in_place_append_tag", 3, "operation", "()"},
		{"ring::digest.digest", 2, "operation", "ring::digest::Digest"},
		{"ring::digest::Context.new", 1, "factory", "ring::digest::Context"},
		{"ring::digest::Context.update", 1, "operation", "()"},
		{"ring::digest::Context.finish", 0, "output", "ring::digest::Digest"},
		{"ring::hmac::Key.new", 2, "factory", "ring::hmac::Key"},
		{"ring::hmac::Key.generate", 2, "factory", "ring::hmac::Key"},
		{"ring::hmac.sign", 2, "operation", "ring::hmac::Tag"},
		{"ring::hmac.verify", 3, "operation", "()"},
		{"ring::hmac::Context.with_key", 1, "factory", "ring::hmac::Context"},
		{"ring::hmac::Context.update", 1, "operation", "()"},
		{"ring::hmac::Context.sign", 0, "output", "ring::hmac::Tag"},
		{"ring::hkdf::Salt.new", 2, "factory", "ring::hkdf::Salt"},
		{"ring::hkdf::Salt.extract", 1, "operation", "ring::hkdf::Prk"},
		{"ring::hkdf::Prk.expand", 2, "operation", "ring::hkdf::Okm"},
		{"ring::hkdf::Okm.fill", 1, "output", "()"},
		{"ring::agreement::EphemeralPrivateKey.generate", 2, "factory", "ring::agreement::EphemeralPrivateKey"},
		{"ring::agreement::EphemeralPrivateKey.compute_public_key", 0, "output", "ring::agreement::PublicKey"},
		{"ring::agreement::UnparsedPublicKey.new", 2, "factory", "ring::agreement::UnparsedPublicKey"},
		{"ring::signature::Ed25519KeyPair.from_pkcs8", 1, "factory", "ring::signature::Ed25519KeyPair"},
		{"ring::signature::Ed25519KeyPair.sign", 1, "operation", "ring::signature::Signature"},
		{"ring::signature::UnparsedPublicKey.new", 2, "factory", "ring::signature::UnparsedPublicKey"},
		{"ring::signature::UnparsedPublicKey.verify", 2, "operation", "()"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "ring" || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = %#v, want ring %s returning %s", tt.method, tt.arity, got[0], tt.role, tt.ret)
			}
		})
	}
}

func TestRingContractParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   []struct{ property, derivation string }
	}{
		{"ring::aead::UnboundKey.new", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}, {"keySize", "argument_bit_length"}}},
		{"ring::aead::Nonce.assume_unique_for_key", 1, []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}}},
		{"ring::aead::LessSafeKey.seal_in_place_append_tag", 3, []struct{ property, derivation string }{{"nonceSize", "argument_bit_length"}, {"associatedData", "argument_value"}, {"plaintext", "argument_value"}}},
		{"ring::digest.digest", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
		{"ring::digest::Context.new", 1, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
		{"ring::hmac::Key.new", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}, {"keySize", "argument_bit_length"}}},
		{"ring::hmac::Key.generate", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
		{"ring::hkdf::Salt.new", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}, {"saltSize", "argument_bit_length"}}},
		{"ring::agreement::EphemeralPrivateKey.generate", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
		{"ring::agreement::UnparsedPublicKey.new", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
		{"ring::signature::UnparsedPublicKey.new", 2, []struct{ property, derivation string }{{"algorithm", "argument_value"}}},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 || len(got[0].Parameters) != len(tt.want) {
				t.Fatalf("%s#%d parameters = %#v, want %d", tt.method, tt.arity, got, len(tt.want))
			}
			for i, want := range tt.want {
				parameter := got[0].Parameters[i]
				role := "metadata-contributing"
				if want.property == "algorithm" {
					role = "operation-determining"
				}
				if parameter.Index == nil || *parameter.Index != i || parameter.Role != role || parameter.Contributes == nil || parameter.Contributes.Property != want.property || parameter.Contributes.Derivation != want.derivation {
					t.Fatalf("%s parameters[%d] = %#v, want %s/%s", tt.method, i, parameter, want.property, want.derivation)
				}
			}
		})
	}
}
