package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedRustIncludesEllipticCurveContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		authored string
		callSite string
		arity    int
		library  string
		role     string
		ret      string
	}
	tests := []row{
		{"k256::SecretKey.generate", "k256.SecretKey.generate", 0, "k256", "factory", "k256::SecretKey"},
		{"k256::SecretKey.random", "k256.SecretKey.random", 1, "k256", "factory", "k256::SecretKey"},
		{"k256::ecdh::EphemeralSecret.generate", "k256::ecdh.EphemeralSecret.generate", 0, "k256", "factory", "k256::ecdh::EphemeralSecret"},
		{"k256::ecdh::EphemeralSecret.diffie_hellman", "k256::ecdh.EphemeralSecret.diffie_hellman", 1, "k256", "operation", "k256::ecdh::SharedSecret"},
		{"k256::ecdh.diffie_hellman", "k256.ecdh.diffie_hellman", 2, "k256", "operation", "k256::ecdh::SharedSecret"},
		{"k256::ecdsa::SigningKey.generate", "k256::ecdsa.SigningKey.generate", 0, "k256", "factory", "k256::ecdsa::SigningKey"},
		{"k256::ecdsa::SigningKey.sign", "k256::ecdsa.SigningKey.sign", 1, "k256", "operation", "k256::ecdsa::Signature"},
		{"k256::ecdsa::VerifyingKey.verify", "k256::ecdsa.VerifyingKey.verify", 2, "k256", "operation", "core::result::Result"},
		{"k256::ecdsa::VerifyingKey.recover_from_digest", "k256::ecdsa.VerifyingKey.recover_from_digest", 3, "k256", "factory", "core::result::Result"},
		{"k256::schnorr::SigningKey.generate", "k256::schnorr.SigningKey.generate", 0, "k256", "factory", "k256::schnorr::SigningKey"},
		{"k256::schnorr::SigningKey.sign", "k256::schnorr.SigningKey.sign", 1, "k256", "operation", "k256::schnorr::Signature"},
		{"p256::ecdsa::SigningKey.generate", "p256::ecdsa.SigningKey.generate", 0, "p256", "factory", "p256::ecdsa::SigningKey"},
		{"p256::ecdh::EphemeralSecret.generate", "p256::ecdh.EphemeralSecret.generate", 0, "p256", "factory", "p256::ecdh::EphemeralSecret"},
		{"p384::ecdsa::SigningKey.sign", "p384::ecdsa.SigningKey.sign", 1, "p384", "operation", "p384::ecdsa::Signature"},
		{"p384::SecretKey.random", "p384.SecretKey.random", 1, "p384", "factory", "p384::SecretKey"},
		{"p521::ecdsa::VerifyingKey.verify", "p521::ecdsa.VerifyingKey.verify", 2, "p521", "operation", "core::result::Result"},
		{"p521::ecdh.diffie_hellman", "p521.ecdh.diffie_hellman", 2, "p521", "operation", "p521::ecdh::SharedSecret"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.authored, tt.arity), func(t *testing.T) {
			t.Parallel()
			for _, key := range []string{tt.authored, tt.callSite} {
				got := kb.ContractsFor(key, tt.arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", key, tt.arity, len(got))
				}
				if got[0].SourceLibrary != tt.library || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
					t.Fatalf("ContractsFor(%q, %d) = %#v, want %s %s returning %s",
						key, tt.arity, got[0], tt.library, tt.role, tt.ret)
				}
			}
		})
	}
}

func TestEllipticCurveGenerateArityDoesNotMatchRandom(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	if got := kb.ContractsFor("k256::ecdsa.SigningKey.generate", 1); len(got) != 0 {
		t.Fatalf("0.14 generate must not match arity 1, got %#v", got)
	}
	if got := kb.ContractsFor("k256::ecdsa.SigningKey.random", 0); len(got) != 0 {
		t.Fatalf("0.13 random must not match arity 0, got %#v", got)
	}
}
