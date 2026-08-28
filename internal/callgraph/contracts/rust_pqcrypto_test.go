package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// pqcrypto is an umbrella over the PQClean algorithm crates, so the same
// PQClean function is reachable under two different module paths. A contract
// keyed on only one of them resolves silently for one import spelling and not
// the other, and the miss shows up only as "(?)" parameter types in an export.
func TestLoadEmbeddedRustIncludesPqcryptoContracts(t *testing.T) {
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
		ret    string
	}{
		// algorithm crate, the three standard variants
		{"pqcrypto_kyber::kyber512.keypair", 0, "pqcrypto-kyber", "factory", "(pqcrypto_kyber::kyber512::PublicKey, pqcrypto_kyber::kyber512::SecretKey)"},
		{"pqcrypto_kyber::kyber512.encapsulate", 1, "pqcrypto-kyber", "operation", "(pqcrypto_kyber::kyber512::SharedSecret, pqcrypto_kyber::kyber512::Ciphertext)"},
		{"pqcrypto_kyber::kyber512.decapsulate", 2, "pqcrypto-kyber", "operation", "pqcrypto_kyber::kyber512::SharedSecret"},
		{"pqcrypto_kyber::kyber768.keypair", 0, "pqcrypto-kyber", "factory", "(pqcrypto_kyber::kyber768::PublicKey, pqcrypto_kyber::kyber768::SecretKey)"},
		{"pqcrypto_kyber::kyber1024.decapsulate", 2, "pqcrypto-kyber", "operation", "pqcrypto_kyber::kyber1024::SharedSecret"},
		// the 90s variants, which exist only between 0.6.0 and 0.7.8
		{"pqcrypto_kyber::kyber51290s.keypair", 0, "pqcrypto-kyber", "factory", "(pqcrypto_kyber::kyber51290s::PublicKey, pqcrypto_kyber::kyber51290s::SecretKey)"},
		{"pqcrypto_kyber::kyber102490s.encapsulate", 1, "pqcrypto-kyber", "operation", "(pqcrypto_kyber::kyber102490s::SharedSecret, pqcrypto_kyber::kyber102490s::Ciphertext)"},
		// umbrella, kyber era (0.1.0 .. 0.17.0)
		{"pqcrypto::kem::kyber768.keypair", 0, "pqcrypto", "factory", "(pqcrypto::kem::kyber768::PublicKey, pqcrypto::kem::kyber768::SecretKey)"},
		{"pqcrypto::kem::kyber768.encapsulate", 1, "pqcrypto", "operation", "(pqcrypto::kem::kyber768::SharedSecret, pqcrypto::kem::kyber768::Ciphertext)"},
		// umbrella, mlkem era (0.18.0 onward) — kyber is gone there
		{"pqcrypto::kem::mlkem768.keypair", 0, "pqcrypto", "factory", "(pqcrypto::kem::mlkem768::PublicKey, pqcrypto::kem::mlkem768::SecretKey)"},
		{"pqcrypto::kem::mlkem1024.decapsulate", 2, "pqcrypto", "operation", "pqcrypto::kem::mlkem1024::SharedSecret"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = %#v, want role %q return %q from %s",
					tt.method, tt.arity, got[0], tt.role, tt.ret, tt.lib)
			}
		})
	}
}

// The parser emits two different keys for the same pqcrypto-kyber call
// depending on the import spelling: `use pqcrypto_kyber::kyber512;` then
// `kyber512::keypair()` yields the dot-joined pqcrypto_kyber.kyber512.keypair,
// while `use pqcrypto_kyber::kyber768::keypair;` then a bare `keypair()` yields
// pqcrypto_kyber::kyber768.keypair. Both are real consumer code and both must
// resolve to the same contract.
func TestPqcryptoContractsResolveBothCallSiteSpellings(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, key := range []string{
		"pqcrypto_kyber.kyber512.keypair",      // dot-joined, from `use pqcrypto_kyber::kyber512;`
		"pqcrypto_kyber::kyber768.keypair",     // already "::"-joined, from a bare imported fn
		"pqcrypto_kyber.kyber1024.encapsulate", // dot-joined
		"pqcrypto::kem::kyber768.encapsulate",  // umbrella, kyber era
		"pqcrypto::kem::mlkem512.keypair",      // umbrella, mlkem era
	} {
		t.Run(key, func(t *testing.T) {
			// -1 is the arity a Rust call site carries when the callee name
			// encodes none, which is the common case.
			if got := kb.ContractsFor(key, -1); len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", key, len(got))
			}
		})
	}
}
