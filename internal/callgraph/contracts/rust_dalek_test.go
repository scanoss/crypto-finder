package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The three Dalek crates ship together and are usually imported together, so a
// contract keyed on the wrong crate resolves silently and mislabels the
// receiver type rather than failing. Assert the exact key, the owning library,
// the role and the return type for each.
func TestLoadEmbeddedRustIncludesDalekContracts(t *testing.T) {
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
		// x25519-dalek: the 2.x constructors, the 1.x/0.4.x `new` spelling and
		// the 0.1.0 free functions all coexist in the committed range.
		{"x25519_dalek::EphemeralSecret.random", 0, "x25519-dalek", "factory", "x25519_dalek::EphemeralSecret"},
		{"x25519_dalek::EphemeralSecret.random_from_rng", 1, "x25519-dalek", "factory", "x25519_dalek::EphemeralSecret"},
		{"x25519_dalek::EphemeralSecret.new", 1, "x25519-dalek", "factory", "x25519_dalek::EphemeralSecret"},
		{"x25519_dalek::EphemeralSecret.diffie_hellman", 1, "x25519-dalek", "operation", "x25519_dalek::SharedSecret"},
		{"x25519_dalek::StaticSecret.diffie_hellman", 1, "x25519-dalek", "operation", "x25519_dalek::SharedSecret"},
		{"x25519_dalek::ReusableSecret.diffie_hellman", 1, "x25519-dalek", "operation", "x25519_dalek::SharedSecret"},
		{"x25519_dalek::PublicKey.from", 1, "x25519-dalek", "factory", "x25519_dalek::PublicKey"},
		{"x25519_dalek::SharedSecret.to_bytes", 0, "x25519-dalek", "output", "[u8; 32]"},
		{"x25519_dalek.x25519", 2, "x25519-dalek", "operation", "[u8; 32]"},
		{"x25519_dalek.diffie_hellman", 2, "x25519-dalek", "operation", "[u8; 32]"},
		{"x25519_dalek.generate_secret", 1, "x25519-dalek", "factory", "[u8; 32]"},

		// ed25519-dalek: 2.x SigningKey/VerifyingKey and the 1.x/0.x
		// Keypair/PublicKey names the rename replaced.
		{"ed25519_dalek::SigningKey.generate", 1, "ed25519-dalek", "factory", "ed25519_dalek::SigningKey"},
		{"ed25519_dalek::SigningKey.from_bytes", 1, "ed25519-dalek", "factory", "ed25519_dalek::SigningKey"},
		{"ed25519_dalek::SigningKey.verifying_key", 0, "ed25519-dalek", "factory", "ed25519_dalek::VerifyingKey"},
		{"ed25519_dalek::SigningKey.sign", 1, "ed25519-dalek", "operation", "ed25519_dalek::Signature"},
		{"ed25519_dalek::SigningKey.sign_prehashed", 2, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::SigningKey.verify_prehashed", 3, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::VerifyingKey.from_bytes", 1, "ed25519-dalek", "factory", "core::result::Result"},
		{"ed25519_dalek::VerifyingKey.verify_prehashed", 3, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::VerifyingKey.verify_strict", 2, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::Keypair.generate", 1, "ed25519-dalek", "factory", "ed25519_dalek::Keypair"},
		{"ed25519_dalek::Keypair.sign", 1, "ed25519-dalek", "operation", "ed25519_dalek::Signature"},
		{"ed25519_dalek::Keypair.try_sign", 1, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::Keypair.sign_prehashed", 2, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::Keypair.verify_prehashed", 3, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::PublicKey.from_bytes", 1, "ed25519-dalek", "factory", "core::result::Result"},
		{"ed25519_dalek::PublicKey.verify_prehashed", 3, "ed25519-dalek", "operation", "core::result::Result"},
		{"ed25519_dalek::SecretKey.sign", 1, "ed25519-dalek", "operation", "ed25519_dalek::Signature"},
		{"ed25519_dalek::ExpandedSecretKey.sign", 2, "ed25519-dalek", "operation", "ed25519_dalek::Signature"},
		{"ed25519_dalek::ExpandedSecretKey.sign_prehashed", 3, "ed25519-dalek", "operation", "core::result::Result"},

		// curve25519-dalek: base-point multiplication and scalar sampling.
		{"curve25519_dalek::EdwardsPoint.mul_base", 1, "curve25519-dalek", "factory", "curve25519_dalek::EdwardsPoint"},
		{"curve25519_dalek::EdwardsPoint.mul_base_clamped", 1, "curve25519-dalek", "factory", "curve25519_dalek::EdwardsPoint"},
		{"curve25519_dalek::MontgomeryPoint.mul_base", 1, "curve25519-dalek", "factory", "curve25519_dalek::MontgomeryPoint"},
		{"curve25519_dalek::RistrettoPoint.random", 1, "curve25519-dalek", "factory", "curve25519_dalek::RistrettoPoint"},
		{"curve25519_dalek::Scalar.random", 1, "curve25519-dalek", "factory", "curve25519_dalek::Scalar"},
		{"curve25519_dalek::Scalar.from_bytes_mod_order", 1, "curve25519-dalek", "factory", "curve25519_dalek::Scalar"},
		{"curve25519_dalek::EdwardsPoint.compress", 0, "curve25519-dalek", "output", "curve25519_dalek::CompressedEdwardsY"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = %#v, want role %q and return %q from %s",
					tt.method, tt.arity, got[0], tt.role, tt.ret, tt.lib)
			}
		})
	}
}

// The call-site FQN joins every FunctionID segment with ".", while the KB keeps
// Rust's own "::" module separator. A contract that only resolves under its
// authored spelling never fires on a real scan, and the miss is silent: the
// export just carries "(?)" parameter types. Assert the dotted call-site key
// resolves too.
func TestDalekContractsResolveFromDottedCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, dotted := range []string{
		"x25519_dalek.EphemeralSecret.diffie_hellman",
		"x25519_dalek.StaticSecret.random",
		"ed25519_dalek.SigningKey.generate",
		"ed25519_dalek.VerifyingKey.verify_strict",
		"ed25519_dalek.SecretKey.sign",
		"ed25519_dalek.Keypair.try_sign",
		"ed25519_dalek.SigningKey.sign_prehashed",
		"ed25519_dalek.Keypair.sign_prehashed",
		"ed25519_dalek.ExpandedSecretKey.sign_prehashed",
		"ed25519_dalek.SigningKey.verify_prehashed",
		"ed25519_dalek.VerifyingKey.verify_prehashed",
		"ed25519_dalek.Keypair.verify_prehashed",
		"ed25519_dalek.PublicKey.verify_prehashed",
		"curve25519_dalek.EdwardsPoint.mul_base",
		"curve25519_dalek.Scalar.random",
	} {
		t.Run(dotted, func(t *testing.T) {
			// -1 is the arity a Rust call site carries when the callee name
			// encodes none, which is the common case.
			if got := kb.ContractsFor(dotted, -1); len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", dotted, len(got))
			}
		})
	}
}

func TestEd25519DalekPrehashedContractsOmitGenericParameterTypes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
	}{
		{"ed25519_dalek::SigningKey.sign_prehashed", 2},
		{"ed25519_dalek::Keypair.sign_prehashed", 2},
		{"ed25519_dalek::ExpandedSecretKey.sign_prehashed", 3},
		{"ed25519_dalek::SigningKey.verify_prehashed", 3},
		{"ed25519_dalek::VerifyingKey.verify_prehashed", 3},
		{"ed25519_dalek::Keypair.verify_prehashed", 3},
		{"ed25519_dalek::PublicKey.verify_prehashed", 3},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if len(got[0].ParameterTypes) != 0 {
				t.Fatalf("%s#%d parameter_types = %v, want empty for generic digest argument", tt.method, tt.arity, got[0].ParameterTypes)
			}
		})
	}
}
