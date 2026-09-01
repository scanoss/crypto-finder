package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The four RustCrypto elliptic-curve crates ship from one upstream repository
// and export IDENTICAL type names (SigningKey, VerifyingKey, SecretKey,
// EphemeralSecret). k256 goes further and exports SigningKey/VerifyingKey from
// two modules implementing two different algorithms — ecdsa and schnorr. So a
// contract keyed on the wrong crate, or on the wrong module inside k256,
// resolves silently and mislabels the receiver rather than failing. Assert the
// exact key, the owning library, the role and the return type for each.
//
// These contracts exist because the generic ecdsa.yaml does NOT cover them: its
// keys are `ecdsa::SigningKey.*`, while the callgraph identifies a call by the
// re-exporting crate's own module path. Before these files, an exported
// callgraph for a consumer carried `k256::ecdsa.SigningKey.random(?)` with
// empty parameter_types — the shape an absent contract takes.
func TestLoadEmbeddedRustIncludesEllipticCurveContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	rng := "&impl elliptic_curve::rand_core::CryptoRngCore"

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
		ret    string
	}{
		// k256 ECDSA. The curve is secp256k1; the hash is deliberately not
		// claimed by the rules, and no hash appears in a contract either.
		{"k256::ecdsa::SigningKey.random", 1, "k256", "factory", "k256::ecdsa::SigningKey"},
		{"k256::ecdsa::SigningKey.from_slice", 1, "k256", "factory", "core::result::Result"},
		// Era 3: the zero-arity trait constructor 0.14 replaced random(rng) with.
		{"k256::ecdsa::SigningKey.generate", 0, "k256", "factory", "k256::ecdsa::SigningKey"},
		{"k256::schnorr::SigningKey.generate", 0, "k256", "factory", "k256::schnorr::SigningKey"},
		{"p256::ecdsa::SigningKey.generate", 0, "p256", "factory", "p256::ecdsa::SigningKey"},
		{"p384::ecdsa::SigningKey.generate", 0, "p384", "factory", "p384::ecdsa::SigningKey"},
		{"p521::ecdsa::SigningKey.generate", 0, "p521", "factory", "p521::ecdsa::SigningKey"},
		{"k256::ecdsa::SigningKey.verifying_key", 0, "k256", "output", "&k256::ecdsa::VerifyingKey"},
		{"k256::ecdsa::VerifyingKey.from_sec1_bytes", 1, "k256", "factory", "core::result::Result"},

		// k256 BIP-340 Schnorr — a DIFFERENT algorithm under the SAME type
		// names, keyed on the schnorr module path so the two identities can
		// never collapse into one.
		{"k256::schnorr::SigningKey.random", 1, "k256", "factory", "k256::schnorr::SigningKey"},
		{"k256::schnorr::SigningKey.verifying_key", 0, "k256", "output", "&k256::schnorr::VerifyingKey"},
		{"k256::schnorr::SigningKey.sign_raw", 2, "k256", "operation", "core::result::Result"},
		{"k256::schnorr::VerifyingKey.from_bytes", 1, "k256", "factory", "core::result::Result"},

		// ECDH, shared shape across all four crates.
		{"k256::ecdh::EphemeralSecret.random", 1, "k256", "factory", "k256::ecdh::EphemeralSecret"},
		{"k256::ecdh::EphemeralSecret.diffie_hellman", 1, "k256", "operation", "k256::ecdh::SharedSecret"},
		{"p256::ecdh::EphemeralSecret.diffie_hellman", 1, "p256", "operation", "p256::ecdh::SharedSecret"},
		{"p384::ecdh::EphemeralSecret.diffie_hellman", 1, "p384", "operation", "p384::ecdh::SharedSecret"},
		{"p521::ecdh::EphemeralSecret.diffie_hellman", 1, "p521", "operation", "p521::ecdh::SharedSecret"},

		// The NIST curves.
		{"p256::ecdsa::SigningKey.random", 1, "p256", "factory", "p256::ecdsa::SigningKey"},
		{"p256::ecdsa::VerifyingKey.from_sec1_bytes", 1, "p256", "factory", "core::result::Result"},
		{"p384::ecdsa::SigningKey.random", 1, "p384", "factory", "p384::ecdsa::SigningKey"},
		{"p384::ecdsa::VerifyingKey.from_sec1_bytes", 1, "p384", "factory", "core::result::Result"},
		{"p521::ecdsa::SigningKey.random", 1, "p521", "factory", "p521::ecdsa::SigningKey"},
		{"p521::ecdsa::VerifyingKey.from_sec1_bytes", 1, "p521", "factory", "core::result::Result"},

		// Key material, claimed once per crate.
		{"k256::SecretKey.random", 1, "k256", "factory", "k256::SecretKey"},
		{"p256::SecretKey.random", 1, "p256", "factory", "p256::SecretKey"},
		{"p384::SecretKey.random", 1, "p384", "factory", "p384::SecretKey"},
		{"p521::SecretKey.random", 1, "p521", "factory", "p521::SecretKey"},
		{"k256::PublicKey.from_sec1_bytes", 1, "k256", "factory", "core::result::Result"},
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

	// Every crate's RNG-taking factory must carry the concrete parameter type.
	// An empty parameter_types is the signature of an absent contract, so a
	// contract that resolves but carries nothing is barely better than none.
	for _, method := range []string{
		"k256::ecdsa::SigningKey.random",
		"p256::ecdsa::SigningKey.random",
		"p384::ecdsa::SigningKey.random",
		"p521::ecdsa::SigningKey.random",
		"k256::schnorr::SigningKey.random",
		"k256::ecdh::EphemeralSecret.random",
	} {
		got := kb.ContractsFor(method, 1)
		if len(got) != 1 {
			t.Fatalf("%s#1 contracts = %d, want 1", method, len(got))
		}
		if len(got[0].ParameterTypes) != 1 || got[0].ParameterTypes[0] != rng {
			t.Fatalf("%s#1 parameter_types = %#v, want [%q]", method, got[0].ParameterTypes, rng)
		}
	}
}

// The call-site FQN dots the receiver-type separator, so a contract authored
// with Rust's "::" only resolves because contracts.rustAuthoredKey rewrites it
// back. That rewrite performs EXACTLY ONE substitution and its doc comment
// assumes callers build at most "package.Type.method" — true for a
// single-segment module like x25519_dalek, and NOT true for the two-segment
// module paths this family uses (k256::ecdsa, k256::schnorr, p521::ecdh).
//
// So the form asserted here is the one an exported callgraph actually emits for
// these crates — `k256::ecdsa.SigningKey.random`, module separator intact and
// only the receiver-type separator dotted. The FULLY dotted variant
// (`k256.ecdsa.SigningKey.random`) is deliberately NOT asserted: rustAuthoredKey
// would rewrite it to `k256.ecdsa::SigningKey.random`, which matches nothing,
// and no observed call site produces it. If a future parser change starts
// emitting it, this comment is the place that explains the miss.
func TestEllipticCurveContractsResolveFromCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, emitted := range []string{
		"k256::ecdsa.SigningKey.random",
		"k256::ecdsa.VerifyingKey.from_sec1_bytes",
		"k256::schnorr.SigningKey.random",
		"k256::schnorr.VerifyingKey.from_bytes",
		"k256::ecdh.EphemeralSecret.diffie_hellman",
		"p256::ecdsa.SigningKey.random",
		"p384::ecdsa.SigningKey.random",
		"p521::ecdsa.SigningKey.random",
		"p521::ecdsa.SigningKey.sign_prehash",
	} {
		t.Run(emitted, func(t *testing.T) {
			// -1 is the arity a Rust call site carries when the callee name
			// encodes none, which is the common case.
			if got := kb.ContractsFor(emitted, -1); len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", emitted, len(got))
			}
		})
	}
}

// p521 is the one crate in this family that does NOT alias the generic ecdsa
// crate: 0.13.3 src/ecdsa.rs:82 wraps it in its own newtype, and :120 returns
// VerifyingKey BY VALUE where the aliased crates return a reference. If the
// contracts ever collapse into one shared template, this is the assertion that
// notices.
func TestP521NewtypeReturnsVerifyingKeyByValue(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	byValue := kb.ContractsFor("p521::ecdsa::SigningKey.verifying_key", 0)
	if len(byValue) != 1 {
		t.Fatalf("p521 verifying_key contracts = %d, want 1", len(byValue))
	}
	if got := byValue[0].Return.Type; got != "p521::ecdsa::VerifyingKey" {
		t.Fatalf("p521 verifying_key return = %q, want p521::ecdsa::VerifyingKey (by value)", got)
	}

	for _, c := range []string{"k256", "p256", "p384"} {
		byRef := kb.ContractsFor(c+"::ecdsa.SigningKey.verifying_key", 0)
		if len(byRef) != 1 {
			t.Fatalf("%s verifying_key contracts = %d, want 1", c, len(byRef))
		}
		if got := byRef[0].Return.Type; got != "&"+c+"::ecdsa::VerifyingKey" {
			t.Fatalf("%s verifying_key return = %q, want a reference", c, got)
		}
	}
}
