package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// sequoia-openpgp re-exports `Cert` at its crate root AND under `cert`, and the
// callee key follows the CONSUMER's import, so both spellings occur in real
// code. Every key here was read off an exported call graph for a probe consumer
// rather than from the crate's documentation; before this contract each one
// appeared as `name(?)` with empty parameter_types.
func TestLoadEmbeddedRustIncludesSequoiaOpenPGPContracts(t *testing.T) {
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
		// Certificates and key material.
		{"sequoia_openpgp::cert::CertBuilder.new", 0, "factory", "sequoia_openpgp::cert::CertBuilder"},
		// `general_purpose` changed arity at 2.0.0 and BOTH forms are in range:
		// 0.15.0-1.22.x take (ciphersuite, userids), 2.x takes (userids). A
		// single entry does not join for any 0.x or 1.x consumer.
		{"sequoia_openpgp::cert::CertBuilder.general_purpose", 2, "factory", "sequoia_openpgp::cert::CertBuilder"},
		{"sequoia_openpgp::cert::CertBuilder.general_purpose", 1, "factory", "sequoia_openpgp::cert::CertBuilder"},
		{"sequoia_openpgp::cert::CertBuilder.set_cipher_suite", 1, "config", "sequoia_openpgp::cert::CertBuilder"},
		{"sequoia_openpgp::cert::CertBuilder.generate", 0, "operation", "core::result::Result"},

		// BOTH `Cert` spellings. The crate re-exports it at its root as well as
		// under `cert`, and the key follows the consumer's import, so a contract
		// carrying only one resolves only half the consumers. Both are authored
		// in the `::` form the rest of this KB uses.
		{"sequoia_openpgp::cert::Cert.from_bytes", 1, "factory", "core::result::Result"},
		{"sequoia_openpgp::Cert.from_bytes", 1, "factory", "core::result::Result"},

		// Streaming signing and encryption.
		{"sequoia_openpgp::serialize::stream::Message.new", 1, "factory", "sequoia_openpgp::serialize::stream::Message"},
		{"sequoia_openpgp::serialize::stream::Signer.new", 2, "factory", "core::result::Result"},
		{"sequoia_openpgp::serialize::stream::Signer.hash_algo", 1, "config", "core::result::Result"},
		{"sequoia_openpgp::serialize::stream::Encryptor.for_recipients", 2, "factory", "sequoia_openpgp::serialize::stream::Encryptor"},
		{"sequoia_openpgp::serialize::stream::Encryptor.symmetric_algo", 1, "config", "sequoia_openpgp::serialize::stream::Encryptor"},
		{"sequoia_openpgp::serialize::stream::Encryptor.aead_algo", 1, "config", "sequoia_openpgp::serialize::stream::Encryptor"},
		{"sequoia_openpgp::serialize::stream::Encryptor.with_passwords", 2, "factory", "sequoia_openpgp::serialize::stream::Encryptor"},
		{"sequoia_openpgp::serialize::stream::Encryptor.with_session_key", 3, "factory", "core::result::Result"},

		// The 1.17.0-1.22.x transitional type, contracted because it exists
		// inside the committed version range.
		{"sequoia_openpgp::serialize::stream::Encryptor2.for_recipients", 2, "factory", "sequoia_openpgp::serialize::stream::Encryptor2"},
		{"sequoia_openpgp::serialize::stream::Encryptor2.add_recipients", 1, "config", "sequoia_openpgp::serialize::stream::Encryptor2"},
		{"sequoia_openpgp::serialize::stream::Encryptor2.symmetric_algo", 1, "config", "sequoia_openpgp::serialize::stream::Encryptor2"},

		// Policy-aware verification and decryption. All three builders share
		// `with_policy`, which is why the RULES anchor the constructors instead:
		// the method name alone cannot carry the operation. It is a `factory`
		// here — it returns the Verifier/Decryptor and does no cryptography at
		// the call site.
		{"sequoia_openpgp::parse::stream::VerifierBuilder.from_bytes", 1, "factory", "core::result::Result"},
		{"sequoia_openpgp::parse::stream::VerifierBuilder.with_policy", 3, "factory", "core::result::Result"},
		{"sequoia_openpgp::parse::stream::DecryptorBuilder.from_bytes", 1, "factory", "core::result::Result"},
		{"sequoia_openpgp::parse::stream::DecryptorBuilder.with_policy", 3, "factory", "core::result::Result"},
		{"sequoia_openpgp::parse::stream::DetachedVerifierBuilder.with_policy", 3, "factory", "core::result::Result"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "sequoia-openpgp" || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = %#v, want role %q return %q from sequoia-openpgp",
					tt.method, tt.arity, got[0], tt.role, tt.ret)
			}
		})
	}
}

// The wiring test the contract convention asks for in the same commit: the
// forms an exported call graph actually emits must resolve. The parser dots the
// receiver-type separator, and contracts.rustAuthoredKey rewrites it back, so
// these are the emitted spellings rather than the authored ones.
func TestSequoiaOpenPGPContractsResolveFromCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// Measured on probe consumers: the left column is what the export carried.
	for _, emitted := range []string{
		"sequoia_openpgp::cert.CertBuilder.general_purpose",
		"sequoia_openpgp::cert.CertBuilder.set_cipher_suite",
		"sequoia_openpgp::cert.Cert.from_bytes",
		"sequoia_openpgp.Cert.from_bytes", // crate-root re-export spelling
		"sequoia_openpgp::serialize::stream.Signer.new",
		"sequoia_openpgp::serialize::stream.Signer.hash_algo",
		"sequoia_openpgp::serialize::stream.Encryptor.for_recipients",
		"sequoia_openpgp::serialize::stream.Encryptor.symmetric_algo",
		"sequoia_openpgp::parse::stream.VerifierBuilder.from_bytes",
		"sequoia_openpgp::parse::stream.DecryptorBuilder.from_bytes",
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
