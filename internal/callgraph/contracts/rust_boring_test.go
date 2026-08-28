package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// boring is Cloudflare's BoringSSL binding and a fork of rust-openssl, so its
// safe surface mirrors the merged openssl contracts module for module while
// carrying its own PURL. The safe crate and the -sys crate ship together and
// are usually imported together, so each key must resolve to its own crate.
func TestLoadEmbeddedRustIncludesBoringContracts(t *testing.T) {
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
		// safe crate: a type inside a module
		{"boring::rsa::Rsa.generate", 1, "boring", "factory"},
		{"boring::ec::EcKey.generate", 1, "boring", "factory"},
		{"boring::pkey::PKey.private_key_from_pem", 1, "boring", "factory"},
		{"boring::sign::Signer.new", 2, "boring", "factory"},
		{"boring::ssl::SslConnector.builder", 1, "boring", "factory"},
		{"boring::x509::X509.from_pem", 1, "boring", "factory"},
		{"boring::symm::Cipher.aes_256_gcm", 0, "boring", "config"},
		// safe crate: a free function in a module
		{"boring::sha.sha256", 1, "boring", "operation"},
		{"boring::symm.encrypt", 4, "boring", "operation"},
		// sys crate: raw FFI free functions
		{"boring_sys.EVP_sha256", 0, "boring-sys", "config"},
		{"boring_sys.EVP_aead_chacha20_poly1305", 0, "boring-sys", "config"},
		{"boring_sys.HMAC_Init_ex", 5, "boring-sys", "operation"},
		{"boring_sys.RSA_generate_key_ex", 4, "boring-sys", "factory"},
		{"boring_sys.ECDSA_do_sign", 3, "boring-sys", "operation"},
		{"boring_sys.SSL_CTX_new", 1, "boring-sys", "factory"},
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

// The call site joins every FunctionID segment with ".", while the KB keeps
// Rust's "::" module separator. A contract that only resolves under its authored
// spelling never fires on a real scan, and the miss is silent — the export just
// carries "(?)" parameter types.
func TestBoringContractsResolveFromDottedCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// These are the keys a real scan produces, taken from an exported graph
	// fragment rather than guessed. Note they are NOT uniformly dot-joined: the
	// parser keeps "::" inside the module path and uses "." for the receiver
	// type and the method, so `use boring::sha;` then `sha::sha256(..)` yields
	// boring.sha.sha256 while `boring::rsa::Rsa::generate(..)` yields
	// boring::rsa.Rsa.generate. Both must reach the authored key.
	for _, tc := range []struct{ key, lib string }{
		{"boring.sha.sha256", "boring"},
		{"boring::rsa.Rsa.generate", "boring"},
		{"boring::ssl.SslConnector.builder", "boring"},
		{"boring::pkey.PKey.private_key_from_pem", "boring"},
		{"boring_sys.EVP_sha256", "boring-sys"},
		{"boring_sys.TLS_method", "boring-sys"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			// -1 is the arity a Rust call site carries when the callee name
			// encodes none, which is the common case.
			got := kb.ContractsFor(tc.key, -1)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", tc.key, len(got))
			}
			if got[0].SourceLibrary != tc.lib {
				t.Fatalf("%s resolved to %q, want %q — the safe and sys crates must stay apart",
					tc.key, got[0].SourceLibrary, tc.lib)
			}
		})
	}
}
