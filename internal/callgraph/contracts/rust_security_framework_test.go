// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// security-framework binds Apple's Security.framework, so what is typed here is
// SecKey (generation, signing, encryption, agreement), SecTrust evaluation,
// SecRandom, PKCS#12 import, and the two macOS SecTransform builders.
//
// Key shapes were read off an exported call graph, not written from the API.
// Call sites emit `<module>.<Type>.<method>` -- `security_framework::key.SecKey.new`
// -- which the Rust key normalisation rewrites to the authored
// `security_framework::key::SecKey.new`. This crate re-exports nothing from its
// root (src/lib.rs:27-48 declares the modules and stops), so EVERY type keeps
// its defining module segment; a key written without one would resolve nothing.
func TestLoadEmbeddedRustIncludesSecurityFrameworkContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		role   string
	}{
		// SecKey generation and operations. Arities exclude the receiver and
		// are read from the declarations: create_signature(alg, data) is 2,
		// verify_signature(alg, data, sig) is 3, key_exchange(alg, pub, size,
		// info) is 4 (src/key.rs:228, :250, :271).
		{"security_framework::key::SecKey.new", 1, "factory"},
		{"security_framework::key::SecKey.generate", 1, "factory"},
		{"security_framework::key::SecKey.from_data", 2, "factory"},
		{"security_framework::key::SecKey.create_signature", 2, "operation"},
		{"security_framework::key::SecKey.verify_signature", 3, "operation"},
		{"security_framework::key::SecKey.encrypt_data", 2, "operation"},
		{"security_framework::key::SecKey.decrypt_data", 2, "operation"},
		{"security_framework::key::SecKey.key_exchange", 4, "operation"},

		// The builder. Its setters return &mut Self, and typing that return is
		// what lets a chained `set_key_type(..).set_size_in_bits(..)` resolve.
		{"security_framework::key::GenerateKeyOptions.set_key_type", 1, "config"},
		{"security_framework::key::GenerateKeyOptions.set_size_in_bits", 1, "config"},
		{"security_framework::key::KeyType.rsa", 0, "factory"},
		{"security_framework::key::KeyType.ec", 0, "factory"},

		{"security_framework::random::SecRandom.default", 0, "factory"},
		{"security_framework::random::SecRandom.copy_bytes", 1, "operation"},

		{"security_framework::trust::SecTrust.create_with_certificates", 2, "factory"},
		{"security_framework::trust::SecTrust.evaluate_with_error", 0, "operation"},
		{"security_framework::trust::SecTrust.evaluate", 0, "operation"},

		{"security_framework::certificate::SecCertificate.from_der", 1, "factory"},
		{"security_framework::identity::SecIdentity.private_key", 0, "output"},

		{"security_framework::import_export::Pkcs12ImportOptions.new", 0, "factory"},
		{"security_framework::import_export::Pkcs12ImportOptions.import", 1, "operation"},

		// The macOS transform builders keep their full module path. A key
		// written as a bare `Builder.type_` would join nothing, and the two
		// builders share the type name, so the module is what tells them apart.
		{"security_framework::os::macos::digest_transform::Builder.type_", 1, "config"},
		{"security_framework::os::macos::digest_transform::Builder.execute", 1, "operation"},
		{"security_framework::os::macos::digest_transform::DigestType.sha2", 0, "factory"},
		{"security_framework::os::macos::encrypt_transform::Builder.mode", 1, "config"},
		{"security_framework::os::macos::encrypt_transform::Builder.padding", 1, "config"},
		{"security_framework::os::macos::encrypt_transform::Builder.encrypt", 2, "operation"},
		{"security_framework::os::macos::encrypt_transform::Mode.cbc", 0, "factory"},
		{"security_framework::os::macos::encrypt_transform::Padding.pkcs7", 0, "factory"},

		{"security_framework::secure_transport::SslContext.new", 2, "factory"},
		{"security_framework::secure_transport::SslContext.set_protocol_version_min", 1, "config"},
		{"security_framework::secure_transport::ClientBuilder.protocol_min", 1, "config"},
		{"security_framework::secure_transport::ClientBuilder.handshake", 2, "operation"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d): %d contracts, want exactly 1", tc.method, tc.arity, len(got))
		}
		if got[0].SourceLibrary != "security-framework" {
			t.Errorf("%s: library = %q, want security-framework", tc.method, got[0].SourceLibrary)
		}
		if got[0].Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, got[0].Role, tc.role)
		}
	}
}

// The dot-joined call-site spelling is what the graph actually emits, and an
// unknown arity has to resolve too. Getting the module separator backwards
// silently produces a contract nothing joins to, which looks exactly like
// having no contract at all.
func TestSecurityFrameworkEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"security_framework::key.SecKey.create_signature",
		"security_framework::key.SecKey.key_exchange",
		"security_framework::key.GenerateKeyOptions.set_key_type",
		"security_framework::random.SecRandom.copy_bytes",
		"security_framework::trust.SecTrust.evaluate_with_error",
		"security_framework::certificate.SecCertificate.from_der",
		"security_framework::import_export.Pkcs12ImportOptions.import",
		"security_framework::os::macos::digest_transform.Builder.type_",
		"security_framework::os::macos::encrypt_transform.Builder.mode",
		"security_framework::secure_transport.ClientBuilder.protocol_min",
	} {
		if got := kb.ContractsFor(m, -1); len(got) == 0 {
			t.Errorf("ContractsFor(%q, -1): no contract for the emitted key", m)
		}
	}
}

// The two SecTransform builders share a type name and differ only by module.
// If either key lost its module segment they would collide, and a digest
// configuration would resolve to the cipher builder or the reverse.
func TestSecurityFrameworkTransformBuildersDoNotCollide(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	digest := kb.ContractsFor("security_framework::os::macos::digest_transform::Builder.type_", 1)
	crypt := kb.ContractsFor("security_framework::os::macos::encrypt_transform::Builder.mode", 1)
	if len(digest) != 1 || len(crypt) != 1 {
		t.Fatalf("digest=%d crypt=%d contracts, want 1 each", len(digest), len(crypt))
	}

	// The collision this guards against is a key losing its module segment, so
	// assert THAT: a bare `Builder.<method>` must resolve to nothing. Comparing
	// the two declared return types instead was a tautology — two literals from
	// one file that differ by construction, which could never fail.
	for _, bare := range []string{"Builder.type_", "Builder.mode", "Builder.execute", "Builder.encrypt"} {
		if got := kb.ContractsFor(bare, -1); len(got) != 0 {
			t.Errorf("ContractsFor(%q, -1) resolved %d contracts; the two SecTransform "+
				"builders share a type name and are told apart only by their module",
				bare, len(got))
		}
	}

	// And each builder's own key must reach its own module, not the sibling's.
	if got := digest[0].Return.Type; !strings.Contains(got, "digest_transform") {
		t.Errorf("digest Builder.type_ returns %q, want the digest_transform builder", got)
	}
	if got := crypt[0].Return.Type; !strings.Contains(got, "encrypt_transform") {
		t.Errorf("encrypt Builder.mode returns %q, want the encrypt_transform builder", got)
	}
}

// SecIdentity.private_key returns a SecKey, and that is the wrapper shape the
// Rust receiver filter exists for: a consumer holds an identity and signs
// through the key it hands back. Without this return type the create_signature
// on the next line has no receiver to resolve.
func TestSecurityFrameworkIdentityYieldsATypedKey(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := kb.ContractsFor("security_framework::identity::SecIdentity.private_key", 0)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(SecIdentity.private_key, 0): %d contracts, want 1", len(got))
	}
	// `return.type` is the RESOLUTION type the parser chains from, and
	// `canonical_return_type` is the full declared one. That is the convention
	// cbc.yaml, ctr.yaml and cfb-mode.yaml already use; this file had it
	// backwards, which handed `Result` back as the next receiver.
	if want := "security_framework::key::SecKey"; got[0].Return.Type != want {
		t.Errorf("return.type = %q, want %q", got[0].Return.Type, want)
	}
	if !strings.HasPrefix(got[0].CanonicalReturnType, "core::result::Result<") {
		t.Errorf("canonical_return_type = %q, want the full Result<...> declaration",
			got[0].CanonicalReturnType)
	}
}

// Every entry in this file follows the KB's return-type convention: the
// resolution type in `return.type`, the full declared type in
// `canonical_return_type`. Getting them the other way round is invisible to
// the loader and produces `core::result.(Result).*` receivers downstream.
func TestSecurityFrameworkReturnTypesFollowTheKBConvention(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	checked := 0
	for _, ctrs := range kb.Contracts {
		for i := range ctrs {
			c := &ctrs[i]
			if c.SourceLibrary != "security-framework" {
				continue
			}
			checked++
			if strings.HasPrefix(c.Return.Type, "core::result::Result") ||
				strings.HasPrefix(c.Return.Type, "core::option::Option") {
				t.Errorf("%s: return.type is the wrapper %q; it must be the type a "+
					"caller chains from, with the wrapper in canonical_return_type",
					c.Method, c.Return.Type)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no security-framework contracts were checked")
	}
}
