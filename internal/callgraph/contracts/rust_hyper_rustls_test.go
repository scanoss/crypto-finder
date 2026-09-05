// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// hyper-rustls is the adapter that wires rustls into hyper. It selects no
// cryptographic algorithm of its own -- over the 104 src/*.rs files of the 28
// releases read for this family there are zero occurrences of cipher_suites,
// kx_groups, SignatureScheme, SupportedCipherSuite or ProtocolVersion, and the
// provider is forwarded through Cargo features rather than chosen. The single
// dangerous() call (0.27.0 src/config.rs:42) installs rustls-platform-verifier's
// verifier, which is a verification-policy decision and is what the rules'
// platform-verifier entry claims. What is typed here is session establishment
// and trust-anchor selection.
//
// Every key this crate emits is a type method carrying two dots, which
// rustAuthoredKey rewrites at the second-to-last dot (contracts.go:267): the
// graph emits `hyper_rustls.HttpsConnectorBuilder.new` and the file must
// contain `hyper_rustls::HttpsConnectorBuilder.new`. There is no crate-root
// free function, so the one-dot case does not arise here.
//
// This is an EXACT SET comparison, not a per-key subset assertion. A per-key
// check cannot see an entry that should not be there, an entry that was
// dropped, or a field that was corrupted -- and every one of those was
// produced by hand while authoring this file.
func TestLoadEmbeddedRustHyperRustlsContractSetIsExact(t *testing.T) {
	t.Parallel()

	const want = `hyper_rustls::AcceptorBuilder.with_single_cert#2|config|Result<hyper_rustls::AcceptorBuilder<WantsAlpn>, rustls::Error>/high|Result<hyper_rustls::AcceptorBuilder<WantsAlpn>, rustls::Error>|[Vec<rustls::pki_types::CertificateDer<'static>> rustls::pki_types::PrivateKeyDer<'static>]|params=none|lib=hyper-rustls
hyper_rustls::AcceptorBuilder.with_tls_config#1|config|hyper_rustls::AcceptorBuilder<WantsAlpn>/high|hyper_rustls::AcceptorBuilder<WantsAlpn>|[rustls::ServerConfig]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.from#1|factory|hyper_rustls::HttpsConnector<H>/low||[(H, C)]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.new#0|factory|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>/high|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.new#1|factory|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>/high|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>|[usize]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.new#2|factory|hyper_rustls::HttpsConnector/high|hyper_rustls::HttpsConnector|[usize &tokio_core::reactor::Handle]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.with_native_roots#0|factory|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>/high|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnector.with_webpki_roots#0|factory|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>/high|hyper_rustls::HttpsConnector<hyper::client::HttpConnector>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.new#0|factory|hyper_rustls::HttpsConnectorBuilder<WantsTlsConfig>/high|hyper_rustls::HttpsConnectorBuilder<WantsTlsConfig>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.try_with_platform_verifier#0|config|Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>, rustls::Error>/high|Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>, rustls::Error>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_native_roots#0|config|std::io::Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>>/low||[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_platform_verifier#0|config|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>/high|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>|[]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_provider_and_native_roots#1|config|std::io::Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>>/high|std::io::Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>>|[impl Into<std::sync::Arc<rustls::crypto::CryptoProvider>>]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_provider_and_platform_verifier#1|config|std::io::Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>>/high|std::io::Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>>|[impl Into<std::sync::Arc<rustls::crypto::CryptoProvider>>]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_provider_and_webpki_roots#1|config|Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>, rustls::Error>/high|Result<hyper_rustls::HttpsConnectorBuilder<WantsSchemes>, rustls::Error>|[impl Into<std::sync::Arc<rustls::crypto::CryptoProvider>>]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_tls_config#1|config|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>/high|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>|[rustls::ClientConfig]|params=none|lib=hyper-rustls
hyper_rustls::HttpsConnectorBuilder.with_webpki_roots#0|config|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>/high|hyper_rustls::HttpsConnectorBuilder<WantsSchemes>|[]|params=none|lib=hyper-rustls
hyper_rustls::TlsAcceptor.builder#0|factory|hyper_rustls::AcceptorBuilder<WantsTlsConfig>/high|hyper_rustls::AcceptorBuilder<WantsTlsConfig>|[]|params=none|lib=hyper-rustls
hyper_rustls::TlsClient.new#0|factory|hyper_rustls::TlsClient/high|hyper_rustls::TlsClient|[]|params=none|lib=hyper-rustls
hyper_rustls::TlsServer.new#2|factory|hyper_rustls::TlsServer/medium|hyper_rustls::TlsServer|[Vec<rustls::Certificate> rustls::PrivateKey]|params=none|lib=hyper-rustls
hyper_rustls::acceptor::AcceptorBuilder.with_single_cert#2|config|Result<hyper_rustls::AcceptorBuilder<WantsAlpn>, rustls::Error>/high|Result<hyper_rustls::AcceptorBuilder<WantsAlpn>, rustls::Error>|[Vec<rustls::pki_types::CertificateDer<'static>> rustls::pki_types::PrivateKeyDer<'static>]|params=none|lib=hyper-rustls
hyper_rustls::acceptor::AcceptorBuilder.with_tls_config#1|config|hyper_rustls::AcceptorBuilder<WantsAlpn>/high|hyper_rustls::AcceptorBuilder<WantsAlpn>|[rustls::ServerConfig]|params=none|lib=hyper-rustls
hyper_rustls::acceptor::TlsAcceptor.builder#0|factory|hyper_rustls::AcceptorBuilder<WantsTlsConfig>/high|hyper_rustls::AcceptorBuilder<WantsTlsConfig>|[]|params=none|lib=hyper-rustls`

	if got := renderHyperRustlsContracts(t); got != want {
		t.Errorf("hyper-rustls contract set changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// renderHyperRustlsContracts renders every loaded hyper-rustls contract as one
// line, including the parameters block and the source library, so that renaming
// a contributed property or corrupting the library name fails the comparison.
// Both were verified to slip past a rendering that stopped at
// method/arity/role/return/params.
func renderHyperRustlsContracts(t *testing.T) string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var lines []string
	for _, entries := range kb.Contracts {
		for i := range entries {
			c := &entries[i]
			if c.SourceLibrary != "hyper-rustls" {
				continue
			}
			params := "none"
			if len(c.Parameters) > 0 {
				var rendered []string
				for _, p := range c.Parameters {
					idx := "-"
					if p.Index != nil {
						idx = fmt.Sprintf("%d", *p.Index)
					}
					contributes := "-"
					if p.Contributes != nil {
						contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
					}
					rendered = append(rendered, fmt.Sprintf("%s/%s/%s/%s", idx, p.Name, p.Role, contributes))
				}
				params = strings.Join(rendered, ",")
			}
			lines = append(lines, fmt.Sprintf(
				"%s#%d|%s|%s/%s|%s|%v|params=%s|lib=%s",
				c.Method, c.Arity, c.Role,
				c.Return.Type, c.Return.Confidence,
				c.CanonicalReturnType,
				c.ParameterTypes,
				params,
				c.SourceLibrary,
			))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no hyper-rustls contracts loaded at all -- the exact-set comparison would be vacuous")
	}
	sort.Strings(lines)
	// Deduplicate: a contract is indexed under more than one key shape.
	out := lines[:0]
	for i, l := range lines {
		if i == 0 || l != lines[i-1] {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// The library block is parsed and then never consulted by any other assertion,
// so corrupting version_range, coordinates or description leaves an
// otherwise-exact test green -- verified by mutating each of them and watching
// every other test here stay green. `LoadEmbedded` merges every rust KB and
// therefore drops `Library` to nil, so the block is asserted by loading this
// one file directly.
func TestRustHyperRustlsLibraryMetadata(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("rust", "hyper-rustls.yaml"))
	if err != nil {
		t.Fatalf("read hyper-rustls.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(hyper-rustls.yaml): %v", err)
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", kb.SchemaVersion)
	}
	if kb.Ecosystem != "rust" {
		t.Errorf("ecosystem = %q, want rust", kb.Ecosystem)
	}
	if kb.Library == nil {
		t.Fatal("library block is missing")
	}
	if kb.Library.Name != "hyper-rustls" {
		t.Errorf("library.name = %q, want hyper-rustls", kb.Library.Name)
	}
	// Both spellings: crates.io uses the hyphen, the emitted call-graph key
	// uses the underscore lib name declared at 0.27.9 Cargo.toml.
	wantCoords := []string{"hyper-rustls", "hyper_rustls"}
	if !reflect.DeepEqual(kb.Library.Coordinates, wantCoords) {
		t.Errorf("library.coordinates = %v, want %v", kb.Library.Coordinates, wantCoords)
	}
	// The committed matrix lists 53 versions, 0.2.0 through 0.27.9.
	if kb.Library.VersionRange != ">=0.2.0,<0.28.0" {
		t.Errorf("library.version_range = %q, want >=0.2.0,<0.28.0", kb.Library.VersionRange)
	}
	if kb.Library.Description == "" {
		t.Error("library.description is empty")
	}

	got := kb.ContractsFor("hyper_rustls::HttpsConnectorBuilder.new", 0)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(HttpsConnectorBuilder.new, 0) = %d contracts, want 1", len(got))
	}
	if got[0].SourceLibrary != "hyper-rustls" {
		t.Errorf("SourceLibrary = %q, want hyper-rustls", got[0].SourceLibrary)
	}
}

// The keys the parser actually emits must resolve, in both the dot-joined
// call-site spelling and at unknown arity. Authoring the emitted form instead
// of the rewritten one produces a contract that loads without error and joins
// nothing -- that failure is invisible to every other test here.
func TestRustHyperRustlsEmittedKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// Exactly as read off `crypto-finder scan --export-callgraph` on a probe
	// consumer, before the rewrite rustAuthoredKey applies at load time.
	emitted := []string{
		"hyper_rustls.TlsClient.new",
		"hyper_rustls.TlsServer.new",
		"hyper_rustls.HttpsConnector.new",
		"hyper_rustls.HttpsConnector.from",
		"hyper_rustls.HttpsConnector.with_native_roots",
		"hyper_rustls.HttpsConnector.with_webpki_roots",
		"hyper_rustls.HttpsConnectorBuilder.new",
		"hyper_rustls.HttpsConnectorBuilder.with_tls_config",
		"hyper_rustls.HttpsConnectorBuilder.with_native_roots",
		"hyper_rustls.HttpsConnectorBuilder.with_webpki_roots",
		"hyper_rustls.HttpsConnectorBuilder.with_provider_and_native_roots",
		"hyper_rustls.HttpsConnectorBuilder.with_provider_and_webpki_roots",
		"hyper_rustls.HttpsConnectorBuilder.with_platform_verifier",
		"hyper_rustls.HttpsConnectorBuilder.try_with_platform_verifier",
		"hyper_rustls.HttpsConnectorBuilder.with_provider_and_platform_verifier",
		"hyper_rustls.TlsAcceptor.builder",
		"hyper_rustls.AcceptorBuilder.with_single_cert",
		"hyper_rustls.AcceptorBuilder.with_tls_config",
		"hyper_rustls::acceptor.TlsAcceptor.builder",
		"hyper_rustls::acceptor.AcceptorBuilder.with_single_cert",
		"hyper_rustls::acceptor.AcceptorBuilder.with_tls_config",
	}
	for _, m := range emitted {
		if got := kb.ContractsFor(m, -1); len(got) == 0 {
			t.Errorf("ContractsFor(%q, -1): no contract for the emitted key", m)
		}
	}
}

// Three shapes are deliberately NOT contracted, and this pins the reasons
// rather than the omissions.
func TestRustHyperRustlsDoesNotContractUnreachableOrNonCryptoKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	cases := []struct {
		method string
		why    string
	}{
		// ConfigBuilderExt is an extension trait implemented on a RUSTLS type
		// (0.27.9 src/config.rs:59). A probe consumer calling
		// `rustls::ClientConfig::builder().with_native_roots()` emits
		// `rustls.ClientConfig.with_native_roots()` -- attributed to rustls,
		// never to hyper_rustls. A contract under a hyper_rustls key here would
		// never join, and would create the appearance of coverage without any.
		{"hyper_rustls::ConfigBuilderExt.with_native_roots", "receiver is a rustls type"},
		{"hyper_rustls::ConfigBuilderExt.with_webpki_roots", "receiver is a rustls type"},
		{"hyper_rustls.ConfigBuilderExt.with_native_roots", "receiver is a rustls type"},

		// With TlsAcceptor.builder's return type declared, the receiver in
		// `let a = TlsAcceptor::builder(); a.with_single_cert(..)` resolves to
		// AcceptorBuilder, so this key is no longer emitted. It WAS emitted
		// before this file existed, which is exactly why it is pinned.
		{"hyper_rustls::TlsAcceptor.with_single_cert", "receiver resolves to AcceptorBuilder once builder() is contracted"},

		// `acceptor::builder` is a private module (0.24.2 src/acceptor.rs:15),
		// so this spelling is not reachable from any consumer.
		{"hyper_rustls::acceptor::builder::AcceptorBuilder.with_single_cert", "private module"},

		// ALPN selects an application protocol and carries no cryptographic
		// operation. These are the most plausible things for a later author to
		// add, which is the reason to pin them.
		{"hyper_rustls::HttpsConnectorBuilder.enable_http1", "ALPN is not cryptography"},
		{"hyper_rustls::HttpsConnectorBuilder.enable_http2", "ALPN is not cryptography"},
		{"hyper_rustls::HttpsConnectorBuilder.enable_all_versions", "ALPN is not cryptography"},
		{"hyper_rustls::AcceptorBuilder.with_http2_alpn", "ALPN is not cryptography"},
		{"hyper_rustls::AcceptorBuilder.with_alpn_protocols", "ALPN is not cryptography"},

		// Scheme policy and terminal builder steps materialize or scope a
		// decision that a contracted call already made.
		{"hyper_rustls::HttpsConnectorBuilder.https_only", "URL policy, not cryptography"},
		{"hyper_rustls::HttpsConnectorBuilder.https_or_http", "URL policy, not cryptography"},
		{"hyper_rustls::HttpsConnectorBuilder.build", "materializes an earlier decision"},
		{"hyper_rustls::HttpsConnectorBuilder.with_server_name", "a hostname, not a key"},
	}

	for _, tc := range cases {
		for _, a := range []int{0, 1, 2, -1} {
			if got := kb.ContractsFor(tc.method, a); len(got) > 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %q: %s",
					tc.method, a, got[0].SourceLibrary, tc.why)
			}
		}
	}
}
