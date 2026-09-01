// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// tokio-rustls carries no cryptography of its own; what is typed is TLS session
// establishment, the boundary a consumer crosses to reach rustls.
//
// Two key shapes, both read off an exported call graph rather than assumed.
// Type methods emit `tokio_rustls.TlsConnector.connect` -- two dots -- which the
// Rust key normalisation rewrites to the authored
// `tokio_rustls::TlsConnector.connect`. The crate-root free functions emit
// `tokio_rustls.connect_async_with_session`, one dot, which rustAuthoredKey
// returns unchanged, so they are authored WITH A DOT. Getting that backwards
// silently produces a contract nothing joins to.
func TestLoadEmbeddedRustIncludesTokioRustlsContracts(t *testing.T) {
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
		{"tokio_rustls::TlsConnector.from", 1, "factory"},
		{"tokio_rustls::TlsConnector.connect", 2, "operation"},
		{"tokio_rustls::TlsConnector.connect_with", 3, "operation"},
		{"tokio_rustls::TlsConnector.early_data", 1, "config"},
		{"tokio_rustls::TlsAcceptor.from", 1, "factory"},
		{"tokio_rustls::TlsAcceptor.accept", 1, "operation"},
		{"tokio_rustls::TlsAcceptor.accept_with", 2, "operation"},
		{"tokio_rustls::LazyConfigAcceptor.new", 2, "factory"},
		{"tokio_rustls.connect_async_with_session", 2, "operation"},
		{"tokio_rustls.accept_async_with_session", 2, "operation"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		if got[0].SourceLibrary != "tokio-rustls" {
			t.Errorf("%s: library = %q, want tokio-rustls", tc.method, got[0].SourceLibrary)
		}
		if got[0].Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, got[0].Role, tc.role)
		}
		if len(got[0].ParameterTypes) != tc.arity {
			t.Errorf("%s: %d parameter_types, want %d", tc.method, len(got[0].ParameterTypes), tc.arity)
		}
	}

	// The dot-joined call-site shape and unknown arity must both resolve.
	for _, m := range []string{
		"tokio_rustls.TlsConnector.connect",
		"tokio_rustls.TlsAcceptor.accept",
		"tokio_rustls.LazyConfigAcceptor.new",
	} {
		if got := kb.ContractsFor(m, -1); len(got) == 0 {
			t.Errorf("ContractsFor(%q, -1): no contract for the emitted key", m)
		}
	}
}

// The pre-0.8 extension-trait methods are deliberately NOT contracted, and this
// pins the reason rather than the omission.
//
// 0.1.0-0.7.2 exposed ClientConfigExt::connect_async and
// ServerConfigExt::accept_async as trait methods implemented on
// Arc<rustls::ClientConfig> / Arc<rustls::ServerConfig> (0.6.0 lib.rs:44-52,
// 64-72). The receiver is a RUSTLS type, so an exported graph attributes
// `client_config.connect_async(domain, tcp)` to the CONSUMER crate, never to
// tokio_rustls -- measured, not assumed. A contract under a tokio_rustls key
// would therefore never join, and writing one would create the appearance of
// coverage without any.
//
// The free functions those traits delegate to are contracted, and they are the
// part of that era a call graph can attribute.
func TestTokioRustlsDoesNotContractUnattributableLegacyTraits(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"tokio_rustls::ClientConfigExt.connect_async",
		"tokio_rustls::ServerConfigExt.accept_async",
		"tokio_rustls.ClientConfigExt.connect_async",
		"tokio_rustls.ServerConfigExt.accept_async",
	} {
		for _, a := range []int{1, 2, -1} {
			if got := kb.ContractsFor(m, a); len(got) > 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %q: the receiver is a rustls type, "+
					"so this key can never be emitted and the contract is unreachable",
					m, a, got[0].SourceLibrary)
			}
		}
	}
}

// ALPN selects an application protocol and carries no cryptographic operation.
// `with_alpn`/TlsConnectorWithAlpn arrived in 0.26.3 (client.rs:103) and is the
// most plausible thing for a later author to add.
func TestTokioRustlsDoesNotContractAlpn(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"tokio_rustls::TlsConnector.with_alpn",
		"tokio_rustls::TlsConnectorWithAlpn.connect",
		"tokio_rustls::TlsConnector.config",
	} {
		for _, a := range []int{1, 2, -1} {
			if got := kb.ContractsFor(m, a); len(got) > 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %q: not a cryptographic operation",
					m, a, got[0].SourceLibrary)
			}
		}
	}
}
