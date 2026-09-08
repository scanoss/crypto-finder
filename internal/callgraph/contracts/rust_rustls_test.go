// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// rustls carries BOTH Rust key shapes in one file, which is why the render below
// is compared as an exact set rather than probed per key.
//
//	rustls::ClientConfig.builder          two dots emitted -> "::" substitution applies
//	rustls::crypto::ring.default_provider one dot emitted  -> authored key IS emitted key
//
// The three ConfigBuilder entries are the fixed-point case. With no contract
// loaded the graph emits `rustls.ClientConfig.with_root_certificates`; once the
// factories carry a canonical_return_type the SAME line emits
// `rustls.ConfigBuilder.with_root_certificates`. The keys below are the
// post-move ones, taken from an export re-run until it stopped changing.
//
// EVERY FIELD THE LOADER POPULATES IS RENDERED, INCLUDING Varargs, Parameters
// AND SourceLibrary. A render that omits a field cannot detect a mutation of it,
// and Varargs specifically is rendered by no other rust exact-set test in this
// directory, so a `varargs: true` mutation survives all of them.
const rustlsLibrary = "rustls"

func renderRustlsContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != rustlsLibrary {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				idx := "nil"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contrib := "nil"
				if p.Contributes != nil {
					contrib = fmt.Sprintf("%s:%s", p.Contributes.Property, p.Contributes.Derivation)
				}
				params = append(params, fmt.Sprintf("%s:%s:%s:%s", idx, p.Name, p.Role, contrib))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/varargs=%t/params=[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				c.Varargs, strings.Join(params, ";"), c.SourceLibrary))
		}
	}
	sort.Strings(got)
	return got
}

var wantRustlsContracts = []string{
	"rustls::ClientConfig.builder#0/factory/rustls::ConfigBuilder<ClientConfig, WantsVerifier>/rustls::ConfigBuilder<ClientConfig, WantsVerifier>/[]/low/varargs=false/params=[]/rustls",
	"rustls::ClientConfig.builder_with_protocol_versions#1/factory/rustls::ConfigBuilder<ClientConfig, WantsVerifier>/rustls::ConfigBuilder<ClientConfig, WantsVerifier>/[rustls::SupportedProtocolVersion]/high/varargs=false/params=[]/rustls",
	"rustls::ClientConfig.builder_with_provider#1/factory/rustls::ConfigBuilder<ClientConfig, WantsVersions>/rustls::ConfigBuilder<ClientConfig, WantsVersions>/[rustls::crypto::CryptoProvider]/high/varargs=false/params=[]/rustls",
	"rustls::ClientConfig.dangerous#0/factory/rustls::DangerousClientConfig/rustls::DangerousClientConfig/[]/high/varargs=false/params=[]/rustls",
	"rustls::ClientConfig.new#0/factory/rustls::ClientConfig/rustls::ClientConfig/[]/high/varargs=false/params=[]/rustls",
	"rustls::ClientConnection.new#2/factory/Result<rustls::ClientConnection, rustls::Error>/Result<rustls::ClientConnection, rustls::Error>/[rustls::ClientConfig,rustls::pki_types::ServerName]/high/varargs=false/params=[]/rustls",
	"rustls::ConfigBuilder.dangerous#0/factory/rustls::DangerousClientConfigBuilder/rustls::DangerousClientConfigBuilder/[]/high/varargs=false/params=[]/rustls",
	"rustls::ConfigBuilder.with_client_auth_cert#2/config/Result<rustls::ClientConfig, rustls::Error>/Result<rustls::ClientConfig, rustls::Error>/[rustls::pki_types::CertificateDer,rustls::pki_types::PrivateKeyDer]/high/varargs=false/params=[]/rustls",
	"rustls::ConfigBuilder.with_custom_certificate_verifier#1/config/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/[rustls::client::danger::ServerCertVerifier]/high/varargs=false/params=[]/rustls",
	"rustls::ConfigBuilder.with_root_certificates#1/config/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/[rustls::RootCertStore]/low/varargs=false/params=[]/rustls",
	"rustls::ConfigBuilder.with_single_cert#2/config/Result<rustls::ServerConfig, rustls::Error>/Result<rustls::ServerConfig, rustls::Error>/[rustls::pki_types::CertificateDer,rustls::pki_types::PrivateKeyDer]/low/varargs=false/params=[]/rustls",
	"rustls::DangerousClientConfig.set_certificate_verifier#1/config/()/()/[rustls::client::danger::ServerCertVerifier]/high/varargs=false/params=[]/rustls",
	"rustls::DangerousClientConfigBuilder.with_custom_certificate_verifier#1/config/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/rustls::ConfigBuilder<ClientConfig, WantsClientCert>/[rustls::client::danger::ServerCertVerifier]/high/varargs=false/params=[]/rustls",
	"rustls::RootCertStore.empty#0/factory/rustls::RootCertStore/rustls::RootCertStore/[]/high/varargs=false/params=[]/rustls",
	"rustls::ServerConfig.builder#0/factory/rustls::ConfigBuilder<ServerConfig, WantsVerifier>/rustls::ConfigBuilder<ServerConfig, WantsVerifier>/[]/low/varargs=false/params=[]/rustls",
	"rustls::ServerConfig.builder_with_protocol_versions#1/factory/rustls::ConfigBuilder<ServerConfig, WantsVerifier>/rustls::ConfigBuilder<ServerConfig, WantsVerifier>/[rustls::SupportedProtocolVersion]/high/varargs=false/params=[]/rustls",
	"rustls::ServerConfig.builder_with_provider#1/factory/rustls::ConfigBuilder<ServerConfig, WantsVersions>/rustls::ConfigBuilder<ServerConfig, WantsVersions>/[rustls::crypto::CryptoProvider]/high/varargs=false/params=[]/rustls",
	"rustls::ServerConfig.new#0/factory/rustls::ServerConfig/rustls::ServerConfig/[]/high/varargs=false/params=[]/rustls",
	"rustls::ServerConfig.new#1/factory/rustls::ServerConfig/rustls::ServerConfig/[rustls::ClientCertVerifier]/high/varargs=false/params=[]/rustls",
	"rustls::ServerConnection.new#1/factory/Result<rustls::ServerConnection, rustls::Error>/Result<rustls::ServerConnection, rustls::Error>/[rustls::ServerConfig]/high/varargs=false/params=[]/rustls",
	"rustls::crypto::aws_lc_rs.default_provider#0/factory/rustls::crypto::CryptoProvider/rustls::crypto::CryptoProvider/[]/high/varargs=false/params=[]/rustls",
	"rustls::crypto::ring.default_provider#0/factory/rustls::crypto::CryptoProvider/rustls::crypto::CryptoProvider/[]/high/varargs=false/params=[]/rustls",
}

func TestLoadEmbeddedRustIncludesRustlsContracts(t *testing.T) {
	got := renderRustlsContracts(t)

	// Vacuity guard. An exact-set comparison over two empty slices passes, and
	// that is how a family ships a contract that never loaded.
	if len(got) == 0 {
		t.Fatal("no rustls contracts loaded — the comparison below would pass vacuously")
	}
	if len(wantRustlsContracts) != 22 {
		t.Fatalf("expected 22 pinned rustls contracts, the literal holds %d", len(wantRustlsContracts))
	}

	if len(got) != len(wantRustlsContracts) {
		t.Errorf("contract count: got %d, want %d", len(got), len(wantRustlsContracts))
	}
	for i := 0; i < len(got) && i < len(wantRustlsContracts); i++ {
		if got[i] != wantRustlsContracts[i] {
			t.Errorf("contract[%d]:\n  got  %s\n  want %s", i, got[i], wantRustlsContracts[i])
		}
	}
	if len(got) > len(wantRustlsContracts) {
		t.Errorf("unexpected extra contracts: %v", got[len(wantRustlsContracts):])
	} else if len(wantRustlsContracts) > len(got) {
		t.Errorf("missing contracts: %v", wantRustlsContracts[len(got):])
	}
}

// rustls' keys are NOT uniform, and this pins both shapes so that a later
// mechanical "fix" applying one rule to the whole file is caught.
func TestRustlsKeyShapesAreNotUniform(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// A crate-root TYPE METHOD: the emitted key has two dots, so the authored
	// key carries "::" before the type.
	if got := kb.ContractsFor("rustls::ClientConfig.builder", 0); len(got) == 0 {
		t.Error("rustls::ClientConfig.builder#0 did not resolve — the type-method key shape is wrong")
	}
	// A MODULE-SCOPED FREE FUNCTION: the emitted key has ONE dot, so the
	// authored key is the emitted key and the substitution must NOT be applied.
	if got := kb.ContractsFor("rustls::crypto::ring.default_provider", 0); len(got) == 0 {
		t.Error("rustls::crypto::ring.default_provider#0 did not resolve — the free-function key shape is wrong")
	}
	// THE ASSERTION THAT ACTUALLY CATCHES A MIS-AUTHORED ONE-DOT KEY IS ON THE
	// STORED METHOD, NOT ON A LOOKUP. `rustAuthoredKey` is applied to the QUERY
	// at lookup time, so querying the mechanically-substituted spelling
	// `rustls::crypto.ring.default_provider` (two dots) normalises straight back
	// onto the correct key and resolves. A negative lookup therefore proves
	// nothing here — measured, after a first draft of this test asserted it and
	// failed. What a wrong authoring WOULD break is the reverse direction: the
	// emitted one-dot key would find nothing. So pin the stored spelling.
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != rustlsLibrary || !strings.HasSuffix(c.Method, ".default_provider") {
				continue
			}
			if strings.Count(c.Method, ".") != 1 {
				t.Errorf("%s is stored with %d dots; a module-scoped free function must be authored "+
					"with the module path in \"::\" form and exactly one dot, or the emitted key will not join",
					c.Method, strings.Count(c.Method, "."))
			}
		}
	}
}

// The fixed-point result, asserted rather than only described in the header.
func TestRustlsBuilderMethodsAreKeyedOnConfigBuilder(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []struct {
		method string
		arity  int
	}{
		{"rustls::ConfigBuilder.with_root_certificates", 1},
		{"rustls::ConfigBuilder.with_client_auth_cert", 2},
		{"rustls::ConfigBuilder.with_custom_certificate_verifier", 1},
	} {
		if got := kb.ContractsFor(m.method, m.arity); len(got) == 0 {
			t.Errorf("%s#%d did not resolve", m.method, m.arity)
		}
	}
	// The PRE-MOVE keys, from the export taken before the factories were
	// contracted. If one of these resolves, the file has been re-keyed backwards.
	for _, m := range []struct {
		method string
		arity  int
	}{
		{"rustls::ClientConfig.with_root_certificates", 1},
		{"rustls::ClientConfig.with_client_auth_cert", 2},
		{"rustls::ClientConfig.with_custom_certificate_verifier", 1},
	} {
		for _, c := range kb.ContractsFor(m.method, m.arity) {
			if c.SourceLibrary == rustlsLibrary {
				t.Errorf("%s#%d resolved to rustls: this is the pre-fixed-point key and joins nothing", m.method, m.arity)
			}
		}
	}
}

// `with_single_cert` resolves only for a receiver that reaches the call
// DIRECTLY from a contracted factory. A receiver arriving through an
// intermediate builder call is still attributed to the consumer crate, and that
// residual is recorded rather than papered over: the contract cannot fix it,
// because there is no rustls-keyed identity to join to.
//
// The first draft of this family OMITTED this entry entirely, on an export taken
// before the factories were contracted. Pinned here so the entry cannot be
// dropped again on that reading.
func TestRustlsContractsWithSingleCertOnTheBuilder(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	got := kb.ContractsFor("rustls::ConfigBuilder.with_single_cert", 2)
	if len(got) == 0 {
		t.Fatal("rustls::ConfigBuilder.with_single_cert#2 did not resolve")
	}
	for _, c := range got {
		if c.SourceLibrary != rustlsLibrary {
			continue
		}
		// The return is side-dependent before 0.22.0 (client and server builders
		// both had the method, returning different config types), so it must
		// carry `low` rather than claim one era's type as universal.
		if c.Return.Confidence != "low" {
			t.Errorf("with_single_cert confidence = %q, want low: the return is "+
				"Result<ClientConfig, Error> on the pre-0.22 client builder and "+
				"Result<ServerConfig, Error> on the server builder",
				c.Return.Confidence)
		}
	}
	// The pre-fixed-point spellings must not resolve to rustls.
	for _, key := range []string{
		"rustls::ServerConfig.with_single_cert",
		"rustls::ClientConfig.with_single_cert",
	} {
		for _, c := range kb.ContractsFor(key, 2) {
			if c.SourceLibrary == rustlsLibrary {
				t.Errorf("%s#2 is keyed on the config type; the export emits ConfigBuilder", key)
			}
		}
	}
}

// rustls and its four merged neighbors must stay separate: none of their keys
// may be claimed by this library, and none of rustls' by them.
func TestRustlsAndItsNeighboursStaySeparate(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	neighbors := map[string]bool{
		"rustls-webpki": true, "rustls-native-certs": true,
		"rustls-native-certs-0.5": true, "rustls-native-certs-0.8": true,
		"hyper-rustls": true, "tokio-rustls": true, "webpki": true,
	}
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary == rustlsLibrary && !strings.HasPrefix(c.Method, "rustls::") {
				t.Errorf("rustls contract %s#%d does not start with the crate segment", c.Method, c.Arity)
			}
			if neighbors[c.SourceLibrary] && strings.HasPrefix(c.Method, "rustls::") {
				t.Errorf("%s claims the rustls key %s#%d", c.SourceLibrary, c.Method, c.Arity)
			}
		}
	}
}

// THE `library:` BLOCK IS PARSED AND THEN NEVER CONSULTED AT LOOKUP, so a wrong
// coordinate or a wrong version_range is a silent false statement rather than a
// caught error. Two mutations of this file survived every other assertion in
// this package until this test existed: changing `coordinates` to
// `rustls-wrong`, and widening `version_range` to a range the crate has never
// published. Both are claims a reader will trust.
func TestRustlsLibraryMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("rust", "rustls.yaml"))
	if err != nil {
		t.Fatalf("read rustls.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rustls.yaml): %v", err)
	}
	if kb.SchemaVersion != "2" {
		t.Errorf("schema_version = %q, want 2", kb.SchemaVersion)
	}
	if kb.Ecosystem != "rust" {
		t.Errorf("ecosystem = %q, want rust", kb.Ecosystem)
	}
	if kb.Library == nil {
		t.Fatal("library block is nil")
	}
	if kb.Library.Name != rustlsLibrary {
		t.Errorf("library.name = %q, want %q", kb.Library.Name, rustlsLibrary)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "rustls"; got != want {
		t.Errorf("coordinates: got %q, want %q", got, want)
	}
	// The declared range covers every row the matrix lists for pkg:cargo/rustls:
	// 0.1.0 is the oldest published release and 0.23.41 the newest stable, with
	// 0.24.0-dev.0 the only row above it.
	if got, want := kb.Library.VersionRange, ">=0.1.0,<0.24.0"; got != want {
		t.Errorf("version_range: got %q, want %q", got, want)
	}
	if kb.Library.Description == "" {
		t.Error("description is empty")
	}
}
