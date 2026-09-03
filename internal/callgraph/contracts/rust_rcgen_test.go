// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// rcgen `pub use`-exports every type from the crate root (0.14.8 lib.rs:44-65),
// so the graph emits `rcgen.KeyPair.generate` with no module segment and the KB
// file authors `rcgen::KeyPair.generate` — rustAuthoredKey moves the
// second-to-last dot when the lookup runs. The free function is the exception:
// `rcgen.generate_simple_self_signed` carries a single dot, rustAuthoredKey
// returns such a key unchanged, and ContractsFor tries the raw key first
// (contracts.go:204), so it is authored in the dot form.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does.
func renderRcgenContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "rcgen" {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence))
		}
	}
	sort.Strings(got)
	return got
}

var wantRcgenContracts = []string{
	"rcgen.generate_simple_self_signed#1/factory/rcgen::CertifiedKey//[impl Into<alloc::vec::Vec<alloc::string::String>>]/high",
	"rcgen::Certificate.der#0/output/rustls_pki_types::CertificateDer//[]/high",
	"rcgen::Certificate.from_params#1/factory/rcgen::Certificate//[rcgen::CertificateParams]/high",
	"rcgen::Certificate.pem#0/output/alloc::string::String//[]/high",
	"rcgen::Certificate.serialize_der#0/output/alloc::vec::Vec/core::result::Result<alloc::vec::Vec<u8>, rcgen::Error>/[]/high",
	"rcgen::Certificate.serialize_der_with_signer#1/operation/alloc::vec::Vec/core::result::Result<alloc::vec::Vec<u8>, rcgen::Error>/[&rcgen::Certificate]/high",
	"rcgen::Certificate.serialize_pem#0/output/alloc::string::String/core::result::Result<alloc::string::String, rcgen::Error>/[]/high",
	"rcgen::Certificate.serialize_pem_with_signer#1/operation/alloc::string::String/core::result::Result<alloc::string::String, rcgen::Error>/[&rcgen::Certificate]/high",
	"rcgen::Certificate.serialize_request_der#0/operation/alloc::vec::Vec/core::result::Result<alloc::vec::Vec<u8>, rcgen::Error>/[]/high",
	"rcgen::Certificate.serialize_request_pem#0/operation/alloc::string::String/core::result::Result<alloc::string::String, rcgen::Error>/[]/high",
	"rcgen::CertificateParams.from_ca_cert_der#1/factory/rcgen::CertificateParams/core::result::Result<rcgen::CertificateParams, rcgen::Error>/[&rustls_pki_types::CertificateDer]/high",
	"rcgen::CertificateParams.from_ca_cert_der#2/factory/rcgen::CertificateParams/core::result::Result<rcgen::CertificateParams, rcgen::Error>/[&[u8],rcgen::KeyPair]/high",
	"rcgen::CertificateParams.from_ca_cert_pem#1/factory/rcgen::CertificateParams/core::result::Result<rcgen::CertificateParams, rcgen::Error>/[&str]/high",
	"rcgen::CertificateParams.from_ca_cert_pem#2/factory/rcgen::CertificateParams/core::result::Result<rcgen::CertificateParams, rcgen::Error>/[&str,rcgen::KeyPair]/high",
	"rcgen::CertificateParams.self_signed#1/operation/rcgen::Certificate/core::result::Result<rcgen::Certificate, rcgen::Error>/[&impl rcgen::SigningKey]/high",
	"rcgen::CertificateParams.serialize_request#1/operation/rcgen::CertificateSigningRequest/core::result::Result<rcgen::CertificateSigningRequest, rcgen::Error>/[]/high",
	"rcgen::CertificateParams.serialize_request_with_attributes#2/operation/rcgen::CertificateSigningRequest/core::result::Result<rcgen::CertificateSigningRequest, rcgen::Error>/[]/high",
	"rcgen::CertificateParams.signed_by#2/operation/rcgen::Certificate/core::result::Result<rcgen::Certificate, rcgen::Error>/[&impl rcgen::PublicKeyData,&rcgen::Issuer<impl rcgen::SigningKey>]/high",
	"rcgen::CertificateParams.signed_by#3/operation/rcgen::Certificate/core::result::Result<rcgen::Certificate, rcgen::Error>/[&impl rcgen::PublicKeyData,&rcgen::Certificate,&rcgen::KeyPair]/high",
	"rcgen::CertificateRevocationList.der#0/output/rustls_pki_types::CertificateRevocationListDer//[]/high",
	"rcgen::CertificateRevocationList.from_params#1/factory/rcgen::CertificateRevocationList/core::result::Result<rcgen::CertificateRevocationList, rcgen::Error>/[rcgen::CertificateRevocationListParams]/high",
	"rcgen::CertificateRevocationList.pem#0/output/alloc::string::String/core::result::Result<alloc::string::String, rcgen::Error>/[]/high",
	"rcgen::CertificateRevocationListParams.signed_by#1/operation/rcgen::CertificateRevocationList/core::result::Result<rcgen::CertificateRevocationList, rcgen::Error>/[&rcgen::Issuer<impl rcgen::SigningKey>]/high",
	"rcgen::CertificateRevocationListParams.signed_by#2/operation/rcgen::CertificateRevocationList/core::result::Result<rcgen::CertificateRevocationList, rcgen::Error>/[&rcgen::Certificate,&rcgen::KeyPair]/high",
	"rcgen::CertificateSigningRequest.der#0/output/rustls_pki_types::CertificateSigningRequestDer//[]/high",
	"rcgen::CertificateSigningRequest.from_der#1/factory/rcgen::CertificateSigningRequest/core::result::Result<rcgen::CertificateSigningRequest, rcgen::Error>/[&[u8]]/high",
	"rcgen::CertificateSigningRequest.from_pem#1/factory/rcgen::CertificateSigningRequest/core::result::Result<rcgen::CertificateSigningRequest, rcgen::Error>/[&str]/high",
	"rcgen::CertificateSigningRequest.pem#0/output/alloc::string::String/core::result::Result<alloc::string::String, rcgen::Error>/[]/high",
	"rcgen::CertificateSigningRequestParams.from_der#1/factory/rcgen::CertificateSigningRequestParams/core::result::Result<rcgen::CertificateSigningRequestParams, rcgen::Error>/[&rustls_pki_types::CertificateSigningRequestDer]/high",
	"rcgen::CertificateSigningRequestParams.from_pem#1/factory/rcgen::CertificateSigningRequestParams/core::result::Result<rcgen::CertificateSigningRequestParams, rcgen::Error>/[&str]/high",
	"rcgen::CertificateSigningRequestParams.signed_by#1/operation/rcgen::Certificate/core::result::Result<rcgen::Certificate, rcgen::Error>/[&rcgen::Issuer<impl rcgen::SigningKey>]/high",
	"rcgen::CertificateSigningRequestParams.signed_by#2/operation/rcgen::Certificate/core::result::Result<rcgen::Certificate, rcgen::Error>/[&rcgen::Certificate,&rcgen::KeyPair]/high",
	"rcgen::CertifiedIssuer.self_signed#2/operation/rcgen::CertifiedIssuer/core::result::Result<rcgen::CertifiedIssuer<impl rcgen::SigningKey>, rcgen::Error>/[rcgen::CertificateParams,impl rcgen::SigningKey]/high",
	"rcgen::CertifiedIssuer.signed_by#3/operation/rcgen::CertifiedIssuer/core::result::Result<rcgen::CertifiedIssuer<impl rcgen::SigningKey>, rcgen::Error>/[rcgen::CertificateParams,impl rcgen::SigningKey,&rcgen::Issuer<impl rcgen::SigningKey>]/high",
	"rcgen::Issuer.from_ca_cert_der#2/factory/rcgen::Issuer/core::result::Result<rcgen::Issuer<impl rcgen::SigningKey>, rcgen::Error>/[&rustls_pki_types::CertificateDer,impl rcgen::SigningKey]/high",
	"rcgen::Issuer.from_ca_cert_pem#2/factory/rcgen::Issuer/core::result::Result<rcgen::Issuer<impl rcgen::SigningKey>, rcgen::Error>/[&str,impl rcgen::SigningKey]/high",
	"rcgen::Issuer.from_params#2/factory/rcgen::Issuer//[&rcgen::CertificateParams,impl rcgen::SigningKey]/high",
	"rcgen::Issuer.new#2/factory/rcgen::Issuer//[rcgen::CertificateParams,impl rcgen::SigningKey]/high",
	"rcgen::KeyPair.from_der#1/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&[u8]]/high",
	"rcgen::KeyPair.from_der_and_sign_algo#2/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&[u8],&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.from_pem#1/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&str]/high",
	"rcgen::KeyPair.from_pem_and_sign_algo#2/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&str,&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.from_pkcs8_der_and_sign_algo#2/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&[u8],&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.from_pkcs8_pem_and_sign_algo#2/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&str,&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.from_remote#1/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[alloc::boxed::Box<dyn rcgen::RemoteKeyPair + Send + Sync>]/high",
	"rcgen::KeyPair.generate#0/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[]/high",
	"rcgen::KeyPair.generate#1/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.generate_for#1/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&'static rcgen::SignatureAlgorithm]/high",
	"rcgen::KeyPair.generate_rsa_for#2/factory/rcgen::KeyPair/core::result::Result<rcgen::KeyPair, rcgen::Error>/[&'static rcgen::SignatureAlgorithm,rcgen::RsaKeySize]/high",
	"rcgen::KeyPair.public_key_der#0/output/alloc::vec::Vec/alloc::vec::Vec<u8>/[]/high",
	"rcgen::KeyPair.public_key_pem#0/output/alloc::string::String//[]/high",
	"rcgen::KeyPair.serialize_der#0/output/alloc::vec::Vec/alloc::vec::Vec<u8>/[]/high",
	"rcgen::KeyPair.serialize_pem#0/output/alloc::string::String//[]/high",
	"rcgen::KeyPair.serialized_der#0/output/&[u8]//[]/high",
}

func TestLoadEmbeddedRustRcgenContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderRcgenContracts(t)
	want := append([]string(nil), wantRcgenContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("rcgen contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected rcgen contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing rcgen contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Every key
// below was read off an exported call graph of a probe consumer that calls the
// crate the way its own documentation shows.
func TestRcgenEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// key -> arity, as read off the exported call graph of the probe consumer.
	emitted := []struct {
		method string
		arity  int
	}{
		{"rcgen.KeyPair.generate", 0},
		{"rcgen.KeyPair.generate", 1},
		{"rcgen.KeyPair.generate_for", 1},
		{"rcgen.KeyPair.generate_rsa_for", 2},
		{"rcgen.KeyPair.from_pem", 1},
		{"rcgen.KeyPair.from_der", 1},
		{"rcgen.KeyPair.from_pem_and_sign_algo", 2},
		{"rcgen.KeyPair.from_der_and_sign_algo", 2},
		{"rcgen.KeyPair.from_pkcs8_pem_and_sign_algo", 2},
		{"rcgen.KeyPair.from_pkcs8_der_and_sign_algo", 2},
		{"rcgen.generate_simple_self_signed", 1},
		{"rcgen.Certificate.from_params", 1},
		{"rcgen.Certificate.serialize_der_with_signer", 1},
		{"rcgen.Certificate.serialize_pem_with_signer", 1},
		{"rcgen.Certificate.serialize_request_der", 0},
		{"rcgen.Certificate.serialize_request_pem", 0},
		{"rcgen.CertificateParams.self_signed", 1},
		{"rcgen.CertificateParams.signed_by", 2},
		{"rcgen.CertificateParams.signed_by", 3},
		{"rcgen.CertificateParams.serialize_request", 1},
		{"rcgen.CertificateParams.serialize_request_with_attributes", 2},
		{"rcgen.CertificateParams.from_ca_cert_pem", 1},
		{"rcgen.CertificateParams.from_ca_cert_der", 1},
		{"rcgen.Issuer.from_ca_cert_pem", 2},
		{"rcgen.Issuer.from_ca_cert_der", 2},
		{"rcgen.CertificateSigningRequest.from_pem", 1},
		{"rcgen.CertificateSigningRequest.from_der", 1},
		{"rcgen.CertificateSigningRequestParams.from_pem", 1},
		{"rcgen.CertificateSigningRequestParams.from_der", 1},
		{"rcgen.CertificateSigningRequestParams.signed_by", 1},
		{"rcgen.CertificateRevocationList.from_params", 1},
		{"rcgen.CertificateRevocationListParams.signed_by", 1},
		{"rcgen.CertifiedIssuer.self_signed", 2},
		{"rcgen.CertifiedIssuer.signed_by", 3},
	}
	for _, e := range emitted {
		got := kb.ContractsFor(e.method, e.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", e.method, e.arity)
			continue
		}
		if got[0].SourceLibrary != "rcgen" {
			t.Errorf("%s: library = %q, want rcgen", e.method, got[0].SourceLibrary)
		}
	}
}

// The eras are keyed apart by ARITY, and neither may swallow the other. rcgen
// moved its signing verb twice: `signed_by` on CertificateParams takes the
// issuer certificate AND its key in 0.13.x (0.13.2 certificate.rs:150) and an
// `Issuer<S>` that already holds the key from 0.14.0 (0.14.8 certificate.rs:140).
// `KeyPair::generate` did the same in the other direction: the algorithm is its
// argument through 0.12.1 (key_pair.rs:181) and it takes none from 0.13.0
// (key_pair.rs:77).
func TestRcgenErasAreKeyedApartByArity(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	gen0 := kb.ContractsFor("rcgen::KeyPair.generate", 0)
	gen1 := kb.ContractsFor("rcgen::KeyPair.generate", 1)
	if len(gen0) != 1 || len(gen1) != 1 {
		t.Fatalf("rcgen::KeyPair.generate: arity 0 -> %d contracts, arity 1 -> %d, want 1 and 1",
			len(gen0), len(gen1))
	}
	if len(gen0[0].ParameterTypes) != 0 {
		t.Errorf("arity 0 generate must take no parameters, got %v", gen0[0].ParameterTypes)
	}
	if len(gen1[0].ParameterTypes) != 1 || !strings.Contains(gen1[0].ParameterTypes[0], "SignatureAlgorithm") {
		t.Errorf("arity 1 generate must take the signature algorithm, got %v", gen1[0].ParameterTypes)
	}

	by2 := kb.ContractsFor("rcgen::CertificateParams.signed_by", 2)
	by3 := kb.ContractsFor("rcgen::CertificateParams.signed_by", 3)
	if len(by2) != 1 || len(by3) != 1 {
		t.Fatalf("rcgen::CertificateParams.signed_by: arity 2 -> %d, arity 3 -> %d, want 1 and 1",
			len(by2), len(by3))
	}
	if !strings.Contains(strings.Join(by2[0].ParameterTypes, ","), "Issuer") {
		t.Errorf("the 0.14 arity-2 signed_by must take an Issuer, got %v", by2[0].ParameterTypes)
	}
	if !strings.Contains(strings.Join(by3[0].ParameterTypes, ","), "KeyPair") {
		t.Errorf("the 0.13 arity-3 signed_by must take the issuer KeyPair, got %v", by3[0].ParameterTypes)
	}
}

// Encoding is not a cryptographic operation. `serialize_der` means opposite
// things on the two receivers rcgen publishes — on a Certificate in 0.1.0-0.12.1
// it SIGNS (0.12.1 lib.rs:1507), on a KeyPair it only encodes bytes that already
// exist (0.12.1 key_pair.rs:285) — so no RULE claims either spelling and both
// carry `role: output` here. This pins that decision so a later author neither
// promotes them to operations nor deletes them as redundant.
func TestRcgenEncodingMethodsAreOutputRole(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, m := range []string{
		"rcgen::Certificate.serialize_der",
		"rcgen::Certificate.serialize_pem",
		"rcgen::Certificate.der",
		"rcgen::Certificate.pem",
		"rcgen::KeyPair.serialize_der",
		"rcgen::KeyPair.serialize_pem",
		"rcgen::KeyPair.serialized_der",
	} {
		got := kb.ContractsFor(m, 0)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, 0): got %d contracts, want 1", m, len(got))
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s: role = %q, want output; moving bytes is not a cryptographic operation", m, got[0].Role)
		}
	}
}
