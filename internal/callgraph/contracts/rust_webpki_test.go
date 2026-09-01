// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// webpki's verification methods live on EndEntityCert, so the emitted call-site
// FQN is `webpki.EndEntityCert.<method>` -- two dots, which the Rust key
// normalisation rewrites to the authored `webpki::EndEntityCert.<method>`.
// These are the keys read off an exported call graph.
func TestLoadEmbeddedRustIncludesWebpkiContracts(t *testing.T) {
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
		{"webpki::EndEntityCert.try_from", 1, "factory"},
		{"webpki::EndEntityCert.verify_is_valid_tls_server_cert", 4, "operation"},
		{"webpki::EndEntityCert.verify_is_valid_tls_server_cert_ext", 4, "operation"},
		{"webpki::EndEntityCert.verify_is_valid_tls_client_cert", 4, "operation"},
		{"webpki::EndEntityCert.verify_is_valid_tls_client_cert_ext", 4, "operation"},
		{"webpki::EndEntityCert.verify_signature", 3, "operation"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		if got[0].SourceLibrary != "webpki" {
			t.Errorf("%s: library = %q, want webpki", tc.method, got[0].SourceLibrary)
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
		"webpki.EndEntityCert.verify_is_valid_tls_server_cert",
		"webpki.EndEntityCert.verify_signature",
	} {
		if got := kb.ContractsFor(m, -1); len(got) == 0 {
			t.Errorf("ContractsFor(%q, -1): no contract for the emitted key", m)
		}
	}
}

// The name-matching API is deliberately not contracted. Five entry points begin
// with `verify_` and carry no cryptography -- they compare strings against the
// certificate's SANs. `verify_is_valid_for_dns_name` reads as a verification and
// delegates straight to `name::verify_cert_dns_name` (end_entity.rs:179).
// Typing them would route hostname matching through the crypto call graph.
func TestWebpkiDoesNotContractNameMatching(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"webpki::EndEntityCert.verify_is_valid_for_dns_name",
		"webpki::EndEntityCert.verify_is_valid_for_at_least_one_dns_name",
		"webpki::DnsNameRef.try_from_ascii",
		"webpki::DnsNameRef.try_from_ascii_str",
		"webpki.verify_cert_dns_name",
	} {
		for _, a := range []int{0, 1, 2, -1} {
			if got := kb.ContractsFor(m, a); len(got) > 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %q: this is hostname matching, not cryptography",
					m, a, got[0].SourceLibrary)
			}
		}
	}
}
