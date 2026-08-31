// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// x509-parser's parse entry points are free functions at the crate root, so the
// emitted call-site FQN carries ONE dot and the Rust key normalisation returns
// it unchanged. These are the keys observed in an exported call graph, verbatim:
// authoring them in the method shape (`x509_parser::parse_x509_certificate`)
// would load fine, pass a lookup on the authored spelling, and still export
// "parse_x509_certificate(?)" -- indistinguishable from having no contract.
func TestLoadEmbeddedRustIncludesX509ParserContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
	}{
		// 0.9.2 and later.
		{"x509_parser.parse_x509_certificate", 1},
		{"x509_parser.parse_x509_crl", 1},
		{"x509_parser::pem.parse_x509_pem", 1},
		// 0.6.5-era names, kept as aliases of the same functions.
		{"x509_parser.parse_x509_der", 1},
		{"x509_parser.parse_crl_der", 1},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		c := got[0]
		if c.SourceLibrary != "x509-parser" {
			t.Errorf("%s: library = %q, want x509-parser", tc.method, c.SourceLibrary)
		}
		if c.Role != "factory" {
			t.Errorf("%s: role = %q, want factory", tc.method, c.Role)
		}
		if len(c.ParameterTypes) != 1 || c.ParameterTypes[0] != "&[u8]" {
			t.Errorf("%s: parameter_types = %v, want [\"&[u8]\"]", tc.method, c.ParameterTypes)
		}
	}

	// Resolution must also work when the caller cannot derive an arity.
	if got := kb.ContractsFor("x509_parser.parse_x509_certificate", -1); len(got) == 0 {
		t.Error("ContractsFor(parse_x509_certificate, -1): no contract at unknown arity")
	}
}

// verify_signature is deliberately NOT contracted. It is gated behind a
// non-default feature (`verify = ["ring"]`, `verify-aws = ["aws-lc-rs"]`) and
// the cryptography is performed by ring or aws-lc-rs, which carry their own
// contracts. Typing it here would route another crate's work through this one.
func TestX509ParserDoesNotContractVerification(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, m := range []string{
		"x509_parser.verify_signature",
		"x509_parser::certificate::X509Certificate.verify_signature",
		"x509_parser::revocation_list::CertificateRevocationList.verify_signature",
	} {
		for _, a := range []int{0, 1, -1} {
			if got := kb.ContractsFor(m, a); len(got) > 0 {
				t.Errorf("ContractsFor(%q, %d) resolved to %q: verification belongs to ring/aws-lc-rs",
					m, a, got[0].SourceLibrary)
			}
		}
	}
}
