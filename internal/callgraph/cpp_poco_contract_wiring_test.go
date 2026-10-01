// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The poco contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestPocoContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "Poco/JWT/Signer.h"
#include "Poco/Net/Context.h"

void flows(Poco::JWT::Signer& signer, Poco::Net::Context::Ptr& ctx, Poco::Net::Context& plain, int x) {
    signer.setAlgorithms(x);
    signer.addAlgorithm(x);
    signer.addAllAlgorithms();
    signer.setHMACKey(x);
    signer.setRSAKey(x);
    signer.setECKey(x);
    signer.sign(x, x);
    signer.verify(x);
    signer.tryVerify(x, x);
    ctx->useCertificate(x);
    ctx->addChainCertificate(x);
    ctx->addCertificateAuthority(x);
    ctx->usePrivateKey(x);
    ctx->enableSessionCache();
    ctx->enableSessionCache(x);
    ctx->enableSessionCache(x, x);
    ctx->enableExtendedCertificateVerification();
    ctx->enableExtendedCertificateVerification(x);
    ctx->disableStatelessSessionResumption();
    ctx->disableProtocols(x);
    ctx->requireMinimumProtocol(x);
    ctx->preferServerCiphers();
    ctx->setInvalidCertificateHandler(x);
    ctx->setSecurityLevel(x);
    plain.useCertificate(x);
    plain.addChainCertificate(x);
    plain.addCertificateAuthority(x);
    plain.usePrivateKey(x);
    plain.enableSessionCache();
    plain.enableSessionCache(x);
    plain.enableSessionCache(x, x);
    plain.enableExtendedCertificateVerification();
    plain.enableExtendedCertificateVerification(x);
    plain.disableStatelessSessionResumption();
    plain.disableProtocols(x);
    plain.requireMinimumProtocol(x);
    plain.preferServerCiphers();
    plain.setInvalidCertificateHandler(x);
    plain.setSecurityLevel(x);
    signer.getAlgorithms();
    signer.encode(x);
    ctx->flushSessionCache();
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"Poco::JWT::Signer.setAlgorithms#1":                               "config",
		"Poco::JWT::Signer.addAlgorithm#1":                                "config",
		"Poco::JWT::Signer.addAllAlgorithms#0":                            "config",
		"Poco::JWT::Signer.setHMACKey#1":                                  "config",
		"Poco::JWT::Signer.setRSAKey#1":                                   "config",
		"Poco::JWT::Signer.setECKey#1":                                    "config",
		"Poco::JWT::Signer.sign#2":                                        "operation",
		"Poco::JWT::Signer.verify#1":                                      "operation",
		"Poco::JWT::Signer.tryVerify#2":                                   "operation",
		"Poco::Net::Context::Ptr.useCertificate#1":                        "config",
		"Poco::Net::Context::Ptr.addChainCertificate#1":                   "config",
		"Poco::Net::Context::Ptr.addCertificateAuthority#1":               "config",
		"Poco::Net::Context::Ptr.usePrivateKey#1":                         "config",
		"Poco::Net::Context::Ptr.enableSessionCache#0":                    "config",
		"Poco::Net::Context::Ptr.enableSessionCache#1":                    "config",
		"Poco::Net::Context::Ptr.enableSessionCache#2":                    "config",
		"Poco::Net::Context::Ptr.enableExtendedCertificateVerification#0": "config",
		"Poco::Net::Context::Ptr.enableExtendedCertificateVerification#1": "config",
		"Poco::Net::Context::Ptr.disableStatelessSessionResumption#0":     "config",
		"Poco::Net::Context::Ptr.disableProtocols#1":                      "config",
		"Poco::Net::Context::Ptr.requireMinimumProtocol#1":                "config",
		"Poco::Net::Context::Ptr.preferServerCiphers#0":                   "config",
		"Poco::Net::Context::Ptr.setInvalidCertificateHandler#1":          "config",
		"Poco::Net::Context::Ptr.setSecurityLevel#1":                      "config",
		"Poco::Net::Context.useCertificate#1":                             "config",
		"Poco::Net::Context.addChainCertificate#1":                        "config",
		"Poco::Net::Context.addCertificateAuthority#1":                    "config",
		"Poco::Net::Context.usePrivateKey#1":                              "config",
		"Poco::Net::Context.enableSessionCache#0":                         "config",
		"Poco::Net::Context.enableSessionCache#1":                         "config",
		"Poco::Net::Context.enableSessionCache#2":                         "config",
		"Poco::Net::Context.enableExtendedCertificateVerification#0":      "config",
		"Poco::Net::Context.enableExtendedCertificateVerification#1":      "config",
		"Poco::Net::Context.disableStatelessSessionResumption#0":          "config",
		"Poco::Net::Context.disableProtocols#1":                           "config",
		"Poco::Net::Context.requireMinimumProtocol#1":                     "config",
		"Poco::Net::Context.preferServerCiphers#0":                        "config",
		"Poco::Net::Context.setInvalidCertificateHandler#1":               "config",
		"Poco::Net::Context.setSecurityLevel#1":                           "config",
	}
	negative := map[string]bool{}
	for _, key := range []string{"Poco::JWT::Signer.getAlgorithms#0", "Poco::JWT::Signer.encode#1", "Poco::Net::Context::Ptr.flushSessionCache#0"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one poco contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "poco" {
					t.Fatalf("contract for %q = role %q library %q, want poco %s", key, got[0].Role, got[0].SourceLibrary, role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}

// Signer::sign names the algorithm it signs with as its second argument.
func TestPocoSignerSignAlgorithmIsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}
	got := kb.ContractsFor("Poco::JWT::Signer.sign", 2)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(Poco::JWT::Signer.sign, 2) = %d, want exactly one", len(got))
	}
	params := got[0].Parameters
	if len(params) != 1 || params[0].Index == nil || *params[0].Index != 1 ||
		params[0].Role != "operation-determining" || params[0].Contributes == nil ||
		params[0].Contributes.Property != "algorithm" {
		t.Fatalf("parameters = %+v, want index 1 operation-determining algorithm", params)
	}
}
