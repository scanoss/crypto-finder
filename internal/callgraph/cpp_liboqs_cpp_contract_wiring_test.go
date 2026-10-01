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

// The liboqs-cpp contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestLiboqsCPPContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "oqs_cpp.hpp"

bool flows(oqs::KeyEncapsulation& kem, oqs::Signature& sig, const oqs::bytes& msg, const oqs::bytes& ctx) {
    oqs::bytes pk = kem.generate_keypair();
    auto ctss = kem.encap_secret(pk);
    oqs::bytes ss = kem.decap_secret(ctss.first);
    oqs::bytes sk = kem.export_secret_key();
    oqs::bytes spk = sig.generate_keypair();
    oqs::bytes s1 = sig.sign(msg);
    oqs::bytes s2 = sig.sign_with_ctx_str(msg, ctx);
    bool ok = sig.verify(msg, s1, spk);
    ok = ok && sig.verify_with_ctx_str(msg, s2, ctx, spk);
    sig.export_secret_key();
    return ok;
}
`
	if err := os.WriteFile(filepath.Join(dir, "pq.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"oqs::KeyEncapsulation.generate_keypair#0": "operation",
		"oqs::KeyEncapsulation.encap_secret#1":     "operation",
		"oqs::KeyEncapsulation.decap_secret#1":     "operation",
		"oqs::Signature.generate_keypair#0":        "operation",
		"oqs::Signature.sign#1":                    "operation",
		"oqs::Signature.sign_with_ctx_str#2":       "operation",
		"oqs::Signature.verify#3":                  "operation",
		"oqs::Signature.verify_with_ctx_str#4":     "operation",
	}
	negative := map[string]bool{}
	for _, key := range []string{"oqs::KeyEncapsulation.export_secret_key#0", "oqs::Signature.export_secret_key#0"} {
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
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one liboqs-cpp contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "liboqs-cpp" {
					t.Fatalf("contract for %q = role %q library %q, want liboqs-cpp %s", key, got[0].Role, got[0].SourceLibrary, role)
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
