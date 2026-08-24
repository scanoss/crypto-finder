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

// The Crypto++ KB is keyed on what the C++ parser actually emits for a receiver,
// so a parser identity change must fail here rather than silently leaving the
// contracts unmatched. Covers the construction form and both truncated
// variants, whose arities carry the parameter roles and drift most easily.
func TestCryptoPPContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include <cryptopp/sha.h>
void streaming(const CryptoPP::byte *in, size_t len, CryptoPP::byte *out) {
    CryptoPP::SHA256 hash;
    hash.Update(in, len);
    hash.Final(out);
    hash.TruncatedFinal(out, 16);
    hash.CalculateDigest(out, in, len);
    hash.CalculateTruncatedDigest(out, 16, in, len);
}
void temporary(const CryptoPP::byte *in, size_t len, CryptoPP::byte *out) {
    CryptoPP::SHA256().CalculateDigest(out, in, len);
}`
	if err := os.WriteFile(filepath.Join(dir, "digest.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Every key the fixture above must produce, with the role it must resolve to.
	want := map[string]string{
		"CryptoPP.SHA256#0":                           "factory",
		"CryptoPP::SHA256.Update#2":                   "operation",
		"CryptoPP::SHA256.Final#1":                    "operation",
		"CryptoPP::SHA256.TruncatedFinal#2":           "operation",
		"CryptoPP::SHA256.CalculateDigest#3":          "operation",
		"CryptoPP::SHA256.CalculateTruncatedDigest#4": "operation",
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
				role, expected := want[key]
				if !expected {
					t.Fatalf("parsed call produced unexpected contract key %q", key)
				}
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one Crypto++ contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "cryptopp" {
					t.Fatalf("contract for %q = %#v, want cryptopp %s", key, got[0], role)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", key, seen)
		}
	}
}
