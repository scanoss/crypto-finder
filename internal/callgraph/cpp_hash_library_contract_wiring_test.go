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

// The hash-library contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestHashLibraryContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "sha256.h"

void flows(MD5& md5, SHA1& sha1, SHA256& sha256, SHA3& sha3, Keccak& keccak, CRC32& crc32, const void* p, size_t n, unsigned char* buf) {
    md5.add(p, n);
    md5.getHash();
    md5.getHash(buf);
    sha1.add(p, n);
    sha1.getHash();
    sha1.getHash(buf);
    sha256.add(p, n);
    sha256.getHash();
    sha256.getHash(buf);
    sha3.add(p, n);
    sha3.getHash();
    keccak.add(p, n);
    keccak.getHash();
    sha256.reset();
    crc32.add(p, n);
    crc32.getHash();
}
`
	if err := os.WriteFile(filepath.Join(dir, "digest.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"MD5.add#2":        "operation",
		"MD5.getHash#0":    "output",
		"MD5.getHash#1":    "output",
		"SHA1.add#2":       "operation",
		"SHA1.getHash#0":   "output",
		"SHA1.getHash#1":   "output",
		"SHA256.add#2":     "operation",
		"SHA256.getHash#0": "output",
		"SHA256.getHash#1": "output",
		"SHA3.add#2":       "operation",
		"SHA3.getHash#0":   "output",
		"Keccak.add#2":     "operation",
		"Keccak.getHash#0": "output",
	}
	negative := map[string]bool{}
	for _, key := range []string{"SHA256.reset#0", "CRC32.add#2", "CRC32.getHash#0"} {
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
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one hash-library contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "hash-library" {
					t.Fatalf("contract for %q = role %q library %q, want hash-library %s", key, got[0].Role, got[0].SourceLibrary, role)
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
