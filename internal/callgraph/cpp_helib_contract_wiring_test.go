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

// The helib contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestHElibContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include <helib/helib.h>

void flows(helib::SecKey& sk, helib::PubKey& pk, helib::EncryptedArray& ea, helib::PtxtArray& pa, int x) {
    sk.GenSecKey();
    sk.GenSecKey(x);
    sk.GenSecKey(x, x);
    sk.GenKeySWmatrix(x, x);
    sk.GenKeySWmatrix(x, x, x);
    sk.GenKeySWmatrix(x, x, x, x);
    sk.GenKeySWmatrix(x, x, x, x, x);
    sk.genRecryptData();
    sk.Encrypt(x, x);
    sk.Encrypt(x, x, x);
    sk.Decrypt(x, x);
    sk.Decrypt(x, x, x);
    sk.reCrypt(x);
    sk.thinReCrypt(x);
    pk.Encrypt(x, x);
    pk.Encrypt(x, x, x);
    pk.Encrypt(x, x, x, x);
    pk.reCrypt(x);
    pk.thinReCrypt(x);
    ea.encrypt(x, x);
    ea.encrypt(x, x, x);
    ea.encrypt(x, x, x, x);
    ea.encrypt(x, x, x, x, x);
    ea.decrypt(x, x, x);
    ea.decrypt(x, x, x, x);
    ea.decryptComplex(x, x, x);
    ea.decryptComplex(x, x, x, x);
    ea.decryptReal(x, x, x);
    ea.decryptReal(x, x, x, x);
    ea.rawDecrypt(x, x, x);
    pa.encrypt(x);
    pa.encrypt(x, x);
    pa.encrypt(x, x, x);
    pa.decrypt(x, x);
    pa.decrypt(x, x, x);
    pa.decryptComplex(x, x);
    pa.decryptComplex(x, x, x);
    pa.decryptReal(x, x);
    pa.decryptReal(x, x, x);
    pa.rawDecrypt(x, x);
    sk.getContext();
    pk.getContext();
    ea.size();
}
`
	if err := os.WriteFile(filepath.Join(dir, "he.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"helib::SecKey.GenSecKey#0":              "operation",
		"helib::SecKey.GenSecKey#1":              "operation",
		"helib::SecKey.GenSecKey#2":              "operation",
		"helib::SecKey.GenKeySWmatrix#2":         "operation",
		"helib::SecKey.GenKeySWmatrix#3":         "operation",
		"helib::SecKey.GenKeySWmatrix#4":         "operation",
		"helib::SecKey.GenKeySWmatrix#5":         "operation",
		"helib::SecKey.genRecryptData#0":         "operation",
		"helib::SecKey.Encrypt#2":                "operation",
		"helib::SecKey.Encrypt#3":                "operation",
		"helib::SecKey.Decrypt#2":                "operation",
		"helib::SecKey.Decrypt#3":                "operation",
		"helib::SecKey.reCrypt#1":                "operation",
		"helib::SecKey.thinReCrypt#1":            "operation",
		"helib::PubKey.Encrypt#2":                "operation",
		"helib::PubKey.Encrypt#3":                "operation",
		"helib::PubKey.Encrypt#4":                "operation",
		"helib::PubKey.reCrypt#1":                "operation",
		"helib::PubKey.thinReCrypt#1":            "operation",
		"helib::EncryptedArray.encrypt#2":        "operation",
		"helib::EncryptedArray.encrypt#3":        "operation",
		"helib::EncryptedArray.encrypt#4":        "operation",
		"helib::EncryptedArray.encrypt#5":        "operation",
		"helib::EncryptedArray.decrypt#3":        "operation",
		"helib::EncryptedArray.decrypt#4":        "operation",
		"helib::EncryptedArray.decryptComplex#3": "operation",
		"helib::EncryptedArray.decryptComplex#4": "operation",
		"helib::EncryptedArray.decryptReal#3":    "operation",
		"helib::EncryptedArray.decryptReal#4":    "operation",
		"helib::EncryptedArray.rawDecrypt#3":     "operation",
		"helib::PtxtArray.encrypt#1":             "operation",
		"helib::PtxtArray.encrypt#2":             "operation",
		"helib::PtxtArray.encrypt#3":             "operation",
		"helib::PtxtArray.decrypt#2":             "operation",
		"helib::PtxtArray.decrypt#3":             "operation",
		"helib::PtxtArray.decryptComplex#2":      "operation",
		"helib::PtxtArray.decryptComplex#3":      "operation",
		"helib::PtxtArray.decryptReal#2":         "operation",
		"helib::PtxtArray.decryptReal#3":         "operation",
		"helib::PtxtArray.rawDecrypt#2":          "operation",
	}
	negative := map[string]bool{}
	for _, key := range []string{"helib::SecKey.getContext#0", "helib::PubKey.getContext#0", "helib::EncryptedArray.size#0"} {
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
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one helib contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "helib" {
					t.Fatalf("contract for %q = role %q library %q, want helib %s", key, got[0].Role, got[0].SourceLibrary, role)
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
