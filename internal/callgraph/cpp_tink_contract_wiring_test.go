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

func TestTinkContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"

void templates_and_keyset() {
    const auto& tmpl = crypto::tink::AeadKeyTemplates::Aes256Gcm();
    auto handle = crypto::tink::KeysetHandle::GenerateNew(tmpl);
    (void)handle;
}

void aead_and_mac(crypto::tink::Aead *aead, crypto::tink::Mac *mac, const char *pt, const char *aad) {
    aead->Encrypt(pt, aad);
    aead->Decrypt(pt, aad);
    mac->ComputeMac(pt);
    mac->VerifyMac(pt, aad);
}
`
	if err := os.WriteFile(filepath.Join(dir, "tink.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"crypto::tink::AeadKeyTemplates.Aes256Gcm#0": "factory",
		"crypto::tink::KeysetHandle.GenerateNew#1":   "factory",
		"crypto::tink::Aead.Encrypt#2":               "operation",
		"crypto::tink::Aead.Decrypt#2":               "operation",
		"crypto::tink::Mac.ComputeMac#1":             "operation",
		"crypto::tink::Mac.VerifyMac#2":              "operation",
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
					t.Fatalf("parsed call produced unexpected contract key %q (raw=%q type=%q name=%q args=%d)", key, call.Raw, callee.Type, callee.Name, arity)
				}
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one Tink contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "tink" {
					t.Fatalf("contract for %q = %#v, want tink %s", key, got[0], role)
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
