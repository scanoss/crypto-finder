// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const bcryptLibrary = "bcrypt"

// wantBcryptContracts is written BY HAND from the bcrypt 5.0.0 stub and the
// 1.0.0 to 3.2.2 sources, never derived from the YAML: a derived expectation
// goes green on a corrupted contract.
func wantBcryptContracts() []string {
	return []string{
		// gensalt(rounds=12, prefix=b"2b"). rounds is the log2 cost written
		// into the salt; prefix arrives at 3.0.0.
		"bcrypt.gensalt#0 bcrypt.gensalt/factory/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=bcrypt",
		"bcrypt.gensalt#1 bcrypt.gensalt/factory/builtins.bytes/high/builtins.int/-/params=0:rounds:metadata-contributing:cost:argument_value/varargs=false/when=-/lib=bcrypt",
		"bcrypt.gensalt#2 bcrypt.gensalt/factory/builtins.bytes/high/builtins.int|builtins.bytes/-/params=0:rounds:metadata-contributing:cost:argument_value/varargs=false/when=-/lib=bcrypt",
		// hashpw and checkpw (3.1.0+) run bcrypt.
		"bcrypt.hashpw#2 bcrypt.hashpw/operation/builtins.bytes/high/-/-/params=-/varargs=false/when=-/lib=bcrypt",
		"bcrypt.checkpw#2 bcrypt.checkpw/operation/builtins.bool/high/-/-/params=-/varargs=false/when=-/lib=bcrypt",
		// kdf(password, salt, desired_key_bytes, rounds) at 3.0.0, plus
		// ignore_few_rounds at 3.1.3. rounds is the bcrypt_pbkdf iteration count.
		"bcrypt.kdf#4 bcrypt.kdf/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int|builtins.int/-/params=2:desired_key_bytes:metadata-contributing:keySize:argument_byte_length,3:rounds:metadata-contributing:iterations:argument_value/varargs=false/when=-/lib=bcrypt",
		"bcrypt.kdf#5 bcrypt.kdf/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int|builtins.int|builtins.bool/-/params=2:desired_key_bytes:metadata-contributing:keySize:argument_byte_length,3:rounds:metadata-contributing:iterations:argument_value/varargs=false/when=-/lib=bcrypt",
	}
}

func TestPythonBcryptContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == bcryptLibrary {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	want := wantBcryptContracts()
	sort.Strings(got)
	sort.Strings(want)

	gotSet := map[string]bool{}
	for _, line := range got {
		gotSet[line] = true
	}
	wantSet := map[string]bool{}
	for _, line := range want {
		wantSet[line] = true
		if !gotSet[line] {
			t.Errorf("declared in the expectation but NOT loaded from the YAML:\n\t%q,", line)
		}
	}
	for _, line := range got {
		if !wantSet[line] {
			t.Errorf("loaded but not expected; if intended, add it to wantBcryptContracts():\n\t%q,", line)
		}
	}
}

func TestPythonBcryptContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "bcrypt.yaml"))
	if err != nil {
		t.Fatalf("read bcrypt.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(bcrypt.yaml): %v", err)
	}
	if kb.Library == nil || kb.Library.Name != bcryptLibrary {
		t.Fatalf("library block = %+v, want name %q", kb.Library, bcryptLibrary)
	}
	// 1.0.0 already ships gensalt and hashpw returning bytes.
	if got, want := kb.Library.VersionRange, ">=1.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
}
