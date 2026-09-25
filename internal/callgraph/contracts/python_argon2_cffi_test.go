// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const argon2CffiLibrary = "argon2-cffi"

// wantArgon2CffiContracts is written BY HAND from the argon2-cffi 25.1.0
// sources, never derived from the YAML: a derived expectation goes green on a
// corrupted contract. renderPyjwtContract renders every field Load populates.
func wantArgon2CffiContracts() []string {
	return []string{
		// PasswordHasher, _password_hasher.py:94. `import argon2;
		// argon2.PasswordHasher()` emits the attribute key and `from argon2
		// import PasswordHasher; PasswordHasher()` the `.<init>` key.
		"argon2.PasswordHasher#0 argon2.PasswordHasher/factory/argon2.PasswordHasher/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.PasswordHasher#4 argon2.PasswordHasher/factory/argon2.PasswordHasher/high/builtins.int|builtins.int|builtins.int|builtins.int/-/params=3:hash_len:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=argon2-cffi",
		"argon2.PasswordHasher.<init>#0 argon2.PasswordHasher.<init>/factory/argon2.PasswordHasher/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.PasswordHasher.<init>#4 argon2.PasswordHasher.<init>/factory/argon2.PasswordHasher/high/builtins.int|builtins.int|builtins.int|builtins.int/-/params=3:hash_len:metadata-contributing:keySize:argument_byte_length/varargs=false/when=-/lib=argon2-cffi",
		// classmethod from_parameters, _password_hasher.py:133 (21.2.0+).
		"argon2.PasswordHasher.from_parameters#1 argon2.PasswordHasher.from_parameters/factory/argon2.PasswordHasher/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		// hash :176 and verify :215 run Argon2. check_needs_rehash :262
		// decodes an existing hash's parameters and runs no Argon2.
		"argon2.PasswordHasher.hash#1 argon2.PasswordHasher.hash/operation/builtins.str/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.PasswordHasher.verify#2 argon2.PasswordHasher.verify/operation/builtins.bool/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.PasswordHasher.check_needs_rehash#1 argon2.PasswordHasher.check_needs_rehash/output/builtins.bool/high/-/-/params=-/varargs=false/when=-/lib=argon2-cffi",
		// low_level.py:52 hash_secret, :123 hash_secret_raw, :163 verify_secret.
		// `type` selects Argon2d, Argon2i or Argon2id.
		"argon2.low_level.hash_secret#7 argon2.low_level.hash_secret/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int|builtins.int|builtins.int|builtins.int|argon2.low_level.Type/-/params=5:hash_len:metadata-contributing:keySize:argument_byte_length,6:type:operation-determining:-:-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.low_level.hash_secret_raw#7 argon2.low_level.hash_secret_raw/operation/builtins.bytes/high/builtins.bytes|builtins.bytes|builtins.int|builtins.int|builtins.int|builtins.int|argon2.low_level.Type/-/params=5:hash_len:metadata-contributing:keySize:argument_byte_length,6:type:operation-determining:-:-/varargs=false/when=-/lib=argon2-cffi",
		"argon2.low_level.verify_secret#3 argon2.low_level.verify_secret/operation/builtins.bool/high/-/-/params=2:type:operation-determining:-:-/varargs=false/when=-/lib=argon2-cffi",
	}
}

func TestPythonArgon2CffiContract_ExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var got []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == argon2CffiLibrary {
				got = append(got, renderPyjwtContract(key, list[i]))
			}
		}
	}
	want := wantArgon2CffiContracts()
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
			t.Errorf("loaded but not expected; if intended, add it to wantArgon2CffiContracts():\n\t%q,", line)
		}
	}
}

// The deprecated pre-16.0 API is reached by no rule spelling, and the
// parameter helpers perform no cryptography. Pinning them absent makes adding
// one later read as a scope decision being reversed.
func TestPythonArgon2CffiContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if len(kb.ContractsFor("argon2.PasswordHasher.hash", 1)) == 0 {
		t.Fatal("positive control failed: argon2.PasswordHasher.hash#1 does not resolve")
	}
	for _, absent := range []string{
		"argon2.hash_password",
		"argon2.hash_password_raw",
		"argon2.verify_password",
		"argon2.extract_parameters",
		"argon2.profiles.get_default_parameters",
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(absent, arity) {
				if c.SourceLibrary == argon2CffiLibrary {
					t.Errorf("%s#%d resolves to an argon2-cffi contract but is deliberately not contracted", absent, arity)
				}
			}
		}
	}
}

func TestPythonArgon2CffiContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "argon2-cffi.yaml"))
	if err != nil {
		t.Fatalf("read argon2-cffi.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(argon2-cffi.yaml): %v", err)
	}
	if kb.Library == nil || kb.Library.Name != argon2CffiLibrary {
		t.Fatalf("library block = %+v, want name %q", kb.Library, argon2CffiLibrary)
	}
	if got, want := strings.Join(kb.Library.Coordinates, ","), "argon2-cffi"; got != want {
		t.Errorf("library.coordinates = %q, want %q", got, want)
	}
	// 16.0.0 introduced PasswordHasher and low_level; 15.x has neither.
	if got, want := kb.Library.VersionRange, ">=16.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
}
