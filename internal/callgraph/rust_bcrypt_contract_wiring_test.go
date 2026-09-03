// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bcrypt's surface is free functions in a single-segment crate, so every key is
// the "<crate>.<fn>" dot form with no module segment. A consumer reaches them
// through two spellings -- a named import and the crate path -- and both must
// land on the same contract. An external call renders as name(?, ?) in an
// exported callgraph whether or not a contract exists, so this test, not that
// rendering, is what says the keys resolve.
func TestBcryptContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use bcrypt::{hash, verify, DEFAULT_COST};

fn register(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}

fn register_with_salt(password: &str, salt: [u8; 16]) -> bcrypt::HashParts {
    bcrypt::hash_with_salt(password, DEFAULT_COST, salt).unwrap()
}

fn register_long(password: &str) -> String {
    bcrypt::non_truncating_hash(password, 12).unwrap()
}

fn login(password: &str, stored: &str) -> bool {
    verify(password, stored).unwrap()
}

fn login_long(password: &str, stored: &str) -> bool {
    bcrypt::non_truncating_verify(password, stored).unwrap()
}

fn raw(cost: u32, salt: [u8; 16], password: &[u8]) -> [u8; 24] {
    bcrypt::bcrypt(cost, salt, password)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"bcrypt.hash":                  "operation",
		"bcrypt.hash_with_salt":        "operation",
		"bcrypt.non_truncating_hash":   "operation",
		"bcrypt.verify":                "operation",
		"bcrypt.non_truncating_verify": "operation",
		"bcrypt.bcrypt":                "operation",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				role, ok := want[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "bcrypt" {
					t.Fatalf("contract for %q = %#v, want bcrypt %s", method, got[0], role)
				}
				seen[method] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// The raw primitive wrote its digest into a caller-supplied buffer through
// 0.12.1 and returns it from 0.13.0, so one name carries two arities across the
// contracted range. A single-arity contract would leave every pre-0.13 call
// site unresolved while looking complete.
func TestBcryptRawPrimitiveIsContractedAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, arity := range []int{3, 4} {
		got := kb.ContractsFor("bcrypt.bcrypt", arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(bcrypt.bcrypt, %d) = %d, want exactly one", arity, len(got))
		}
		if got[0].SourceLibrary != "bcrypt" {
			t.Fatalf("ContractsFor(bcrypt.bcrypt, %d) resolved to %q", arity, got[0].SourceLibrary)
		}
	}
}

// Every entry in the KB, not only the six a probe consumer happened to
// exercise. Each is looked up at its declared arity, and each is looked up at a
// neighboring arity to prove the arity is load-bearing rather than ignored.
func TestBcryptEveryContractedIdentityResolves(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	// The return type is part of the contract and nothing else in this file
	// reads it: without this column, reverting the unit type to a token no
	// parser knows would leave the suite green.
	const res = "core::result::Result"
	type sig struct {
		arity int
		ret   string
	}
	want := map[string][]sig{
		"bcrypt.hash":                                {{2, res}},
		"bcrypt.hash_with_result":                    {{2, res}},
		"bcrypt.hash_bytes":                          {{2, res}},
		"bcrypt.non_truncating_hash":                 {{2, res}},
		"bcrypt.non_truncating_hash_with_result":     {{2, res}},
		"bcrypt.non_truncating_hash_bytes":           {{2, res}},
		"bcrypt.hash_with_salt":                      {{3, res}},
		"bcrypt.hash_with_salt_bytes":                {{3, res}},
		"bcrypt.non_truncating_hash_with_salt":       {{3, res}},
		"bcrypt.non_truncating_hash_with_salt_bytes": {{3, res}},
		"bcrypt.verify":                              {{2, res}},
		"bcrypt.non_truncating_verify":               {{2, res}},
		// 0.13.0 on returns the digest; 0.5.0-0.12.1 wrote into a buffer.
		"bcrypt.bcrypt": {{3, "[u8; 24]"}, {4, "()"}},
	}
	total := 0
	for method, sigs := range want {
		declared := map[int]bool{}
		for _, sg := range sigs {
			a := sg.arity
			declared[a] = true
			got := kb.ContractsFor(method, a)
			if len(got) != 1 {
				t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", method, a, len(got))
				continue
			}
			if got[0].SourceLibrary != "bcrypt" || got[0].Role != "operation" {
				t.Errorf("ContractsFor(%q, %d) = %#v, want a bcrypt operation", method, a, got[0])
			}
			if got[0].Return.Type != sg.ret {
				t.Errorf("ContractsFor(%q, %d) return = %q, want %q", method, a, got[0].Return.Type, sg.ret)
			}
			// confidence is exported too; every signature here is read straight
			// from the crate's source, so none of them is anything but high.
			if got[0].Return.Confidence != "high" {
				t.Errorf("ContractsFor(%q, %d) confidence = %q, want high", method, a, got[0].Return.Confidence)
			}
			total++
		}
		for a := 0; a <= 5; a++ {
			if declared[a] {
				continue
			}
			if got := kb.ContractsFor(method, a); len(got) != 0 {
				t.Errorf("ContractsFor(%q, %d) = %#v, want none at an undeclared arity", method, a, got)
			}
		}
	}
	if total != 14 {
		t.Fatalf("resolved %d contracts, want all 14 in the KB", total)
	}
	// total counts what was EXPECTED and found; it cannot notice a fifteenth
	// entry nobody declared here. Count what the KB actually holds too.
	if n := countBcryptContracts(t); n != 14 {
		t.Fatalf("the KB holds %d bcrypt contracts, want exactly the 14 asserted above", n)
	}
}

// The parameter semantics ARE the payload: which argument is the password, the
// cost, the salt, the stored hash. Nothing above would notice if two of them
// were swapped, and a swapped pair publishes a password as a salt.
func TestBcryptParameterSemantics(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	cases := []struct {
		method string
		arity  int
		want   map[int]string // index -> contributed property
		names  map[int]string // index -> the crate's own argument name
	}{
		{"bcrypt.hash", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.hash_with_result", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.hash_bytes", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.non_truncating_hash", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.non_truncating_hash_with_result", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.non_truncating_hash_bytes", 2, map[int]string{0: "password", 1: "cost"}, map[int]string{0: "password", 1: "cost"}},
		{"bcrypt.hash_with_salt", 3, map[int]string{0: "password", 1: "cost", 2: "salt"}, map[int]string{0: "password", 1: "cost", 2: "salt"}},
		{"bcrypt.hash_with_salt_bytes", 3, map[int]string{0: "password", 1: "cost", 2: "salt"}, map[int]string{0: "password", 1: "cost", 2: "salt"}},
		{"bcrypt.non_truncating_hash_with_salt", 3, map[int]string{0: "password", 1: "cost", 2: "salt"}, map[int]string{0: "password", 1: "cost", 2: "salt"}},
		{"bcrypt.non_truncating_hash_with_salt_bytes", 3, map[int]string{0: "password", 1: "cost", 2: "salt"}, map[int]string{0: "password", 1: "cost", 2: "salt"}},
		// The stored digest is a passwordHash, not ciphertext: the same spelling
		// golang-x-crypto's CompareHashAndPassword uses for the same argument.
		{"bcrypt.verify", 2, map[int]string{0: "password", 1: "passwordHash"}, map[int]string{0: "password", 1: "hash"}},
		{"bcrypt.non_truncating_verify", 2, map[int]string{0: "password", 1: "passwordHash"}, map[int]string{0: "password", 1: "hash"}},
		// The raw primitive takes cost FIRST; password is last. Reading it in the
		// hash(password, cost) order would attribute a cost as a password.
		{"bcrypt.bcrypt", 3, map[int]string{0: "cost", 1: "salt", 2: "password"}, map[int]string{0: "cost", 1: "salt", 2: "password"}},
		{"bcrypt.bcrypt", 4, map[int]string{0: "cost", 1: "salt", 2: "password", 3: "output"}, map[int]string{0: "cost", 1: "salt", 2: "password", 3: "output"}},
	}
	for _, c := range cases {
		got := kb.ContractsFor(c.method, c.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d, want exactly one", c.method, c.arity, len(got))
			continue
		}
		params := got[0].Parameters
		if len(params) != len(c.want) {
			t.Errorf("%s/%d: parameters = %d, want %d", c.method, c.arity, len(params), len(c.want))
			continue
		}
		for _, prm := range params {
			if prm.Index == nil {
				t.Errorf("%s/%d: parameter %#v has no index", c.method, c.arity, prm)
				continue
			}
			prop, ok := c.want[*prm.Index]
			if !ok {
				t.Errorf("%s/%d: unexpected parameter index %d", c.method, c.arity, *prm.Index)
				continue
			}
			if prm.Role != "metadata-contributing" || prm.Contributes == nil || prm.Contributes.Property != prop {
				t.Errorf("%s/%d: parameter %d = %#v, want metadata-contributing property %q",
					c.method, c.arity, *prm.Index, prm, prop)
				continue
			}
			// A &mut [u8] output buffer carries no length, so a type-derived
			// property here could never resolve to a value.
			if prm.Contributes.Derivation != "argument_value" {
				t.Errorf("%s/%d: parameter %d derivation = %q, want argument_value",
					c.method, c.arity, *prm.Index, prm.Contributes.Derivation)
			}
			// name is exported on every parameter role, so a wrong one ships.
			// The NAME is the crate's own argument name and the PROPERTY is what
			// it contributes; they differ where the two vocabularies differ --
			// verify's second argument is named `hash` and contributes a
			// passwordHash. Both are exported, so both are pinned.
			if want := c.names[*prm.Index]; prm.Name != want {
				t.Errorf("%s/%d: parameter %d name = %q, want %q",
					c.method, c.arity, *prm.Index, prm.Name, want)
			}
		}
	}
}

// DEFAULT_COST, BASE_64 and Version are not call sites. Contracting them would
// put a callable identity in the KB that no parser can ever emit.
func TestBcryptConstantsAreNotContracted(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	// Without this the test passes just as happily with bcrypt.yaml deleted.
	if got := kb.ContractsFor("bcrypt.hash", 2); len(got) != 1 {
		t.Fatalf("bcrypt contracts are not loaded at all; this test would pass vacuously")
	}
	for _, name := range []string{"bcrypt.DEFAULT_COST", "bcrypt.BASE_64", "bcrypt.Version"} {
		for arity := 0; arity <= 4; arity++ {
			if got := kb.ContractsFor(name, arity); len(got) != 0 {
				t.Fatalf("ContractsFor(%q, %d) = %#v, want none", name, arity, got)
			}
		}
	}
}

// countBcryptContracts reports how many contracts the embedded Rust KB
// attributes to bcrypt, by walking the KB itself. An earlier version swept a
// hardcoded list of names across arities 0-6, which let a spurious entry hide
// behind an unlisted name or an out-of-range arity -- including the invented
// return token an earlier review had already caught once.
func countBcryptContracts(t *testing.T) int {
	t.Helper()
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	n := 0
	for key := range kb.Contracts {
		ctrs := kb.Contracts[key]
		for i := range ctrs {
			if ctrs[i].SourceLibrary == "bcrypt" {
				n++
			}
		}
	}
	return n
}
