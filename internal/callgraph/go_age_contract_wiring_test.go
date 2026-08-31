// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The age KB is keyed on what the Go parser actually emits, so a parser
// identity change must fail here rather than silently leaving the contracts
// unmatched. Package-level functions and receiver methods are asserted
// separately because they resolve through different paths.
func TestAgeContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	dir := t.TempDir()
	src := `package main

import (
	"io"

	"filippo.io/age"
)

func packageLevel(dst io.Writer, src io.Reader, r age.Recipient, i age.Identity, pw string) {
	age.GenerateX25519Identity()
	age.ParseX25519Identity("AGE-SECRET-KEY-1")
	age.ParseX25519Recipient("age1")
	age.NewScryptRecipient(pw)
	age.NewScryptIdentity(pw)
	age.Encrypt(dst, r)
	age.Decrypt(src, i)
	age.GenerateHybridIdentity()
}

func receiverMethods(rec *age.X25519Recipient, id *age.X25519Identity, sr *age.ScryptRecipient, fileKey []byte) {
	rec.Wrap(fileKey)
	id.Unwrap(nil)
	id.Recipient()
	sr.SetWorkFactor(18)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Every age key the fixture above must produce, with the role it must
	// resolve to in the KB.
	want := map[string]string{
		"filippo.io/age.GenerateX25519Identity#0":           "factory",
		"filippo.io/age.ParseX25519Identity#1":              "factory",
		"filippo.io/age.ParseX25519Recipient#1":             "factory",
		"filippo.io/age.NewScryptRecipient#1":               "factory",
		"filippo.io/age.NewScryptIdentity#1":                "factory",
		"filippo.io/age.GenerateHybridIdentity#0":           "factory",
		"filippo.io/age.Encrypt#2":                          "operation",
		"filippo.io/age.Decrypt#2":                          "operation",
		"filippo.io/age.(*X25519Recipient).Wrap#1":          "operation",
		"filippo.io/age.(*X25519Identity).Unwrap#1":         "operation",
		"filippo.io/age.(*X25519Identity).Recipient#0":      "factory",
		"filippo.io/age.(*ScryptRecipient).SetWorkFactor#1": "config",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				method := call.Callee.String()
				if !strings.HasPrefix(method, "filippo.io/age.") {
					continue
				}
				key := method + "#" + strconv.Itoa(len(call.Arguments))
				role, expected := want[key]
				if !expected {
					t.Fatalf("parsed call produced unexpected age contract key %q", key)
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d contracts, want exactly one", method, len(call.Arguments), len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "age" {
					t.Fatalf("contract for %q = role %q library %q, want role %q library age", key, got[0].Role, got[0].SourceLibrary, role)
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

// A receiver bound by a short variable declaration over a library constructor
// resolves through the constructor's contract return type — including a
// chained binding whose producer is only known once the previous receiver has
// been typed. This landed as Go binding resolution (the assigned-var pass run
// to a fixed point); this test previously pinned the opposite behavior and
// carried instructions to flip it when the resolution arrived.
func TestAgeReceiverFromShortVarDeclResolvesViaContract(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `package main

import "filippo.io/age"

func consumer(fileKey []byte) {
	id, _ := age.GenerateX25519Identity()
	r := id.Recipient()
	r.Wrap(fileKey)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			got[fn.Calls[i].Callee.String()] = true
		}
	}

	for _, want := range []string{
		"filippo.io/age.GenerateX25519Identity",
		"filippo.io/age.(*X25519Identity).Recipient",
		"filippo.io/age.(*X25519Recipient).Wrap",
	} {
		if !got[want] {
			t.Fatalf("missing %q; got %v", want, ageCalleeKeys(got))
		}
	}
}

func ageCalleeKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
