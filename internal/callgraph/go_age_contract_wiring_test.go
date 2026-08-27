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

// A receiver whose type comes from a short variable declaration over a library
// constructor is NOT resolved to the library today: the Go parser types a
// receiver from explicit syntax (a typed var, a typed parameter) and has no
// pass that carries a contract's return type onto the variable it binds. The
// call is therefore keyed to the consuming package instead.
//
// This is pinned rather than fixed here. Carrying contract return types onto
// short variable declarations is Go binding resolution, a shared-behavior
// change to the analyzer that belongs to the per-language parser parity series
// rather than to one library's coverage ticket. When that lands, this test is
// the one that must be updated, and the expectation below becomes the age key.
func TestAgeReceiverFromShortVarDeclIsNotYetResolved(t *testing.T) {
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
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				got[call.Callee.String()] = true
			}
		}
	}

	// The constructor itself resolves; the two calls on its result do not.
	if !got["filippo.io/age.GenerateX25519Identity"] {
		t.Fatalf("constructor identity regressed; got %v", ageCalleeKeys(got))
	}
	if !got["app.Recipient"] || !got["app.Wrap"] {
		t.Fatalf("short-var receiver resolution changed; got %v.\n"+
			"If Go binding resolution has landed, these should now be "+
			"filippo.io/age.(*X25519Identity).Recipient and "+
			"filippo.io/age.(*X25519Recipient).Wrap, and this test plus the age "+
			"coverage notes must be updated together.", ageCalleeKeys(got))
	}
}

func ageCalleeKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
