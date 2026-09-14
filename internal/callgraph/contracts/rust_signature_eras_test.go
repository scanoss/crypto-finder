// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// THE dsa AND ecdsa CRATES EACH SPAN TWO ERAS THAT CANNOT SHARE A version_range,
// AND THIS IS THE TEST THAT PINS THE SPLIT.
//
// A KB entry is keyed on METHOD PLUS ARITY, and `version_range` is declared per
// LIBRARY FILE, so a file may only claim versions for which EVERY entry in it is
// true. Both crates renamed or re-shaped their constructor across a boundary the
// matrix covers on both sides:
//
//	dsa 0.6.3   SigningKey::generate(rng, components) -> SigningKey  signing_key.rs:53
//	dsa 0.7.0   SigningKey::generate()                -> SigningKey  crypto_common::Generate
//	                                                                 default method,
//	                                                                 impl at signing_key.rs:182
//
//	ecdsa 0.16.9  SigningKey::random(rng) -> SigningKey    signing.rs:87
//	              (no `generate` AT ALL -- E0599)
//	ecdsa 0.17.0  SigningKey::generate()  -> SigningKey    elliptic_curve's re-export of
//	                                                       crypto_common::Generate,
//	                                                       impl at signing.rs:130
//
// So `generate` at arity 2 and `generate` at arity 0 are different entries and
// neither holds across the whole span. Widening either base file's range would
// assert one of them over versions where it is false; that is why
// `dsa-0.7.yaml` and `ecdsa-0.17.yaml` exist as separate files.
//
// Every symbol below was verified BY COMPILING it against the exact published
// version, not by reading `pub fn`: the arity-0 and arity-1 constructors are
// DEFAULT METHODS on the `Generate` trait and appear in no `pub fn` listing of
// either crate.
//
// The set is compared EXACTLY, not per key. A per-key assertion cannot see an
// entry that should not be there, an entry that was dropped, or a field that was
// corrupted; only the whole-set comparison does. It renders role, both return
// fields, parameter types and confidence, because each of those has been
// corrupted in a merged contract on this campaign without any other assertion
// noticing.
var signatureEraLibraries = map[string]bool{
	"dsa":        true,
	"dsa-0.7":    true,
	"ecdsa":      true,
	"ecdsa-0.17": true,
}

func renderSignatureEraContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if !signatureEraLibraries[c.SourceLibrary] {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence, c.SourceLibrary))
		}
	}
	sort.Strings(got)
	return got
}

var wantSignatureEraContracts = []string{
	"dsa::Components.generate#0/factory/dsa::Components//[]/high/dsa-0.7",
	"dsa::Components.generate#2/factory/dsa::Components//[]/high/dsa",
	"dsa::Components.generate_from_rng#1/factory/dsa::Components//[]/high/dsa-0.7",
	"dsa::Components.try_generate#0/factory/dsa::Components//[]/high/dsa-0.7",
	"dsa::Components.try_generate_from_rng#1/factory/dsa::Components//[]/high/dsa-0.7",
	"dsa::Components.try_generate_from_rng_with_key_size#2/factory/dsa::Components//[]/high/dsa-0.7",
	"dsa::SigningKey.from_components#2/factory/dsa::SigningKey//[]/high/dsa",
	"dsa::SigningKey.generate#0/factory/dsa::SigningKey//[]/high/dsa-0.7",
	"dsa::SigningKey.generate#2/factory/dsa::SigningKey//[]/high/dsa",
	"dsa::SigningKey.generate_from_rng#1/factory/dsa::SigningKey//[]/high/dsa-0.7",
	"dsa::SigningKey.try_generate#0/factory/dsa::SigningKey//[]/high/dsa-0.7",
	"dsa::SigningKey.try_generate_from_rng#1/factory/dsa::SigningKey//[]/high/dsa-0.7",
	"dsa::SigningKey.try_generate_from_rng_with_components#2/factory/dsa::SigningKey//[]/high/dsa-0.7",
	"dsa::VerifyingKey.from_components#2/factory/dsa::VerifyingKey//[]/high/dsa",
	"ecdsa::SigningKey.from_bytes#1/factory/ecdsa::SigningKey//[]/high/ecdsa",
	"ecdsa::SigningKey.from_slice#1/factory/core::result::Result//[]/high/ecdsa",
	"ecdsa::SigningKey.generate#0/factory/ecdsa::SigningKey//[]/high/ecdsa-0.17",
	// KNOWN-FALSE, PRE-EXISTING, AND DELIBERATELY STILL LISTED. `ecdsa::SigningKey
	// ::generate` at ARITY 1 exists in NO published ecdsa release: rustc gives E0599
	// at 0.16.9 (and names `random`/`from_bytes`/`from_slice` as the era's whole
	// constructor set), while at 0.17.0 `generate` is arity 0. The entry is merged and
	// delivered, so retracting it is an operator decision rather than this change's;
	// it is listed here because the assertion is an EXACT SET and omitting it would
	// fail. Do not read its presence as verification. Removing the contract entry and
	// this line together is the correct fix once signed off.
	"ecdsa::SigningKey.generate#1/factory/ecdsa::SigningKey//[]/high/ecdsa",
	"ecdsa::SigningKey.generate_from_rng#1/factory/ecdsa::SigningKey//[]/high/ecdsa-0.17",
	"ecdsa::SigningKey.random#1/factory/ecdsa::SigningKey//[]/high/ecdsa",
	"ecdsa::SigningKey.try_generate#0/factory/ecdsa::SigningKey//[]/high/ecdsa-0.17",
	"ecdsa::SigningKey.try_generate_from_rng#1/factory/ecdsa::SigningKey//[]/high/ecdsa-0.17",
	"ecdsa::VerifyingKey.from_encoded_point#1/factory/ecdsa::VerifyingKey//[]/high/ecdsa",
	"ecdsa::VerifyingKey.from_sec1_bytes#1/factory/core::result::Result//[]/high/ecdsa",
	"ecdsa::VerifyingKey.from_sec1_point#1/factory/ecdsa::VerifyingKey//[]/high/ecdsa-0.17",
}

func TestLoadEmbeddedRustSignatureEraContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderSignatureEraContracts(t)
	want := append([]string(nil), wantSignatureEraContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("signature-era contracts: got %d, want %d", len(got), len(want))
	}
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected signature-era contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing signature-era contract:    %s", w)
		}
	}
}

// EACH ERA'S CONSTRUCTOR MUST RESOLVE UNDER THE ARITY THAT ERA ACTUALLY USES,
// and must NOT resolve under the other era's arity where the crate has no such
// callable. This is the assertion that a widened range would have hidden: with
// both eras collapsed into one file the arities would still differ, but nothing
// would say which range each is true for.
func TestSignatureEraConstructorsResolvePerArity(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	resolves := []struct {
		method  string
		arity   int
		library string
	}{
		// dsa 0.6 era — arity 2, returns the key directly.
		{"dsa.SigningKey.generate", 2, "dsa"},
		{"dsa.Components.generate", 2, "dsa"},
		// dsa 0.7 era — the Generate trait, arity 0, plus the inherent arity-2
		// constructor that replaced the old `generate`.
		{"dsa.SigningKey.generate", 0, "dsa-0.7"},
		{"dsa.SigningKey.try_generate_from_rng_with_components", 2, "dsa-0.7"},
		{"dsa.SigningKey.try_generate", 0, "dsa-0.7"},
		{"dsa.Components.try_generate", 0, "dsa-0.7"},
		{"dsa.Components.try_generate_from_rng_with_key_size", 2, "dsa-0.7"},
		// ecdsa 0.16 era — `random` is the only generator this era has.
		{"ecdsa.SigningKey.random", 1, "ecdsa"},
		{"ecdsa.VerifyingKey.from_encoded_point", 1, "ecdsa"},
		// ecdsa 0.17 era — the Generate trait at arity 0 and the renamed codec.
		{"ecdsa.SigningKey.generate", 0, "ecdsa-0.17"},
		{"ecdsa.SigningKey.try_generate", 0, "ecdsa-0.17"},
		{"ecdsa.VerifyingKey.from_sec1_point", 1, "ecdsa-0.17"},
	}
	for _, r := range resolves {
		got := kb.ContractsFor(r.method, r.arity)
		if len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want exactly 1",
				r.method, r.arity, len(got))
			continue
		}
		if got[0].SourceLibrary != r.library {
			t.Errorf("ContractsFor(%q, %d): library = %q, want %q",
				r.method, r.arity, got[0].SourceLibrary, r.library)
		}
	}

	// Arities no published release of either crate emits. `dsa::Components`
	// gained its arity-0 `Generate` impl only at 0.7.0 and `ecdsa::SigningKey`
	// never had an arity-2 `generate`; a contract answering these would be
	// claiming a callable that exists in no version.
	absent := []struct {
		method string
		arity  int
	}{
		{"dsa.SigningKey.generate", 1},
		{"dsa.SigningKey.generate", 3},
		{"ecdsa.SigningKey.generate", 2},
		{"ecdsa.SigningKey.random", 0},
		{"dsa.SigningKey.try_generate", 1},
		{"ecdsa.SigningKey.try_generate", 1},
		{"ecdsa.VerifyingKey.from_sec1_point", 2},
	}
	for _, a := range absent {
		if got := kb.ContractsFor(a.method, a.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want none -- no published "+
				"release declares that arity", a.method, a.arity, len(got))
		}
	}
}

// THE RANGES ARE THE CLAIM, SO THEY ARE ASSERTED RATHER THAN LEFT TO THE FILE
// HEADERS. `version_range`, `coordinates` and `name` are parsed (contracts.go)
// and consulted by no other assertion in this file, so corrupting any of them
// leaves every check above green. That is exactly how a range silently widens
// over a signature that changed.
//
// The two pairs must ABUT AND NOT OVERLAP: each era's constructor exists only
// on its own side of the boundary, so an overlap would assert a callable over
// versions where compiling it fails.
func TestSignatureEraVersionRangesDoNotOverlap(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file       string
		name       string
		wantRange  string
		coordinate string
	}{
		{"rust/dsa.yaml", "dsa", ">=0.6.0,<0.7.0", "dsa"},
		{"rust/dsa-0.7.yaml", "dsa-0.7", ">=0.7.0,<0.8.0", "dsa"},
		{"rust/ecdsa.yaml", "ecdsa", ">=0.16.0,<0.17.0", "ecdsa"},
		{"rust/ecdsa-0.17.yaml", "ecdsa-0.17", ">=0.17.0,<0.18.0", "ecdsa"},
	} {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Errorf("read %s: %v", tc.file, err)
			continue
		}
		kb, err := contracts.Load(data)
		if err != nil {
			t.Errorf("Load(%s): %v", tc.file, err)
			continue
		}
		if kb.Library == nil {
			t.Errorf("%s declares no library: block", tc.file)
			continue
		}
		if kb.Library.Name != tc.name {
			t.Errorf("%s: library.name = %q, want %q", tc.file, kb.Library.Name, tc.name)
		}
		if kb.Library.VersionRange != tc.wantRange {
			t.Errorf("%s: version_range = %q, want %q -- the range must cover only "+
				"versions for which EVERY entry in this file is true, and each era's "+
				"constructor compiles on only one side of the boundary",
				tc.file, kb.Library.VersionRange, tc.wantRange)
		}
		// Both files of a pair describe the ONE crate, whatever library.name is.
		if len(kb.Library.Coordinates) != 1 || kb.Library.Coordinates[0] != tc.coordinate {
			t.Errorf("%s: coordinates = %v, want [%s]", tc.file, kb.Library.Coordinates, tc.coordinate)
		}
	}
}
