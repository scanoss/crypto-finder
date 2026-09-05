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

// `getrandom` exports every entry point from the crate ROOT, so the graph emits
// `getrandom.fill` with no module or type segment and the KB file authors the
// same spelling: rustAuthoredKey (contracts.go:267) moves the second-to-last
// dot, and a key with fewer than two dots has none to move. That the authored
// and emitted keys coincide here is a property of this crate's flat surface,
// not of Rust, which is why TestGetrandomEmittedCallSiteKeysResolve pins the
// emitted spellings separately rather than assuming they follow.
//
// The set below is compared EXACTLY, not per key, and it renders the
// `parameters:` block as well as the scalar fields: renaming a contributed
// property loads cleanly through the schema's presence checks and would
// otherwise leave every assertion green.

// renderGetrandomContracts renders every loaded getrandom contract as one
// deterministic line, sorted. Everything a KB consumer reads is in the line.
func renderGetrandomContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "getrandom" {
				continue
			}
			params := make([]string, 0, len(c.Parameters))
			for _, p := range c.Parameters {
				idx := "-"
				if p.Index != nil {
					idx = fmt.Sprintf("%d", *p.Index)
				}
				contributes := "-"
				if p.Contributes != nil {
					contributes = p.Contributes.Property + ":" + p.Contributes.Derivation
				}
				params = append(params, fmt.Sprintf("%s=%s:%s:%s", idx, p.Name, p.Role, contributes))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s/{%s}",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence,
				strings.Join(params, ";")))
		}
	}
	sort.Strings(got)
	return got
}

// The two eras are disjoint by version and both are in the matrix range:
// `getrandom`/`getrandom_uninit` exist only in 0.1.0-0.2.17, `fill`,
// `fill_uninit`, `u32` and `u64` only from 0.3.0. `SysRng` deliberately has no
// entry -- it is a unit struct, so naming it is a value expression and not a
// call, and a contract keyed on a type name would join nothing.
var wantGetrandomContracts = []string{
	"getrandom.fill#1/output/Result<(), getrandom::Error>/Result<(), getrandom::Error>/[&mut [u8]]/high/{0=dest:metadata-contributing:dataLength:argument_byte_length}",
	"getrandom.fill_uninit#1/output/Result<&mut [u8], getrandom::Error>/Result<&mut [u8], getrandom::Error>/[&mut [core::mem::MaybeUninit<u8>]]/high/{0=dest:metadata-contributing:dataLength:argument_byte_length}",
	"getrandom.getrandom#1/output/Result<(), getrandom::Error>/Result<(), getrandom::Error>/[&mut [u8]]/high/{0=dest:metadata-contributing:dataLength:argument_byte_length}",
	"getrandom.getrandom_uninit#1/output/Result<&mut [u8], getrandom::Error>/Result<&mut [u8], getrandom::Error>/[&mut [core::mem::MaybeUninit<u8>]]/high/{0=dest:metadata-contributing:dataLength:argument_byte_length}",
	"getrandom.u32#0/output/Result<u32, getrandom::Error>/Result<u32, getrandom::Error>/[]/high/{}",
	"getrandom.u64#0/output/Result<u64, getrandom::Error>/Result<u64, getrandom::Error>/[]/high/{}",
}

func TestLoadEmbeddedRustGetrandomContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderGetrandomContracts(t)
	want := append([]string(nil), wantGetrandomContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("getrandom contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected getrandom contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing getrandom contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that -- not the authored spelling -- is what the parser looks up. Every key
// and arity below was read off `--export-callgraph` for a probe consumer that
// calls each entry point in both the crate-qualified and the imported form;
// before getrandom.yaml existed all six rendered as `name(?)` with empty
// parameter_types.
func TestGetrandomEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := map[string]int{
		"getrandom.getrandom":        1,
		"getrandom.getrandom_uninit": 1,
		"getrandom.fill":             1,
		"getrandom.fill_uninit":      1,
		"getrandom.u32":              0,
		"getrandom.u64":              0,
	}
	for m, a := range emitted {
		got := kb.ContractsFor(m, a)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", m, a)
			continue
		}
		if got[0].SourceLibrary != "getrandom" {
			t.Errorf("%s: library = %q, want getrandom", m, got[0].SourceLibrary)
		}
	}
}

// THE BYTES THESE CALLS PRODUCE ARE NOT A KEY, and the contract must never say
// they are. `internal/scan/key_length.go:20` consumes the `keySize` property
// and nothing else to emit `resolved_key_length` evidence, so a `keySize`
// contribution on the destination buffer would publish a key length for random
// bytes whose use the call site does not determine. The buffer length is
// declared as `dataLength` instead, following blake3.yaml:313-318 for the same
// out-parameter shape.
func TestGetrandomContributesNoKeySize(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	seen := 0
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "getrandom" {
				continue
			}
			seen++
			for _, p := range c.Parameters {
				if p.Contributes == nil {
					continue
				}
				if p.Contributes.Property == "keySize" {
					t.Errorf("%s parameter %q contributes keySize: getrandom returns "+
						"raw OS entropy, not key material, and the caller's buffer "+
						"length is not a key length", c.Method, p.Name)
				}
			}
		}
	}
	// Positive control: a zero here would pass the assertion above for the
	// wrong reason -- see the campaign rule that every zero needs the count
	// proving the tool was loaded.
	if seen != len(wantGetrandomContracts) {
		t.Fatalf("scanned %d getrandom contracts, want %d -- the assertion above "+
			"proves nothing if the library did not load", seen, len(wantGetrandomContracts))
	}
}

// The library block is parsed and then never consulted by any assertion above,
// so corrupting version_range, coordinates, name or description loads cleanly
// and leaves every contract assertion green. Read the file itself and pin them.
//
// The range starts at 0.1.0 rather than 0.0.0 because 0.0.0 is a name
// reservation whose src/lib.rs is a license header with no API at all. It stops
// below 0.5.0 so every 0.4.x row the Tier 0 matrix lists is inside it.
func TestRustGetrandomLibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("rust/getrandom.yaml")
	if err != nil {
		t.Fatalf("read rust/getrandom.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(rust/getrandom.yaml): %v", err)
	}
	if kb.Library == nil {
		t.Fatal("getrandom.yaml declares no library block")
	}
	lib := kb.Library

	if lib.Name != "getrandom" {
		t.Errorf("library.name = %q, want %q", lib.Name, "getrandom")
	}
	if want := ">=0.1.0,<0.5.0"; lib.VersionRange != want {
		t.Errorf("version_range = %q, want %q -- 0.0.0 declares no API and the "+
			"upper bound must admit every 0.4.x row the matrix lists",
			lib.VersionRange, want)
	}
	if len(lib.Coordinates) != 1 || lib.Coordinates[0] != "getrandom" {
		t.Errorf("coordinates = %v, want [getrandom]", lib.Coordinates)
	}
	if lib.Description == "" {
		t.Error("library.description is empty")
	}
	if kb.Ecosystem != "rust" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema_version = %q/%q, want rust/2", kb.Ecosystem, kb.SchemaVersion)
	}
}
