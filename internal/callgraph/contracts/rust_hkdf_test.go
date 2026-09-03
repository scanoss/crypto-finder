// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// RustCrypto hkdf exports every type from the crate ROOT, so the graph emits
// `hkdf.Hkdf.new` with no module segment and the KB file authors
// `hkdf::Hkdf.new` — rustAuthoredKey moves the second-to-last dot when the file
// loads. Authoring the emitted form instead produces a KB that loads without
// error and joins nothing, which is indistinguishable from having no contract.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does.
func renderHkdfContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "hkdf" {
				continue
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/%s/[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, c.CanonicalReturnType,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence))
		}
	}
	sort.Strings(got)
	return got
}

var wantHkdfContracts = []string{
	"hkdf::GenericHkdf.expand#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[u8],&mut [u8]]/high",
	"hkdf::GenericHkdf.expand_multi_info#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[&[u8]],&mut [u8]]/high",
	"hkdf::GenericHkdf.extract#2/factory/hkdf::GenericHkdf/(digest::Output<H>, hkdf::GenericHkdf<H>)/[Option<&[u8]>,&[u8]]/high",
	"hkdf::GenericHkdf.from_prk#1/factory/hkdf::GenericHkdf/core::result::Result<hkdf::GenericHkdf<H>, hkdf::InvalidPrkLength>/[&[u8]]/high",
	"hkdf::GenericHkdf.new#2/factory/hkdf::GenericHkdf//[Option<&[u8]>,&[u8]]/high",
	"hkdf::GenericHkdfExtract.finalize#0/output/hkdf::GenericHkdf/(digest::Output<H>, hkdf::GenericHkdf<H>)/[]/high",
	"hkdf::GenericHkdfExtract.input_ikm#1/operation/()//[&[u8]]/high",
	"hkdf::GenericHkdfExtract.new#1/factory/hkdf::GenericHkdfExtract//[Option<&[u8]>]/high",
	"hkdf::Hkdf.derive#2/output/alloc::vec::Vec/alloc::vec::Vec<u8>/[&[u8],usize]/high",
	"hkdf::Hkdf.expand#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[u8],&mut [u8]]/high",
	"hkdf::Hkdf.expand_multi_info#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[&[u8]],&mut [u8]]/high",
	"hkdf::Hkdf.extract#2/factory/hkdf::Hkdf/(digest::Output<H>, hkdf::Hkdf<H, I>)/[Option<&[u8]>,&[u8]]/high",
	"hkdf::Hkdf.from_prk#1/factory/hkdf::Hkdf/core::result::Result<hkdf::Hkdf<H, I>, hkdf::InvalidPrkLength>/[&[u8]]/high",
	"hkdf::Hkdf.new#2/factory/hkdf::Hkdf//[Option<&[u8]>,&[u8]]/high",
	"hkdf::Hkdf.new#3/factory/hkdf::Hkdf//[&str,&[u8],&[u8]]/high",
	"hkdf::HkdfExtract.finalize#0/output/hkdf::Hkdf/(digest::Output<H>, hkdf::Hkdf<H, I>)/[]/high",
	"hkdf::HkdfExtract.input_ikm#1/operation/()//[&[u8]]/high",
	"hkdf::HkdfExtract.new#1/factory/hkdf::HkdfExtract//[Option<&[u8]>]/high",
	"hkdf::SimpleHkdf.expand#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[u8],&mut [u8]]/high",
	"hkdf::SimpleHkdf.expand_multi_info#2/operation/()/core::result::Result<(), hkdf::InvalidLength>/[&[&[u8]],&mut [u8]]/high",
	"hkdf::SimpleHkdf.extract#2/factory/hkdf::SimpleHkdf/(digest::Output<H>, hkdf::SimpleHkdf<H>)/[Option<&[u8]>,&[u8]]/high",
	"hkdf::SimpleHkdf.from_prk#1/factory/hkdf::SimpleHkdf/core::result::Result<hkdf::SimpleHkdf<H>, hkdf::InvalidPrkLength>/[&[u8]]/high",
	"hkdf::SimpleHkdf.new#2/factory/hkdf::SimpleHkdf//[Option<&[u8]>,&[u8]]/high",
	"hkdf::SimpleHkdfExtract.finalize#0/output/hkdf::SimpleHkdf/(digest::Output<H>, hkdf::SimpleHkdf<H>)/[]/high",
	"hkdf::SimpleHkdfExtract.input_ikm#1/operation/()//[&[u8]]/high",
	"hkdf::SimpleHkdfExtract.new#1/factory/hkdf::SimpleHkdfExtract//[Option<&[u8]>]/high",
}

func TestLoadEmbeddedRustHkdfContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderHkdfContracts(t)
	want := append([]string(nil), wantHkdfContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("hkdf contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected hkdf contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing hkdf contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Measured on a
// probe consumer: `Hkdf::<Sha256>::new(Some(salt), ikm)` emits `hkdf.Hkdf.new`.
func TestHkdfEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// key -> arity, as read off the exported call graph of the probe consumer.
	emitted := map[string]int{
		"hkdf.Hkdf.new":                     2,
		"hkdf.Hkdf.extract":                 2,
		"hkdf.Hkdf.from_prk":                1,
		"hkdf.Hkdf.expand":                  2,
		"hkdf.Hkdf.expand_multi_info":       2,
		"hkdf.HkdfExtract.new":              1,
		"hkdf.HkdfExtract.input_ikm":        1,
		"hkdf.HkdfExtract.finalize":         0,
		"hkdf.SimpleHkdf.new":               2,
		"hkdf.SimpleHkdf.expand":            2,
		"hkdf.SimpleHkdfExtract.new":        1,
		"hkdf.SimpleHkdfExtract.input_ikm":  1,
		"hkdf.GenericHkdf.new":              2,
		"hkdf.GenericHkdf.expand":           2,
		"hkdf.GenericHkdfExtract.new":       1,
		"hkdf.GenericHkdfExtract.input_ikm": 1,
	}
	for m, a := range emitted {
		got := kb.ContractsFor(m, a)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", m, a)
			continue
		}
		if got[0].SourceLibrary != "hkdf" {
			t.Errorf("%s: library = %q, want hkdf", m, got[0].SourceLibrary)
		}
	}
}

// `new` is the one method whose arity genuinely differs across the supported
// window: 0.1.0 takes the digest by name (hkdf.rs:20), every release from 0.8.0
// takes `Option<&[u8]>` salt first (hkdf.rs:66). The method+arity index keys
// them apart, and neither may swallow the other.
func TestHkdfNewIsKeyedAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	two := kb.ContractsFor("hkdf::Hkdf.new", 2)
	three := kb.ContractsFor("hkdf::Hkdf.new", 3)
	if len(two) != 1 || len(three) != 1 {
		t.Fatalf("hkdf::Hkdf.new: arity 2 -> %d contracts, arity 3 -> %d, want 1 and 1", len(two), len(three))
	}
	if two[0].ParameterTypes[0] != "Option<&[u8]>" {
		t.Errorf("arity 2 first parameter = %q, want Option<&[u8]>", two[0].ParameterTypes[0])
	}
	if three[0].ParameterTypes[0] != "&str" {
		t.Errorf("arity 3 first parameter = %q, want &str (0.1.0 selects the digest by name)", three[0].ParameterTypes[0])
	}
}
