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

// boringtun never re-exports `Tunn` from the crate root, so the graph emits
// `boringtun::noise.Tunn.new` and the KB file authors
// `boringtun::noise::Tunn.new` — rustAuthoredKey moves the second-to-last dot
// when the file loads. Authoring the emitted form instead produces a KB that
// loads without error and joins nothing, which is indistinguishable from
// having no contract.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does.
func renderBoringtunContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "boringtun" {
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

var wantBoringtunContracts = []string{
	"boringtun::noise::Tunn.decapsulate#3/operation/boringtun::noise::TunnResult/TunnResult<'a>/[Option<IpAddr>,&[u8],&mut [u8]]/high",
	"boringtun::noise::Tunn.encapsulate#2/operation/boringtun::noise::TunnResult/TunnResult<'a>/[&[u8],&mut [u8]]/high",
	"boringtun::noise::Tunn.network_to_tunnel#2/operation/boringtun::noise::TunnResult/TunnResult<'a>/[&[u8],&mut [u8]]/high",
	"boringtun::noise::Tunn.new#5/factory/boringtun::noise::Tunn/Result<Box<Tunn>, &'static str>/[Arc<X25519SecretKey>,Arc<X25519PublicKey>,Option<[u8; 32]>,Option<u16>,u32]/high",
	"boringtun::noise::Tunn.new#6/factory/boringtun::noise::Tunn//[]/high",
	"boringtun::noise::Tunn.tunnel_to_network#2/operation/boringtun::noise::TunnResult/TunnResult<'a>/[&[u8],&mut [u8]]/high",
	"boringtun::noise::Tunn.update_timers#1/operation/boringtun::noise::TunnResult/TunnResult<'a>/[&mut [u8]]/high",
}

func TestLoadEmbeddedRustBoringtunContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderBoringtunContracts(t)
	want := append([]string(nil), wantBoringtunContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("boringtun contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected boringtun contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing boringtun contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Read off the
// exported call graph of a probe consumer holding a `Tunn` in a struct field:
// every key came back `boringtun::noise.Tunn.<method>` with empty
// parameter_types before this KB existed.
func TestBoringtunEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	emitted := map[string]int{
		"boringtun::noise.Tunn.new":               6,
		"boringtun::noise.Tunn.encapsulate":       2,
		"boringtun::noise.Tunn.decapsulate":       3,
		"boringtun::noise.Tunn.update_timers":     1,
		"boringtun::noise.Tunn.tunnel_to_network": 2,
		"boringtun::noise.Tunn.network_to_tunnel": 2,
	}
	for m, a := range emitted {
		got := kb.ContractsFor(m, a)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", m, a)
			continue
		}
		if got[0].SourceLibrary != "boringtun" {
			t.Errorf("%s: library = %q, want boringtun", m, got[0].SourceLibrary)
		}
	}

	// The 0.2.0 constructor arity must resolve independently of the modern one.
	if got := kb.ContractsFor("boringtun::noise.Tunn.new", 5); len(got) == 0 {
		t.Error(`ContractsFor("boringtun::noise.Tunn.new", 5): the 0.2.0 arity did not resolve`)
	} else if got[0].CanonicalReturnType == "" {
		t.Error("the arity-5 constructor should declare its canonical return; only the arity-6 one omits it")
	}

	// And the arity-6 constructor deliberately declares NO canonical return —
	// its declared return changed at 0.7.0 without a name or arity change, so
	// any single value would be false for part of the range.
	if got := kb.ContractsFor("boringtun::noise.Tunn.new", 6); len(got) != 0 && got[0].CanonicalReturnType != "" {
		t.Errorf("the arity-6 constructor must omit canonical_return_type, got %q", got[0].CanonicalReturnType)
	}
}
