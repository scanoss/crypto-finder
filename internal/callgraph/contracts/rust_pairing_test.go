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

// `pairing` is a trait vocabulary for pairing-friendly curves. Its four traits
// live at the CRATE ROOT, so the graph emits `pairing.Engine.pairing` with no
// module segment and the KB file authors `pairing::Engine.pairing`
// (rustAuthoredKey moves the second-to-last dot at load time). The 0.9.0-0.16.0
// bundled curve is reached through a submodule and keeps its segment, so the
// same file carries both shapes: `pairing::bls12_381::Bls12.pairing` for a key
// the graph emits as `pairing::bls12_381.Bls12.pairing`. Authoring the emitted
// form produces a KB that loads without error and joins nothing.
//
// The set below is compared EXACTLY, not per key. A per-key assertion cannot
// see an entry that should not be there, an entry that was dropped, or a field
// that was corrupted; only the whole-set comparison does.
func renderPairingContracts(t *testing.T) []string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "pairing" {
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

var wantPairingContracts = []string{
	"pairing::CurveAffine.pairing_with#1/operation/pairing::CurveAffine::PairingResult/pairing::CurveAffine::PairingResult/[&pairing::CurveAffine::Pair]/high",
	"pairing::CurveAffine.pairing_with#2/operation/pairing::CurveAffine::PairingResult/pairing::CurveAffine::PairingResult/[&pairing::CurveAffine,&pairing::CurveAffine::Pair]/high",
	"pairing::Engine.final_exponentiation#1/operation/core::option::Option/core::option::Option/[&pairing::Engine::Fqk]/high",
	"pairing::Engine.miller_loop#1/operation/pairing::Engine::Fqk/pairing::Engine::Fqk/[I]/high",
	"pairing::Engine.pairing#2/operation/pairing::Engine::Gt//[]/medium",
	"pairing::MillerLoopResult.final_exponentiation#0/output/pairing::MillerLoopResult::Gt/pairing::MillerLoopResult::Gt/[]/high",
	"pairing::MillerLoopResult.final_exponentiation#1/output/pairing::MillerLoopResult::Gt/pairing::MillerLoopResult::Gt/[&pairing::MillerLoopResult]/high",
	"pairing::MultiMillerLoop.multi_miller_loop#1/operation/pairing::MultiMillerLoop::Result/pairing::MultiMillerLoop::Result/[&[(&pairing::Engine::G1Affine, &pairing::MultiMillerLoop::G2Prepared)]]/high",
	"pairing::PairingCurveAffine.pairing_with#1/operation/pairing::PairingCurveAffine::PairingResult/pairing::PairingCurveAffine::PairingResult/[&pairing::PairingCurveAffine::Pair]/high",
	"pairing::PairingCurveAffine.pairing_with#2/operation/pairing::PairingCurveAffine::PairingResult/pairing::PairingCurveAffine::PairingResult/[&pairing::PairingCurveAffine,&pairing::PairingCurveAffine::Pair]/high",
	"pairing::bls12_381::Bls12.final_exponentiation#1/operation/core::option::Option/core::option::Option/[&pairing::bls12_381::Fq12]/high",
	"pairing::bls12_381::Bls12.miller_loop#1/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[I]/high",
	"pairing::bls12_381::Bls12.pairing#2/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[G1,G2]/high",
	"pairing::bls12_381::G1Affine.pairing_with#1/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[&pairing::bls12_381::G2Affine]/high",
	"pairing::bls12_381::G1Affine.pairing_with#2/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[&pairing::bls12_381::G1Affine,&pairing::bls12_381::G2Affine]/high",
	"pairing::bls12_381::G2Affine.pairing_with#1/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[&pairing::bls12_381::G1Affine]/high",
	"pairing::bls12_381::G2Affine.pairing_with#2/operation/pairing::bls12_381::Fq12/pairing::bls12_381::Fq12/[&pairing::bls12_381::G2Affine,&pairing::bls12_381::G1Affine]/high",
}

func TestLoadEmbeddedRustPairingContractsExactSet(t *testing.T) {
	t.Parallel()

	got := renderPairingContracts(t)
	want := append([]string(nil), wantPairingContracts...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("pairing contracts: got %d, want %d", len(got), len(want))
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
			t.Errorf("unexpected pairing contract: %s", g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing pairing contract:    %s", w)
		}
	}
}

// The dot-joined spelling the call graph actually emits must resolve, because
// that — not the authored spelling — is what the parser looks up. Every key
// below was read off the exported call graph of a probe crate that imports
// `pairing` and calls each entry point the way published consumers do.
func TestPairingEmittedCallSiteKeysResolve(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// A SLICE, not a map: several keys must resolve at MORE THAN ONE arity, and
	// a map cannot express that. `rustContractsFor` (contracts.go:240) is
	// exact-arity for every ecosystem but Python, so a key declared at one
	// arity resolves for one spelling only — the UFCS form counts the receiver
	// and the method form does not.
	emitted := []struct {
		method string
		arity  int
	}{
		{"pairing.Engine.pairing", 2},
		{"pairing.Engine.miller_loop", 1},
		{"pairing.Engine.final_exponentiation", 1},
		{"pairing.MultiMillerLoop.multi_miller_loop", 1},
		{"pairing.MillerLoopResult.final_exponentiation", 0},
		{"pairing.MillerLoopResult.final_exponentiation", 1},
		{"pairing.PairingCurveAffine.pairing_with", 1},
		{"pairing.PairingCurveAffine.pairing_with", 2},
		{"pairing.CurveAffine.pairing_with", 1},
		{"pairing.CurveAffine.pairing_with", 2},
		{"pairing::bls12_381.Bls12.pairing", 2},
		{"pairing::bls12_381.Bls12.miller_loop", 1},
		{"pairing::bls12_381.Bls12.final_exponentiation", 1},
		{"pairing::bls12_381.G1Affine.pairing_with", 1},
		{"pairing::bls12_381.G1Affine.pairing_with", 2},
		{"pairing::bls12_381.G2Affine.pairing_with", 1},
		{"pairing::bls12_381.G2Affine.pairing_with", 2},
	}
	for _, tc := range emitted {
		m, a := tc.method, tc.arity
		got := kb.ContractsFor(m, a)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for the emitted key", m, a)
			continue
		}
		if got[0].SourceLibrary != "pairing" {
			t.Errorf("%s: library = %q, want pairing", m, got[0].SourceLibrary)
		}
	}
}

// `final_exponentiation` is keyed at BOTH arities on purpose and the two must
// not swallow each other: `ml.final_exponentiation()` counts no receiver while
// `pairing::MillerLoopResult::final_exponentiation(&ml)` counts one. Both
// spellings were observed on the probe.
func TestPairingFinalExponentiationIsKeyedAtBothArities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	zero := kb.ContractsFor("pairing::MillerLoopResult.final_exponentiation", 0)
	one := kb.ContractsFor("pairing::MillerLoopResult.final_exponentiation", 1)
	if len(zero) != 1 || len(one) != 1 {
		t.Fatalf("final_exponentiation: arity 0 -> %d contracts, arity 1 -> %d, want 1 and 1",
			len(zero), len(one))
	}
	if len(zero[0].ParameterTypes) != 0 {
		t.Errorf("arity 0 declares parameter types %v, want none", zero[0].ParameterTypes)
	}
	if len(one[0].ParameterTypes) != 1 {
		t.Errorf("arity 1 declares parameter types %v, want exactly the receiver", one[0].ParameterTypes)
	}
	// The 0.9.0-0.16.0 Engine also declares a `final_exponentiation`, at the
	// crate root rather than on MillerLoopResult, and it must stay a separate
	// key: it returns Option and takes the Miller-loop value by reference.
	era1 := kb.ContractsFor("pairing::Engine.final_exponentiation", 1)
	if len(era1) != 1 {
		t.Fatalf("pairing::Engine.final_exponentiation#1 -> %d contracts, want 1", len(era1))
	}
	if era1[0].CanonicalReturnType != "core::option::Option" {
		t.Errorf("era-1 final_exponentiation returns %q, want core::option::Option",
			era1[0].CanonicalReturnType)
	}
}

// The one key the 0.16.0 -> 0.17.0 break does not split. 0.23.0 lib.rs:77
// declares `pairing(&Self::G1Affine, &Self::G2Affine) -> Self::Gt` and 0.16.0
// lib.rs:89 declares `pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk`; the trait
// never moves modules, so both eras land on one method+arity. Publishing either
// declared signature as canonical would be false for half the supported range,
// so this entry deliberately carries neither and its confidence is medium.
// A future edit that "completes" it would silently publish a wrong signature.
func TestPairingEngineDeclaresNoCanonicalSignature(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	got := kb.ContractsFor("pairing::Engine.pairing", 2)
	if len(got) != 1 {
		t.Fatalf("pairing::Engine.pairing#2 -> %d contracts, want 1", len(got))
	}
	c := got[0]
	if c.CanonicalReturnType != "" {
		t.Errorf("canonical_return_type = %q, want empty across the version break", c.CanonicalReturnType)
	}
	if len(c.ParameterTypes) != 0 {
		t.Errorf("parameter_types = %v, want none across the version break", c.ParameterTypes)
	}
	if c.Return.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", c.Return.Confidence)
	}
}

// The bundled BLS12-381 engine is the ONLY part of this crate that names a
// curve, and only in 0.9.0-0.16.0 (`pub mod bls12_381`, 0.16.0 lib.rs:21;
// removed at 0.17.0). Its keys must keep the module segment, because a key
// without it would collide with the generic trait entries.
func TestPairingBundledCurveKeysKeepTheModuleSegment(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"pairing::bls12_381::Bls12.pairing", 2},
		{"pairing::bls12_381::Bls12.miller_loop", 1},
		{"pairing::bls12_381::Bls12.final_exponentiation", 1},
		{"pairing::bls12_381::G1Affine.pairing_with", 1},
		{"pairing::bls12_381::G2Affine.pairing_with", 1},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 1 {
			t.Errorf("ContractsFor(%q, %d) -> %d contracts, want 1", tc.method, tc.arity, len(got))
		}
	}
	// The unqualified spelling must NOT resolve: it is the generic trait's key.
	if got := kb.ContractsFor("pairing::Bls12.pairing", 2); len(got) != 0 {
		t.Errorf("pairing::Bls12.pairing#2 resolved to %d contracts, want 0", len(got))
	}
}
