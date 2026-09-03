// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The KB is asserted as a SET, not as a sample.
//
// A per-key subset assertion cannot see an entry that should not be there, an
// entry that was dropped, or a field that was corrupted. Comparing the whole
// rendered set means no entry can be added, removed or altered without this
// test saying so, which is what makes a short mutation check sufficient.
func TestBlstrsContractSetIsExact(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	type row struct {
		method string
		arity  int
		role   string
		ret    string
		params []string
	}
	want := []row{
		{"blstrs.pairing", 2, "operation", "blstrs::Gt", []string{"blstrs::G1Affine", "blstrs::G2Affine"}},
		{"blstrs::Bls12.multi_miller_loop", 1, "operation", "blstrs::MillerLoopResult", []string{"&[(&blstrs::G1Affine, &blstrs::G2Prepared)]"}},
		{"blstrs::Bls12.pairing", 2, "operation", "blstrs::Gt", []string{"blstrs::G1Affine", "blstrs::G2Affine"}},
		{"blstrs::G1Affine.from_compressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 48]"}},
		{"blstrs::G1Affine.from_compressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 48]"}},
		{"blstrs::G1Affine.from_uncompressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G1Affine.from_uncompressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G1Affine.to_compressed", 0, "output", "[u8; 48]", []string{}},
		{"blstrs::G1Affine.to_uncompressed", 0, "output", "[u8; 96]", []string{}},
		{"blstrs::G1Projective.from_compressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 48]"}},
		{"blstrs::G1Projective.from_compressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 48]"}},
		{"blstrs::G1Projective.from_uncompressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G1Projective.from_uncompressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G1Projective.hash_to_curve", 3, "operation", "blstrs::G1Projective", []string{"&[u8]", "&[u8]", "&[u8]"}},
		{"blstrs::G1Projective.to_compressed", 0, "output", "[u8; 48]", []string{}},
		{"blstrs::G1Projective.to_uncompressed", 0, "output", "[u8; 96]", []string{}},
		{"blstrs::G2Affine.from_compressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G2Affine.from_compressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G2Affine.from_uncompressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 192]"}},
		{"blstrs::G2Affine.from_uncompressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 192]"}},
		{"blstrs::G2Affine.to_compressed", 0, "output", "[u8; 96]", []string{}},
		{"blstrs::G2Affine.to_uncompressed", 0, "output", "[u8; 192]", []string{}},
		{"blstrs::G2Projective.from_compressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G2Projective.from_compressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 96]"}},
		{"blstrs::G2Projective.from_uncompressed", 1, "factory", "subtle::CtOption", []string{"&[u8; 192]"}},
		{"blstrs::G2Projective.from_uncompressed_unchecked", 1, "factory", "subtle::CtOption", []string{"&[u8; 192]"}},
		{"blstrs::G2Projective.hash_to_curve", 3, "operation", "blstrs::G2Projective", []string{"&[u8]", "&[u8]", "&[u8]"}},
		{"blstrs::G2Projective.to_compressed", 0, "output", "[u8; 96]", []string{}},
		{"blstrs::G2Projective.to_uncompressed", 0, "output", "[u8; 192]", []string{}},
		{"blstrs::Gt.read_compressed", 1, "factory", "std::io::Result", []string{"std::io::Read"}},
		{"blstrs::Gt.write_compressed", 1, "output", "std::io::Result", []string{"std::io::Write"}},
		{"blstrs::MillerLoopResult.final_exponentiation", 0, "operation", "blstrs::Gt", []string{}},
		{"blstrs::PairingG1G2.new", 2, "factory", "blstrs::PairingG1G2", []string{"bool", "&[u8]"}},
		{"blstrs::PairingG2G1.new", 2, "factory", "blstrs::PairingG2G1", []string{"bool", "&[u8]"}},
	}

	render := func(r row) string {
		return fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=high",
			r.method, r.arity, r.role, r.ret, strings.Join(r.params, ","))
	}

	wantSet := map[string]bool{}
	for _, r := range want {
		wantSet[render(r)] = true
	}

	gotSet := map[string]bool{}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "blstrs" {
				continue
			}
			gotSet[fmt.Sprintf("%s#%d role=%s ret=%s params=[%s] conf=%s",
				c.Method, c.Arity, c.Role, c.Return.Type,
				strings.Join(c.ParameterTypes, ","), c.Return.Confidence)] = true
		}
	}

	var missing, unexpected []string
	for k := range wantSet {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for k := range gotSet {
		if !wantSet[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	for _, m := range missing {
		t.Errorf("missing from the KB: %s", m)
	}
	for _, u := range unexpected {
		t.Errorf("present in the KB but not declared here: %s", u)
	}
}

// Keys are authored in the CONVENTION shape `blstrs::Type.method`, not in the
// shape the call graph emits (`blstrs.Type.method`). rustAuthoredKey bridges
// the emitted form onto this one; authoring the emitted form leaves the entry
// loadable but unreachable, which looks exactly like having no contract.
//
// The free function `blstrs.pairing` is the deliberate exception: it has no
// receiver type, so there is no module/type separator to move, and
// rustAuthoredKey returns a key with fewer than two dots unchanged.
func TestBlstrsKeysUseTheAuthoredShape(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "blstrs" {
				continue
			}
			if c.Method == "blstrs.pairing" {
				continue
			}
			head := c.Method
			if i := strings.LastIndex(head, "."); i > 0 {
				head = head[:i]
			}
			if strings.Contains(head, ".") {
				t.Errorf("%s: module path uses '.', want '::' (the authored shape)", c.Method)
			}
		}
	}
}

// `final_exponentiation` on a chained receiver must be keyed on
// MillerLoopResult, not on Bls12.
//
// This pins a measurement, not a preference. Before the contract declared
// `multi_miller_loop`'s return type, the parser had nothing to type the
// receiver of `Bls12::multi_miller_loop(..).final_exponentiation()` with and
// emitted `blstrs.Bls12.final_exponentiation()` -- a key no contract can join,
// and a fact about the missing return type rather than about the library.
// blstrs 0.7.1 pairing.rs:167-170 implements the method on MillerLoopResult.
func TestBlstrsChainedFinalExponentiationIsTypedOnMillerLoopResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use blstrs::{Bls12, G1Affine, G2Prepared, Gt};
fn f(a: &G1Affine, b: &G2Prepared) -> Gt {
    let ml = Bls12::multi_miller_loop(&[(a, b)]);
    ml.final_exponentiation()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for ai := range analyses {
		fns := analyses[ai].Functions
		for fi := range fns {
			calls := fns[fi].Calls
			for ci := range calls {
				callee := calls[ci].Callee
				m, _ := splitMethodArity(&callee)
				seen[m] = len(calls[ci].Arguments)
			}
		}
	}
	if _, ok := seen["blstrs.MillerLoopResult.final_exponentiation"]; !ok {
		t.Errorf("chained final_exponentiation is not keyed on MillerLoopResult; seen = %v", seen)
	}
	if _, ok := seen["blstrs.Bls12.final_exponentiation"]; ok {
		t.Errorf("chained final_exponentiation is still keyed on Bls12; seen = %v", seen)
	}
}

// The curve-arithmetic surface must stay out: those calls move a value between
// representations or do field arithmetic, and carry no crypto asset. This is
// what the family note means by "exclude generic scalar arithmetic".
func TestBlstrsArithmeticSurfaceIsAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"blstrs::G1Projective.double", 0},
		{"blstrs::G1Projective.add", 1},
		{"blstrs::G1Projective.add_mixed", 1},
		{"blstrs::G1Projective.multi_exp", 2},
		{"blstrs::G1Projective.to_affine", 0},
		{"blstrs::G1Projective.generator", 0},
		{"blstrs::G1Projective.identity", 0},
		{"blstrs::G1Affine.x", 0},
		{"blstrs::G1Affine.y", 0},
		{"blstrs::G1Affine.is_on_curve", 0},
		{"blstrs::G1Affine.is_torsion_free", 0},
		{"blstrs::G1Affine.from_raw_unchecked", 3},
		{"blstrs::G1Affine.write_raw", 1},
		{"blstrs::G1Affine.read_raw", 1},
		{"blstrs::Scalar.invert", 0},
		{"blstrs::Scalar.square", 0},
		// Not arithmetic, but absent for the reason the file header gives: these
		// two exist only in 0.1.0-0.3.1, which is outside the declared range.
		{"blstrs::Bls12.miller_loop", 1},
		{"blstrs::Bls12.final_exponentiation", 1},
	} {
		if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 0 {
			t.Errorf("%s/%d resolved to %d contracts; it must stay absent", tc.method, tc.arity, len(got))
		}
	}
}
