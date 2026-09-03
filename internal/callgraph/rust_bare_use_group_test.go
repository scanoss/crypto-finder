// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A BARE brace group -- `use { a::B, c::{D, E} };` with no path in front of the
// brace -- binds imports exactly as the one-per-line form does. Before this was
// handled, the whole declaration was skipped: none of its items were recorded,
// and every type it brought in resolved to the SCANNED crate instead of the
// crate it came from.
//
// That is a wrong identity rather than a missing one, so no contract can join
// it and the receiver of a chained call is mistyped along with it. Measured on
// agave-bls12-381 4.0.3 src/pairing.rs, which uses this form: the graph emitted
// `agave_bls12_381::pairing.Bls12.multi_miller_loop(?)` where the same code
// written one import per line emits `blstrs.Bls12.multi_miller_loop(..)`.
//
// The form is not exotic: it is what `rustfmt` produces under
// `imports_granularity=One`, and the Solana and Agave trees use it throughout.
func calleeArities(t *testing.T, src string) map[string]int {
	t.Helper()
	dir := t.TempDir()
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
	return seen
}

// calleePackages renders each call as "Type.name" -> the package the parser
// attributed it to, which is what a wrong import binding corrupts.
func calleePackages(t *testing.T, src string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for ai := range analyses {
		fns := analyses[ai].Functions
		for fi := range fns {
			calls := fns[fi].Calls
			for ci := range calls {
				c := &calls[ci].Callee
				seen[c.Type+"."+c.Name] = c.Package
			}
		}
	}
	return seen
}

func TestRustBareUseGroupBindsImportsLikeTheOnePerLineForm(t *testing.T) {
	t.Parallel()

	plain := `use blstrs::{Bls12, G1Affine, G2Prepared, Gt};
use group::Group;
fn f(a: &G1Affine, b: &G2Prepared) -> Gt {
    let ml = Bls12::multi_miller_loop(&[(a, b)]);
    ml.final_exponentiation()
}
`
	bare := `use {
    blstrs::{Bls12, G1Affine, G2Prepared, Gt},
    group::Group,
};
fn f(a: &G1Affine, b: &G2Prepared) -> Gt {
    let ml = Bls12::multi_miller_loop(&[(a, b)]);
    ml.final_exponentiation()
}
`
	want := calleeArities(t, plain)
	got := calleeArities(t, bare)

	if _, ok := want["blstrs.Bls12.multi_miller_loop"]; !ok {
		t.Fatalf("the one-per-line control did not resolve to blstrs; seen = %v", want)
	}
	for key, arity := range want {
		if gotArity, ok := got[key]; !ok || gotArity != arity {
			t.Errorf("bare use group lost %s/%d (present=%v, arity=%d); seen = %v",
				key, arity, ok, gotArity, got)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("bare use group produced an extra callee %s; seen = %v", key, got)
		}
	}
}

// A bare group mixing a relative root with a dependency is the shape that made
// the defect visible, because `crate::` in the same braces is what a reader
// assumes anchors the whole declaration. It does not: each item carries its own
// root, and BOTH halves have to come out right. An earlier revision of this fix
// routed the group's items through the use-LIST handler, which gave every item
// an empty prefix -- so the dependency half resolved while `crate::config` was
// recorded as a literal package that joins nothing. Both are asserted here.
func TestRustBareUseGroupMixesRelativeAndDependencyRoots(t *testing.T) {
	t.Parallel()

	src := `pub mod config { pub struct Version; }
use {
    crate::config::Version,
    blstrs::{Bls12, G1Affine, G2Affine, Gt},
};
fn f(a: &G1Affine, b: &G2Affine) -> Gt {
    let _ = Version::parse();
    Bls12::pairing(a, b)
}
`
	seen := calleePackages(t, src)
	if got := seen["Bls12.pairing"]; got != "blstrs" {
		t.Errorf("Bls12::pairing attributed to %q, want blstrs; seen = %v", got, seen)
	}
	if got := seen["Version.parse"]; got != "app::config" {
		t.Errorf("Version::parse attributed to %q, want app::config (the resolved module, "+
			"not the literal \"crate::config\"); seen = %v", got, seen)
	}
}

// EVERY item shape inside a bare group must come out exactly as it does when
// written one import per line. The four here are the ones that went wrong when
// the fix was first written: a plain crate name lost its package entirely, a
// relative root stayed literal, a glob was dropped, and only the aliased and
// braced forms happened to work.
func TestRustBareUseGroupMatchesOnePerLineForEveryItemShape(t *testing.T) {
	t.Parallel()

	for name, pair := range map[string][2]string{
		"plain crate item": {
			"use serde_json;\nfn f(v: &str) { serde_json::to_string(v); }\n",
			"use { serde_json, blstrs::Bls12 };\nfn f(v: &str) { serde_json::to_string(v); }\n",
		},
		"relative root": {
			"pub mod config { pub struct Version; }\nuse crate::config::Version;\nfn f() { Version::parse(); }\n",
			"pub mod config { pub struct Version; }\nuse { crate::config::Version, blstrs::Bls12 };\nfn f() { Version::parse(); }\n",
		},
		"glob": {
			"use blstrs::*;\nfn f() { let _ = G1Projective::hash_to_curve(b\"m\", b\"d\", b\"\"); }\n",
			"use { blstrs::* };\nfn f() { let _ = G1Projective::hash_to_curve(b\"m\", b\"d\", b\"\"); }\n",
		},
		"crate alias": {
			"use blstrs as bl;\nfn f() { let _ = bl::Bls12::pairing(1, 2); }\n",
			"use { blstrs as bl };\nfn f() { let _ = bl::Bls12::pairing(1, 2); }\n",
		},
	} {
		onePerLine := calleePackages(t, pair[0])
		bareGroup := calleePackages(t, pair[1])
		for key, want := range onePerLine {
			if got, ok := bareGroup[key]; !ok || got != want {
				t.Errorf("%s: %s attributed to %q in a bare group, %q one import per line",
					name, key, got, want)
			}
		}
		if len(bareGroup) != len(onePerLine) {
			t.Errorf("%s: bare group produced %v, one import per line produced %v",
				name, bareGroup, onePerLine)
		}
	}
}

// The forms that already worked must keep working: a path-prefixed group, a
// simple scoped import and a crate alias.
//
// A glob (`use blstrs::*;`) is not asserted HERE, because RESOLVING one needs
// the crate index built from the manifest, so in a bare temp directory it falls
// back to the scanned crate on origin/main exactly as it does on this branch --
// measured both ways before writing this. What this change is responsible for is
// that the glob is RECORDED at all, and that is asserted by the parity test
// above, which compares `WildcardImports` through the callee it produces. The
// glob resolution path keeps its own coverage in
// rust_glob_declaring_module_test.go and friends.
func TestRustExistingUseFormsAreUnchanged(t *testing.T) {
	t.Parallel()

	for name, src := range map[string]string{
		"scoped group": `use blstrs::{Bls12, G1Affine, G2Affine};
fn f(a: &G1Affine, b: &G2Affine) { let _ = Bls12::pairing(a, b); }
`,
		"scoped identifier": `use blstrs::Bls12;
fn f(a: u8, b: u8) { let _ = Bls12::pairing(a, b); }
`,
		"crate alias": `use blstrs as bl;
fn f(a: u8, b: u8) { let _ = bl::Bls12::pairing(a, b); }
`,
	} {
		seen := calleeArities(t, src)
		if _, ok := seen["blstrs.Bls12.pairing"]; !ok {
			t.Errorf("%s: Bls12::pairing no longer resolves to blstrs; seen = %v", name, seen)
		}
	}
}
