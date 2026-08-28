// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"sort"
	"strings"
	"testing"
)

// parseRustKeysWithTests returns every callee key a source emits, with the
// scan's test-inclusion setting under the caller's control.
func parseRustKeysWithTests(t *testing.T, src string, includeTests bool) []string {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser(WithIncludeTests(includeTests)).ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var keys []string
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				callee := analysis.Functions[i].Calls[j].Callee
				fqn, _ := splitMethodArity(&callee)
				keys = append(keys, fqn)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// TestRustParser_CfgTestModulesAreSkippedByDefault pins the boundary between
// two requirements that pull in opposite directions: inline modules must be
// walked, and a default scan must not report a crate's test-only code.
//
// Walking inline modules is what made these bodies reachable in the first
// place. Without the cfg gate, a crate whose published artifact uses only AES
// but whose `#[cfg(test)] mod tests` exercises DES emitted
// `des.Des.encrypt_block` and matched the des.yaml weak-cipher contract, in
// a scan that never asked for tests. Measured across 53 published crates, 59
// of 398 contract matches came from inline test bodies.
func TestRustParser_CfgTestModulesAreSkippedByDefault(t *testing.T) {
	const src = `
use aes::Aes128;
use des::Des;

pub fn ship(key: &[u8], block: &mut [u8; 16]) {
    let c = Aes128::new_from_slice(key);
    c.encrypt_block(block);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn only_under_cargo_test(key: &[u8], block: &mut [u8; 8]) {
        let c = Des::new_from_slice(key);
        c.encrypt_block(block);
    }
}
`
	t.Run("default scan reports only the shipped code", func(t *testing.T) {
		keys := parseRustKeysWithTests(t, src, false)
		joined := strings.Join(keys, "\n")
		if !strings.Contains(joined, "aes.Aes128.encrypt_block") {
			t.Errorf("production AES call lost; got:\n%s", joined)
		}
		for _, unwanted := range []string{
			"des.Des.encrypt_block", // the des.yaml weak-cipher key
			"des.Des.new_from_slice",
		} {
			if strings.Contains(joined, unwanted) {
				t.Errorf("test-only call %q reported in a default scan; got:\n%s", unwanted, joined)
			}
		}
	})

	t.Run("a scan that asks for tests still sees them", func(t *testing.T) {
		keys := parseRustKeysWithTests(t, src, true)
		joined := strings.Join(keys, "\n")
		for _, want := range []string{
			"aes.Aes128.encrypt_block",
			"des.Des.encrypt_block",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("want %q with tests included; got:\n%s", want, joined)
			}
		}
	})
}

// TestRustParser_OnlyTheTestCfgGatesAModule pins which predicates count. A
// module gated on a feature merely NAMED "test-utils" ships, so its calls must
// still be reported; `test` inside `all(..)` does not ship, so it must not.
func TestRustParser_OnlyTheTestCfgGatesAModule(t *testing.T) {
	cases := []struct {
		name    string
		attr    string
		skipped bool
	}{
		{"plain cfg(test)", "#[cfg(test)]", true},
		{"test nested in all()", "#[cfg(all(test, unix))]", true},
		{"test nested in any()", "#[cfg(any(test, feature = \"x\"))]", true},
		{"a feature whose name contains test", "#[cfg(feature = \"test-utils\")]", false},
		{"an unrelated cfg", "#[cfg(unix)]", false},
		{"a non-cfg attribute", "#[allow(dead_code)]", false},
		{"no attribute at all", "", false},
		// `not(test)` gates the module on NOT being a test build: it is the
		// standard spelling for the real implementation paired with a
		// `#[cfg(test)]` mock. Descending into `not(..)` read it as test-only
		// and dropped production code, which is the worse direction.
		{"not(test) is production, not test", "#[cfg(not(test))]", false},
		{"not(test) nested under any()", "#[cfg(any(not(test), feature = \"x\"))]", false},
		// An attribute stack and an intervening comment both still decorate
		// the same item; the walk back must not stop at either.
		{"an attribute stack", "#[allow(dead_code)]\n#[cfg(test)]", true},
		{"a line comment in between", "#[cfg(test)]\n// only under cargo test", true},
		{"a doc comment in between", "#[cfg(test)]\n/// only under cargo test", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.attr + `
mod gated {
    use des::Des;
    pub fn run(key: &[u8], block: &mut [u8; 8]) {
        let c = Des::new_from_slice(key);
        c.encrypt_block(block);
    }
}
`
			joined := strings.Join(parseRustKeysWithTests(t, src, false), "\n")
			got := !strings.Contains(joined, "des.Des.encrypt_block")
			if got != tc.skipped {
				verb := "was skipped"
				if !got {
					verb = "was walked"
				}
				t.Errorf("%s: module %s, want skipped=%v; got:\n%s", tc.attr, verb, tc.skipped, joined)
			}
		})
	}
}

// TestRustParser_PreludeTypeBoundary pins where prelude attribution holds and
// where it stops. A prelude type the source WRITES belongs to the standard
// library; a prelude type INFERRED from a constructor's return still carries
// the analyzed crate's package, which is the wrapper-package gap the spec
// records under "Known gaps". Measured at 64 of 109,880 edges across 53
// published crates. No contract keys `Vec.clone` or `Box.as_mut`, so no
// cryptographic identity is fabricated by it.
//
// This test exists so the boundary moves deliberately: if the inferred case
// starts resolving to `std`, this test fails and the spec is updated with it.
func TestRustParser_PreludeTypeBoundary(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a written annotation resolves to the standard library",
			src:  "pub fn a(v: Vec<u8>) -> usize { v.len() }",
			want: "std.Vec.len",
		},
		{
			name: "a written parameter resolves to the standard library",
			src:  "pub fn b(o: Option<u8>) -> u8 { o.unwrap() }",
			want: "std.Option.unwrap",
		},
		{
			name: "the constructor call itself resolves to the standard library",
			src:  "pub fn c(p: &[u8]) { let _v = Vec::from(p); }",
			want: "std.Vec.from",
		},
		{
			name: "a type inferred from the constructor keeps the crate package",
			src:  "pub fn d(p: &[u8]) { let v = Vec::from(p); v.clone(); }",
			want: "app.Vec.clone",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			joined := strings.Join(parseRustCalleeKeys(t, tc.src), "\n")
			if !strings.Contains(joined, tc.want) {
				t.Errorf("want %q; got:\n%s", tc.want, joined)
			}
		})
	}
}

// TestRustParser_CfgTestDeclarationsStayOutOfTheCrateIndex pins the half of the
// cfg gate that the call walk alone did not cover. `processRustModItem` skipped
// a test-only module, but the DECLARATION walk that feeds the crate-wide index
// had no such check, so a factory declared only for tests still typed a
// receiver in production code.
//
// dryoc 0.6.2 is the shape this protects: a pure-Rust libsodium reimplementation
// that dev-depends on sodiumoxide purely to cross-check test vectors. Without
// the gate it is reported as a sodiumoxide user.
func TestRustParser_CfgTestDeclarationsStayOutOfTheCrateIndex(t *testing.T) {
	files := map[string]string{
		"Cargo.toml": `[package]
name = "app"
version = "0.1.0"
edition = "2021"
[dependencies]
des = "0.8"
`,
		"src/helper.rs": `#[cfg(test)]
mod tests {
    use des::Des;
    pub fn build() -> Des { Des::new_from_slice(&[0u8; 8]) }
    pub struct Session { pub cipher: Des }
}
`,
		"src/prod.rs": `use crate::helper::tests::{build, Session};

pub fn go(b: &mut [u8; 8]) {
    let c = build();
    c.encrypt_block(b);
}

pub fn field(s: &Session, b: &mut [u8; 8]) {
    s.cipher.encrypt_block(b);
}
`,
	}
	joined := strings.Join(parseRustCrateAllKeys(t, files, "app"), "\n")
	if strings.Contains(joined, "des.Des.encrypt_block") {
		t.Errorf("a test-only declaration typed production code; got:\n%s", joined)
	}
}
