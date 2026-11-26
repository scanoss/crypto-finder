// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"maps"
	"slices"
	"testing"
)

const cRulesSrc = `rules:
- id: acme-c-kdf
  languages: [c, cpp]
  pattern: acme_kdf_derive(...)
  metadata: {crypto: {algorithmName: KDF}}
- id: acme-cpp-cipher
  languages: [cpp]
  pattern: acme::Cipher::encrypt(...)
  metadata: {crypto: {algorithmName: ACME}}
- id: acme-java
  languages: [java]
  pattern: new Acme(...)
  metadata: {crypto: {algorithmName: ACME}}
`

// C and C++ rules go through the C compiler, one record each: a C call
// compiles, a C++ qualified call compiles with the C++ shapes (a rule of
// languages [cpp]), and a rule of another language in the same directory
// compiles as before.
func TestCRulesCompileWithTheCShapes(t *testing.T) {
	rules, err := ExportRules(writeRules(t, cRulesSrc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range rules {
		status[r.ID] = r.Status
		if r.Status == "skipped" && !slices.Contains(cSkipReasons, cSkip(r.Reason)) {
			t.Errorf("rule %s reason %q is not a C reason", r.ID, r.Reason)
		}
	}
	want := map[string]string{"acme-c-kdf": "compiled", "acme-cpp-cipher": "compiled", "acme-java": "compiled"}
	if !maps.Equal(status, want) {
		t.Errorf("status %v, want %v", status, want)
	}
}

// A fragment of a C or C++ target reaches the C dispatch; a call it ships no
// source line for is not read, so it finds nothing (c_match_test.go matches
// calls with their source).
func TestCFragmentDispatchWithoutSource(t *testing.T) {
	assets, err := Load("", "", writeRules(t, cRulesSrc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ecosystem := range []string{"c", "cpp"} {
		frag := pyFrag(nil, pyCall("acme_kdf_derive", "acme_kdf_derive", 7))
		frag.ScanMetadata.Ecosystem = ecosystem
		if !frag.c() || frag.python() || frag.rust() {
			t.Fatalf("%s fragment is not read in C mode", ecosystem)
		}
		found, sites := assets.mustMatch(t, frag)
		if len(found) != 0 {
			t.Errorf("%s fragment found %v, want nothing", ecosystem, ruleLines(found))
		}
		if sites != 1 {
			t.Errorf("%s: sites = %d, want 1", ecosystem, sites)
		}
	}
}
