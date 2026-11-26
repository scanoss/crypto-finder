// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"testing"
)

const rustRulesSrc = `rules:
- id: acme-kdf
  languages: [rust]
  pattern: acme_kdf::Kdf::new(...)
  metadata: {crypto: {algorithmName: KDF}}
- id: acme-taint
  languages: [rust]
  mode: taint
  pattern-sources:
  - pattern: acme_kdf::source()
  pattern-sinks:
  - pattern: acme_kdf::sink(...)
- id: acme-java
  languages: [java]
  pattern: new Acme(...)
  metadata: {crypto: {algorithmName: ACME}}
`

func writeRules(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A fragment of a Rust target reaches the Rust dispatch and yields no
// findings, whatever rules the index holds.
func TestRustFragmentDispatchFindsNothing(t *testing.T) {
	assets, err := Load("", "", writeRules(t, rustRulesSrc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	frag := pyFrag(nil, pyCall("acme_kdf.(Kdf).new", "acme_kdf::Kdf::new", 7))
	frag.ScanMetadata.Ecosystem = "rust"
	if !frag.rust() || frag.python() {
		t.Fatal("fragment is not read in Rust mode")
	}
	found, sites := assets.mustMatch(t, frag)
	if len(found) != 0 {
		t.Errorf("Rust fragment found %v, want nothing", ruleLines(found))
	}
	if sites != 1 {
		t.Errorf("sites = %d, want 1", sites)
	}
}

// A Rust entry never matches a Java or Python fragment, even when its method
// bucket and arity fit a site there.
func TestRustEntriesStayOutOfOtherLanguages(t *testing.T) {
	assets, err := Load("", "", writeRules(t, rustRuleYAML(map[string]string{"acme.derive": "pattern: $X.derive($OUT)"})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.index.Entries) != 1 || assets.index.Entries[0].Rust == nil {
		t.Fatalf("index = %+v", assets.index.Entries)
	}
	for _, eco := range []string{"java", "python"} {
		frag := pyFrag(nil, pyCall("acme.(Kdf).derive", "kdf.derive", 7, pos(0, "out")))
		frag.ScanMetadata.Ecosystem = eco
		if found, _ := assets.mustMatch(t, frag); len(found) != 0 {
			t.Errorf("%s fragment found %v", eco, ruleLines(found))
		}
	}
}
