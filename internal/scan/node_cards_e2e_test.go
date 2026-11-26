// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/cardmatch"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// The rule and the source below are invented: "acme-crypto" is not a real
// library and the rule comes from no ruleset.
const acmeNodeRules = `rules:
- id: acme-cipher
  message: acme cipher
  severity: INFO
  languages: [javascript, typescript]
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: $algo
  patterns:
  - pattern-either:
    - pattern-inside: |
        $NS = require("acme-crypto")
        ...
    - pattern-inside: |
        import $NS from "acme-crypto"
        ...
    - pattern-inside: |
        import * as $NS from "acme-crypto"
        ...
  - pattern-either:
    - pattern: |
        $NS.cipher.encrypt($DATA, {..., alg: $ALG, ...})
    - pattern: |
        new $NS.Cipher({..., alg: $ALG, ...})
  - metavariable-regex:
      metavariable: $ALG
      regex: '^"(?P<algo>AES|DES)"$'
- id: acme-digest-update
  message: acme digest update
  severity: INFO
  languages: [javascript, typescript]
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: $H
  patterns:
  - pattern-inside: |
      $NS = require("acme-crypto")
      ...
  - pattern-inside: |
      $D = $NS.createDigest($H)
      ...
  - pattern: $D.update(...)
`

// A node fragment built by the graph builder from JavaScript source, matched
// with entries the compiler made from a rule: every import spelling meets the
// callee key reach gives the call, arguments and constraints decide.
func TestNodeCardsEndToEnd(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"src/cjs.js": `const acme = require('acme-crypto');
const c1 = acme.cipher.encrypt(data, { alg: "AES", iv });
const c2 = acme.cipher.encrypt(data, { alg: "RC4" });
const d = acme.createDigest("sha256");
d.update(chunk);
`,
		"src/esm.mjs": `import * as A from 'acme-crypto';
import other from 'other-lib';
export const c = new A.Cipher({ alg: 'DES' });
export const e = other.cipher.encrypt(data, { alg: "AES" });
`,
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	fragPath := filepath.Join(t.TempDir(), "fragment.json")
	if err := exportGraphFragment(fragPath, &engine.DepScanResult{CallGraph: graph, Ecosystem: "node", ProjectRoot: root}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fragPath)
	if err != nil {
		t.Fatal(err)
	}
	var frag cardmatch.FragmentJSON
	if err := json.Unmarshal(data, &frag); err != nil {
		t.Fatal(err)
	}

	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "rules.yaml"), []byte(acmeNodeRules), 0o600); err != nil {
		t.Fatal(err)
	}
	assets, err := cardmatch.Load("", "", rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	found, _, err := assets.Match(&frag)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s %s:%d %v", f.RuleID, f.File, f.Line, f.MetadataMap()))
	}
	want := []string{
		"acme-cipher src/cjs.js:2 map[algorithmName:AES assetType:algorithm]",
		"acme-digest-update src/cjs.js:5 map[algorithmName:sha256 assetType:algorithm]",
		"acme-cipher src/esm.mjs:3 map[algorithmName:DES assetType:algorithm]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
}
