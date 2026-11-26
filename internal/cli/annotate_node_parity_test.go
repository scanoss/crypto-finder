//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Invented rules for a hash and a random draw on Node's crypto module.
const annotateNodeRules = `rules:
- id: acme-random
  languages: [javascript]
  message: Acme random bytes
  severity: INFO
  patterns:
  - pattern: $C.randomBytes(...)
  - pattern-inside: |
      $C = require("crypto");
      ...
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: drbg
- id: acme-hash
  languages: [javascript]
  message: Acme hash
  severity: INFO
  patterns:
  - pattern: $C.createHash(...)
  - pattern-inside: |
      $C = require("crypto");
      ...
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: hash
`

// A hash chain in a function named after the chain's last link: the
// `.digest()` call resolves to the module's own digest, an edge the graph
// does not record, so the stored graph holds that call only as the parser
// recorded it.
const annotateNodeChain = `const crypto = require("crypto");

const digest = (algorithm, data) => crypto.createHash(algorithm).update(data).digest();

module.exports = { digest };
`

// annotate of a stored Node graph, given the package source as the miner
// gives it, attributes a chained hash to the chain's terminal call, as the
// scan that stored the graph did.
func TestAnnotateNodeChainWritesTheScanFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	annotateNodeRoundTrip(t, map[string]string{"package.json": `{"name": "acme", "version": "1.0.0"}`, "digest.js": annotateNodeChain}, "acme-hash")
}

// annotateNodeRoundTrip scans the JavaScript files with annotateNodeRules,
// annotates the structural fragment with --source as the miner does, and
// wants the scan's findings and crypto sections, among them an asset of each
// of wantRules.
func annotateNodeRoundTrip(t *testing.T, files map[string]string, wantRules ...string) {
	t.Helper()
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	for name, content := range files {
		writeAnnotateCardsFile(t, filepath.Join(source, filepath.FromSlash(name)), content)
	}
	rules := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", "javascript", "x", "rules.yaml"), annotateNodeRules)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = progressTestEnv(dir)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	common := []string{"--no-remote-rules", "--rules-dir", rules, "--languages", "javascript,typescript"}

	scanFindings := filepath.Join(dir, "scan-findings.json")
	fragment := filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--output", scanFindings, "--export-graph-fragment", fragment, source}, common...)...)
	structural := filepath.Join(dir, "structural.json")
	writeStructuralFragment(t, fragment, structural)
	annotateFindings := filepath.Join(dir, "annotate-findings.json")
	annotation := filepath.Join(dir, "annotation.json")
	run(append([]string{"annotate", "--import-fragment", structural, "--source", source, "--output", annotation, "--findings-output", annotateFindings}, common...)...)

	want, got := readFindingAssets(t, scanFindings), readFindingAssets(t, annotateFindings)
	count := map[string]int{}
	for _, asset := range want {
		count[asset["rule"].(string)]++
	}
	for _, rule := range wantRules {
		if count[rule] == 0 {
			t.Fatalf("scan findings = %v, want an asset of %s", want, rule)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("annotate findings:\n%v\nwant the scan's:\n%v", got, want)
	}
	scanned, annotated := readCryptoSections(t, fragment), readCryptoSections(t, annotation)
	for section, value := range scanned {
		if string(annotated[section]) != string(value) {
			t.Errorf("annotation %s:\n%s\nwant the scan's:\n%s", section, annotated[section], value)
		}
	}
}
