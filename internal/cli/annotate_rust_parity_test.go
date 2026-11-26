//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// annotateRustHashRule is an invented rule for acme_hash's hasher.
const annotateRustHashRule = `rules:
- id: acme.hash.new
  languages: [rust]
  severity: INFO
  message: Acme hasher
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: hash
  pattern: acme_hash::Hasher::new(...)
`

// annotateRustCrate is an invented crate. Sealer is declared in a private
// module and re-exported at the crate root, where a rule's api names it.
// fill's hasher takes its length from fill's out parameter, which seal
// passes on from its own parameter while seal_block passes a local whose
// value the parser does not trace.
var annotateRustCrate = map[string]string{
	"Cargo.toml": "[package]\nname = \"sealkit\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
	"src/lib.rs": `mod long;
mod sealer;

pub use sealer::Sealer;

pub fn seal(out: &mut [u8]) {
    long::fill(&[b"seed"], out);
}

pub fn seal_block(key: &[u8]) {
    let inputs = &[key.as_ref()];
    let mut block = [0u8; 64];
    long::fill(inputs, &mut block);
}
`,
	"src/long.rs": `pub fn fill(inputs: &[&[u8]], out: &mut [u8]) {
    let mut hasher = acme_hash::Hasher::new(out.len());
    hasher.update(inputs[0]);
    hasher.finish(out);
}
`,
	"src/sealer.rs": `pub struct Sealer {
    key: [u8; 32],
}

impl Sealer {
    pub fn new(key: [u8; 32]) -> Self {
        Sealer { key }
    }
}
`,
}

// annotate of a stored Rust graph, without the source as the miner runs it,
// writes the findings and crypto sections the scan that stored the graph
// wrote: the entry point of an api a `pub use` names, the language of each
// finding, and the provenance of a parameter one caller passes untraced.
func TestAnnotateRustWritesTheScanFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	for name, content := range annotateRustCrate {
		writeAnnotateCardsFile(t, filepath.Join(source, filepath.FromSlash(name)), content)
	}
	rules := annotateRustRuleset(t, dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = progressTestEnv(dir)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	common := []string{"--no-remote-rules", "--rules-dir", rules, "--languages", "rust"}

	scanFindings := filepath.Join(dir, "scan-findings.json")
	fragment := filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--output", scanFindings, "--export-graph-fragment", fragment, source}, common...)...)
	structural := filepath.Join(dir, "structural.json")
	writeStructuralFragment(t, fragment, structural)
	annotateFindings := filepath.Join(dir, "annotate-findings.json")
	annotation := filepath.Join(dir, "annotation.json")
	run(append([]string{"annotate", "--import-fragment", structural, "--output", annotation, "--findings-output", annotateFindings}, common...)...)

	want, got := readFindingAssets(t, scanFindings), readFindingAssets(t, annotateFindings)
	where := map[string]string{}
	for _, asset := range want {
		where[asset["rule"].(string)] = asset["file"].(string) + " " + asset["language"].(string)
	}
	for rule, at := range map[string]string{"acme.hash.new": "src/long.rs rust", "crypto-finder.api-entry-point": "src/sealer.rs rust"} {
		if where[rule] != at {
			t.Fatalf("scan findings = %v, want an asset of %s in %s", want, rule, at)
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

// annotateRustRuleset is a ruleset of one invented Rust card file: the
// acme.hash.new rule, and a rule whose api names the crate's re-exported
// Sealer.new and matches no call.
func annotateRustRuleset(t *testing.T, dir string) string {
	t.Helper()
	yamlDir := filepath.Join(dir, "yaml", "rust")
	writeAnnotateCardsFile(t, filepath.Join(yamlDir, "acme", "rules.yaml"), annotateRustHashRule)
	doc, err := exportCards(yamlDir, "rust")
	if err != nil || doc.Counts.Entries == 0 {
		t.Fatalf("the rule compiled to no entry: %v %+v", err, doc)
	}
	text := "format: scanoss-cards/3\nrules:\n" +
		"  acme.hash.new:\n    severity: INFO\n    message: Acme hasher\n    crypto:\n      assetType: algorithm\n      algorithmPrimitive: hash\n" +
		"  sealkit.sealer:\n    severity: INFO\n    message: Sealkit sealer\n    crypto:\n      assetType: algorithm\n      algorithmPrimitive: ae\n      api: sealkit.Sealer.new\n" +
		"cards:\n"
	for _, s := range doc.Rules[0].Sites {
		var site map[string]json.RawMessage
		if err := json.Unmarshal(s, &site); err != nil {
			t.Fatal(err)
		}
		delete(site, "lossy")
		flow, err := json.Marshal(site)
		if err != nil {
			t.Fatal(err)
		}
		text += "- rule: acme.hash.new\n  site: " + string(flow) + "\n"
	}
	ruleset := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "rust", "acme", "rules.cards"), text)
	return ruleset
}
