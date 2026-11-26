// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

const cardsOnlyNodeRule = `rules:
- id: acme.hash.digest
  languages: [javascript]
  severity: INFO
  message: Acme digest
  metadata:
    crypto:
      assetType: algorithm
  patterns:
  - pattern: $H.digest(...)
  - pattern-inside: |
      $H = require("acme-hash");
      ...
`

// A ruleset of JavaScript v3 card files alone (the ruleset's cards/javascript/,
// no rule YAML) is the scan's whole ruleset: the scan hints the language its
// card directory is named after, not the node ecosystem, so the rule filter
// keeps the card file and drops an earlier card file (it carries no rules), so
// rule ids carry their directory under cards/javascript/ as they carry it under
// semgrep-rules/javascript/.
func TestScanCardsOnlyJavaScriptRuleset(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	dir := t.TempDir()
	yamlDir := filepath.Join(dir, "yaml", "javascript")
	writeAnnotateCardsFile(t, filepath.Join(yamlDir, "lib", "rules.yaml"), cardsOnlyNodeRule)
	doc, err := exportCards(yamlDir, "javascript")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Counts.Entries == 0 {
		t.Fatalf("the rule compiled to no entry: %+v", doc.Rules)
	}
	text := "format: scanoss-cards/3\nrules:\n  acme.hash.digest:\n    severity: INFO\n    message: Acme digest\n    crypto:\n      assetType: algorithm\ncards:\n"
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
		text += "- rule: acme.hash.digest\n  site: " + string(flow) + "\n"
	}
	ruleset := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "javascript", "lib", "rules.cards"), text)
	// A second card file, so the scan materializes the filtered files and ids carry their directory.
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "javascript", "other", "rules.cards"),
		"format: scanoss-cards/3\nrules:\n  acme.other.digest:\n    severity: INFO\n    message: Acme other\n    crypto:\n      assetType: algorithm\n    pending: a text search\n")
	// An earlier (v2) card file of another language, its rules in a rule YAML the
	// tree does not hold: it carries no rules, so the parameter condition check
	// skips it and the filter drops it; kept, it widened the ids' prefix to
	// cards/ (javascript.lib...). The hints themselves: TestScannedLanguageHints.
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "rust", "lib", "rules.cards"),
		"cards:\n- rule: acme.rust.digest\n  rust:\n    pattern: acme_digest(...)\n")
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "index.js"), "const h = require(\"acme-hash\");\nh.digest(\"x\");\n")

	binary := buildProgressCryptoFinder(t)
	out := filepath.Join(dir, "report.json")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--rules-dir", ruleset, "--no-remote-rules",
		"--languages", "javascript", "--output", out, project)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath            string `json:"file_path"`
			CryptographicAssets []struct {
				Rules []struct{ ID string } `json:"rules"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	raw := readBytes(t, out)
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FilePath != "index.js" {
		t.Fatalf("findings = %s, want the one index.js finding", raw)
	}
	if assets := report.Findings[0].CryptographicAssets; len(assets) != 1 || len(assets[0].Rules) != 1 ||
		assets[0].Rules[0].ID != "lib.acme.hash.digest" {
		t.Errorf("asset rules = %+v, want the one lib.acme.hash.digest", assets)
	}
}

// A target holding Java beside TypeScript is scanned for both, and a
// cards-only ruleset's JavaScript card file must reach the node scan: the
// filter reads the card file's language from its directory (javascript), so
// the scan hints the canonical name of every scanned language whether or not
// Java is among them. The scan hinted the detector's names (java, typescript,
// tsx) when Java was present, and lost every JavaScript card.
func TestScanCardsOnlyJavaScriptRulesetMixedWithJava(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	dir := t.TempDir()
	yamlDir := filepath.Join(dir, "yaml", "javascript")
	writeAnnotateCardsFile(t, filepath.Join(yamlDir, "lib", "rules.yaml"), cardsOnlyNodeRule)
	doc, err := exportCards(yamlDir, "javascript")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Counts.Entries == 0 {
		t.Fatalf("the rule compiled to no entry: %+v", doc.Rules)
	}
	text := "format: scanoss-cards/3\nrules:\n  acme.hash.digest:\n    severity: INFO\n    message: Acme digest\n    crypto:\n      assetType: algorithm\ncards:\n"
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
		text += "- rule: acme.hash.digest\n  site: " + string(flow) + "\n"
	}
	ruleset := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "javascript", "lib", "rules.cards"), text)
	// A Java card file, so the filter keeps something without the JavaScript
	// one and does not fall back to every rule.
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "java", "lib", "rules.cards"),
		"format: scanoss-cards/3\nrules:\n  acme.java.digest:\n    severity: INFO\n    message: Acme Java\n    crypto:\n      assetType: algorithm\n    pending: a text search\n")
	project := filepath.Join(dir, "project")
	// More Java than TypeScript, so Java is the primary ecosystem.
	writeAnnotateCardsFile(t, filepath.Join(project, "src", "A.java"), "class A { void a() {} }\n")
	writeAnnotateCardsFile(t, filepath.Join(project, "src", "B.java"), "class B { void b() {} }\n")
	writeAnnotateCardsFile(t, filepath.Join(project, "web", "hash.ts"), "const h = require(\"acme-hash\");\nh.digest(\"x\");\n")

	binary := buildProgressCryptoFinder(t)
	out := filepath.Join(dir, "report.json")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--rules-dir", ruleset, "--no-remote-rules",
		"--output", out, project)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath string `json:"file_path"`
		} `json:"findings"`
	}
	raw := readBytes(t, out)
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].FilePath != "web/hash.ts" {
		t.Fatalf("findings = %s, want the one web/hash.ts finding\n%s", raw, stderr.String())
	}
}
