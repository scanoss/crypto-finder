// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// syntheticExportRules are made-up rules of each kind the export reports: a
// compiled search rule, a conditioned taint rule with a capture binder, a
// Python rule binding its receiver, and a rule the compiler skips.
const syntheticExportRules = `rules:
- id: example.digest
  languages: [java]
  severity: INFO
  message: Example digest
  metadata:
    purl: pkg:maven/com.example/lib
    crypto:
      assetType: algorithm
      api: com.example.Digest.compute
  pattern: com.example.Digest.compute(...)
- id: example.cipher
  languages: [java]
  severity: INFO
  message: Example cipher
  mode: taint
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: $alg
      parameterCondition: param[0]:type~=^com\.example\.Engine$
  pattern-sources:
  - patterns:
    - pattern: $X
    - metavariable-regex:
        metavariable: $X
        regex: (?<alg>AES|DES)
  pattern-sinks:
  - patterns:
    - pattern: com.example.Cipher.create($X)
    - focus-metavariable: $X
- id: example.skipped
  languages: [java]
  severity: INFO
  message: Example skipped
  metadata:
    crypto:
      assetType: algorithm
  pattern-regex: example
`

const syntheticExportPythonRules = `rules:
- id: example.update
  languages: [python]
  severity: INFO
  message: Example update
  metadata:
    crypto:
      assetType: algorithm
  pattern: $H.update(...)
`

func TestExportCardsSynthetic(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{"java/lib/rules.yaml": syntheticExportRules, "python/lib/rules.yaml": syntheticExportPythonRules} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	doc, err := exportCards(filepath.Join(dir, "java"), "java")
	if err != nil {
		t.Fatal(err)
	}
	if want := (cardsExportCounts{Rules: 3, Compiled: 2, Skipped: 1, Entries: 2}); doc.Counts != want {
		t.Fatalf("counts = %+v, want %+v", doc.Counts, want)
	}
	byID := map[string]cardsExportedRule{}
	for _, r := range doc.Rules {
		byID[r.ID] = r
		for _, s := range r.Sites {
			var site map[string]any
			if err := json.Unmarshal(s, &site); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"rule_id", "metadata", "pattern", "dropped_clauses"} {
				if _, has := site[k]; has {
					t.Errorf("%s: site has %s", r.ID, k)
				}
			}
		}
	}
	if r := byID["example.skipped"]; r.Status != "skipped" || r.Reason != "pattern-regex" || len(r.Sites) != 0 {
		t.Errorf("skipped rule = %+v", r)
	}
	if r := byID["example.digest"]; r.Status != "compiled" || r.File != "lib/rules.yaml" || r.Conditioned != nil {
		t.Errorf("digest rule = %+v", r)
	}
	c := byID["example.cipher"].Conditioned
	if c == nil || !reflect.DeepEqual(c.Symbols, []string{"com.example.Cipher.create"}) ||
		!reflect.DeepEqual(c.CaptureNames, []string{"alg"}) || !reflect.DeepEqual(c.CaptureBinders, []string{`^(?:(?<alg>AES|DES))`}) {
		t.Errorf("conditioned = %+v", c)
	}

	py, err := exportCards(filepath.Join(dir, "python"), "python")
	if err != nil {
		t.Fatal(err)
	}
	var site map[string]any
	if err := json.Unmarshal(py.Rules[0].Sites[0], &site); err != nil {
		t.Fatal(err)
	}
	if site["receiver_var"] != "$H" || site["receiver"] != "any" {
		t.Errorf("python site = %v", site)
	}
}

// writeSyntheticV3 writes the v3 card file of syntheticExportRules from its
// export, as the ruleset repository's generator writes it: the rules entries
// as in the YAML, the compiled rules' entries as site cards, the skipped rule
// pending.
func writeSyntheticV3(t *testing.T, doc *cardsExport, path string) {
	t.Helper()
	text := `format: scanoss-cards/3
rules:
  example.digest:
    severity: "INFO"
    message: "Example digest"
    purl: "pkg:maven/com.example/lib"
    crypto:
      assetType: "algorithm"
      api: "com.example.Digest.compute"
  example.cipher:
    severity: "INFO"
    message: "Example cipher"
    crypto:
      assetType: "algorithm"
      algorithmName: "$alg"
      parameterCondition: "param[0]:type~=^com\\.example\\.Engine$"
`
	byID := map[string]cardsExportedRule{}
	for _, r := range doc.Rules {
		byID[r.ID] = r
	}
	cond, err := json.Marshal(byID["example.cipher"].Conditioned)
	if err != nil {
		t.Fatal(err)
	}
	text += "    conditioned: " + string(cond) + "\n"
	text += `  example.skipped:
    severity: "INFO"
    message: "Example skipped"
    crypto:
      assetType: "algorithm"
    pending: "a text search"
cards:
`
	for _, id := range []string{"example.digest", "example.cipher"} {
		for _, s := range byID[id].Sites {
			var site map[string]json.RawMessage
			if err := json.Unmarshal(s, &site); err != nil {
				t.Fatal(err)
			}
			lossy := site["lossy"]
			delete(site, "lossy")
			flow, err := json.Marshal(site)
			if err != nil {
				t.Fatal(err)
			}
			text += "- rule: " + id + "\n  site: " + string(flow) + "\n"
			if lossy != nil {
				text += "  lossy: " + string(lossy) + "\n"
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCardsSynthetic(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "semgrep-rules", "java")
	if err := os.MkdirAll(filepath.Join(rulesDir, "lib"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "lib", "rules.yaml"), []byte(syntheticExportRules), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := exportCards(rulesDir, "java")
	if err != nil {
		t.Fatal(err)
	}
	cardsDir := filepath.Join(dir, "cards", "java")
	card := filepath.Join(cardsDir, "lib", "rules.cards")
	writeSyntheticV3(t, doc, card)

	var out bytes.Buffer
	diffs, err := verifyCards(&out, rulesDir, cardsDir, "java")
	if err != nil || diffs != 0 {
		t.Fatalf("verify = %d differences, %v\n%s", diffs, err, out.String())
	}
	for _, want := range []string{
		"A1 site entries: 2 rules with site cards (2 cards), 2 index entries loaded; 0 hand-carded, 1 pending",
		"A2 conditioned catalog: 1 rules", "A3 synthesis map: 1 api symbols", "A4 rule info: 3 rules",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}

	data, err := os.ReadFile(card)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(data), `message: "Example digest"`, `message: "Changed"`, 1)
	broken = strings.Replace(broken, `api: "com.example.Digest.compute"`, `api: "com.example.Digest.other"`, 1)
	if err := os.WriteFile(card, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if diffs, err = verifyCards(&out, rulesDir, cardsDir, "java"); err != nil || diffs == 0 {
		t.Fatalf("a changed message and api: %d differences, %v", diffs, err)
	}
	for _, want := range []string{"A3 synthesis map: 1 api symbols: 2 differences", "A4", "crypto differs"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}
