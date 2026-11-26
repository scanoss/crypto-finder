//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const annotateCardsJava = `package org.example;

import javax.crypto.Cipher;

public class Box {
    public byte[] seal(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        return c.doFinal(data);
    }

    public void wipe(byte[] key) {
        java.util.Arrays.fill(key, (byte) 0);
    }
}
`

// A detection rule and a rule whose api is a method the scanned library
// declares, which the scan surfaces as an entry point after detection.
const annotateCardsRules = `rules:
- id: cipher-aes-gcm
  languages: [java]
  message: AES-GCM cipher
  severity: INFO
  pattern: javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: AES
      algorithmPrimitive: ae
      mode: GCM
- id: box-wipe
  languages: [java]
  message: Box key wipe
  severity: INFO
  pattern: org.example.Box.wipe(...)
  metadata:
    crypto:
      assetType: related-crypto-material
      materialType: secret-key
      api: org.example.Box.wipe
`

// annotate re-detects a stored graph with no source tree and
// runs the scan's steps after detection, so its findings are the ones the
// scan that exported the graph wrote: the matched assets with their text,
// the entry points the ruleset names, and every asset's identity, source,
// OID and PQC classification. Its annotation holds the crypto sections the
// scan's fragment export wrote.
func TestAnnotateCardsWithoutSourceWritesTheScanFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	writeAnnotateCardsFile(t, filepath.Join(source, "org", "example", "Box.java"), annotateCardsJava)
	rules := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", "java", "x", "rules.yaml"), annotateCardsRules)
	env := append(os.Environ(), "HOME="+dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	ruleArgs := []string{"--no-remote-rules", "--rules-dir", rules}

	scanFindings := filepath.Join(dir, "scan-findings.json")
	fragment := filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--languages", "java", "--output", scanFindings, "--export-graph-fragment", fragment, source}, ruleArgs...)...)
	// The miner stores the graph without its crypto sections, and the
	// annotation runs where the source is gone.
	structural := filepath.Join(dir, "structural.json")
	writeStructuralFragment(t, fragment, structural)
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	annotateFindings := filepath.Join(dir, "annotate-findings.json")
	run(append([]string{"annotate", "--import-fragment", structural, "--output", filepath.Join(dir, "annotation.json"), "--findings-output", annotateFindings}, ruleArgs...)...)

	want, got := readFindingAssets(t, scanFindings), readFindingAssets(t, annotateFindings)
	rules2 := map[string]bool{}
	for _, asset := range want {
		rules2[asset["rule"].(string)] = true
		if asset["finding_id"] == nil || asset["source"] == nil || asset["occurrence_key"] == nil {
			t.Errorf("scan asset %v lacks its identity", asset)
		}
	}
	if !rules2["cipher-aes-gcm"] || !rules2["crypto-finder.api-entry-point"] {
		t.Fatalf("scan findings = %v, want the cipher and the wipe entry point", want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("annotate findings:\n%v\nwant the scan's:\n%v", got, want)
	}

	scanned, annotated := readCryptoSections(t, fragment), readCryptoSections(t, filepath.Join(dir, "annotation.json"))
	if len(scanned["crypto_annotations"]) == 0 || len(scanned["crypto_entry_points"]) == 0 {
		t.Fatalf("scan fragment crypto sections = %v, want annotations and entry points", scanned)
	}
	for section, value := range scanned {
		if string(annotated[section]) != string(value) {
			t.Errorf("annotation %s:\n%s\nwant the scan's:\n%s", section, annotated[section], value)
		}
	}
}

// A Python library that hashes, and declares a function a rule's api names
// (by its declaring module).
var annotateCardsPython = map[string]string{
	"sealer/__init__.py": "",
	"sealer/box.py": `import hashlib


def digest(data):
    return hashlib.sha256(data).digest()


def new_nonce():
    return bytes(12)
`,
}

// A ruleset with Java and Python rules: annotate must pick the Python ones
// for a Python graph.
const annotateCardsPythonRules = `rules:
- id: py-sha256
  languages: [python]
  message: SHA-256
  severity: INFO
  pattern: hashlib.sha256(...)
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: SHA-256
      algorithmPrimitive: hash
- id: sealer-nonce
  languages: [python]
  message: sealer nonce
  severity: INFO
  pattern: sealer.box.new_nonce(...)
  metadata:
    crypto:
      assetType: related-crypto-material
      materialType: nonce
      api: sealer.box.new_nonce
`

// annotate matches a stored Python graph with the Python cards, which the
// graph's ecosystem picks (no --languages), and writes the findings the scan
// that exported it wrote, entry points included.
func TestAnnotateCardsPythonGraphWritesTheScanFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	annotatePythonRoundTrip(t, annotateCardsPython, annotateCardsPythonRules, "py-sha256", "crypto-finder.api-entry-point")
}

// A Python library whose package re-exports a class and a function its rules
// name by the public path (`sealer.Box.<init>`, `sealer.new_nonce`): the
// scan surfaces both declarations as entry points, and so does annotate from
// the stored graph alone.
func TestAnnotateCardsPythonGraphSurfacesReExportedAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	files := map[string]string{
		"sealer/__init__.py": "from sealer.box import Box, new_nonce\n",
		"sealer/box.py": `class Box:
    def __init__(self, key):
        self.key = key


def new_nonce():
    return bytes(12)
`,
	}
	rules := `rules:
- id: sealer-box
  languages: [python]
  message: sealer box
  severity: INFO
  pattern: sealer.Box(...)
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: XSalsa20-Poly1305
      algorithmPrimitive: ae
      api: sealer.Box.<init>
- id: sealer-nonce
  languages: [python]
  message: sealer nonce
  severity: INFO
  pattern: sealer.new_nonce(...)
  metadata:
    crypto:
      assetType: related-crypto-material
      materialType: nonce
      api: sealer.new_nonce
`
	assets := annotatePythonRoundTrip(t, files, rules, "crypto-finder.api-entry-point")
	if len(assets) != 2 {
		t.Errorf("scan assets = %v, want the two re-exported entry points", assets)
	}
}

// annotatePythonRoundTrip scans the Python files with the rules (next to the
// Java rules of annotateCardsRules), annotates the structural fragment with no
// source and no --languages, and wants the scan's findings, among them an
// asset of each of wantRules. It returns the scan's assets.
func annotatePythonRoundTrip(t *testing.T, files map[string]string, pythonRules string, wantRules ...string) []map[string]any {
	t.Helper()
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "src")
	for name, content := range files {
		writeAnnotateCardsFile(t, filepath.Join(source, filepath.FromSlash(name)), content)
	}
	rules := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", "java", "x", "rules.yaml"), annotateCardsRules)
	writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", "python", "x", "rules.yaml"), pythonRules)
	env := append(os.Environ(), "HOME="+dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	ruleArgs := []string{"--no-remote-rules", "--rules-dir", rules}

	scanFindings := filepath.Join(dir, "scan-findings.json")
	fragment := filepath.Join(dir, "fragment.json")
	run(append([]string{"scan", "--languages", "python", "--output", scanFindings, "--export-graph-fragment", fragment, source}, ruleArgs...)...)
	structural := filepath.Join(dir, "structural.json")
	writeStructuralFragment(t, fragment, structural)
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	annotateFindings := filepath.Join(dir, "annotate-findings.json")
	run(append([]string{"annotate", "--import-fragment", structural, "--output", filepath.Join(dir, "annotation.json"), "--findings-output", annotateFindings}, ruleArgs...)...)

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
	return want
}

// readCryptoSections reads an export's crypto sections and the counts its
// scan metadata keeps of them, each compacted.
func readCryptoSections(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		CryptoAnnotations json.RawMessage `json:"crypto_annotations"`
		SupportingCalls   json.RawMessage `json:"supporting_calls"`
		CryptoEntryPoints json.RawMessage `json:"crypto_entry_points"`
		ScanMetadata      struct {
			CryptoOps         int `json:"crypto_operation_count"`
			SupportingCalls   int `json:"supporting_call_count"`
			CryptoEntryPoints int `json:"crypto_entry_point_count"`
		} `json:"scan_metadata"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	counts, _ := json.Marshal(document.ScanMetadata)
	out := map[string]json.RawMessage{"counts": counts}
	for name, raw := range map[string]json.RawMessage{
		"crypto_annotations": document.CryptoAnnotations, "supporting_calls": document.SupportingCalls, "crypto_entry_points": document.CryptoEntryPoints,
	} {
		var compact bytes.Buffer
		if len(raw) > 0 {
			if err := json.Compact(&compact, raw); err != nil {
				t.Fatal(err)
			}
		}
		out[name] = compact.Bytes()
	}
	return out
}

// Without --source a fragment older than graph-fragment-1.16 holds no source
// lines to report the findings' text from, and annotate says so.
func TestAnnotateWithoutSourceNeedsSourceLines(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	rules := filepath.Join(dir, "ruleset")
	writeAnnotateCardsFile(t, filepath.Join(rules, "semgrep-rules", "java", "x", "rules.yaml"), annotateCardsRules)
	old := filepath.Join(dir, "old.json")
	writeAnnotateCardsFile(t, old, `{"schema_version": "graph-fragment-1.15", "functions": []}`)
	cmd := exec.CommandContext(t.Context(), binary, "annotate", "--no-remote-rules", "--import-fragment", old, "--rules-dir", rules)
	cmd.Env = append(os.Environ(), "HOME="+dir)
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "has no source lines") {
		t.Errorf("err = %v, output:\n%s\nwant an error naming the missing source lines", err, output)
	}
}

func writeAnnotateCardsFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeStructuralFragment copies a fragment without its crypto sections.
func writeStructuralFragment(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"crypto_annotations", "supporting_calls", "crypto_entry_points"} {
		delete(document, section)
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeAnnotateCardsFile(t, to, string(data))
}

// readFindingAssets lists a findings report's assets, each with its file and
// first rule id.
func readFindingAssets(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []struct {
			FilePath string           `json:"file_path"`
			Language string           `json:"language"`
			Assets   []map[string]any `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	var assets []map[string]any
	for _, finding := range report.Findings {
		for _, asset := range finding.Assets {
			asset["file"], asset["language"] = finding.FilePath, finding.Language
			asset["rule"] = asset["rules"].([]any)[0].(map[string]any)["id"]
			assets = append(assets, asset)
		}
	}
	return assets
}
