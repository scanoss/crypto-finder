// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const rustDependencyRule = `rules:
- id: acme.hash.digest
  languages: [rust]
  severity: INFO
  message: Acme digest
  metadata:
    crypto:
      assetType: algorithm
  pattern: acme_hash::digest(...)
`

// rustDependencyRuleset is a ruleset of one invented Rust card file:
// acme_hash's digest call.
func rustDependencyRuleset(t *testing.T, dir string) string {
	t.Helper()
	yamlDir := filepath.Join(dir, "yaml", "rust")
	writeAnnotateCardsFile(t, filepath.Join(yamlDir, "lib", "rules.yaml"), rustDependencyRule)
	doc, err := exportCards(yamlDir, "rust")
	if err != nil || doc.Counts.Entries == 0 {
		t.Fatalf("the rule compiled to no entry: %v %+v", err, doc)
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
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "cards", "rust", "lib", "rules.cards"), text)
	return ruleset
}

// rustToolchainEnv keeps cargo working under the test's HOME override: a
// rustup proxy finds its toolchains and Cargo its home through these, not
// through HOME.
func rustToolchainEnv() []string {
	var env []string
	home, _ := os.UserHomeDir()
	for name, fallback := range map[string]string{"RUSTUP_HOME": ".rustup", "CARGO_HOME": ".cargo"} {
		value := os.Getenv(name)
		if value == "" && home != "" {
			value = filepath.Join(home, fallback)
		}
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// A Rust target's --scan-dependencies --offline resolves its pinned crate
// closure with cargo metadata --locked (a dev-only crate left out) and mines
// each dependency from its source under vendor/: the first-party finding and
// the dependency's finding under its crate, with the stitch's verdict
// (reachable: main calls acme-sign's sign, which digests). The dependencies
// progress event names the rust ecosystem.
func TestScanRustProjectOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	ruleset := rustDependencyRuleset(t, dir)
	project := filepath.Join(dir, "project")
	writeRustProject(t, project)

	out := filepath.Join(dir, "verdicts")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--no-remote-rules", "--rules-dir", ruleset, "--languages", "rust", "--progress",
		"--scan-dependencies", "--offline", "--offline-cache-dir", filepath.Join(dir, "cache"),
		"--output", out+".json", "--export-callgraph", out+".callgraph.json", project)
	cmd.Env = append(progressTestEnv(dir), rustToolchainEnv()...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath            string `json:"file_path"`
			CryptographicAssets []struct {
				FindingID      string `json:"finding_id"`
				Source         string `json:"source"`
				DependencyInfo *struct {
					Module, Version, PURL string
				} `json:"dependency_info"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	readPythonScanJSON(t, out+".json", &report)
	var callgraph struct {
		FindingGraphs []struct {
			FindingID        string `json:"finding_id"`
			UnresolvedReason string `json:"unresolved_reason"`
			Reachability     string `json:"reachability"`
		} `json:"finding_graphs"`
	}
	readPythonScanJSON(t, out+".callgraph.json", &callgraph)
	verdicts := map[string]string{}
	for _, g := range callgraph.FindingGraphs {
		verdicts[g.FindingID] = g.Reachability + g.UnresolvedReason
	}
	got := map[string]string{}
	for _, f := range report.Findings {
		for _, a := range f.CryptographicAssets {
			where := a.Source + " " + filepath.ToSlash(f.FilePath)
			if a.DependencyInfo != nil {
				where += " " + a.DependencyInfo.PURL
				got[where] = verdicts[a.FindingID]
				continue
			}
			got[where] = "-"
		}
	}
	want := map[string]string{
		"direct src/main.rs":                              "-",
		"dependency src/lib.rs pkg:cargo/acme-sign@2.0.1": "reachable",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v\nstderr:\n%s", got, want, stderr.String())
	}
	var details map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["phase"] == "dependencies" && event["status"] == "completed" {
			details, _ = event["details"].(map[string]any)
		}
	}
	if ecosystems, _ := details["ecosystems"].([]any); len(ecosystems) != 1 || ecosystems[0] != "rust" {
		t.Errorf("dependency phase details = %v", details)
	}
}

// A consumer calls a crate by the paths its `pub use` items and modules give,
// not by the modules that declare them, and so does one dependency calling
// another. Here main calls acme-sign's sign through the crate root (declared
// in sig.rs), its Key::derive through the crate root (declared in keys.rs),
// and sig::seal through an imported module, which calls acme-pad's pad
// through its crate root (declared in imp.rs). Each digest those reach is
// reachable; the one in a function nothing calls is not.
func TestScanRustProjectOfflineReExports(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	ruleset := rustDependencyRuleset(t, dir)
	project := filepath.Join(dir, "project")
	writeRustProject(t, project)
	for name, text := range map[string]string{
		"vendor/acme-sign/src/lib.rs":  "pub mod sig;\nmod keys;\npub use keys::Key;\npub use sig::sign;\n",
		"vendor/acme-sign/src/sig.rs":  "pub fn sign(x: &[u8]) -> Vec<u8> {\n    acme_hash::digest(x)\n}\n\npub fn seal(x: &[u8]) -> Vec<u8> {\n    acme_pad::pad(x)\n}\n\npub fn unused(x: &[u8]) -> Vec<u8> {\n    acme_hash::digest(x)\n}\n",
		"vendor/acme-sign/src/keys.rs": "pub struct Key;\n\nimpl Key {\n    pub fn derive(x: &[u8]) -> Vec<u8> {\n        acme_hash::digest(x)\n    }\n}\n",
		"vendor/acme-pad/src/lib.rs":   "mod imp;\npub use imp::pad;\n",
		"vendor/acme-pad/src/imp.rs":   "pub fn pad(x: &[u8]) -> Vec<u8> {\n    acme_hash::digest(x)\n}\n",
		"src/main.rs":                  "use acme_sign::sig;\n\nfn main() {\n    let _ = acme_sign::sign(b\"x\");\n    let _ = acme_sign::Key::derive(b\"y\");\n    let _ = sig::seal(b\"z\");\n}\n",
	} {
		writeAnnotateCardsFile(t, filepath.Join(project, name), text)
	}

	out := filepath.Join(dir, "verdicts")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--no-remote-rules", "--rules-dir", ruleset, "--languages", "rust",
		"--scan-dependencies", "--offline", "--offline-cache-dir", filepath.Join(dir, "cache"),
		"--output", out+".json", "--export-callgraph", out+".callgraph.json", project)
	cmd.Env = append(progressTestEnv(dir), rustToolchainEnv()...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath            string `json:"file_path"`
			CryptographicAssets []struct {
				FindingID      string `json:"finding_id"`
				StartLine      int    `json:"start_line"`
				DependencyInfo *struct {
					PURL string
				} `json:"dependency_info"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	readPythonScanJSON(t, out+".json", &report)
	var callgraph struct {
		FindingGraphs []struct {
			FindingID    string `json:"finding_id"`
			Reachability string `json:"reachability"`
		} `json:"finding_graphs"`
	}
	readPythonScanJSON(t, out+".callgraph.json", &callgraph)
	verdicts := map[string]string{}
	for _, g := range callgraph.FindingGraphs {
		verdicts[g.FindingID] = g.Reachability
	}
	got := map[string]string{}
	for _, f := range report.Findings {
		for _, a := range f.CryptographicAssets {
			if a.DependencyInfo != nil {
				got[a.DependencyInfo.PURL+" "+filepath.ToSlash(f.FilePath)+":"+strconv.Itoa(a.StartLine)] = verdicts[a.FindingID]
			}
		}
	}
	want := map[string]string{
		"pkg:cargo/acme-sign@2.0.1 src/sig.rs:2":  "reachable",
		"pkg:cargo/acme-sign@2.0.1 src/sig.rs:10": "unreachable",
		"pkg:cargo/acme-sign@2.0.1 src/keys.rs:5": "reachable",
		"pkg:cargo/acme-pad@1.2.0 src/imp.rs:2":   "reachable",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependency verdicts\n got %v\nwant %v\nstderr:\n%s", got, want, stderr.String())
	}
}
