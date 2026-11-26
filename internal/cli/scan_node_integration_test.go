// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// nodeDependencyRuleset is a ruleset of one invented JavaScript card file:
// acme-hash's digest call.
func nodeDependencyRuleset(t *testing.T, dir string) string {
	t.Helper()
	yamlDir := filepath.Join(dir, "yaml", "javascript")
	writeAnnotateCardsFile(t, filepath.Join(yamlDir, "lib", "rules.yaml"), cardsOnlyNodeRule)
	doc, err := exportCards(yamlDir, "javascript")
	if err != nil || doc.Counts.Entries == 0 {
		t.Fatalf("the rule compiled to no entry: %v %+v", err, doc.Rules)
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
	return ruleset
}

// A JavaScript target's --scan-dependencies --offline resolves its pinned npm
// closure from package-lock.json (dev packages left out) and mines each
// dependency from its installed package under node_modules: the first-party
// finding, the dependency's finding under its package with the stitch's
// verdict (reachable: the project calls acme-sign's sign, which digests), and
// a pinned package that is not installed listed without data. The project
// requires acme-sign by its bare package specifier and acme-seal by a
// subpath (acme-seal/index); the bare one meets the mined entry module because the mined
// fragment's package exports (acme-sign.sign) resolve to the entry module.
func TestScanNodeProjectOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	ruleset := nodeDependencyRuleset(t, dir)
	project := filepath.Join(dir, "project")
	writeAnnotateCardsFile(t, filepath.Join(project, "package.json"),
		`{"name":"app","main":"index.js","dependencies":{"acme-hash":"^1.0.0","acme-sign":"^2.0.0","acme-seal":"^3.0.0","@acme/missing":"^1.0.0"},"devDependencies":{"jest":"^29.0.0"}}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "package-lock.json"), `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"acme-sign":"^2.0.0","acme-seal":"^3.0.0","@acme/missing":"^1.0.0"},"devDependencies":{"jest":"^29.0.0"}},
"node_modules/acme-sign":{"version":"2.0.1"},
"node_modules/acme-seal":{"version":"3.0.0"},
"node_modules/@acme/missing":{"version":"1.0.0"},
"node_modules/jest":{"version":"29.0.0","dev":true}}}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "index.js"), `const hash = require("acme-hash");
const signer = require("acme-sign");
const sealer = require("acme-seal/index");

function direct(x) {
  return hash.digest(x);
}

function viaDependency(x) {
  return signer.sign(x);
}

function viaSubpath(x) {
  return sealer.seal(x);
}

viaSubpath("z");
viaDependency("x");
direct("y");
`)
	writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", "acme-sign", "package.json"), `{"name":"acme-sign","version":"2.0.1","main":"index.js"}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", "acme-sign", "index.js"), `const h = require("acme-hash");

exports.sign = function (x) {
  return h.digest(x);
};
`)

	writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", "acme-seal", "package.json"), `{"name":"acme-seal","version":"3.0.0","main":"index.js"}`)
	writeAnnotateCardsFile(t, filepath.Join(project, "node_modules", "acme-seal", "index.js"), `const h = require("acme-hash");

exports.seal = function (x) {
  return h.digest(x);
};
`)

	out := filepath.Join(dir, "verdicts")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--no-remote-rules", "--rules-dir", ruleset, "--languages", "javascript", "--progress",
		"--scan-dependencies", "--offline", "--offline-cache-dir", filepath.Join(dir, "cache"),
		"--output", out+".json", "--export-callgraph", out+".callgraph.json", project)
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
			where := a.Source + " " + f.FilePath
			if a.DependencyInfo != nil {
				where += " " + a.DependencyInfo.Module + "@" + a.DependencyInfo.Version
				got[where] = verdicts[a.FindingID]
				continue
			}
			got[where] = "-"
		}
	}
	want := map[string]string{
		"direct index.js":                     "-",
		"dependency index.js acme-sign@2.0.1": "reachable",
		"dependency index.js acme-seal@3.0.0": "reachable",
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
	missing := []any{map[string]any{"module": "@acme/missing", "version": "1.0.0", "purl": "pkg:npm/%40acme/missing", "reason": "no_reachability_data", "error_code": "NO_INFO"}}
	if !reflect.DeepEqual(details["deps_skipped_list"], missing) || details["ecosystems"].([]any)[0] != "node" {
		t.Errorf("dependency phase details = %v", details)
	}
}

// nodeEntryPointRule names two methods of acme-sign's exported Signer as its
// crypto API: sign, whose body digests (the digest finding covers it), and
// verify, whose body has no finding (an entry point is synthesized at it).
const nodeEntryPointRule = `rules:
- id: acme.sign.api
  languages: [javascript]
  severity: INFO
  message: Acme signing API
  pattern: acmeSignNeverCalled()
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: signature
      algorithmName: ECDSA
      api: acme-sign.Signer.sign
- id: acme.verify.api
  languages: [javascript]
  severity: INFO
  message: Acme verifying API
  pattern: acmeVerifyNeverCalled()
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: signature
      algorithmName: ECDSA
      api: acme-sign.Signer.verify
`

// The offline mode mines an npm dependency as the miner's crypto-finder run
// does, `scan --languages javascript --output F --export-graph-fragment G`,
// and re-annotates its graph as the miner's annotate job does, `annotate
// --languages javascript --source PKG`: the same findings, graph fragment and
// annotation, byte for byte, so the same rule ids, finding ids and entry
// points. The ruleset, laid out as a release, also holds another language's
// rules, which the scan's language hints leave out. The dependency is mined
// through a relative path, as an offline scan of "." finds it under
// node_modules, and the miner's workspace is absolute.
func TestInProcessMinerMinesNodeAsTheScan(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	ruleset := nodeDependencyRuleset(t, dir)
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "semgrep-rules", "javascript", "lib", "rules.yaml"), cardsOnlyNodeRule)
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "semgrep-rules", "javascript", "lib", "api.yaml"), nodeEntryPointRule)
	writeAnnotateCardsFile(t, filepath.Join(ruleset, "semgrep-rules", "java", "x", "rules.yaml"), annotateCardsRules)
	source := filepath.Join(dir, "node_modules", "acme-sign")
	writeAnnotateCardsFile(t, filepath.Join(source, "package.json"), `{"name":"acme-sign","version":"2.0.1","main":"index.js"}`)
	writeAnnotateCardsFile(t, filepath.Join(source, "index.js"), `const h = require("acme-hash");

class Signer {
  sign(x) {
    return h.digest(x);
  }

  verify(x) {
    return x.length > 0;
  }
}

module.exports = { Signer };
`)
	t.Setenv("HOME", dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, append(args, "--languages", "javascript", "--no-remote-rules", "--rules-dir", ruleset)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	findingsPath, fragmentPath := filepath.Join(dir, "findings.json"), filepath.Join(dir, "fragment.json")
	run("scan", "--output", findingsPath, "--export-graph-fragment", fragmentPath, source)

	miner := &inProcessMiner{
		rules:    rules.NewManager(&lockedRules{manager: rules.NewManager(rules.NewLocalRuleSource(nil, []string{ruleset}))}),
		ruleDirs: []string{ruleset},
		timeout:  5 * time.Minute,
		catalogs: cards.NewCatalogs(),
		language: ecosystemNode,
	}
	t.Chdir(dir)
	relative := filepath.Join("node_modules", "acme-sign")
	findings, fragment, err := miner.Mine(t.Context(), relative, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := readBytes(t, findingsPath)
	for _, id := range []string{`"id": "acme.hash.digest"`, `"api": "acme-sign.Signer.verify"`} {
		if !bytes.Contains(want, []byte(id)) {
			t.Fatalf("the scan reports no %s:\n%s", id, want)
		}
	}
	if bytes.Contains(want, []byte(`"api": "acme-sign.Signer.sign"`)) {
		t.Fatalf("the scan synthesizes acme-sign.Signer.sign, whose body's digest covers it:\n%s", want)
	}
	assertSameBytes(t, "findings", want, findings)
	assertSameBytes(t, "fragment", withoutExportTime(readBytes(t, fragmentPath)), withoutExportTime(fragment))

	structural, err := graphfrag.StructuralExport(fragment)
	if err != nil {
		t.Fatal(err)
	}
	structuralPath := filepath.Join(dir, "structural.json")
	if err := os.WriteFile(structuralPath, structural, 0o600); err != nil {
		t.Fatal(err)
	}
	annotation, annotateFindings := filepath.Join(dir, "annotation.json"), filepath.Join(dir, "annotate-findings.json")
	run("annotate", "--import-fragment", structuralPath, "--source", source, "--output", annotation, "--findings-output", annotateFindings)
	gotAnnotation, gotFindings, err := miner.Annotate(t.Context(), structural, func(context.Context) (string, error) { return relative, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(gotAnnotation, []byte("acme-sign.Signer.verify")) {
		t.Errorf("the annotation has no entry point at acme-sign.Signer.verify:\n%s", gotAnnotation)
	}
	assertSameBytes(t, "annotation", withoutExportTime(readBytes(t, annotation)), withoutExportTime(gotAnnotation))
	assertSameBytes(t, "annotate findings", readBytes(t, annotateFindings), gotFindings)
}
