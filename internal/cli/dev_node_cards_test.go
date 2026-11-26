// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/crypto-finder/internal/entities"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// cardsLanguageJavaScript is the cards language of the node ecosystem.
const cardsLanguageJavaScript = "javascript"

// TestDevNodeCardsScan is the developer route to the cards scanner on
// JavaScript and TypeScript. The scan command refuses them
// (language_not_supported) until the node pipeline is validated; this test
// builds the target's node graph, matches a ruleset's JavaScript rules
// (compiled into the index) and cards against it and writes the cards
// scanner's report, as TestDevPythonCardsScan does for Python. It lives in a
// test file so the shipped binary has no route to it.
//
//	CRYPTO_FINDER_DEV_NODE_TARGET=<dir> CRYPTO_FINDER_DEV_NODE_RULES=<ruleset> \
//	CRYPTO_FINDER_DEV_NODE_REPORT=<report.json> [CRYPTO_FINDER_DEV_NODE_CARDS=<cards dir>] \
//	[CRYPTO_FINDER_DEV_NODE_INCLUDE_TESTS=1] \
//	  go test ./internal/cli/ -run TestDevNodeCardsScan -count=1
//
// The ruleset is a directory with semgrep-rules/javascript (and
// cards/javascript); CRYPTO_FINDER_DEV_NODE_INCLUDE_TESTS scans test sources
// as --include-tests does; CRYPTO_FINDER_DEV_NODE_FRAGMENT=<file> also writes
// the graph fragment the cards were matched against.
//
// Without the variables it scans the graph algorithm guard's node corpus with
// the synthetic v3 test ruleset, so the route stays exercised.
func TestDevNodeCardsScan(t *testing.T) {
	target, rules := os.Getenv("CRYPTO_FINDER_DEV_NODE_TARGET"), os.Getenv("CRYPTO_FINDER_DEV_NODE_RULES")
	out, cardsDir := os.Getenv("CRYPTO_FINDER_DEV_NODE_REPORT"), os.Getenv("CRYPTO_FINDER_DEV_NODE_CARDS")
	includeTests := os.Getenv("CRYPTO_FINDER_DEV_NODE_INCLUDE_TESTS") != ""
	if target == "" {
		target = filepath.Join("..", "graphalgoguard", "testdata", "graph_algo_guard", "node", "app")
		rules = devNodeTestRuleset(t)
		out = filepath.Join(t.TempDir(), "report.json")
	}
	if rules == "" || out == "" {
		t.Fatal("CRYPTO_FINDER_DEV_NODE_RULES and CRYPTO_FINDER_DEV_NODE_REPORT must be set with CRYPTO_FINDER_DEV_NODE_TARGET")
	}
	target, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if cardsDir != "" {
		if cardsDir, err = filepath.Abs(cardsDir); err != nil {
			t.Fatal(err)
		}
	}

	report := devNodeCardsScan(t, target, rules, cardsDir, includeTests)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		t.Fatal(err)
	}
	assets := 0
	for _, finding := range report.Findings {
		assets += len(finding.CryptographicAssets)
	}
	t.Logf("%s: %d files with findings, %d assets -> %s", target, len(report.Findings), assets, out)
	if os.Getenv("CRYPTO_FINDER_DEV_NODE_TARGET") == "" && assets != 2 {
		t.Errorf("the invented rule found %d assets in the guard corpus, want 2 (the two digest calls)", assets)
	}
}

// devNodeTestRule is an invented rule for the guard corpus's own "dep"
// module; it comes from no ruleset.
const devNodeTestRule = `rules:
- id: dep-digest
  message: dep digest
  severity: INFO
  languages: [javascript, typescript]
  metadata:
    crypto:
      assetType: algorithm
      algorithmName: DEP
  patterns:
  - pattern-either:
    - pattern-inside: |
        $NS = require("dep")
        ...
    - pattern-inside: |
        const {..., $FN, ...} = require("dep")
        ...
  - pattern-either:
    - pattern: $NS.digest(...)
    - pattern: $FN(...)
  - metavariable-regex:
      metavariable: $FN
      regex: ^digest$
`

// devNodeTestRuleset writes a ruleset holding devNodeTestRule.
func devNodeTestRuleset(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "semgrep-rules", cardsLanguageJavaScript, "dep")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(devNodeTestRule), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// devNodeCardsScan builds target's node graph fragment and matches the
// ruleset's JavaScript rules and the cards of cardsDir against it: the cards
// scanner's report.
func devNodeCardsScan(t *testing.T, target, rules, cardsDir string, includeTests bool) *entities.InterimReport {
	t.Helper()
	fragment := func(dir string) (graphfrag.GraphFragmentExport, error) {
		empty := &entities.InterimReport{}
		graphs := newGraphStore(dir, "")
		result, err := buildStandaloneCallGraphResultForEcosystem(graphs, dir, empty, ecosystemNode,
			javaruntime.Config{}, includeTests, "", devNodeSkipMatcher(dir, includeTests), true)
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		resolved, err := prepareScanOIDProjection(empty, false)
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		export := scanutil.BuildGraphFragmentExport(result, resolved)
		if path := os.Getenv("CRYPTO_FINDER_DEV_NODE_FRAGMENT"); path != "" {
			data, err := json.Marshal(export)
			if err != nil {
				return graphfrag.GraphFragmentExport{}, err
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return graphfrag.GraphFragmentExport{}, err
			}
		}
		return export, nil
	}
	scanner := cards.NewScannerFactory(cards.Options{Language: cardsLanguageJavaScript, RulesDir: rules, CardsDir: cardsDir, Fragment: fragment})()
	var rulePaths []string
	for _, dir := range []string{"javascript", "typescript"} {
		if path := filepath.Join(rules, "semgrep-rules", dir); isDevDir(path) {
			rulePaths = append(rulePaths, path)
		}
	}
	if len(rulePaths) == 0 {
		rulePaths = []string{filepath.Join(rules, "cards", cardsLanguageJavaScript)} // a ruleset of v3 card files
	}
	report, err := scanner.Scan(t.Context(), target, rulePaths,
		entities.ToolInfo{Name: "crypto-finder", Version: "dev-node-cards"})
	if err != nil {
		t.Fatalf("cards scan of %s: %v", target, err)
	}
	return report
}

// devNodeSkipMatcher skips what `scan` skips by default, and test sources
// unless includeTests is set, as --include-tests does.
func devNodeSkipMatcher(target string, includeTests bool) skip.SkipMatcher {
	patterns, _ := buildSkipPatterns(target, false, nil)
	patterns = applyTestSkipPatterns(patterns, includeTests)
	return skip.NewMatcher(patterns, true)
}

func isDevDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
