// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/crypto-finder/internal/entities"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// v3TestRuleset is a synthetic ruleset of v3 card files (cards/java,
// cards/python): made-up rules for the scan tests.
var v3TestRuleset = filepath.Join("testdata", "v3-ruleset")

// TestDevPythonCardsScan is the developer route to the cards scanner on Python
// (E2.7-py.9). The scan command refuses Python targets
// (language_not_supported) until the whole Python pipeline is validated; this
// test builds the target's Python graph as TestDevPythonFragmentExport does,
// matches a ruleset's Python rules (compiled into the index) and cards
// against it and writes the cards scanner's report (the interim report the
// scan pipeline starts from). It lives in a test file so the shipped binary
// has no route to it.
//
//	CRYPTO_FINDER_DEV_PY_TARGET=<dir> CRYPTO_FINDER_DEV_PY_RULES=<ruleset> \
//	CRYPTO_FINDER_DEV_PY_REPORT=<report.json> [CRYPTO_FINDER_DEV_PY_CARDS=<cards dir>] \
//	  go test ./internal/cli/ -run TestDevPythonCardsScan -count=1
//
// The ruleset is a directory with semgrep-rules/python (and cards/python);
// CRYPTO_FINDER_DEV_PY_CARDS overrides the cards directory;
// CRYPTO_FINDER_DEV_PY_TYPE_PACKAGES types the graph as --type-packages does. The index is
// compiled from the Python rules; a card replaces its rule's entries.
//
// Without the variables it scans the graph algorithm guard's Python corpus
// with the synthetic v3 test ruleset, so the route stays exercised.
func TestDevPythonCardsScan(t *testing.T) {
	target, rules := os.Getenv("CRYPTO_FINDER_DEV_PY_TARGET"), os.Getenv("CRYPTO_FINDER_DEV_PY_RULES")
	out, cardsDir := os.Getenv("CRYPTO_FINDER_DEV_PY_REPORT"), os.Getenv("CRYPTO_FINDER_DEV_PY_CARDS")
	if target == "" {
		target = filepath.Join("..", "graphalgoguard", "testdata", "graph_algo_guard", "python", "app")
		rules = v3TestRuleset
		out = filepath.Join(t.TempDir(), "report.json")
	}
	if rules == "" || out == "" {
		t.Fatal("CRYPTO_FINDER_DEV_PY_RULES and CRYPTO_FINDER_DEV_PY_REPORT must be set with CRYPTO_FINDER_DEV_PY_TARGET")
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

	report := devPythonCardsScan(t, target, rules, cardsDir)
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
	if os.Getenv("CRYPTO_FINDER_DEV_PY_TARGET") == "" && assets == 0 {
		t.Error("the fixture cards found nothing in the guard corpus (hashlib and hmac calls)")
	}
}

// devPythonCardsScan builds target's Python graph fragment and matches the
// ruleset's Python rules and the cards of cardsDir against it: the cards
// scanner's report.
func devPythonCardsScan(t *testing.T, target, rules, cardsDir string) *entities.InterimReport {
	t.Helper()
	fragment := func(dir string) (graphfrag.GraphFragmentExport, error) {
		empty := &entities.InterimReport{}
		graphs := newGraphStore(dir, "")
		graphs.typePackages = os.Getenv("CRYPTO_FINDER_DEV_PY_TYPE_PACKAGES")
		result, err := buildStandaloneCallGraphResult(graphs, dir, empty, []string{ecosystemPython},
			javaruntime.Config{}, false, "", devScanSkipMatcher(dir))
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		resolved, err := prepareScanOIDProjection(empty, false)
		if err != nil {
			return graphfrag.GraphFragmentExport{}, err
		}
		return scanutil.BuildGraphFragmentExport(result, resolved), nil
	}
	scanner := cards.NewScannerFactory(cards.Options{Language: ecosystemPython, RulesDir: rules, CardsDir: cardsDir, Fragment: fragment})()
	rulePath := filepath.Join(rules, "semgrep-rules", ecosystemPython)
	if _, err := os.Stat(rulePath); err != nil {
		rulePath = filepath.Join(rules, "cards", ecosystemPython) // a ruleset of v3 card files
	}
	report, err := scanner.Scan(t.Context(), target, []string{rulePath},
		entities.ToolInfo{Name: "crypto-finder", Version: "dev-python-cards"})
	if err != nil {
		t.Fatalf("cards scan of %s: %v", target, err)
	}
	return report
}

// devScanSkipMatcher skips what `scan` skips by default (built-in and
// project exclusions, test sources), so the developer route reads the files a
// released scan of the same target reads.
func devScanSkipMatcher(target string) skip.SkipMatcher {
	patterns, _ := buildSkipPatterns(target, false, nil)
	patterns = applyTestSkipPatterns(patterns, false)
	patterns = applyCTestSkipPatterns(patterns, target, false)
	return skip.NewMatcher(patterns, true)
}

var cardRuleID = regexp.MustCompile(`(?m)^- rule: (\S+)$`)

// stubPythonRuleset writes a ruleset with a stub rule for each card's rule id
// under cardsDir (semgrep-rules/python/stub/rules.yaml).
func stubPythonRuleset(t *testing.T, cardsDir string) string {
	t.Helper()
	root := t.TempDir()
	rules := "rules:\n"
	err := filepath.WalkDir(cardsDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".cards" {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a fixture under testdata.
		if err != nil {
			return err
		}
		for _, m := range cardRuleID.FindAllStringSubmatch(string(data), -1) {
			rules += "- {id: " + m[1] + ", languages: [python], message: stub, severity: INFO, pattern: x(), metadata: {crypto: {assetType: algorithm}}}\n"
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "semgrep-rules", ecosystemPython, "stub")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
