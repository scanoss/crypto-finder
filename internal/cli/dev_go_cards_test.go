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

	"github.com/scanoss/crypto-finder/internal/entities"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/cards"
)

// devGoTestRule is a made-up Go rule for the default run of the dev scan.
const devGoTestRule = `rules:
  - id: sum256
    message: SHA-256 digest
    severity: INFO
    languages: [go]
    patterns:
      - pattern-either:
          - pattern-inside: |
              import (
                ...
                "crypto/sha256"
                ...
              )
              ...
          - pattern-inside: |
              import "crypto/sha256"
      - pattern: sha256.Sum256(...)
    metadata:
      purl: pkg:golang/example.com/test
      crypto:
        assetType: algorithm
        algorithmPrimitive: hash
        algorithmName: SHA-256
  - id: tls-version
    message: TLS version constant
    severity: INFO
    languages: [go]
    patterns:
      - pattern: tls.$V
      - metavariable-regex:
          metavariable: $V
          regex: ^VersionTLS1[0-3]$
    metadata:
      purl: pkg:golang/example.com/test
      crypto:
        assetType: protocol
        protocolType: tls
`

// devGoTestCards is a made-up hand card for the rule the compiler cannot
// compile (a constant reference).
const devGoTestCards = `cards:
- rule: tls-version
  constant: {const: crypto/tls, member: '^VersionTLS1[0-3]$'}
`

// TestDevGoCardsScan is the developer route to the cards scanner on Go, as
// TestDevPythonCardsScan is for Python: it builds the target's Go graph,
// matches a ruleset's Go rules (compiled into the index) and cards against it
// and writes the cards scanner's report, without scan's pipeline.
//
//	CRYPTO_FINDER_DEV_GO_TARGET=<dir> CRYPTO_FINDER_DEV_GO_RULES=<ruleset> \
//	CRYPTO_FINDER_DEV_GO_REPORT=<report.json> [CRYPTO_FINDER_DEV_GO_CARDS=<cards dir>] \
//	  go test ./internal/cli/ -run TestDevGoCardsScan -count=1
//
// Without the variables it scans the graph algorithm guard's Go corpus with a
// made-up rule, so the route stays exercised.
func TestDevGoCardsScan(t *testing.T) {
	target, rules := os.Getenv("CRYPTO_FINDER_DEV_GO_TARGET"), os.Getenv("CRYPTO_FINDER_DEV_GO_RULES")
	out, cardsDir := os.Getenv("CRYPTO_FINDER_DEV_GO_REPORT"), os.Getenv("CRYPTO_FINDER_DEV_GO_CARDS")
	if target == "" {
		target = filepath.Join("..", "graphalgoguard", "testdata", "graph_algo_guard", "go", "app")
		rules = t.TempDir()
		dir := filepath.Join(rules, "semgrep-rules", "go", "test")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(devGoTestRule), 0o600); err != nil {
			t.Fatal(err)
		}
		cardsDir = filepath.Join(rules, "cards", "go")
		if err := os.MkdirAll(filepath.Join(cardsDir, "test"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cardsDir, "test", "rules.cards"), []byte(devGoTestCards), 0o600); err != nil {
			t.Fatal(err)
		}
		out = filepath.Join(t.TempDir(), "report.json")
	}
	if rules == "" || out == "" {
		t.Fatal("CRYPTO_FINDER_DEV_GO_RULES and CRYPTO_FINDER_DEV_GO_REPORT must be set with CRYPTO_FINDER_DEV_GO_TARGET")
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

	fragment := func(dir string) (graphfrag.GraphFragmentExport, error) {
		empty := &entities.InterimReport{}
		result, err := buildStandaloneCallGraphResult(newGraphStore(dir, ""), dir, empty, []string{"go"},
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
	scanner := cards.NewScannerFactory(cards.Options{Language: "go", RulesDir: rules, CardsDir: cardsDir, Fragment: fragment})()
	report, err := scanner.Scan(t.Context(), target, []string{filepath.Join(rules, "semgrep-rules", "go")},
		entities.ToolInfo{Name: "crypto-finder", Version: "dev-go-cards"})
	if err != nil {
		t.Fatalf("cards scan of %s: %v", target, err)
	}
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
	if os.Getenv("CRYPTO_FINDER_DEV_GO_TARGET") == "" {
		found := map[string]int{}
		for _, finding := range report.Findings {
			for _, asset := range finding.CryptographicAssets {
				for _, rule := range asset.Rules {
					found[rule.ID]++
				}
			}
		}
		if found["test.sum256"] == 0 || found["test.tls-version"] == 0 {
			t.Errorf("findings by rule %v: want the compiled rule (sha256.Sum256) and the hand card (tls.VersionTLS1x)", found)
		}
	}
}
