// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/config"
)

const v3CardFile = `format: scanoss-cards/3
rules:
  example.b:
    severity: "INFO"
    message: "Example B"
    purl: "pkg:pypi/example"
    crypto:
      assetType: "algorithm"
      parameterCondition: "param[0]:type~=^x$"
    conditioned:
      symbols: ["example.b"]
      capture_names: []
      capture_binders: ["^(?:(?<alg>X))"]
  example.a:
    severity: "HIGH"
    message: "Example A"
    pending: "a text search"
cards:
- rule: example.b
  match: {call: example.b}
`

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadCardsRules(t *testing.T) {
	found, err := ReadCardsRules([]byte(v3CardFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].ID != "example.b" || found[1].ID != "example.a" {
		t.Fatalf("rules = %+v, want example.b then example.a", found)
	}
	b := found[0]
	if b.Severity != "INFO" || b.PURL != "pkg:pypi/example" || b.Crypto["assetType"] != "algorithm" ||
		!reflect.DeepEqual(b.Conditioned, &CardsConditioned{Symbols: []string{"example.b"}, CaptureNames: []string{}, CaptureBinders: []string{"^(?:(?<alg>X))"}}) {
		t.Errorf("example.b = %+v", b)
	}
	if found[1].Pending != "a text search" || found[1].Conditioned != nil {
		t.Errorf("example.a = %+v", found[1])
	}
	if _, err := ReadCardsRules([]byte("cards:\n- rule: x\n")); !errors.Is(err, ErrNotV3Cards) {
		t.Errorf("a v2 card file: err = %v, want ErrNotV3Cards", err)
	}
	if _, err := ReadCardsRules([]byte("format: scanoss-cards/9\n")); err == nil || !strings.Contains(err.Error(), "scanoss-cards/9") {
		t.Errorf("another format: err = %v", err)
	}
}

func TestCardsLanguageAndFiles(t *testing.T) {
	for path, want := range map[string]string{
		"/r/cards/python/lib/x/rules.cards":  "python",
		"/r/cards/java/rules.cards":          "java",
		"/tmp/run/python/lib/rules.cards":    "",
		"/r/cards/java/cards/python/a.cards": "python",
	} {
		if got := config.CardsLanguage(path); got != want {
			t.Errorf("config.CardsLanguage(%s) = %q, want %q", path, got, want)
		}
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cards", "python", "b", "rules.cards"), v3CardFile)
	writeFile(t, filepath.Join(root, "cards", "python", "a", "ssl.cards"), v3CardFile)
	writeFile(t, filepath.Join(root, "cards", "python", "a", "rules.marks"), "format: scanoss-marks/1\n")
	writeFile(t, filepath.Join(root, ".hidden", "x.cards"), v3CardFile)
	got := CardFilesUnder(root)
	want := []string{filepath.Join(root, "cards", "python", "a", "ssl.cards"), filepath.Join(root, "cards", "python", "b", "rules.cards")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CardFilesUnder = %v, want %v", got, want)
	}
}

// A ruleset of v3 card files only loads its card files as its rules; one with
// rule YAML loads the YAML (its cards/ is the matcher's).
func TestLocalRuleSourceCardsOnly(t *testing.T) {
	root := t.TempDir()
	card := filepath.Join(root, "cards", "python", "lib", "rules.cards")
	writeFile(t, card, v3CardFile)
	paths, err := NewLocalRuleSource(nil, []string{root}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{card}) {
		t.Errorf("cards-only ruleset paths = %v, want %v", paths, []string{card})
	}
	rule := filepath.Join(root, "semgrep-rules", "python", "rules.yaml")
	writeFile(t, rule, "rules: []\n")
	if paths, err = NewLocalRuleSource(nil, []string{root}).Load(); err != nil || !reflect.DeepEqual(paths, []string{rule}) {
		t.Errorf("mixed ruleset paths = %v (%v), want %v", paths, err, []string{rule})
	}
}

func TestValidateParameterConditionsOfCardFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cards", "python", "ok", "rules.cards"), v3CardFile)
	if err := ValidateParameterConditions([]string{root}); err != nil {
		t.Fatalf("valid conditions: %v", err)
	}
	// An earlier card file (no format key, its rules in a rule YAML beside it) carries no
	// rules to validate, as the cards scanner skips it.
	writeFile(t, filepath.Join(root, "cards", "rust", "lib", "rules.cards"),
		"cards:\n- rule: example.c\n  rust:\n    pattern: example_c(...)\n")
	if err := ValidateParameterConditions([]string{root}); err != nil {
		t.Fatalf("an earlier card file beside v3 ones: %v", err)
	}
	writeFile(t, filepath.Join(root, "cards", "python", "bad", "rules.cards"),
		strings.Replace(v3CardFile, `param[0]:type~=^x$`, `param[0]:nope`, 1))
	err := ValidateParameterConditions([]string{root})
	if err == nil || !strings.Contains(err.Error(), `"example.b"`) {
		t.Errorf("bad condition: err = %v", err)
	}
}

func TestReadCardsRulesParsesEachContentOnce(t *testing.T) {
	if _, err := ReadCardsRules([]byte(v3CardFile)); err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(20, func() { _, _ = ReadCardsRules([]byte(v3CardFile)) }); allocs > 5 {
		t.Errorf("reading a card file already read allocates %v times, want it served without parsing", allocs)
	}
	other := strings.Replace(v3CardFile, "example.b:", "example.c:", 1)
	found, err := ReadCardsRules([]byte(other))
	if err != nil || len(found) != 2 || found[0].ID != "example.c" {
		t.Errorf("other content = %+v, %v, want its own rules", found, err)
	}
	for range 2 {
		if _, err := ReadCardsRules([]byte("format: scanoss-cards/9\n")); err == nil {
			t.Error("another format read twice: want the error both times")
		}
	}
}

func TestReadCardsRulesFileReadsAFileAgainOnlyWhenItChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cards", "python", "example.cards")
	writeFile(t, path, v3CardFile)
	if found, err := ReadCardsRulesFile(path); err != nil || len(found) != 2 {
		t.Fatalf("first read = %v, %v", found, err)
	}

	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	found, err := ReadCardsRulesFile(path)
	if err != nil || len(found) != 2 || found[0].ID != "example.b" {
		t.Fatalf("unchanged file = %v, %v, want its rules without reading it", found, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	changed := strings.Replace(v3CardFile, "example.a:", "example.c:", 1)
	writeFile(t, path, changed)
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	found, err = ReadCardsRulesFile(path)
	if err != nil || len(found) != 2 || found[1].ID != "example.c" {
		t.Fatalf("changed file = %v, %v, want example.c", found, err)
	}
}
