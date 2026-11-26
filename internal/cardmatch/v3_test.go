// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const v3Synthetic = `format: scanoss-cards/3
rules:
  example.hand:
    severity: "INFO"
    message: "Hand"
    crypto: {assetType: "algorithm", algorithmName: "X"}
  example.site:
    severity: "INFO"
    message: "Site"
    crypto: {assetType: "algorithm"}
  example.pending:
    severity: "INFO"
    message: "Pending"
    pending: "a text search"
x-call: &call {call: example.Hand.make}
cards:
- rule: example.hand
  match: *call
- rule: example.site
  site: {receiver: "any", type: null, method: "update", min_arity: 0, max_arity: null, args: [], receiver_var: "$H", taint: false}
  lossy: ["pattern-not"]
`

func writeCards(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A directory of v3 card files is the whole ruleset: site cards are the
// index (with the rule's metadata and the card's lossy clauses), the other
// cards the hand cards, and no rules directory is read.
func TestLoadV3(t *testing.T) {
	dir := writeCards(t, map[string]string{"lib/rules.cards": v3Synthetic})
	a, err := Load("", dir, filepath.Join(dir, "no-such-rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.index.Entries) != 1 {
		t.Fatalf("index = %d entries, want 1", len(a.index.Entries))
	}
	e := a.index.Entries[0]
	if e.RuleID != "example.site" || e.receiverMetavar() != "$H" || jsonValue(e.Metadata.M) != `{"assetType": "algorithm"}` ||
		len(e.DroppedClauses) != 1 || e.DroppedClauses[0] != "pattern-not" {
		t.Errorf("site entry = %+v", e)
	}
	if len(a.cards.Cards) != 1 || a.cards.Cards[0].Rule != "example.hand" || jsonValue(a.cards.Cards[0].Metadata) != `{"assetType": "algorithm", "algorithmName": "X"}` {
		t.Errorf("hand cards = %+v", a.cards.Cards)
	}
	if _, err := Load(filepath.Join(dir, "index.json"), dir, ""); err == nil {
		t.Error("a compiled index with v3 cards loaded")
	}
}

func TestLoadV3Refuses(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"mixed formats":      {"a/rules.cards": v3Synthetic, "b/rules.cards": "cards:\n- rule: x\n  match: {call: x}\n"},
		"another format":     {"a/rules.cards": strings.Replace(v3Synthetic, "scanoss-cards/3", "scanoss-cards/4", 1)},
		"card on pending":    {"a/rules.cards": v3Synthetic + "- rule: example.pending\n  match: {call: x}\n"},
		"card on no rule":    {"a/rules.cards": v3Synthetic + "- rule: example.none\n  site: {receiver: any}\n"},
		"site card key":      {"a/rules.cards": v3Synthetic + "- rule: example.site\n  site: {receiver: any}\n  with: []\n"},
		"rule key":           {"a/rules.cards": strings.Replace(v3Synthetic, `message: "Site"`, "message: Site\n    mode: taint", 1)},
		"rule defined twice": {"a/rules.cards": v3Synthetic, "b/rules.cards": v3Synthetic},
		"unknown file key":   {"a/rules.cards": strings.Replace(v3Synthetic, "cards:\n", "extra: 1\ncards:\n", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load("", writeCards(t, files), ""); err == nil {
				t.Error("loaded")
			}
		})
	}
}

// A card (hand or site) under one language's directory naming a rule
// another language's card file defines is rejected at load, even when both are loaded together
// (go-port audit C6): it would drop that rule's entries from its own
// language's scans and run on this one's.
func TestV3CardOfAnotherLanguage(t *testing.T) {
	dir := writeCards(t, map[string]string{
		"cards/go/a.cards": "format: scanoss-cards/3\nrules:\n  acme.go.rule:\n    severity: INFO\n    message: m\n    crypto: {assetType: algorithm}\ncards: []\n",
		"cards/python/b.cards": "format: scanoss-cards/3\nrules:\n  acme.py.rule:\n    severity: INFO\n    message: m\n    crypto: {assetType: algorithm}\n" +
			"cards:\n- rule: acme.go.rule\n  match: {call: acme.Make}\n",
	})
	_, err := Load("", filepath.Join(dir, "cards"), "")
	if err == nil || !strings.Contains(err.Error(), "the rule is a go rule, the card is under cards/python") {
		t.Fatalf("err = %v, want the cross-language card rejected", err)
	}
	site := writeCards(t, map[string]string{
		"cards/go/a.cards":     "format: scanoss-cards/3\nrules:\n  acme.go.rule:\n    severity: INFO\n    message: m\n    crypto: {assetType: algorithm}\ncards: []\n",
		"cards/python/b.cards": "format: scanoss-cards/3\ncards:\n- rule: acme.go.rule\n  site: {receiver: \"any\", type: null, method: \"make\", min_arity: 0, max_arity: null, args: [], taint: false}\n",
	})
	if _, err := Load("", filepath.Join(site, "cards"), ""); err == nil || !strings.Contains(err.Error(), "the rule is a go rule, the card is under cards/python") {
		t.Fatalf("site card: err = %v, want the cross-language card rejected", err)
	}
	ok := writeCards(t, map[string]string{
		"cards/go/a.cards": "format: scanoss-cards/3\nrules:\n  acme.go.rule:\n    severity: INFO\n    message: m\n    crypto: {assetType: algorithm}\ncards: []\n",
		"cards/go/b.cards": "format: scanoss-cards/3\ncards:\n- rule: acme.go.rule\n  match: {call: acme.Make}\n",
	})
	if _, err := Load("", filepath.Join(ok, "cards"), ""); err != nil {
		t.Fatalf("a card in its rule's language: %v", err)
	}
}
