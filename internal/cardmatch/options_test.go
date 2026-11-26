package cardmatch

import (
	"path/filepath"
	"strings"
	"testing"
)

// Options.MetadataKey names the rules entry block a finding carries, and
// Options.ExtraRuleKeys admits further keys in a rules entry; without them
// such a file is refused.
func TestOptionsMetadataKey(t *testing.T) {
	file := strings.NewReplacer(`crypto: {assetType: "algorithm", algorithmName: "X"}`, `usage: {kind: "model", provider: "acme"}`+"\n    owner: team",
		`crypto: {assetType: "algorithm"}`, `usage: {kind: "site"}`).Replace(v3Synthetic)
	dir := writeCards(t, map[string]string{"lib/rules.cards": file})
	if _, err := Load("", dir, "", Options{}); err == nil {
		t.Fatal("rules entries with another metadata key loaded under the default key")
	}
	a, err := Load("", dir, "", Options{MetadataKey: "usage", ExtraRuleKeys: []string{"owner"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := jsonValue(a.cards.Cards[0].Metadata); got != `{"kind": "model", "provider": "acme"}` {
		t.Errorf("hand card metadata = %s", got)
	}
	if got := jsonValue(a.index.Entries[0].Metadata.M); got != `{"kind": "site"}` {
		t.Errorf("site entry metadata = %s", got)
	}
}

// Options.LanguageOf replaces the cards/<language>/ layout: here a card file
// names its language in its file name.
func TestOptionsLanguageOf(t *testing.T) {
	dir := writeCards(t, map[string]string{
		"a.go.cards": "format: scanoss-cards/3\nrules:\n  acme.go.rule:\n    severity: INFO\n    message: m\n    crypto: {assetType: algorithm}\ncards: []\n",
		"b.py.cards": "format: scanoss-cards/3\ncards:\n- rule: acme.go.rule\n  match: {call: acme.Make}\n",
	})
	if _, err := Load("", dir, "", Options{}); err != nil {
		t.Fatalf("no language without a cards/ directory: %v", err)
	}
	byName := func(path string) string { return strings.Split(filepath.Base(path), ".")[1] }
	_, err := Load("", dir, "", Options{LanguageOf: byName})
	if err == nil || !strings.Contains(err.Error(), "the rule is a go rule, the card is under cards/py") {
		t.Fatalf("err = %v, want the cross-language card rejected", err)
	}
}

func TestCardsDirLanguage(t *testing.T) {
	for path, want := range map[string]string{
		"/r/cards/python/lib/a.cards": "python",
		"cards/go/a.cards":            "go",
		"/r/rules/a.yaml":             "",
		"/r/cards/a.cards":            "",
	} {
		if got := CardsDirLanguage(path); got != want {
			t.Errorf("CardsDirLanguage(%q) = %q, want %q", path, got, want)
		}
	}
}
