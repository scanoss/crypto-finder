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

package cardmatch

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var rustHandDir = filepath.Join("testdata", "rust_hand")

// rustHandFragment is testdata/rust_hand's fragment.
func rustHandFragment(t *testing.T) *FragmentJSON {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rustHandDir, "fragment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frag FragmentJSON
	if err := json.Unmarshal(data, &frag); err != nil {
		t.Fatal(err)
	}
	return &frag
}

// rustHandRegexOnly are OpenGrep's results of testdata/rust_hand that only a
// text regex finds: an Encryptor call in a comment (line 19) and a Decryptor
// call in a string literal (line 20). The hand cards read code and do not
// report them.
var rustHandRegexOnly = map[string][]int{"acme-enc": {19}, "acme-dec": {20}}

// TestRustHandCardsAsOpenGrep pins Rust hand cards to what OpenGrep 1.33.1
// reports for invented pattern-regex rules on an invented file: a turbofish
// constructor whose generic is written bare, qualified, through a use, over
// two lines, with a named group the metadata reads, and an alternative
// constructor name. Same (file, line, rule) set apart from rustHandRegexOnly,
// same metadata, same start column. The end column differs by design:
// OpenGrep's range is the regex match, which ends at the call's `(`; the
// card's is the call's, which ends after its `)` (on line 10 for the call
// written over two lines).
func TestRustHandCardsAsOpenGrep(t *testing.T) {
	assets, err := Load("", filepath.Join(rustHandDir, "cards"), filepath.Join(rustHandDir, "rules"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]opengrepHit
	data, err := os.ReadFile(filepath.Join(rustHandDir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	fr := newFrag(rustHandFragment(t))
	fr.ResolveParams = true
	found, stats := matchRustStats(assets, fr)
	if stats.Held != 0 || len(stats.Undecided) != 0 {
		t.Fatalf("stats = %+v, want none held or undecided", stats)
	}
	type place struct {
		File      string
		Line, Col int
	}
	got := map[string]map[place]string{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[place]string{}
		}
		got[f.RuleID][place{f.File, f.Line, f.Col}] = f.MetadataFields()["algorithmName"].(string)
		if f.EndCol == 0 {
			t.Errorf("%s at %d: no end column", f.RuleID, f.Line)
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), []string{"acme-dec", "acme-enc"}) {
		t.Fatalf("rules found = %v", slices.Sorted(maps.Keys(got)))
	}
	for id, hits := range want {
		exp := map[place]string{}
		for _, h := range hits {
			if slices.Contains(rustHandRegexOnly[id], h.Line) {
				continue
			}
			tmpl := assets.cardMeta(id)
			exp[place{h.File, h.Line, h.Col}] = strings.ReplaceAll(tmpl, "$bits", h.Metavar["$bits"])
		}
		if !maps.Equal(got[id], exp) {
			t.Errorf("%s\n got %v\nwant %v", id, got[id], exp)
		}
		if len(exp)+len(rustHandRegexOnly[id]) != len(hits) {
			t.Errorf("%s: %d OpenGrep results, %d matched and %v regex only", id, len(hits), len(exp), rustHandRegexOnly[id])
		}
	}
}

// cardMeta is the algorithmName template of rule id's hand card entries.
func (a *Assets) cardMeta(id string) string {
	for _, e := range a.cards.Rust {
		if e.RuleID == id {
			s, _ := e.Metadata.M.GetOr("algorithmName").(string)
			return s
		}
	}
	return ""
}

const rustCardRules = `rules:
- id: acme-search
  languages: [rust]
  message: m
  severity: INFO
  metadata: {crypto: {assetType: algorithm, algorithmName: "S-$C"}}
  pattern: Encryptor::<$C>::new_from_slices(...)
- id: acme-taint
  languages: [rust]
  message: m
  severity: INFO
  mode: taint
  metadata: {crypto: {assetType: algorithm}}
  pattern-sources: [{pattern: acme_rng::fill(...)}]
  pattern-sinks: [{pattern: acme_mode::seal($K)}]
`

// rustCardSet loads the cards text against rustCardRules.
func rustCardSet(t *testing.T, cards string) (*CardSet, error) {
	t.Helper()
	dir := writeCards(t, map[string]string{"rules/rules.yaml": rustCardRules, "cards/c.cards": cards})
	return defaults.loadCards(filepath.Join(dir, "cards"), filepath.Join(dir, "rules"))
}

// A Rust hand card that would not replace its rule with working entries is
// a load error naming the card.
func TestRustCardLoadErrors(t *testing.T) {
	for name, tc := range map[string]struct{ card, want string }{
		"two kinds": {
			"- rule: acme-search\n  rust: {pattern: 'acme::f()'}\n  match: {call: acme.f}\n", "bad card acme-search",
		},
		"taint rule": {
			"- rule: acme-taint\n  rust: {pattern: 'acme_mode::seal($K)'}\n", "rust card acme-taint: a rust card replaces a search rule",
		},
		"skipped formula": {
			"- rule: acme-search\n  rust:\n    patterns:\n    - pattern: 'acme::f()'\n    - metavariable-regex: {metavariable: $X, regex: a}\n",
			"rust card acme-search does not compile: " + string(skipRustUnbound),
		},
		"regex formula": {
			"- rule: acme-search\n  rust: {pattern-regex: 'acme'}\n", "rust card acme-search: want one of pattern, patterns, pattern-either",
		},
		"two formulas": {
			"- rule: acme-search\n  rust: {pattern: 'acme::f()', pattern-either: []}\n", "rust card acme-search: want one of",
		},
		"unknown rule": {
			"- rule: acme-nope\n  rust: {pattern: 'acme::f()'}\n", "bad card acme-nope",
		},
		"java refinement": {
			"- rule: acme-search\n  rust: {pattern: 'acme::f()'}\n  not_in: [acme.T]\n", "bad rust card acme-search ['not_in']",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := rustCardSet(t, "cards:\n"+tc.card)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A Rust hand card replaces every compiled entry of its rule in the Rust
// matcher, and neither runs in the Java/Python path.
func TestRustCardReplacesCompiledEntries(t *testing.T) {
	dir := writeCards(t, map[string]string{
		"rules/rules.yaml": rustCardRules,
		"cards/c.cards": `cards:
- rule: acme-search
  rust:
    patterns:
    - pattern: Decryptor::<$C>::new(...)
    - metavariable-regex: {metavariable: $C, regex: 'Blk(?P<bits>\d+)'}
`,
	})
	lines := func(cardsDir string) map[int]string {
		a, err := Load("", cardsDir, filepath.Join(dir, "rules"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		out := map[int]string{}
		found, _ := a.mustMatch(t, rustHandFragment(t))
		for _, f := range found {
			out[f.Line] = f.RuleID + " " + f.MetadataFields()["algorithmName"].(string)
		}
		java := rustHandFragment(t)
		java.ScanMetadata.Ecosystem = "java"
		if found, _ := a.mustMatch(t, java); len(found) != 0 {
			t.Errorf("the Java path found %d", len(found))
		}
		return out
	}
	if got := lines(""); !maps.Equal(got, map[int]string{11: "acme-search S-Blk128"}) {
		t.Errorf("compiled: %v", got)
	}
	if got := lines(filepath.Join(dir, "cards")); !maps.Equal(got, map[int]string{16: "acme-search S-Blk256"}) {
		t.Errorf("hand card: %v", got)
	}
}

// A Rust hand card for a Java or Python rule is a load error: it would drop
// the rule's Java or Python entries and run only in the Rust matcher. A
// rule YAML's languages say whether a rule is Rust; a v3 rules entry is
// Rust when its card file is under cards/rust/.
func TestRustCardForAnotherLanguageIsAnError(t *testing.T) {
	card := "- rule: acme-java\n  rust: {pattern: 'acme::f()'}\n"
	dir := writeCards(t, map[string]string{
		"rules/rules.yaml": "rules:\n- id: acme-java\n  languages: [java]\n  message: m\n  severity: INFO\n" +
			"  metadata: {crypto: {assetType: algorithm}}\n  pattern: acme.Kdf.derive(...)\n",
		"cards/c.cards": "cards:\n" + card,
	})
	want := "rust card acme-java: acme-java is not a rust rule"
	if _, err := defaults.loadCards(filepath.Join(dir, "cards"), filepath.Join(dir, "rules")); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("v2: err = %v, want %q", err, want)
	}
	v3 := "format: scanoss-cards/3\nrules:\n  acme-java: {severity: INFO, message: m, crypto: {assetType: algorithm}}\ncards:\n" + card
	dir = writeCards(t, map[string]string{"cards/java/rules.cards": v3})
	if _, err := Load("", filepath.Join(dir, "cards"), "", Options{}); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("v3: err = %v, want %q", err, want)
	}
}

// v3 card files carry Rust hand cards too, with the rules entry's crypto as
// their metadata.
func TestLoadV3RustCard(t *testing.T) {
	dir := writeCards(t, map[string]string{"cards/rust/rules.cards": `format: scanoss-cards/3
rules:
  acme-enc:
    severity: "INFO"
    message: "m"
    crypto: {assetType: "algorithm", algorithmName: "V3-$bits"}
cards:
- rule: acme-enc
  rust:
    patterns:
    - pattern: Encryptor::<$C>::new(...)
    - metavariable-regex: {metavariable: $C, regex: '^Blk(?P<bits>128|256)$'}
`})
	a, err := Load("", dir, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.cards.Cards) != 0 || len(a.cards.Rust) != 1 || !a.cards.RuleIDs["acme-enc"] {
		t.Fatalf("cards = %d, rust = %d, rules = %v", len(a.cards.Cards), len(a.cards.Rust), a.cards.RuleIDs)
	}
	found, _ := a.mustMatch(t, rustHandFragment(t))
	got := map[int]string{}
	for _, f := range found {
		got[f.Line] = f.MetadataFields()["algorithmName"].(string)
	}
	if !maps.Equal(got, map[int]string{6: "V3-256", 9: "V3-256"}) {
		t.Errorf("found %v", got)
	}
}

var rustAliasDir = filepath.Join("testdata", "rust_alias")

// rustAliasHit is an OpenGrep result of testdata/rust_alias with the line it
// ends on.
type rustAliasHit struct {
	opengrepHit
	EndLine int `json:"end_line"`
}

// rustAliasRegexOnly are OpenGrep's results of testdata/rust_alias that only
// a text regex finds: an alias in a comment (line 46) and in a string literal
// (line 47).
var rustAliasRegexOnly = map[string][]int{"acme-mode": {46, 47}}

// rustAliasCardOnly are the type aliases of testdata/rust_alias the cards
// report and the regex does not: spaces inside `<...>` (line 48, the card
// reads the aliased type, not its spelling) and generic parameters on the
// alias (line 49, which the items do not carry).
var rustAliasCardOnly = map[string][]int{"acme-mode": {48, 49}}

// TestRustAliasCardsAsOpenGrep pins Rust hand cards with a type alias
// pattern, `type $A = acme_mode::$D<$C>;`, to what OpenGrep 1.33.1 reports for
// invented pattern-regex rules on an invented file: an alias plain, `pub` or
// `pub(crate)`, its mode path qualified or bare, its generic bare or
// qualified, with several arguments, written over two or three lines, in a
// mod, in a fn, as an impl's associated type, after a use the rule requires;
// and look-alikes neither reports (another crate's mode, another size, a
// wrapper, another arity, a local's type, a path the regex does not allow).
// Same (file, line, rule) set apart from rustAliasRegexOnly and
// rustAliasCardOnly, same start and end, same metadata from the named groups.
//
// The fixture's type item rule (acme-item) is OpenGrep's own reading of the
// pattern: it reports from the alias name to the end of the aliased type and
// tells paths apart by their last segment (`other::Encryptor` at line 33).
// The compiler holds it in a rule YAML; only a hand card's is served.
func TestRustAliasCardsAsOpenGrep(t *testing.T) {
	assets, err := Load("", filepath.Join(rustAliasDir, "cards"), filepath.Join(rustAliasDir, "rules"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]rustAliasHit
	data, err := os.ReadFile(filepath.Join(rustAliasDir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	frag := rustAliasFragment(t)
	found, stats := matchRustStats(assets, newFrag(frag))
	if stats.Held != 1 || stats.HeldBy[holdItemPos] != 1 || len(stats.Undecided) != 0 || stats.UnreadableSites != 0 {
		t.Fatalf("stats = %+v, want the type item rule held, nothing undecided or unreadable", stats)
	}
	if len(want["acme-item"]) == 0 {
		t.Fatal("OpenGrep reports nothing for the type item rule")
	}
	type place struct {
		File                       string
		Line, Col, EndLine, EndCol int
	}
	got := map[string]map[place]string{}
	for _, f := range found {
		if got[f.RuleID] == nil {
			got[f.RuleID] = map[place]string{}
		}
		got[f.RuleID][place{f.File, f.Line, f.Col, max(f.EndLine, f.Line), f.EndCol}] = f.MetadataFields()["algorithmName"].(string)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), []string{"acme-mode", "acme-seal"}) {
		t.Fatalf("rules found = %v", slices.Sorted(maps.Keys(got)))
	}
	for _, id := range []string{"acme-mode", "acme-seal"} {
		exp := map[place]string{}
		for _, h := range want[id] {
			if slices.Contains(rustAliasRegexOnly[id], h.Line) {
				continue
			}
			name := assets.cardMeta(id)
			for _, k := range []string{"$bits", "$dir"} {
				name = strings.ReplaceAll(name, k, h.Metavar[k])
			}
			exp[place{h.File, h.Line, h.Col, h.EndLine, h.EndCol}] = name
		}
		var cardOnly []int
		for p := range got[id] {
			if slices.Contains(rustAliasCardOnly[id], p.Line) {
				cardOnly = append(cardOnly, p.Line)
				delete(got[id], p)
			}
		}
		slices.Sort(cardOnly)
		if !slices.Equal(cardOnly, rustAliasCardOnly[id]) {
			t.Errorf("%s: card only at %v, want %v", id, cardOnly, rustAliasCardOnly[id])
		}
		if !maps.Equal(got[id], exp) {
			t.Errorf("%s\n got %v\nwant %v", id, got[id], exp)
		}
		if len(exp)+len(rustAliasRegexOnly[id]) != len(want[id]) {
			t.Errorf("%s: %d OpenGrep results, %d matched and %v regex only", id, len(want[id]), len(exp), rustAliasRegexOnly[id])
		}
	}
}

// rustAliasFragment is testdata/rust_alias's fragment.
func rustAliasFragment(t *testing.T) *FragmentJSON {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rustAliasDir, "fragment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frag FragmentJSON
	if err := json.Unmarshal(data, &frag); err != nil {
		t.Fatal(err)
	}
	return &frag
}

// A hand card's type alias pattern waits for the aliased types a
// graph-fragment-1.27 lists; an older fragment holds it.
func TestRustAliasCardsHeldOnOlderFragment(t *testing.T) {
	assets, err := Load("", filepath.Join(rustAliasDir, "cards"), filepath.Join(rustAliasDir, "rules"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	frag := rustAliasFragment(t)
	frag.SchemaVersion = "graph-fragment-1.26"
	found, stats := matchRustStats(assets, newFrag(frag))
	if len(found) != 0 || stats.Held != 5 || stats.HeldBy[holdItemTypes] != 4 || stats.HeldBy[holdItemPos] != 1 {
		t.Errorf("found %d, stats = %+v, want the 4 card entries held for item types", len(found), stats)
	}
}
