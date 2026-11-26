// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"strings"
	"testing"
)

// An args key of the `"i|name"` form (a parameter passed by position or by
// keyword, docs/CARDS.md) is read as position i on a fragment of a language
// with no keyword arguments, and a keyword-only key matches no argument
// there: a card tree loaded whole runs every language's cards on every
// fragment, and neither key may stop the scan.
func TestArgKeysOnAFragmentWithoutKeywords(t *testing.T) {
	for name, tc := range map[string]struct {
		card string
		want int
	}{
		"position or keyword": {`{call: KeyPairGenerator.getInstance, args: {"0|algorithm": {regex: '^"(?<name>RSA)"$'}}}`, 1},
		"keyword only":        {`{call: KeyPairGenerator.getInstance, args: {algorithm: {regex: '^"(?<name>RSA)"$'}}}`, 0},
		"position":            {`{call: KeyPairGenerator.getInstance, args: {0: {regex: '^"(?<name>RSA)"$'}}}`, 1},
	} {
		t.Run(name, func(t *testing.T) {
			got := matchCards(cardsFrom(t, "- rule: r\n  match: "+tc.card+"\n"), tinyFrag())
			if len(got) != tc.want {
				t.Fatalf("findings = %d, want %d", len(got), tc.want)
			}
		})
	}
}

// A card the matcher cannot evaluate stops the scan with an error naming
// the card, never with a panic.
func TestMatchReportsACardItCannotEvaluate(t *testing.T) {
	cards := cardsFrom(t, "- rule: acme.broken\n  match: {call: KeyPairGenerator.getInstance, arity: x}\n")
	a := &Assets{index: &Index{}, cards: &CardSet{Cards: cards, RuleIDs: map[string]bool{}}}
	_, _, err := a.Match(tinyFragJSON())
	if err == nil || !strings.Contains(err.Error(), "acme.broken") || !strings.Contains(err.Error(), "t.yaml") {
		t.Fatalf("err = %v, want an error naming the card and its file", err)
	}
}

// mustMatch is Match failing the test on an error.
func (a *Assets) mustMatch(t testing.TB, frag *FragmentJSON) ([]*Finding, int) {
	t.Helper()
	found, sites, err := a.Match(frag)
	if err != nil {
		t.Fatal(err)
	}
	return found, sites
}
