// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package rules

import (
	"crypto/sha256"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/scanoss/reach/parsememo"
)

const memoCardFile = `format: scanoss-cards/3
rules:
  example.mixed:
    severity: "INFO"
    message: "Mixed values"
    purl: "pkg:pypi/example"
    crypto:
      assetType: algorithm
      keySize: 256
      ratio: 0.5
      fips: true
      none: null
      modes: [cbc, gcm]
      empty_list: []
      empty_map: {}
      nested: {a: [1, {b: x}]}
    conditioned:
      symbols: ["example.mixed"]
      capture_names: []
      capture_binders: ["^(?:X)$"]
  example.plain:
    severity: "LOW"
    message: "No crypto"
    pending: "a text search"
cards:
- rule: example.mixed
  match: {call: example.mixed}
`

// startProcess gives the test a new process: no card file parsed yet, the
// memo not loaded, and its files under home.
func startProcess(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	parsememo.Enable(home)
	cardsParsed = sync.Map{}
	cardsFilesRead = sync.Map{}
	cardsMemo = parsememo.New("cards-rules")
	t.Cleanup(func() {
		cardsParsed = sync.Map{}
		cardsFilesRead = sync.Map{}
		cardsMemo = parsememo.New("cards-rules")
	})
}

func TestCardsMemoServesTheNextProcess(t *testing.T) {
	home := t.TempDir()
	startProcess(t, home)
	parsed, err := ReadCardsRules([]byte(memoCardFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCardsMemo(); err != nil {
		t.Fatal(err)
	}

	startProcess(t, home)
	served, ok := memoCardsRules(sha256.Sum256([]byte(memoCardFile)))
	if !ok {
		t.Fatal("the next process finds no memo entry")
	}
	if !reflect.DeepEqual(served, parsed) {
		t.Fatalf("served %#v\nparsed %#v", served, parsed)
	}
	mixed := served[0]
	if mixed.Crypto["keySize"] != 256 || mixed.Crypto["ratio"] != 0.5 || mixed.Crypto["fips"] != true {
		t.Errorf("scalars = %#v", mixed.Crypto)
	}
	if got := mixed.Crypto["empty_list"]; !reflect.DeepEqual(got, []any{}) {
		t.Errorf("empty_list = %#v, want an empty, non-nil list", got)
	}
	if got := mixed.Conditioned.CaptureNames; got == nil || len(got) != 0 {
		t.Errorf("capture_names = %#v, want an empty, non-nil list", got)
	}
	if served[1].Crypto != nil || served[1].Conditioned != nil || served[1].Pending != "a text search" {
		t.Errorf("example.plain = %#v", served[1])
	}
}

func TestCardsMemoLeavesOutValuesItCannotEncode(t *testing.T) {
	home := t.TempDir()
	startProcess(t, home)
	stamped := "format: scanoss-cards/3\nrules:\n  example.t:\n    crypto: {since: 2001-02-03}\n"
	if _, err := ReadCardsRules([]byte(stamped)); err != nil {
		t.Fatal(err)
	}
	if err := SaveCardsMemo(); err != nil {
		t.Fatal(err)
	}

	startProcess(t, home)
	if _, ok := memoCardsRules(sha256.Sum256([]byte(stamped))); ok {
		t.Fatal("a rule with a timestamp is in the memo")
	}
	found, err := ReadCardsRules([]byte(stamped))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC); found[0].Crypto["since"] != want {
		t.Errorf("since = %#v, want %v", found[0].Crypto["since"], want)
	}
}
