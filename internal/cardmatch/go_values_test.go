// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// Go rules written as a composite literal, a new(T) or a field store match a
// 1.34 fragment's go_values where OpenGrep 1.33.1 reports them (go-port audit
// E3): the pin's source, its facts as reach records them, and OpenGrep's
// findings with their start columns and bound $V.
func TestGoValueRules(t *testing.T) {
	const rules = `rules:
  - {id: lit-field, message: m, severity: INFO, languages: [go], pattern: 'tls.Config{..., MinVersion: $V, ...}', metadata: {crypto: {version: $V}}}
  - {id: lit-addr, message: m, severity: INFO, languages: [go], pattern: '&tls.Config{..., InsecureSkipVerify: true, ...}'}
  - {id: lit-any, message: m, severity: INFO, languages: [go], pattern: 'rsa.PSSOptions{...}'}
  - {id: lit-exact, message: m, severity: INFO, languages: [go], pattern: 'tls.Config{MinVersion: $V}'}
  - {id: new-t, message: m, severity: INFO, languages: [go], pattern: 'new(ecdsa.PrivateKey)'}
  - {id: store, message: m, severity: INFO, languages: [go], pattern: '$C.MinVersion = $V', metadata: {crypto: {version: $V}}}
  - {id: store-typed, message: m, severity: INFO, languages: [go], pattern: '($C : *tls.Config).CipherSuites = $V'}
`
	assets, err := Load("", "", writeRules(t, rules), Options{})
	if err != nil {
		t.Fatal(err)
	}
	field := func(name, value string) graphfrag.GraphFragmentGoValueField {
		return graphfrag.GraphFragmentGoValueField{Name: name, Value: value}
	}
	frag := &FragmentJSON{SchemaVersion: "graph-fragment-1.34", GoValues: map[string][]graphfrag.GraphFragmentGoValue{"main.go": {
		{
			Kind: "composite", Line: 10, StartCol: 7, EndCol: 47, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []graphfrag.GraphFragmentGoValueField{field("MinVersion", "tls.VersionTLS10")},
		},
		{
			Kind: "composite", Line: 11, StartCol: 8, EndCol: 3, EndLine: 13, AddrCol: 7, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []graphfrag.GraphFragmentGoValueField{field("InsecureSkipVerify", "true")},
		},
		{
			Kind: "composite", Line: 14, StartCol: 11, EndCol: 40, AddrCol: 10, TypeText: "rsa.PSSOptions", Package: "crypto/rsa", Type: "PSSOptions",
			Fields: []graphfrag.GraphFragmentGoValueField{field("SaltLength", "0")},
		},
		{Kind: "new", Line: 15, StartCol: 7, EndCol: 28, TypeText: "ecdsa.PrivateKey", Package: "crypto/ecdsa", Type: "PrivateKey"},
		{
			Kind: "store", Line: 17, StartCol: 2, EndCol: 33, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config", Receiver: "c",
			Fields: []graphfrag.GraphFragmentGoValueField{field("MinVersion", "tls.VersionTLS11")},
		},
		{
			Kind: "store", Line: 18, StartCol: 2, EndCol: 57, TypeText: "*tls.Config", Package: "crypto/tls", Type: "*Config", Receiver: "b",
			Fields: []graphfrag.GraphFragmentGoValueField{field("CipherSuites", "[]uint16{tls.TLS_RSA_WITH_RC4_128_SHA}")},
		},
		{
			Kind: "composite", Line: 19, StartCol: 4, EndCol: 44, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []graphfrag.GraphFragmentGoValueField{field("MinVersion", "tls.VersionTLS12")},
		},
	}}}
	frag.ScanMetadata.Ecosystem = ecosystemGo
	found, _ := assets.mustMatch(t, frag)
	got := make([]string, 0, len(found))
	for _, f := range found {
		v := ""
		if f.Metadata != nil {
			v, _ = f.Metadata.GetOr("version").(string)
		}
		got = append(got, f.RuleID+"@"+strconv.Itoa(f.Line)+":"+strconv.Itoa(f.Col)+" "+v)
	}
	sort.Strings(got)
	want := []string{
		"lit-addr@11:7 ",
		"lit-any@14:11 ",
		"lit-exact@10:7 ",
		"lit-exact@19:4 ",
		"lit-field@10:7 tls.VersionTLS10",
		"lit-field@19:4 tls.VersionTLS12",
		"new-t@15:10 ",
		"store-typed@18:2 ",
		"store@17:2 tls.VersionTLS11",
	}
	if len(got) != len(want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d = %q, want %q (all %v)", i, got[i], want[i], got)
		}
	}
}

// A store rule written inside an import clause with an untyped receiver
// matches a store only in a file importing that path (OpenGrep 1.33.1 pin: a
// tls file's `cfg.MinVersion = v` reported, a local struct's store in another
// file not).
func TestGoStoreInImportingFile(t *testing.T) {
	const rule = `rules:
  - id: r
    message: m
    severity: INFO
    languages: [go]
    patterns:
      - pattern-inside: |
          import "crypto/tls"
          ...
      - pattern: $CONFIG.MinVersion = $V
`
	assets, err := Load("", "", writeRules(t, rule), Options{})
	if err != nil {
		t.Fatal(err)
	}
	store := func(receiver string) graphfrag.GraphFragmentGoValue {
		return graphfrag.GraphFragmentGoValue{
			Kind: "store", Line: 6, StartCol: 2, EndCol: 35, Receiver: receiver,
			Fields: []graphfrag.GraphFragmentGoValueField{{Name: "MinVersion", Value: "1"}},
		}
	}
	frag := &FragmentJSON{
		SchemaVersion: "graph-fragment-1.34",
		Imports:       map[string][]graphfrag.GraphFragmentImport{"x.go": {{Module: "crypto/tls"}}},
		GoValues:      map[string][]graphfrag.GraphFragmentGoValue{"x.go": {store("cfg")}, "y.go": {store("o")}},
	}
	frag.ScanMetadata.Ecosystem = ecosystemGo
	found, _ := assets.mustMatch(t, frag)
	if len(found) != 1 || found[0].File != "x.go" {
		got := make([]string, 0, len(found))
		for _, f := range found {
			got = append(got, f.File)
		}
		t.Errorf("findings in %v, want x.go only", got)
	}
}

// A Go value rule written inside an import clause (`tls.Config{...}`,
// `&ssh.ServerConfig{...}`, `new(ssh.Key)`) names a type of the imported
// package: the clause qualifies its package, and the type stays (go-port
// audit C8; before, the type was dropped and the rule matched nothing).
// Pinned to OpenGrep 1.33.1: a file importing the package, one importing
// it under an alias, not one importing a package of that name at another
// path.
func TestGoValueRulesInImportClause(t *testing.T) {
	dir := filepath.Join("testdata", "go_value_import")
	assets, frag, want := rustFixtureAt(t, dir)
	found, _ := assets.mustMatch(t, frag)
	got := map[rustPinKey]string{}
	for _, f := range found {
		got[rustPinKey{f.File, f.Line, f.Col, 0}] = f.RuleID
	}
	exp := map[rustPinKey]string{}
	for id, hits := range want {
		for _, h := range hits {
			exp[rustPinKey{h.File, h.Line, h.Col, 0}] = id
		}
	}
	if g, w := rustPinKeys(got), rustPinKeys(exp); !slices.Equal(g, w) {
		t.Fatalf("\n got %v\nwant %v", g, w)
	}
	for k, id := range exp {
		if got[k] != id {
			t.Errorf("%v: rule %s, want %s", k, got[k], id)
		}
	}
	rules, err := ExportRules(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == "config" && !strings.Contains(string(r.Sites[0]), `"type": "example.com/acme/tls.Config"`) {
			t.Errorf("config site %s, want the type example.com/acme/tls.Config", r.Sites[0])
		}
	}
}
