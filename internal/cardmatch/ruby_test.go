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
	"testing"
)

// A Ruby rule beside a rule of another language: the Ruby one is skipped until
// the compiler lands, the other still compiles.
const rubyRulesSrc = `rules:
- id: acme-digest
  languages: [ruby]
  pattern: Acme::Digest.new(...)
  metadata: {crypto: {algorithmName: ACME}}
- id: acme-hmac
  languages: [ruby]
  pattern: Acme::HMAC.new(...)
  metadata: {crypto: {algorithmName: ACME}}
- id: acme-java
  languages: [java]
  pattern: new Acme(...)
  metadata: {crypto: {algorithmName: ACME}}
`

// A Ruby rule compiles to site entries of its own, beside a rule of another
// language in the same directory: the constant path is the receiver and the
// `::` segments are read as one qualified name.
func TestRubyRulesCompile(t *testing.T) {
	rules, err := ExportRules(writeRules(t, rubyRulesSrc))
	if err != nil {
		t.Fatal(err)
	}
	var compiled, skipped int
	for _, r := range rules {
		switch r.Status {
		case "compiled":
			compiled++
			if len(r.Sites) == 0 {
				t.Errorf("rule %s compiled to no site entry", r.ID)
			}
		case "skipped":
			skipped++
			t.Errorf("rule %s skipped: %s", r.ID, r.Reason)
		default:
			t.Errorf("rule %s status %q", r.ID, r.Status)
		}
	}
	if compiled+skipped != len(rules) || len(rules) != 3 || compiled != 3 {
		t.Errorf("compiled %d + skipped %d of %d rules, want 3 + 0 of 3", compiled, skipped, len(rules))
	}
}

// A Ruby fragment is matched against the compiled entries of its own rules,
// in the two shapes the ruleset writes: the whole receiver as the
// metavariable, and the last segment of a constant path. A regex that does
// not name the site's class reports nothing.
const rubyMatchSrc = `rules:
- id: acme-whole
  languages: [ruby]
  patterns:
  - pattern: $ALGO.hexdigest(...)
  - metavariable-regex: {metavariable: $ALGO, regex: '^Acme::(?<name>MD5)$'}
  metadata: {crypto: {algorithmName: $name, assetType: algorithm, library: acme, api: x}}
- id: acme-segment
  languages: [ruby]
  patterns:
  - pattern: Acme::Digest::$ALGO.hexdigest(...)
  - metavariable-regex: {metavariable: $ALGO, regex: '^(?<name>SHA256)$'}
  metadata: {crypto: {algorithmName: $name, assetType: algorithm, library: acme, api: x}}
`

func TestRubyTypeMetavariableShapes(t *testing.T) {
	assets, err := Load("", "", writeRules(t, rubyMatchSrc))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key, want string
	}{
		{"whole receiver", "lib.(Acme::MD5).hexdigest#1", "acme-whole"},
		{"last segment", "lib.(Acme::Digest::SHA256).hexdigest#1", "acme-segment"},
		{"regex does not name the class", "lib.(Acme::SHA1).hexdigest#1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := pyCall(tc.key, "x.hexdigest(data)", 7, pos(0, `"data"`))
			call.MethodName, call.Arity = "hexdigest", 1
			frag := pyFrag(nil, call)
			frag.ScanMetadata.Ecosystem = ecosystemRuby
			found, _ := assets.mustMatch(t, frag)
			var ids []string
			for _, f := range found {
				ids = append(ids, f.RuleID)
			}
			if tc.want == "" {
				if len(ids) != 0 {
					t.Errorf("found %v, want nothing", ids)
				}
				return
			}
			if len(ids) != 1 || ids[0] != tc.want {
				t.Errorf("found %v, want [%s]", ids, tc.want)
			}
		})
	}
}

// A metavariable receiver means two different things, and the entry has to
// say which: with a metavariable-regex it names the class that regex
// matches, and the type slot carries it; without one it is semgrep's "any
// object", and asking for a class literally named `$H` would match nothing.
const rubyLooseReceiverSrc = `rules:
- id: acme-anyrecv
  languages: [ruby]
  pattern: $H.digest(...)
  metadata: {crypto: {algorithmName: ACME}}
- id: acme-typedrecv
  languages: [ruby]
  patterns:
  - pattern: $ALGO.digest(...)
  - metavariable-regex: {metavariable: $ALGO, regex: '^Acme::(?<name>MD5)$'}
  metadata: {crypto: {algorithmName: $name}}
`

func TestRubyMetavariableReceiver(t *testing.T) {
	rules, err := ExportRules(writeRules(t, rubyLooseReceiverSrc))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string][2]string{}
	for _, r := range rules {
		for _, raw := range r.Sites {
			var site struct {
				Receiver string  `json:"receiver"`
				Type     *string `json:"type"`
			}
			if err := json.Unmarshal(raw, &site); err != nil {
				t.Fatal(err)
			}
			typ := ""
			if site.Type != nil {
				typ = *site.Type
			}
			seen[r.ID] = [2]string{site.Receiver, typ}
		}
	}
	if got := seen["acme-anyrecv"]; got[0] != "any" || got[1] != "" {
		t.Errorf("unconstrained `$H.digest(...)` = receiver %q type %q, want any and no type", got[0], got[1])
	}
	if got := seen["acme-typedrecv"]; got[0] != "type" || got[1] != "$ALGO" {
		t.Errorf("`$ALGO.digest(...)` under a regex = receiver %q type %q, want type and $ALGO", got[0], got[1])
	}
}

// A Ruby call site counts its keyword arguments in its arity, so a pattern
// that names one must too: compiled without it, a keyword pattern with no
// ellipsis asks for an arity no call can have.
func TestRubyKeywordArityCountsTheKeyword(t *testing.T) {
	rules, err := ExportRules(writeRules(t, `rules:
- id: acme-kw
  languages: [ruby]
  pattern: "Acme::KDF.derive($P, salt: $S)"
  metadata: {crypto: {algorithmName: ACME}}
- id: acme-kw-only
  languages: [ruby]
  pattern: "Acme::KDF.derive(length: $L)"
  metadata: {crypto: {algorithmName: ACME}}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]int64{"acme-kw": {2, 2}, "acme-kw-only": {1, 1}}
	for _, r := range rules {
		if r.Status != "compiled" || len(r.Sites) == 0 {
			t.Fatalf("rule %s: status %q, %d sites (%s)", r.ID, r.Status, len(r.Sites), r.Reason)
		}
		var got [2]int64
		raw, err := json.Marshal(r.Sites[0])
		if err != nil {
			t.Fatal(err)
		}
		var site struct {
			MinArity int64 `json:"min_arity"`
			MaxArity int64 `json:"max_arity"`
		}
		if err := json.Unmarshal(raw, &site); err != nil {
			t.Fatal(err)
		}
		got = [2]int64{site.MinArity, site.MaxArity}
		if got != want[r.ID] {
			t.Errorf("%s arity = %v, want %v", r.ID, got, want[r.ID])
		}
	}
}
