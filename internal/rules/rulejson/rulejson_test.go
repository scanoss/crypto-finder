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

package rulejson

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEncodeRulesYAMLAndJSONAgree(t *testing.T) {
	yamlText := []byte("rules:\n  - id: a\n    message: m\n    severity: INFO\n    languages: [go]\n    pattern: foo()\n    metadata: {size: 2.0}\n")
	jsonText := []byte(`{"rules":[{"id":"a","message":"m","severity":"INFO","languages":["go"],"pattern":"foo()","metadata":{"size":2.0}}]}`)
	fromYAML, ok := EncodeRules(yamlText, "p.")
	if !ok {
		t.Fatal("YAML rules must encode")
	}
	fromJSON, ok := EncodeRules(jsonText, "p.")
	if !ok {
		t.Fatal("JSON rules must encode")
	}
	var a, b any
	if json.Unmarshal(fromYAML[0], &a) != nil || json.Unmarshal(fromJSON[0], &b) != nil || !reflect.DeepEqual(a, b) {
		t.Errorf("YAML %s and JSON %s encode differently", fromYAML[0], fromJSON[0])
	}
	if a.(map[string]any)["id"] != "p.a" {
		t.Errorf("id not prefixed: %s", fromYAML[0])
	}
}

func TestPrefixRuleIDRejectsBadRules(t *testing.T) {
	for _, raw := range []string{`{"message":"m"}`, `{"id":1}`, `{"id":"a","id":"b"}`, `[]`} {
		if _, ok := PrefixRuleID([]byte(raw), "p."); ok {
			t.Errorf("PrefixRuleID(%s) accepted a rule without one string id", raw)
		}
	}
	out, ok := PrefixRuleID([]byte(`{"id":"a","pattern":"x"}`), "m.")
	if !ok || string(out) != `{"id":"m.a","pattern":"x"}` {
		t.Errorf("PrefixRuleID = %s, %v", out, ok)
	}
}
