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

func TestEncodeYAMLRulesPrefixesEachID(t *testing.T) {
	yamlText := []byte("rules:\n  - id: a\n    message: m\n    severity: INFO\n    languages: [go]\n    pattern: foo()\n    metadata: {size: 2.0}\n")
	encoded, ok := EncodeYAMLRules(yamlText, "p.")
	if !ok || len(encoded) != 1 {
		t.Fatalf("YAML rules must encode, got %q, %v", encoded, ok)
	}
	var got, want any
	wantJSON := `{"id":"p.a","message":"m","severity":"INFO","languages":["go"],"pattern":"foo()","metadata":{"size":2.0}}`
	if json.Unmarshal(encoded[0], &got) != nil || json.Unmarshal([]byte(wantJSON), &want) != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("EncodeYAMLRules = %s, want %s", encoded[0], wantJSON)
	}
}

func TestEncodeYAMLRulesRejectsRulesWithoutOneStringID(t *testing.T) {
	for _, raw := range []string{"rules:\n  - message: m\n", "rules:\n  - id: 1\n", "rules: {}\n", "other: []\n"} {
		if _, ok := EncodeYAMLRules([]byte(raw), "p."); ok {
			t.Errorf("EncodeYAMLRules(%q) accepted a rule file it cannot prefix", raw)
		}
	}
}
