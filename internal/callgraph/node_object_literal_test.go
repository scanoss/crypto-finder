// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

func TestNodeObjectLiteralProperty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		expression string
		property   string
		want       string
		wantOK     bool
	}{
		{"integer", `{ modulusLength: 2048 }`, "modulusLength", "2048", true},
		{"no spaces", `{modulusLength:4096}`, "modulusLength", "4096", true},
		{"among other properties", `{ publicExponent: 65537, modulusLength: 3072, hashAlgorithm: 'sha256' }`, "modulusLength", "3072", true},
		{"trailing comma", `{ modulusLength: 2048, }`, "modulusLength", "2048", true},
		{"multi-line with nested objects", "{\n  modulusLength: 2560,\n  publicKeyEncoding: { type: 'spki', format: 'pem' },\n  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },\n}", "modulusLength", "2560", true},
		{"quoted key", `{ "modulusLength": 1024 }`, "modulusLength", "1024", true},
		{"single-quoted key", `{ 'modulusLength': 1024 }`, "modulusLength", "1024", true},
		{"single-quoted string value", `{ namedCurve: 'prime256v1' }`, "namedCurve", `"prime256v1"`, true},
		{"double-quoted string value", `{ namedCurve: "P-384" }`, "namedCurve", `"P-384"`, true},
		{"template without substitution", "{ namedCurve: `secp521r1` }", "namedCurve", `"secp521r1"`, true},
		{"comma inside a string value", `{ label: 'a,b', modulusLength: 2048 }`, "modulusLength", "2048", true},
		{"zero", `{ length: 0 }`, "length", "0", true},

		{"not an object", `opts`, "modulusLength", "", false},
		{"empty object", `{}`, "modulusLength", "", false},
		{"property absent", `{ publicExponent: 65537 }`, "modulusLength", "", false},
		{"variable value", `{ modulusLength: bits }`, "modulusLength", "", false},
		{"expression value", `{ modulusLength: 1024 * 2 }`, "modulusLength", "", false},
		{"call value", `{ modulusLength: Number(process.env.BITS) }`, "modulusLength", "", false},
		{"hex value", `{ modulusLength: 0x800 }`, "modulusLength", "", false},
		{"legacy octal", `{ modulusLength: 0777 }`, "modulusLength", "", false},
		{"separator", `{ modulusLength: 2_048 }`, "modulusLength", "", false},
		{"fraction", `{ modulusLength: 2048.5 }`, "modulusLength", "", false},
		{"negative", `{ modulusLength: -2048 }`, "modulusLength", "", false},
		{"template with substitution", "{ namedCurve: `p-${n}` }", "namedCurve", "", false},
		{"shorthand", `{ modulusLength }`, "modulusLength", "", false},
		{"method", `{ modulusLength() { return 2048 } }`, "modulusLength", "", false},
		{"accessor", `{ get modulusLength() { return 2048 } }`, "modulusLength", "", false},
		{"duplicate", `{ modulusLength: 2048, modulusLength: 4096 }`, "modulusLength", "", false},
		{"spread before", `{ ...base, modulusLength: 2048 }`, "modulusLength", "", false},
		{"spread after", `{ modulusLength: 2048, ...override }`, "modulusLength", "", false},
		{"computed key", `{ ['modulus' + 'Length']: 2048, modulusLength: 2048 }`, "modulusLength", "", false},
		{"generator method", `{ *modulusLength() {} }`, "modulusLength", "", false},
		{"line comment", "{ modulusLength: 2048 // bits\n}", "modulusLength", "", false},
		{"block comment", `{ /* bits */ modulusLength: 2048 }`, "modulusLength", "", false},
		{"unbalanced", `{ modulusLength: 2048`, "modulusLength", "", false},
		{"property name is a prefix", `{ modulusLengthBits: 2048 }`, "modulusLength", "", false},
		{"nested property is not top level", `{ opts: { modulusLength: 2048 } }`, "modulusLength", "", false},
		{"empty entry", `{ modulusLength: 2048,, publicExponent: 3 }`, "modulusLength", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := NodeObjectLiteralProperty(tc.expression, tc.property)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("NodeObjectLiteralProperty(%q, %q) = (%q, %v), want (%q, %v)", tc.expression, tc.property, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
