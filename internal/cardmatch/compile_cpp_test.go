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
	"testing"
)

// A rule whose languages name C++ and not C compiles the C++ shapes; one
// that names C keeps the C shapes. A shape no C++ fact can match all
// OpenGrep matches of skips the whole rule with its reason.
func TestCompileCPPShapes(t *testing.T) {
	compiled := map[string]string{
		"qualified":       "pattern: crypto::tink::KeysetHandle::GenerateNew($T)",
		"member":          "pattern: $R.create_public_key(...)",
		"arrow":           "pattern: $K->Encrypt($C, $P, ...)",
		"template":        "pattern: Poco::HMACEngine<$T>(...)",
		"functor":         "pattern: SHA256()($X)",
		"chain":           "pattern: $OBJ.header().algo($ALG)",
		"init-list":       "pattern: jwt::params::algorithms({..., $ALG, ...})",
		"new":             "pattern: new seal::KeyGenerator(...)",
		"brace":           "patterns:\n- pattern: jwt::algorithm::$A{...}\n- focus-metavariable: $A",
		"decl":            "pattern: seal::KeyGenerator $K(...);",
		"decl-none":       "pattern: Poco::SHA2Engine $E;",
		"after-decl":      "patterns:\n- pattern-inside: |\n    seal::KeyGenerator $R(...);\n    ...\n- pattern: $R.create_public_key(...)",
		"around-new":      "patterns:\n- pattern-inside: new QSslKey(...)\n- pattern-regex: '\\bQSsl::Rsa\\b'",
		"not-regex":       "patterns:\n- pattern: $CC.KeyGen()\n- pattern-not-regex: ->\\s*KeyGen",
		"member-name":     "pattern: $X.$M(...)",
		"site-regex":      "patterns:\n- pattern-inside: |\n    #include \"$H\"\n    ...\n- pattern-regex: '\\boqs::Signature\\s*(?:\\w+\\s*)?[({]\\s*\"ML-DSA-(?<n>44|65|87)\"'",
		"either-regex":    "pattern-either:\n- pattern: f(...)\n- pattern-regex: '\\bML_KEM_PrivateKey\\b[^;]*?ML_KEM_768'",
		"lookbehind-line": "patterns:\n- pattern-inside: Poco::Crypto::ECKey(\"...\", ...)\n- pattern-regex: '(?<=\")(?<curve>sec[pt]\\d+[kr]1)(?=\")'",
		"decl-init":       "pattern: picosha2::hash256_one_by_one $H = ...;",
		"decl-empty":      "pattern: Poco::SHA2Engine $E();",
		"decl-brace":      "pattern: jwt::jwt_object $O{..., secret($KEY), ...};",
		"typed":           "pattern: (helib::EncryptedArray $EA).encrypt(...)",
		"typed-ptr":       "pattern: (const CryptoPP::SHA256 *$P)->Update(...)",
		"typed-int":       "pattern: COTP::TOTP $O(..., (int $LIT));",
		"typed-param":     "patterns:\n- pattern-inside: $RET $FN(..., seal::KeyGenerator &$R, ...) { ... }\n- pattern: $R.f()",
		"around-span":     "patterns:\n- pattern-inside: QSslKey(...)\n- pattern-regex: 'QSsl::[^;]*Rsa'",
	}
	skipped := map[string]struct{ rule, reason string }{
		"typed-char":   {"pattern: (char $C).f()", string(skipCPPTyped)},
		"return-type":  {"patterns:\n- pattern-inside: void $FN(...) { ... }\n- pattern: f()", string(skipCFunction)},
		"anchored":     {"pattern-regex: '^#define ACME_KEY'", string(skipCPPRegex)},
		"regex-not-in": {"patterns:\n- pattern-regex: 'ACME'\n- pattern-not-inside: f(...)", string(skipCPatternRegex)},
		"metavar-type": {"pattern: new $T(...)", string(skipCPPConstruct)},
		"lookbehind":   {"patterns:\n- pattern-inside: QSslKey(...)\n- pattern-regex: '(?<=\\s)Rsa'", string(skipCPPRegex)},
	}
	rules := map[string]string{}
	for id, r := range compiled {
		rules[id] = r
	}
	for id, s := range skipped {
		rules[id] = s.rule
	}
	out, err := ExportRules(writeRules(t, cppRuleYAML(rules)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range out {
		if _, ok := compiled[r.ID]; ok && r.Status != "compiled" {
			t.Errorf("%s: %s %s", r.ID, r.Status, r.Reason)
		}
		if s, ok := skipped[r.ID]; ok && (r.Status != "skipped" || r.Reason != s.reason) {
			t.Errorf("%s: %s %q, want skipped %q", r.ID, r.Status, r.Reason, s.reason)
		}
	}
	if len(out) != len(rules) {
		t.Errorf("%d records for %d rules", len(out), len(rules))
	}
	// A C rule (languages [c, cpp]) keeps the C shapes.
	c := exportC(t, map[string]string{"member": "pattern: $R.create_public_key(...)", "qualified": "pattern: a::b(...)"})
	if c["member"].Status != "skipped" || c["qualified"].Status != "skipped" {
		t.Errorf("C rules: %+v", c)
	}
}

// The C++ declaration reader reads the last declarator, its form and
// whether the declaration declares more than one name.
func TestCPPReadDecl(t *testing.T) {
	for _, tc := range []struct {
		text, name, form string
		multi            bool
	}{
		{"const seal::KeyGenerator k(ctx);", "k", cppDeclFunction, false},
		{`Poco::Crypto::CipherKey key("aes-256-cbc", pwd)`, "key", cppDeclInit, false},
		{"Poco::PBKDF2Engine<Poco::HMACEngine<Poco::SHA1Engine>> p1(salt, 1000)", "p1", cppDeclInit, false},
		{"Poco::HMACEngine<Poco::SHA2Engine> h(key)", "h", cppDeclFunction, false},
		{"oqs::KeyEncapsulation kem{\"ML-KEM-768\"}", "kem", cppDeclInit, false},
		{"Poco::SHA2Engine e", "e", cppDeclNone, false},
		{"T a(1), b(2)", "b", cppDeclInit, true},
	} {
		d, ok := readCPPDecl(tc.text, false)
		if !ok {
			t.Errorf("%s: unreadable", tc.text)
			continue
		}
		if d.Callee.Name != tc.name || d.Text != tc.form || d.Multi != tc.multi {
			t.Errorf("%s: %s %s %v", tc.text, d.Callee.Name, d.Text, d.Multi)
		}
	}
	for _, text := range []string{"T *p(x)", "T x = f()", "T& r(x)", "f(x)"} {
		if _, ok := readCPPDecl(text, false); ok {
			t.Errorf("reads %s", text)
		}
	}
}
