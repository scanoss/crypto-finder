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

package prefilter

import "testing"

func TestAlwaysOnImportsKeepRule(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["*"]}, "patterns": [{"pattern-inside": "import javax.crypto.Cipher;\n...\n"}, {"pattern": "Cipher.getInstance(...)"}]}`)
	if !keeps(t, rule, []string{"java"}, evidenceOf("java", "")) {
		t.Error("metadata.imports [\"*\"] must keep the rule for an empty unit, whatever its patterns import")
	}
	if Requirement(rule, []string{"java"}).known() {
		t.Error("an always-on rule has no requirement")
	}
}

func TestDeclaredImportsSpelledOutWithoutImport(t *testing.T) {
	java := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["javax.crypto.spec"]}, "pattern": "new SecretKeySpec(...)"}`)
	qualified := "class A { Object k = new javax.crypto.spec.SecretKeySpec(bytes, \"AES\"); }\n"
	if !keeps(t, java, []string{"java"}, evidenceOf("java", qualified)) {
		t.Error("a fully qualified use of the declared package must keep the rule without an import")
	}
	if keeps(t, java, []string{"java"}, evidenceOf("java", "import java.util.List;\nclass A { List<String> spec; }\n")) {
		t.Error("a unit spelling only some segments of the declared package must drop the rule")
	}
	rust := mustRule(t, `{"id": "r", "languages": ["rust"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["ed25519_dalek"]}, "pattern": "SigningKey::generate(...)"}`)
	if !keeps(t, rust, []string{"rust"}, evidenceOf("rust", "fn main() { let k = ed25519_dalek::SigningKey::generate(&mut rng); }\n")) {
		t.Error("a crate used by path without use must keep the rule")
	}
	if keeps(t, rust, []string{"rust"}, evidenceOf("rust", "use aes_gcm::Aes256Gcm;\nfn main() {}\n")) {
		t.Error("a unit without the crate must drop the rule")
	}
	goRule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["filippo.io/age"]}, "pattern": "age.Encrypt(...)"}`)
	if keeps(t, goRule, []string{"go"}, evidenceOf("go", "package x\n// filippo.io/age is not imported here\nvar filippo, io, age int\n")) {
		t.Error("the spelled-out fallback does not apply to Go")
	}
}

func TestDeclaredCIncludeMatchesPathSegment(t *testing.T) {
	cases := []struct {
		declared string
		include  string
		want     bool
	}{
		{"openssl", "openssl/evp.h", true},
		{"openssl", "deps/openssl/evp.h", true},
		{"sodium", "sodium.h", true},
		{"sodium", "../include/sodium/core.h", true},
		{"QSsl", "QtNetwork/QSslSocket", true},
		{"relic", "relic_core.h", true},
		{"openssl", "libopenssl/evp.h", false},
		{"qssl", "QtNetwork/QSslSocket", false},
		{"mbedtls", "openssl/evp.h", false},
	}
	for _, c := range cases {
		rule := mustRule(t, `{"id": "r", "languages": ["c", "cpp"], "message": "m", "severity": "INFO",
		  "metadata": {"imports": ["`+c.declared+`"]}, "pattern": "EVP_EncryptInit(...)"}`)
		source := "#include <" + c.include + ">\nint main(void) { return 0; }\n"
		if got := keeps(t, rule, []string{"c", "cpp"}, evidenceOf("c", source)); got != c.want {
			t.Errorf("declared %q with include %q: keep=%v, want %v", c.declared, c.include, got, c.want)
		}
	}
	guard := mustRule(t, `{"id": "r", "languages": ["c"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-inside": "#include <openssl/evp.h>\n...\n"}, {"pattern": "EVP_EncryptInit(...)"}]}`)
	if keeps(t, guard, []string{"c"}, evidenceOf("c", "#include <deps/openssl/evp.h>\n")) {
		t.Error("an include pattern keeps its literal matching")
	}
}
