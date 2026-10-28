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

import (
	"strings"
	"testing"
)

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
		{"openssl", "..\\third_party\\openssl\\include\\openssl\\evp.h", true},
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

func TestGoImportBlockWithCommentOnOpeningLine(t *testing.T) {
	source := "package x\nimport ( // stdlib first (crypto), then third party\n\t\"crypto/ecdsa\"\n\t\"github.com/golang-jwt/jwt/v5\"\n)\n"
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["github.com/golang-jwt/jwt/v5"]}, "pattern": "jwt.New(...)"}`)
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", source)) {
		t.Error("a comment with a parenthesis on the import ( line must not end the block")
	}
}

func TestJSStringLiteralsStayInStep(t *testing.T) {
	long := strings.Repeat("A", 700)
	source := "const banner = \"Don't share this key\", CryptoJS = require('crypto-js');\n" +
		"const data = \"" + long + "\"; const forge = require(\"node-forge\");\n" +
		"const m = {'\"': \"&quot;\"}; const jose = require(`jose`);\n" +
		"/* it's the legacy hasher */ import sjcl from 'sjcl';\n" +
		"const QUOTES = /[\"']/g; const bcrypt = require(\"bcryptjs\");\n" +
		"/** The `secret must stay private */\nconst argon = require(\"argon2\");\n" +
		"const esc = /[\\\\`*_{}]/g; function f() { return require('tweetnacl'); }\n" +
		"var h=/[&<>\"']/g,x=require(\"jsonwebtoken\");\n"
	ev := evidenceOf("js", source)
	for _, want := range []string{"crypto-js", "node-forge", "jose", "sjcl", "bcryptjs", "argon2", "tweetnacl", "jsonwebtoken"} {
		found := false
		for _, candidate := range ev.imports[FamilyJS] {
			found = found || candidate == want
		}
		if !found {
			t.Errorf("%q not read from %v", want, ev.imports[FamilyJS])
		}
	}
}

func TestGoImportAfterCodeOnTheSameLine(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["crypto/ecdh"]}, "pattern": "ecdh.X25519()"}`)
	for _, source := range []string{
		"package main; import \"crypto/ecdh\"\n",
		"package main\n/* keep */ import \"crypto/ecdh\"\n",
		"package main\nimport /* standard library only */ (\n\t\"crypto/ecdh\"\n)\n",
		"package main\nimport\n(\n\t\"crypto/ecdh\"\n)\n",
		"package main\nimport /*\nstdlib only\n*/ (\n\t\"crypto/ecdh\"\n)\n",
		"package main\nimport (\n\t/* legacy\n\t) removed: see notes */\n\t\"crypto/ecdh\"\n)\n",
	} {
		if !keeps(t, rule, []string{"go"}, evidenceOf("go", source)) {
			t.Errorf("import after code on the same line must be read: %q", source)
		}
	}
}

func TestCIncludeAfterFormFeed(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["c"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["sodium"]}, "pattern": "crypto_secretbox_easy(...)"}`)
	if !keeps(t, rule, []string{"c"}, evidenceOf("c", "\f#include <sodium.h>\nint main(void) { return 0; }\n")) {
		t.Error("a form feed before #include is whitespace to the preprocessor")
	}
}
