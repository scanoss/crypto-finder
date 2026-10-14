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
	"encoding/json"
	"testing"
)

func mustRule(t *testing.T, text string) map[string]any {
	t.Helper()
	var rule map[string]any
	if err := json.Unmarshal([]byte(text), &rule); err != nil {
		t.Fatalf("bad rule JSON: %v", err)
	}
	return rule
}

func evidenceOf(analyzer, source string) *Evidence {
	ev := NewEvidence()
	ev.AddFile([]string{analyzer}, []byte(source))
	return ev
}

func keeps(t *testing.T, rule map[string]any, analyzers []string, ev *Evidence) bool {
	t.Helper()
	keep, _ := Decide([]Rule{{Analyzers: analyzers, Requirement: Requirement(rule, analyzers)}}, ev)
	return keep[0]
}

const goHKDFRule = `{
  "id": "go.xcrypto.hkdf.new", "languages": ["go"], "message": "m", "severity": "INFO",
  "patterns": [
    {"pattern-either": [
      {"pattern-inside": "import (\n  ...\n  \"golang.org/x/crypto/hkdf\"\n  ...\n)\n...\n"},
      {"pattern-inside": "import \"golang.org/x/crypto/hkdf\"\n...\n"}]},
    {"pattern": "hkdf.New(...)"}]}`

func TestGoImportGuard(t *testing.T) {
	rule := mustRule(t, goHKDFRule)
	grouped := "package x\n\nimport (\n\t\"fmt\"\n\th \"golang.org/x/crypto/hkdf\"\n)\n"
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", grouped)) {
		t.Error("grouped aliased import of the guarded package must keep the rule")
	}
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\nimport \"golang.org/x/crypto/hkdf\"\n")) {
		t.Error("single import of the guarded package must keep the rule")
	}
	if keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\nimport \"crypto/sha256\"\n// hkdf.New is mentioned here\n")) {
		t.Error("a unit that never imports the guarded package must drop the rule")
	}
}

// A rule id or message naming a package is never a requirement: an earlier
// prototype lost hundreds of Go findings by reading go.crypto.sha256 from ids.
func TestRuleIDAndMessageAreNeverRequirements(t *testing.T) {
	rule := mustRule(t, `{"id": "go.crypto.sha256.hash", "languages": ["go"], "message": "Detected golang.org/x/crypto/sha3 usage",
	  "severity": "INFO", "metadata": {"purl": "pkg:golang/golang.org/x/crypto"}, "pattern": "sha256.Sum256(...)"}`)
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\nimport \"fmt\"\n")) {
		t.Error("a rule without import guard must be kept whatever its id, message or purl say")
	}
}

func TestUnknownBranchKeepsRule(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "pattern-either": [
	    {"patterns": [{"pattern-inside": "import \"golang.org/x/crypto/hkdf\"\n...\n"}, {"pattern": "hkdf.New(...)"}]},
	    {"pattern": "sha256.New()"}]}`)
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\n")) {
		t.Error("a disjunct without requirement must keep the rule")
	}
}

func TestNegativePatternsAreIgnored(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-not-inside": "import \"golang.org/x/crypto/hkdf\"\n...\n"}, {"pattern": "foo()"}]}`)
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\n")) {
		t.Error("pattern-not-inside must not become a requirement")
	}
}

func TestJavaScriptRequire(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["javascript", "typescript"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-either": [
	      {"pattern-inside": "$NS = <... require(\"node-ssh\") ...>\n...\n"},
	      {"pattern-inside": "import $NS from \"node-ssh\"\n...\n"},
	      {"pattern-inside": "import * as $NS from 'node-ssh'\n...\n"}]},
	    {"pattern": "$NS.connect(...)"}]}`)
	langs := []string{"js", "ts"}
	for _, source := range []string{
		`const { NodeSSH } = require("node-ssh")`,
		`import { NodeSSH } from 'node-ssh';`,
		`const name = "node-ssh"; const m = require(name);`,
	} {
		if !keeps(t, rule, langs, evidenceOf("js", source)) {
			t.Errorf("source %q must keep the node-ssh rule", source)
		}
	}
	if keeps(t, rule, langs, evidenceOf("ts", `import ssh2 from "ssh2"; // node ssh client`)) {
		t.Error("a unit without the node-ssh specifier must drop the rule")
	}
}

func TestRustUseWithMetavariableRegex(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["rust"], "message": "m", "severity": "INFO",
	  "patterns": [
	    {"pattern-inside": "use $IMPORT;\n...\n"},
	    {"metavariable-regex": {"metavariable": "$IMPORT", "regex": "^(::)?ring::(aead\\s*$|aead::\\{\\s*self\\b|\\{[\\s\\S]*\\baead\\s*(,|\\}|$|::\\{\\s*self\\b))"}},
	    {"pattern": "aead::quic::CHACHA20"}]}`)
	for _, source := range []string{
		"use ring::aead;\n",
		"use ring::{digest, aead};\n",
		"pub(crate) use ring::{\n    aead,\n    rand,\n};\n",
	} {
		source += "fn f() { let k = aead::quic::CHACHA20; }\n"
		if !keeps(t, rule, []string{"rust"}, evidenceOf("rust", source)) {
			t.Errorf("source %q must keep the ring rule", source)
		}
	}
	if keeps(t, rule, []string{"rust"}, evidenceOf("rust", "use ring::digest;\nuse aes_gcm::aead;\nfn f() { aead::quic::CHACHA20; }\n")) {
		t.Error("a unit that imports no ring::aead must drop the rule")
	}
}

func TestRustQualifiedNameTokens(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["rust"], "message": "m", "severity": "INFO",
	  "pattern": "aes_gcm::Aes256Gcm::new(...)"}`)
	if !keeps(t, rule, []string{"rust"}, evidenceOf("rust", "use aes_gcm::{Aes256Gcm, KeyInit};\nfn f() { Aes256Gcm::new(&k); }\n")) {
		t.Error("an imported, then called, type must keep the rule")
	}
	if keeps(t, rule, []string{"rust"}, evidenceOf("rust", "use chacha20poly1305::ChaCha20Poly1305;\nfn f() { ChaCha20Poly1305::new(&k); }\n")) {
		t.Error("a unit never naming aes_gcm must drop the rule")
	}
	std := mustRule(t, `{"id": "r", "languages": ["rust"], "message": "m", "severity": "INFO", "pattern": "std::collections::HashMap::new()"}`)
	if !keeps(t, std, []string{"rust"}, evidenceOf("rust", "use std::collections::HashMap; fn f() { HashMap::new(); }")) {
		t.Error("an std-rooted path must not require the std token")
	}
}

func TestCIncludeWithRegexAndMacroInclude(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["c"], "message": "m", "severity": "INFO",
	  "patterns": [
	    {"pattern-inside": "#include \"$HEADER\"\n...\n"},
	    {"metavariable-regex": {"metavariable": "$HEADER", "regex": "^<?(?:[\\w.\\-/]*/)?sodium(?:\\.h|/\\w+\\.h)>?$"}},
	    {"pattern": "crypto_secretbox_easy(...)"}]}`)
	if !keeps(t, rule, []string{"c"}, evidenceOf("c", "#include <sodium.h>\n")) {
		t.Error("an angle include of sodium.h must keep the rule")
	}
	if !keeps(t, rule, []string{"c"}, evidenceOf("c", "#include \"vendor/sodium/crypto_box.h\"\n")) {
		t.Error("a quoted include below sodium/ must keep the rule")
	}
	if keeps(t, rule, []string{"c"}, evidenceOf("c", "#include <openssl/evp.h>\n")) {
		t.Error("an openssl-only unit must drop the libsodium rule")
	}
	if !keeps(t, rule, []string{"c"}, evidenceOf("c", "#include CRYPTO_HEADER\n")) {
		t.Error("an include through a macro must keep every include-guarded rule")
	}
}

func TestJavaQualifiedNames(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO",
	  "pattern": "new org.bouncycastle.crypto.engines.AESEngine()"}`)
	for _, source := range []string{
		"import org.bouncycastle.crypto.engines.AESEngine;\nclass A { Object e = new AESEngine(); }",
		"import org.bouncycastle.crypto.engines.*;\nclass A { Object e = new AESEngine(); }",
		"package org.bouncycastle.crypto.engines;\nclass A { Object e = new AESEngine(); }",
		"class A { Object e = new org.bouncycastle.crypto.engines.AESEngine(); }",
	} {
		if !keeps(t, rule, []string{"java"}, evidenceOf("java", source)) {
			t.Errorf("source %q must keep the BouncyCastle rule", source)
		}
	}
	if keeps(t, rule, []string{"java"}, evidenceOf("java", "import javax.crypto.Cipher;\nclass A { Cipher c; }")) {
		t.Error("a JCA-only unit must drop the BouncyCastle rule")
	}
	implicit := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO", "pattern": "java.lang.String.format(...)"}`)
	if !keeps(t, implicit, []string{"java"}, evidenceOf("java", "class A { String s = String.format(\"x\"); }")) {
		t.Error("java.lang names are implicit and must not be required")
	}
	short := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO", "pattern": "Cipher.getInstance(\"AES\")"}`)
	if !keeps(t, short, []string{"java"}, evidenceOf("java", "import static javax.crypto.Cipher.getInstance;\nclass A { Object c = getInstance(\"AES\"); }")) {
		t.Error("a static import spells the whole name and must keep the rule")
	}
	if keeps(t, short, []string{"java"}, evidenceOf("java", "class A { Object c = Signature.getInstance(\"AES\"); }")) {
		t.Error("a unit never naming Cipher must drop the rule")
	}
}

func TestPythonImportsAndNames(t *testing.T) {
	guard := mustRule(t, `{"id": "r", "languages": ["python"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-inside": "from jose import jwe\n...\n"}, {"pattern": "jwe.encrypt(...)"}]}`)
	if !keeps(t, guard, []string{"python"}, evidenceOf("python", "from jose import (\n    jwe,\n    jwk,\n)\njwe.encrypt(b, k)\n")) {
		t.Error("a parenthesized from-import must keep the rule")
	}
	if keeps(t, guard, []string{"python"}, evidenceOf("python", "import jwt\njwe.encrypt(b, k)\n")) {
		t.Error("a unit without jose must drop the rule")
	}
	fqn := mustRule(t, `{"id": "r", "languages": ["python"], "message": "m", "severity": "INFO",
	  "pattern": "Crypto.Cipher.AES.new($K, Crypto.Cipher.AES.MODE_ECB)"}`)
	if !keeps(t, fqn, []string{"python"}, evidenceOf("python", "from Crypto.Cipher import AES as A\nA.new(k, A.MODE_ECB)\n")) {
		t.Error("an aliased import of the qualified name must keep the rule")
	}
	if keeps(t, fqn, []string{"python"}, evidenceOf("python", "from Cryptodome.Cipher import AES\nAES.new(k, AES.MODE_ECB)\n")) {
		t.Error("pycryptodomex code must drop the pycryptodome rule")
	}
	strings := mustRule(t, `{"id": "r", "languages": ["python"], "message": "m", "severity": "INFO", "pattern": "hashlib.new(\"Crypto.Cipher.x\")"}`)
	if keeps(t, strings, []string{"python"}, evidenceOf("python", "import os\n")) {
		t.Error("names outside strings still count: hashlib is required")
	}
	if !keeps(t, strings, []string{"python"}, evidenceOf("python", "import hashlib\nhashlib.new(x)\n")) {
		t.Error("names inside string literals must not become requirements")
	}
}

func TestTaintNeedsSourceAndSink(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["python"], "message": "m", "severity": "INFO", "mode": "taint",
	  "pattern-sources": [{"pattern": "nacl.utils.random(...)"}],
	  "pattern-sinks": [{"patterns": [{"pattern-inside": "import nacl.secret\n...\n"}, {"pattern": "nacl.secret.SecretBox($K)"}]}]}`)
	if !keeps(t, rule, []string{"python"}, evidenceOf("python", "import nacl.secret\nimport nacl.utils\nnacl.secret.SecretBox(nacl.utils.random(32))\n")) {
		t.Error("source and sink present must keep the taint rule")
	}
	if keeps(t, rule, []string{"python"}, evidenceOf("python", "import nacl.utils\nnacl.utils.random(32)\n")) {
		t.Error("a missing sink library must drop the taint rule")
	}
}

func TestExplicitMetadataImports(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["filippo.io/age"]}, "pattern": "age.Encrypt(...)"}`)
	if keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\nimport \"fmt\"\n")) {
		t.Error("metadata.imports must drop the rule when the unit imports none of them")
	}
	if !keeps(t, rule, []string{"go"}, evidenceOf("go", "package x\nimport \"filippo.io/age/armor\"\n")) {
		t.Error("a subpackage import must satisfy metadata.imports")
	}
}

func TestLanguageWithoutFilesIsDropped(t *testing.T) {
	rule := mustRule(t, `{"id": "r", "languages": ["go"], "message": "m", "severity": "INFO", "pattern": "foo()"}`)
	keep, stats := Decide([]Rule{{Analyzers: []string{"go"}, Requirement: Requirement(rule, []string{"go"})}}, evidenceOf("java", "class A {}"))
	if keep[0] || stats.DroppedLanguage != 1 {
		t.Errorf("a Go rule in a Java-only unit must be dropped for its language, got keep=%v stats=%+v", keep[0], stats)
	}
	keep, stats = Decide([]Rule{{Requirement: True}}, evidenceOf("java", "class A {}"))
	if !keep[0] || stats.Unknown != 1 {
		t.Errorf("a rule whose languages are unknown must be kept, got keep=%v stats=%+v", keep[0], stats)
	}
}

func TestExpandUseTree(t *testing.T) {
	got := expandUseTree("a::{b, c::{d, self}, e as f}")
	want := map[string]bool{"a": true, "a::b": true, "a::c": true, "a::c::d": true, "a::e": true}
	if len(got) != len(want) {
		t.Fatalf("expandUseTree = %v", got)
	}
	for _, path := range got {
		if !want[path] {
			t.Errorf("unexpected path %q in %v", path, got)
		}
	}
}

func TestRelated(t *testing.T) {
	cases := []struct {
		a, b, sep string
		want      bool
	}{
		{"golang.org/x/crypto", "golang.org/x/crypto/hkdf", "/", true},
		{"golang.org/x/crypto/hkdf", "golang.org/x/crypto", "/", true},
		{"golang.org/x/cryptography", "golang.org/x/crypto", "/", false},
		{"org.bouncycastle", "org.bouncycastle.crypto", ".", true},
		{"ring", "ring::aead", "::", true},
		{"rin", "ring", "::", false},
	}
	for _, c := range cases {
		if got := related(c.a, c.b, c.sep); got != c.want {
			t.Errorf("related(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestJavaImportShapesKeepEveryRuleOpenGrepMatches runs Java import guards
// and qualified names over the import shapes real code uses and requires
// the prefilter to keep every rule OpenGrep matches. The matches were pinned
// with opengrep 1.30.2 on these exact sources: a wildcard import satisfies a
// qualified name but not a metavariable guard, an import of a nested class
// satisfies its outer class's guard, a static import satisfies a qualified
// method name, and same-package code satisfies only unguarded rules. Keeping
// more than OpenGrep matches is allowed; dropping a match is the defect.
func TestJavaImportShapesKeepEveryRuleOpenGrepMatches(t *testing.T) {
	guard := func(id, imp string) string {
		return `{"id": "` + id + `", "languages": ["java"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "import ` + imp + `;\n...\n"}, {"pattern": "new PBEKeySpec(...)"}]}`
	}
	rules := map[string]map[string]any{
		"g-explicit": mustRule(t, guard("g-explicit", "javax.crypto.spec.PBEKeySpec")),
		"g-wild":     mustRule(t, guard("g-wild", "javax.crypto.spec.*")),
		"g-metavar":  mustRule(t, guard("g-metavar", "javax.crypto.spec.$X")),
		"q-ctor":     mustRule(t, `{"id": "q-ctor", "languages": ["java"], "message": "m", "severity": "INFO", "pattern": "new javax.crypto.spec.PBEKeySpec(...)"}`),
		"q-static":   mustRule(t, `{"id": "q-static", "languages": ["java"], "message": "m", "severity": "INFO", "pattern": "javax.crypto.Cipher.getInstance(...)"}`),
		"plain":      mustRule(t, `{"id": "plain", "languages": ["java"], "message": "m", "severity": "INFO", "pattern": "new PBEKeySpec(...)"}`),
	}
	body := `class A { void f(char[] p) { Object k = new PBEKeySpec(p); Cipher.getInstance("AES"); } }`
	cases := []struct {
		name, source string
		openGrep     []string
	}{
		{
			"explicit", "package p;\nimport javax.crypto.spec.PBEKeySpec;\nimport javax.crypto.Cipher;\n" + body,
			[]string{"g-explicit", "g-metavar", "plain", "q-ctor", "q-static"},
		},
		{
			"wildcard", "package p;\nimport javax.crypto.spec.*;\nimport javax.crypto.*;\n" + body,
			[]string{"g-wild", "plain", "q-ctor", "q-static"},
		},
		{
			"fully qualified", "package p;\nclass A { void f(char[] p) { Object k = new javax.crypto.spec.PBEKeySpec(p); javax.crypto.Cipher.getInstance(\"AES\"); } }",
			[]string{"q-ctor", "q-static"},
		},
		{
			"same package", "package javax.crypto.spec;\nclass A { void f(char[] p) { Object k = new PBEKeySpec(p); } }",
			[]string{"plain"},
		},
		{
			"static import", "package p;\nimport static javax.crypto.Cipher.getInstance;\nimport static javax.crypto.spec.*;\nclass A { void f() { getInstance(\"AES\"); } }",
			[]string{"q-static"},
		},
		{
			"nested class import", "package p;\nimport javax.crypto.spec.PBEKeySpec.Inner;\nclass A { void f(char[] p) { Object k = new PBEKeySpec(p); } }",
			[]string{"g-explicit", "g-metavar", "plain"},
		},
		{"no import", "package p;\n" + body, []string{"plain"}},
	}
	for _, c := range cases {
		ev := evidenceOf("java", c.source)
		for _, id := range c.openGrep {
			if !keeps(t, rules[id], []string{"java"}, ev) {
				t.Errorf("%s: OpenGrep matches %s, the prefilter must keep it", c.name, id)
			}
		}
	}
}

// TestJJWTPbkdf2RulesAreKept covers jjwt 0.12.6's Pbes2HsAkwAlgorithm, where
// one benchmark run lacked pbkdf2-detailed with the prefilter on. Neither
// PBKDF2 rule names an import or a qualified name, so both are kept for any
// Java unit: the prefilter cannot have dropped the finding.
func TestJJWTPbkdf2RulesAreKept(t *testing.T) {
	plain := mustRule(t, `{"id": "java.jca.algorithm.kdf.pbkdf2", "languages": ["java"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-either": [{"pattern": "new PBEKeySpec($PASSWORD, $SALT, $ITERATIONS)"},
	    {"pattern": "new PBEKeySpec($PASSWORD, $SALT, $ITERATIONS, $KEY_LENGTH)"}]}]}`)
	detailed := mustRule(t, `{"id": "java.jca.algorithm.kdf.pbkdf2-detailed", "languages": ["java"], "message": "m", "severity": "INFO",
	  "mode": "taint", "options": {"interfile": true},
	  "pattern-sources": [{"patterns": [{"pattern": "$KEYLEN"}, {"metavariable-regex": {"metavariable": "$KEYLEN", "regex": "(?<keysize>\\d+)"}}]}],
	  "pattern-sinks": [{"patterns": [{"pattern": "new PBEKeySpec($PASSWORD, $SALT, $ITERATIONS, $KEYLEN)"}, {"focus-metavariable": "$KEYLEN"}]}]}`)
	jjwt := `package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.KeyAlgorithm;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Pbes2HsAkwAlgorithm {
    private final int DERIVED_KEY_BIT_LENGTH;
    public Pbes2HsAkwAlgorithm(int hashBitLength) { this.DERIVED_KEY_BIT_LENGTH = hashBitLength / 2; }
    protected SecretKey deriveKey(SecretKeyFactory factory, final char[] password, final byte[] rfcSalt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, rfcSalt, iterations, DERIVED_KEY_BIT_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}
`
	for name, rule := range map[string]map[string]any{"pbkdf2": plain, "pbkdf2-detailed": detailed} {
		if req := Requirement(rule, []string{"java"}); req.known() {
			t.Errorf("%s: requirement must be unknown (no import or qualified name), got %#v", name, req)
		}
		for _, source := range []string{jjwt, "package x;\nclass B {}\n"} {
			if !keeps(t, rule, []string{"java"}, evidenceOf("java", source)) {
				t.Errorf("%s must be kept for every Java unit", name)
			}
		}
	}
}

// TestImportsBeyondLineStartKeepEveryRuleOpenGrepMatches pins import shapes
// the line-anchored import patterns once missed: an import after another
// statement, a brace, a Rust attribute or a block comment on the same line,
// and an import on a first line behind a UTF-8 byte order mark. OpenGrep
// 1.29.0 matches each rule on its sources, so the prefilter must keep it.
func TestImportsBeyondLineStartKeepEveryRuleOpenGrepMatches(t *testing.T) {
	const bom = "\uFEFF"
	rules := map[string]map[string]any{
		"java": mustRule(t, `{"id": "java", "languages": ["java"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "import io.jsonwebtoken.SignatureAlgorithm;\n...\n"}, {"pattern": "SignatureAlgorithm.$X"}]}`),
		"rust": mustRule(t, `{"id": "rust", "languages": ["rust"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "use $IMPORT;\n...\n"},
		    {"metavariable-regex": {"metavariable": "$IMPORT", "regex": "^aes_gcm(?:::|$)"}},
		    {"pattern": "Aes256Gcm::new(...)"}]}`),
		"python": mustRule(t, `{"id": "python", "languages": ["python"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "import jwt\n...\n"}, {"pattern": "jwt.decode(...)"}]}`),
		"python-from": mustRule(t, `{"id": "python-from", "languages": ["python"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "from jose import jwe\n...\n"}, {"pattern": "jwe.encrypt(...)"}]}`),
		"c": mustRule(t, `{"id": "c", "languages": ["c"], "message": "m", "severity": "INFO",
		  "patterns": [{"pattern-inside": "#include <sodium.h>\n...\n"}, {"pattern": "crypto_secretbox_easy(...)"}]}`),
	}
	javaBody := "\nclass A { Object a = SignatureAlgorithm.HS256; }\n"
	rustBody := "\nfn f(k: &[u8]) { let c = Aes256Gcm::new(k); }\n"
	cBody := "\nvoid f(void) { crypto_secretbox_easy(c, m, l, n, k); }\n"
	cases := []struct {
		name, rule, analyzer, source string
	}{
		{"java after another import", "java", "java", "import java.util.List; import io.jsonwebtoken.SignatureAlgorithm;" + javaBody},
		{"java after a block comment", "java", "java", "/* header */ import io.jsonwebtoken.SignatureAlgorithm;" + javaBody},
		{"java behind a BOM", "java", "java", bom + "import io.jsonwebtoken.SignatureAlgorithm;" + javaBody},
		{"rust after an attribute", "rust", "rust", `#[cfg(feature = "gcm")] use aes_gcm::Aes256Gcm;` + rustBody},
		{"rust inside a module", "rust", "rust", "mod m { use aes_gcm::Aes256Gcm; fn f(k: &[u8]) { let c = Aes256Gcm::new(k); } }\n"},
		{"rust behind a BOM", "rust", "rust", bom + "use aes_gcm::Aes256Gcm;" + rustBody},
		{"python import after a semicolon", "python", "python", "import os; import jwt\ndef f(t): return jwt.decode(t)\n"},
		{"python from-import after a semicolon", "python-from", "python", "import os; from jose import jwe\ndef f(b, k): return jwe.encrypt(b, k)\n"},
		{"python behind a BOM", "python", "python", bom + "import jwt\ndef f(t): return jwt.decode(t)\n"},
		{"c behind a BOM", "c", "c", bom + "#include <sodium.h>" + cBody},
		{"c after a block comment", "c", "c", "/* x */ #include <sodium.h>" + cBody},
	}
	for _, c := range cases {
		if !keeps(t, rules[c.rule], []string{c.analyzer}, evidenceOf(c.analyzer, c.source)) {
			t.Errorf("%s: OpenGrep matches %s, the prefilter must keep it", c.name, c.rule)
		}
	}
	for _, c := range []struct{ rule, analyzer, source string }{
		{"java", "java", "import java.util.List; import io.jsonwebtoken.Jwts;" + javaBody},
		{"rust", "rust", `#[cfg(feature = "gcm")] use chacha20poly1305::Aes256Gcm;` + rustBody},
		{"python", "python", "import os; import json\ndef f(t): return jwt.decode(t)\n"},
		{"c", "c", "/* sodium.h */ #include <openssl/evp.h>" + cBody},
	} {
		if keeps(t, rules[c.rule], []string{c.analyzer}, evidenceOf(c.analyzer, c.source)) {
			t.Errorf("%s: a unit that imports another module on the same line must still drop the rule", c.rule)
		}
	}
}

// TestExplicitMetadataImportsAcceptWildcard: metadata.imports names a class a
// match uses, which `import javax.crypto.*;` supplies. A pattern-derived
// literal guard matches an import statement, which OpenGrep does not match
// against a wildcard import, so that guard stays unsatisfied.
func TestExplicitMetadataImportsAcceptWildcard(t *testing.T) {
	declared := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO",
	  "metadata": {"imports": ["javax.crypto.Cipher"]}, "pattern": "Cipher.getInstance(...)"}`)
	wild := "import javax.crypto.*;\nclass A { Object c = Cipher.getInstance(\"AES\"); }\n"
	if !keeps(t, declared, []string{"java"}, evidenceOf("java", wild)) {
		t.Error("a wildcard import of the declared class's package must satisfy metadata.imports")
	}
	if keeps(t, declared, []string{"java"}, evidenceOf("java", "import javax.net.*;\nclass A { Object c = Cipher.getInstance(\"AES\"); }\n")) {
		t.Error("a wildcard import of an unrelated package must not satisfy metadata.imports")
	}
	guard := mustRule(t, `{"id": "r", "languages": ["java"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-inside": "import javax.crypto.Cipher;\n...\n"}, {"pattern": "Cipher.getInstance(...)"}]}`)
	if keeps(t, guard, []string{"java"}, evidenceOf("java", wild)) {
		t.Error("a literal import guard must not be satisfied by a wildcard import")
	}
}

// TestJavaScriptStatementBraceGuardIsNoRequirement: OpenGrep 1.30.2 parses
// the pattern `{..., $F, ...} = require("jsonwebtoken")` as the leading
// brace alone, which matches any object literal, so the rule matches files
// that never require jsonwebtoken, such as one that requires fast-jwt. The
// require in that pattern constrains nothing and must not drop the rule.
func TestJavaScriptStatementBraceGuardIsNoRequirement(t *testing.T) {
	rule := mustRule(t, `{"id": "javascript.jsonwebtoken.algorithm.jwa.hs256", "languages": ["javascript", "typescript"], "message": "m", "severity": "INFO",
	  "patterns": [
	    {"pattern-either": [
	      {"pattern-inside": "$NS = <... require(\"jsonwebtoken\") ...>\n...\n"},
	      {"pattern-inside": "{..., $F, ...} = require(\"jsonwebtoken\")\n...\n"},
	      {"pattern-inside": "import $NS from \"jsonwebtoken\"\n...\n"}]},
	    {"pattern": "{..., algorithm: \"HS256\", ...}"}]}`)
	source := "const { createSigner } = require('fast-jwt');\nconst v = createSigner({ key, algorithm: 'HS256' });\n"
	if !keeps(t, rule, []string{"js", "ts"}, evidenceOf("js", source)) {
		t.Error("OpenGrep matches the jsonwebtoken rule in a fast-jwt file, the prefilter must keep it")
	}
	guarded := mustRule(t, `{"id": "r", "languages": ["javascript"], "message": "m", "severity": "INFO",
	  "patterns": [{"pattern-inside": "$NS = <... require(\"jsonwebtoken\") ...>\n...\n"}, {"pattern": "{..., algorithm: \"HS256\", ...}"}]}`)
	if keeps(t, guarded, []string{"js"}, evidenceOf("js", source)) {
		t.Error("an assignment-rooted require guard must still drop the rule in a unit without jsonwebtoken")
	}
}
