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
