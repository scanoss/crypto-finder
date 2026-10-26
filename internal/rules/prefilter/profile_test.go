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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
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

func TestBuildProfile(t *testing.T) {
	ev := NewEvidence()
	ev.AddFile([]string{"java"}, []byte("import javax.crypto.Cipher;\nclass A { org.bouncycastle.jce.provider.BouncyCastleProvider p; }\n"))
	ev.AddFile([]string{"python"}, []byte("import os\n"))
	ev.AddFile([]string{"ts"}, []byte("import { sign } from 'jsonwebtoken';\n"))
	ev.AddFile([]string{"c"}, []byte("#include \"../deps/sodium.h\"\n"))
	ev.AddFile([]string{"csharp"}, []byte("class A {}\n"))
	index := &Index{
		Languages: []string{"c", "cpp", "csharp", "go", "java", "javascript", "python", "ruby", "rust", "typescript"},
		Modules: map[Family][]string{
			FamilyJava:   {"org.bouncycastle", "javax.crypto", "com.nimbusds.jose"},
			FamilyPython: {"hashlib", "cryptography.hazmat"},
			FamilyJS:     {"jsonwebtoken", "@noble/hashes"},
			FamilyGo:     {"crypto/aes"},
			FamilyRust:   {"aes_gcm"},
			FamilyC:      {"openssl", "sodium"},
		},
	}
	got := BuildProfile(ev, index)
	want := Profile{
		Languages: []string{"c", "csharp", "java", "python", "typescript"},
		Modules: map[Family][]string{ //nolint:exhaustive // A partial profile.
			FamilyJava:   {"javax.crypto", "org.bouncycastle"},
			FamilyPython: {},
			FamilyJS:     {"jsonwebtoken"},
			FamilyC:      {"sodium"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildProfile = %+v, want %+v", got, want)
	}
	if BuildProfile(NewEvidence(), index).IsEmpty() != true {
		t.Error("a unit without files has an empty profile")
	}
	if BuildProfile(ev, &Index{}).Languages[0] != "c" {
		t.Error("an index without languages takes the evidence's analyzers")
	}
}

func TestProfileHashIsCanonical(t *testing.T) {
	a := Profile{Languages: []string{"python", "java"}, Modules: map[Family][]string{FamilyPython: {"hashlib", "cryptography.hazmat"}, FamilyJava: {"javax.crypto"}}} //nolint:exhaustive // A partial profile.
	b := Profile{Languages: []string{"java", "python"}, Modules: map[Family][]string{FamilyJava: {"javax.crypto"}, FamilyPython: {"cryptography.hazmat", "hashlib"}}} //nolint:exhaustive // A partial profile.
	canonical := `{"languages":["java","python"],"modules":{"java":["javax.crypto"],"python":["cryptography.hazmat","hashlib"]}}`
	sum := sha256.Sum256([]byte(canonical))
	if got := a.Hash(); got != hex.EncodeToString(sum[:]) || got != b.Hash() {
		t.Errorf("Hash() = %s, want the hash of %s for both orderings", got, canonical)
	}
	empty := sha256.Sum256([]byte(`{"languages":[],"modules":{}}`))
	if got := (Profile{}).Hash(); got != hex.EncodeToString(empty[:]) {
		t.Errorf("empty Hash() = %s, want the hash of empty lists", got)
	}
}

func TestEvidenceFromTree(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"src/main/App.java":       "import javax.crypto.Cipher;\n",
		"lib/sign.ts":             "import { sign } from 'jsonwebtoken';\n",
		"native/hash.c":           "#include <openssl/evp.h>\n",
		"tool.py":                 "import hashlib\n",
		"node_modules/x/index.js": "require('node-forge')\n",
		"vendor/y/y.go":           "package y\nimport \"filippo.io/age\"\n",
		"build/out.rs":            "use aes_gcm::Aes256Gcm;\n",
		"skipped/secret.java":     "import org.bouncycastle.jce.X;\n",
		"README.md":               "import nothing\n",
		"huge.go":                 "package h\nimport \"crypto/sha256\"\n" + strings.Repeat("//", maxTreeFileBytes/2),
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	skip := func(path string, isDir bool) bool { return isDir && filepath.Base(path) == "skipped" }
	ev, err := EvidenceFromTree(root, skip)
	if err != nil {
		t.Fatalf("EvidenceFromTree: %v", err)
	}
	if got := ev.Analyzers(); !reflect.DeepEqual(got, []string{"c", "java", "python", "ts"}) {
		t.Errorf("Analyzers = %v", got)
	}
	if ev.Files() != 4 {
		t.Errorf("Files = %d, want 4", ev.Files())
	}
	satisfied := func(family Family, module string) bool {
		return (&importAtom{family: family, literal: module, declared: true}).eval(ev)
	}
	for _, c := range []struct {
		family Family
		module string
		want   bool
	}{
		{FamilyJava, "javax.crypto", true},
		{FamilyJS, "jsonwebtoken", true},
		{FamilyC, "openssl", true},
		{FamilyPython, "hashlib", true},
		{FamilyJS, "node-forge", false},
		{FamilyGo, "filippo.io/age", false},
		{FamilyRust, "aes_gcm", false},
		{FamilyJava, "org.bouncycastle", false},
		{FamilyGo, "crypto/sha256", false},
	} {
		if got := satisfied(c.family, c.module); got != c.want {
			t.Errorf("%s %q satisfied=%v, want %v", c.family, c.module, got, c.want)
		}
	}
	single, err := EvidenceFromTree(filepath.Join(root, "tool.py"), nil)
	if err != nil || single.Files() != 1 || !single.HasAnalyzer("python") {
		t.Errorf("a file target reads that file alone: err=%v files=%d", err, single.Files())
	}
	if _, err := EvidenceFromTree(filepath.Join(root, "missing"), nil); err == nil {
		t.Error("a missing root is an error")
	}
}
