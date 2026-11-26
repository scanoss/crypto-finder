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

package cli

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUnsupportedLanguages(t *testing.T) {
	for _, tc := range []struct {
		languages   []string
		unsupported []string
		java        bool
	}{
		{languages: []string{"java", "xml", "markdown"}, java: true},
		{languages: []string{"python"}, unsupported: []string{"python"}},
		{languages: []string{"Java", "Python", "shell", "TSX", "typescript", "c++"}, unsupported: []string{"cpp", "javascript", "python"}, java: true},
		{languages: []string{"go", "c#", "ruby", "rust", "c", "javascript"}, unsupported: []string{"c", "csharp", "go", "javascript", "ruby", "rust"}},
		{languages: nil},
	} {
		unsupported, java := unsupportedLanguages(tc.languages)
		if !reflect.DeepEqual(unsupported, tc.unsupported) || java != tc.java {
			t.Errorf("unsupportedLanguages(%v) = %v, %v; want %v, %v", tc.languages, unsupported, java, tc.unsupported, tc.java)
		}
	}
}

// Java, Python, Go, JavaScript/TypeScript, Rust, Ruby, C, C++ and C# are
// scanned, all of them when a target holds several, in the order detection
// names them.
func TestScannedEcosystems(t *testing.T) {
	for _, tc := range []struct {
		languages   []string
		ecosystems  []string
		unsupported []string
	}{
		{languages: []string{"python"}, ecosystems: []string{"python"}, unsupported: []string{}},
		{languages: []string{"Python", "c#", "javascript", "yaml"}, ecosystems: []string{"python", "csharp", "node"}, unsupported: []string{}},
		{languages: []string{"java", "python"}, ecosystems: []string{"java", "python"}, unsupported: []string{}},
		{languages: []string{"python", "xml", "Java", "go"}, ecosystems: []string{"python", "java", "go"}, unsupported: []string{}},
		{languages: []string{"go"}, ecosystems: []string{"go"}, unsupported: []string{}},
		{languages: []string{"go", "c#"}, ecosystems: []string{"go", "csharp"}, unsupported: []string{}},
		{languages: []string{"c#"}, ecosystems: []string{"csharp"}, unsupported: []string{}},
		{languages: []string{"ruby", "java"}, ecosystems: []string{"ruby", "java"}, unsupported: []string{}},
		{languages: []string{"rust", "java", "go"}, ecosystems: []string{"rust", "java", "go"}, unsupported: []string{}},
		{languages: nil},
	} {
		ecosystems, unsupported := scannedEcosystems(tc.languages)
		if !reflect.DeepEqual(ecosystems, tc.ecosystems) || !reflect.DeepEqual(unsupported, tc.unsupported) {
			t.Errorf("scannedEcosystems(%v) = %v, %v; want %v, %v", tc.languages, ecosystems, unsupported, tc.ecosystems, tc.unsupported)
		}
	}
}

// C and C++ are scanned without a switch; CRYPTO_FINDER_CARDS_C is accepted and
// changes nothing.
func TestScannedEcosystemsC(t *testing.T) {
	languages := []string{"c", "java", "c++"}
	for _, env := range []string{"", "1"} {
		t.Setenv("CRYPTO_FINDER_CARDS_C", env)
		ecosystems, unsupported := scannedEcosystems(languages)
		if !reflect.DeepEqual(ecosystems, []string{"c", "java", "cpp"}) || len(unsupported) != 0 {
			t.Errorf("CRYPTO_FINDER_CARDS_C=%q: %v, %v", env, ecosystems, unsupported)
		}
	}
}

// JavaScript and TypeScript are one scanned ecosystem, node, beside Java.
func TestScannedEcosystemsNode(t *testing.T) {
	ecosystems, unsupported := scannedEcosystems([]string{"javascript", "typescript", "java"})
	if !reflect.DeepEqual(ecosystems, []string{"node", "java"}) || len(unsupported) != 0 {
		t.Errorf("scannedEcosystems = %v, %v, want [node java], none unsupported", ecosystems, unsupported)
	}
}

// The scan hints each ecosystem by the names its rule files and card
// directories use: the language name and its aliases.
func TestScannedLanguageHints(t *testing.T) {
	got := scannedLanguageHints([]string{"node", "python"})
	if want := []string{"javascript", "typescript", "python"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hints = %v, want %v", got, want)
	}
}

// A C# target is scanned, with no environment variable: it never fails with
// language_not_supported.
func TestScanOfACSharpTargetIsScanned(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	writeCardsRule(t, dir, progressRuleID, progressMatched)
	writeFile(t, filepath.Join(dir, "Main.cs"), "using System.Security.Cryptography;\n\nclass Main { void F() { SHA256.Create(); } }\n")
	for name, args := range map[string][]string{
		"detected":    {filepath.Join(dir, "Main.cs")},
		"--languages": {"--languages", "csharp", dir},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, append([]string{"--error-format", "json", "scan", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml")}, args...)...)
			cmd.Env = progressTestEnv(dir)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("scan of a C# target failed: %v\n%s", err, stderr.String())
			}
			if strings.Contains(stderr.String(), "language_not_supported") {
				t.Errorf("a C# target is reported as not supported: %s", stderr.String())
			}
		})
	}
}

// A Java target with Python and C# sources is scanned for all of them: the
// detection progress event names no unsupported language.
func TestScanOfAMixedTargetHasNoUnsupportedLanguages(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	writeJavaFindingFixture(t, dir, dir)
	writeFile(t, filepath.Join(dir, "tool.py"), "import hashlib\nhashlib.sha256(b'x')\n")
	writeFile(t, filepath.Join(dir, "Main.cs"), "using System.Security.Cryptography;\n\nclass Main { void F() { SHA256.Create(); } }\n")
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), dir)
	cmd.Env = progressTestEnv(dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	var report struct {
		Findings []struct {
			FilePath string `json:"file_path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || len(report.Findings) != 1 || report.Findings[0].FilePath != "src/Use.java" {
		t.Fatalf("report = %s (%v), want the one Java finding", stdout.String(), err)
	}
	var detection map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["phase"] == "detection" && event["status"] == "completed" {
			detection, _ = event["details"].(map[string]any)
		}
	}
	if got, present := detection["unsupported_languages"]; present {
		t.Errorf("detection details = %v, want no unsupported_languages (got %v)", detection, got)
	}
	progressTransitions(t, stderr.String())
}

// An ecosystem with no scanned cards language fails; it is never matched with
// the Java cards.
func TestCardsLanguageOf(t *testing.T) {
	for ecosystem, want := range map[string]string{ecosystemJava: "java", ecosystemPython: "python", ecosystemGo: "go", ecosystemNode: "javascript", ecosystemRust: "rust", ecosystemRuby: "ruby", "c": "c", "cpp": "cpp", "csharp": "csharp"} {
		if got, err := cardsLanguageOf(ecosystem); err != nil || got != want {
			t.Errorf("cardsLanguageOf(%q) = %q, %v; want %q", ecosystem, got, err, want)
		}
	}
	for _, ecosystem := range []string{"", "cobol"} {
		if got, err := cardsLanguageOf(ecosystem); err == nil {
			t.Errorf("cardsLanguageOf(%q) = %q, want an error", ecosystem, got)
		}
	}
	for _, name := range []string{"javascript", "TypeScript"} {
		if lang, err := cardsDevLanguage(name); err != nil || lang.Name != "javascript" {
			t.Errorf("cardsDevLanguage(%s) = %v, %v; want javascript", name, lang, err)
		}
	}
	if lang, err := cardsDevLanguage("csharp"); err != nil || lang.Name != "csharp" {
		t.Errorf("cardsDevLanguage(csharp) = %v, %v; want csharp", lang, err)
	}
	if lang, err := cardsDevLanguage("Ruby"); err != nil || lang.Name != "ruby" {
		t.Errorf("cardsDevLanguage(Ruby) = %v, %v; want ruby", lang, err)
	}
	if lang, err := cardsDevLanguage("Python"); err != nil || lang.Name != "python" {
		t.Errorf("cardsDevLanguage(Python) = %v, %v", lang, err)
	}
}
