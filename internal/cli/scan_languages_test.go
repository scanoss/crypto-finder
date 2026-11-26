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

// Java, Python, Go, JavaScript/TypeScript, Rust and Ruby are scanned, all of
// them when a target holds several, in the order detection names them; the
// other crypto languages are unsupported.
func TestScannedEcosystems(t *testing.T) {
	for _, tc := range []struct {
		languages   []string
		ecosystems  []string
		unsupported []string
	}{
		{languages: []string{"python"}, ecosystems: []string{"python"}, unsupported: []string{}},
		{languages: []string{"Python", "c#", "javascript", "yaml"}, ecosystems: []string{"python", "node"}, unsupported: []string{"csharp"}},
		{languages: []string{"java", "python"}, ecosystems: []string{"java", "python"}, unsupported: []string{}},
		{languages: []string{"python", "xml", "Java", "go"}, ecosystems: []string{"python", "java", "go"}, unsupported: []string{}},
		{languages: []string{"go"}, ecosystems: []string{"go"}, unsupported: []string{}},
		{languages: []string{"go", "c#"}, ecosystems: []string{"go"}, unsupported: []string{"csharp"}},
		{languages: []string{"c#"}, unsupported: []string{"csharp"}},
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

// C and C++ are out of a production scan and let through by CRYPTO_FINDER_CARDS_C=1.
func TestScannedEcosystemsCSwitch(t *testing.T) {
	languages := []string{"c", "java", "c++"}
	ecosystems, unsupported := scannedEcosystems(languages)
	if !reflect.DeepEqual(ecosystems, []string{"java"}) || !reflect.DeepEqual(unsupported, []string{"c", "cpp"}) {
		t.Errorf("without the switch: %v, %v", ecosystems, unsupported)
	}
	t.Setenv("CRYPTO_FINDER_CARDS_C", "1")
	ecosystems, unsupported = scannedEcosystems(languages)
	if !reflect.DeepEqual(ecosystems, []string{"c", "java", "cpp"}) || len(unsupported) != 0 {
		t.Errorf("with the switch: %v, %v", ecosystems, unsupported)
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

// A target with no source in a scanned language fails: an empty report would
// read as "no cryptography".
func TestScanOfAnUnsupportedLanguageFails(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	binary := buildProgressCryptoFinder(t)
	dir := t.TempDir()
	writeCardsRule(t, dir, progressRuleID, progressMatched)
	writeFile(t, filepath.Join(dir, "Main.cs"), "using System.Security.Cryptography;\n\nclass Main { void F() { SHA256.Create(); } }\n")
	for name, args := range map[string][]string{
		"detected":         {filepath.Join(dir, "Main.cs")},
		"--languages":      {"--languages", "csharp", dir},
		"progress stream":  {"--progress", filepath.Join(dir, "Main.cs")},
		"dependency phase": {"--scan-dependencies", filepath.Join(dir, "Main.cs")},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, append([]string{"--error-format", "json", "scan", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml")}, args...)...)
			cmd.Env = progressTestEnv(dir)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err == nil {
				t.Fatalf("scan of a C# target succeeded:\n%s", stdout.String())
			}
			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			var payload map[string]any
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &payload); err != nil {
				t.Fatalf("last stderr line is not the structured error: %q", stderr.String())
			}
			if payload["code"] != "language_not_supported" || payload["stage"] != "scan" {
				t.Fatalf("failure payload = %#v, want language_not_supported at stage scan", payload)
			}
			if !strings.Contains(payload["message"].(string), "not supported by this version") {
				t.Errorf("message %q does not say the language is not supported by this version", payload["message"])
			}
			if stdout.Len() != 0 {
				t.Errorf("a failed scan wrote a report: %s", stdout.String())
			}
			if name == "progress stream" {
				transitions := progressTransitions(t, strings.Join(lines[:len(lines)-1], "\n"))
				if tail := strings.Join(transitions[len(transitions)-2:], "\n"); tail != "scan/detection:failed\n/scan:failed" {
					t.Errorf("progress ends with\n%s\nwant detection and scan failed", tail)
				}
			}
		})
	}
}

// A Java target with sources in other crypto languages is scanned for its
// scanned languages and names the unsupported ones on the detection progress
// event.
func TestScanOfAMixedTargetReportsTheUnsupportedLanguages(t *testing.T) {
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
	if got := detection["unsupported_languages"]; !reflect.DeepEqual(got, []any{"csharp"}) {
		t.Errorf("detection details = %v, want unsupported_languages [csharp]", detection)
	}
	progressTransitions(t, stderr.String())
}

// An ecosystem with no scanned cards language fails; it is never matched with
// the Java cards.
func TestCardsLanguageOf(t *testing.T) {
	for ecosystem, want := range map[string]string{ecosystemJava: "java", ecosystemPython: "python", ecosystemGo: "go", ecosystemNode: "javascript", ecosystemRust: "rust", ecosystemRuby: "ruby"} {
		if got, err := cardsLanguageOf(ecosystem); err != nil || got != want {
			t.Errorf("cardsLanguageOf(%q) = %q, %v; want %q", ecosystem, got, err, want)
		}
	}
	for _, ecosystem := range []string{"", "csharp"} {
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
