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

package cards

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"

	"github.com/go-enry/go-enry/v2"
	"github.com/scanoss/reach/paramcondition"
)

func TestExtractCryptoMetadata(t *testing.T) {
	tests := []struct {
		name           string
		cryptoMetadata map[string]any
		wantMetadata   map[string]string
	}{
		{
			name: "Boolean value",
			cryptoMetadata: map[string]any{
				"algorithmName": "RSA",
				"certified":     true,
			},
			wantMetadata: map[string]string{
				"algorithmName": "RSA",
				"certified":     "true",
			},
		},
		{
			name: "Numeric value",
			cryptoMetadata: map[string]any{
				"algorithmName": "AES",
				"keySize":       float64(256),
			},
			wantMetadata: map[string]string{
				"algorithmName": "AES",
				"keySize":       "256",
			},
		},
		{
			name: "Literal string value",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
		},
		{
			name:           "Empty metadata",
			cryptoMetadata: map[string]any{},
			wantMetadata:   map[string]string{},
		},
		{
			// A card match binds no metavariable, so a template that
			// references one is left out instead of becoming a valid-looking
			// but wrong value such as "ECDH-" or "PBKDF2---32".
			name: "A template with a reference drops only that field",
			cryptoMetadata: map[string]any{
				"algorithmFamily":        "ECDH",
				"algorithmName":          "ECDH-$1",
				"curve":                  "$1",
				"kdfName":                "PBKDF2-$hash-$iterations-$keylen",
				"parameterSetIdentifier": "$keylen",
				"api":                    "MessageDigest.getInstance",
			},
			wantMetadata: map[string]string{
				"algorithmFamily": "ECDH",
				"api":             "MessageDigest.getInstance",
			},
		},
		{
			// A parameterCondition is a predicate, not a template: a literal
			// "$z$" in it is kept as written.
			name: "parameterCondition keeps a reference",
			cryptoMetadata: map[string]any{
				"parameterCondition": `param[0]=="$z$"`,
			},
			wantMetadata: map[string]string{
				"parameterCondition": `param[0]=="$z$"`,
			},
		},
		{
			name: "Operation aliases to cryptoFunction",
			cryptoMetadata: map[string]any{
				"assetType": "algorithm",
				"operation": "encrypt",
			},
			wantMetadata: map[string]string{
				"assetType":      "algorithm",
				"operation":      "encrypt",
				"cryptoFunction": "encrypt",
			},
		},
		{
			name: "Explicit cryptoFunction wins over operation",
			cryptoMetadata: map[string]any{
				"assetType":      "algorithm",
				"operation":      "verify",
				"cryptoFunction": "sign",
			},
			wantMetadata: map[string]string{
				"assetType":      "algorithm",
				"operation":      "verify",
				"cryptoFunction": "sign",
			},
		},
		{
			name: "Public key material size aliases to publicKeySize",
			cryptoMetadata: map[string]any{
				"assetType":    "related-crypto-material",
				"materialType": "public-key",
				"materialSize": "2048",
			},
			wantMetadata: map[string]string{
				"assetType":     "related-crypto-material",
				"materialType":  "public-key",
				"materialSize":  "2048",
				"publicKeySize": "2048",
			},
		},
		{
			name: "Private key material size aliases to privateKeySize",
			cryptoMetadata: map[string]any{
				"assetType":    "related-crypto-material",
				"materialType": "private-key",
				"materialSize": float64(4096),
			},
			wantMetadata: map[string]string{
				"assetType":      "related-crypto-material",
				"materialType":   "private-key",
				"materialSize":   "4096",
				"privateKeySize": "4096",
			},
		},
		{
			name: "Ambiguous key material does not infer side specific size",
			cryptoMetadata: map[string]any{
				"assetType":    "related-crypto-material",
				"materialType": "key-pair",
				"materialSize": "256",
			},
			wantMetadata: map[string]string{
				"assetType":    "related-crypto-material",
				"materialType": "key-pair",
				"materialSize": "256",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: make(map[string]string),
			}

			extractCryptoMetadata(asset, tt.cryptoMetadata)

			if len(asset.Metadata) != len(tt.wantMetadata) {
				t.Errorf("extractCryptoMetadata() got %d metadata entries, want %d",
					len(asset.Metadata), len(tt.wantMetadata))
			}

			for key, want := range tt.wantMetadata {
				got, ok := asset.Metadata[key]
				if !ok {
					t.Errorf("extractCryptoMetadata() missing key %q", key)
					continue
				}
				if got != want {
					t.Errorf("extractCryptoMetadata() metadata[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestExtractCryptoMetadata_ParameterConditions(t *testing.T) {
	t.Run("populates ParameterConditions from metadata.parameterCondition", func(t *testing.T) {
		asset := &entities.CryptographicAsset{
			Metadata: make(map[string]string),
		}
		cryptoMetadata := map[string]any{
			"operation":          "encrypt",
			"parameterCondition": "param[0]==yes",
			"api":                "org.bouncycastle.crypto.engines.AESEngine.init",
		}

		extractCryptoMetadata(asset, cryptoMetadata)

		if len(asset.ParameterConditions) != 1 {
			t.Fatalf("ParameterConditions = %#v, want 1 entry", asset.ParameterConditions)
		}
		want := paramcondition.Condition{
			Raw:      "param[0]==yes",
			Selector: paramcondition.Selector{Index: intPtr(0)},
			Operator: paramcondition.OpExact,
			Match:    paramcondition.MatchValue,
			Value:    "yes",
		}
		got := asset.ParameterConditions[0]
		if got.Raw != want.Raw || got.Operator != want.Operator || got.Match != want.Match || got.Value != want.Value {
			t.Errorf("ParameterConditions[0] = %+v, want %+v", got, want)
		}
		if got.Selector.Index == nil || *got.Selector.Index != 0 {
			t.Errorf("ParameterConditions[0].Selector.Index = %v, want 0", got.Selector.Index)
		}

		// Verbatim flat string must still be present, unbroken.
		if asset.Metadata["parameterCondition"] != "param[0]==yes" {
			t.Errorf("Metadata[parameterCondition] = %q, want %q", asset.Metadata["parameterCondition"], "param[0]==yes")
		}
	})

	t.Run("no parameterCondition key means nil slice", func(t *testing.T) {
		asset := &entities.CryptographicAsset{
			Metadata: make(map[string]string),
		}
		cryptoMetadata := map[string]any{
			"algorithmName": "AES",
		}

		extractCryptoMetadata(asset, cryptoMetadata)

		if asset.ParameterConditions != nil {
			t.Errorf("ParameterConditions = %#v, want nil", asset.ParameterConditions)
		}

		b, err := json.Marshal(asset)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(b), "parameter_conditions") {
			t.Errorf("marshaled asset contains parameter_conditions key when no predicate was set: %s", b)
		}
	})
}

func intPtr(i int) *int { return &i }

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "Java file",
			filePath: "/path/to/File.java",
			want:     "java",
		},
		{
			name:     "Python file",
			filePath: "/path/to/script.py",
			want:     "python",
		},
		{
			name:     "Go file",
			filePath: "/path/to/main.go",
			want:     "go",
		},
		{
			name:     "JavaScript file",
			filePath: "/path/to/app.js",
			want:     "javascript",
		},
		{
			name:     "TypeScript file",
			filePath: "/path/to/app.ts",
			want:     "typescript",
		},
		{
			name:     "Unknown extension",
			filePath: "/path/to/file.xyz",
			want:     "unknown",
		},
		{
			name:     "No extension",
			filePath: "/path/to/Makefile",
			want:     "makefile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectLanguage(tt.filePath, "")
			if got != tt.want {
				t.Errorf("detectLanguage(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestTransformToInterimReport(t *testing.T) {
	t.Parallel()

	detections := []detection{
		{
			ruleID:   "fixture.go.crypto.load-key-pair",
			path:     "/test/main.go",
			start:    position{10, 5},
			message:  "TLS certificate loading detected",
			severity: "info",
			lines:    "tls.LoadX509KeyPair(...)",
			crypto: map[string]any{
				"assetType": "certificate",
				"library":   "crypto/tls",
			},
		},
		{
			ruleID:   "go.crypto.aes",
			path:     "/test/crypto.go",
			start:    position{20, 1},
			message:  "AES detected",
			severity: "warning",
			lines:    "aes.NewCipher(key)",
			crypto:   map[string]any{"algorithm": "AES"},
		},
	}

	toolInfo := entities.ToolInfo{
		Name:    "semgrep",
		Version: "1.0.0",
	}

	report := transformToInterimReport(detections, toolInfo, "/test", nil, false)

	if report == nil {
		t.Fatal("Expected non-nil report")
	}

	if report.Version != "1.1" {
		t.Errorf("Expected version '1.1', got '%s'", report.Version)
	}

	if report.Tool.Name != "semgrep" {
		t.Errorf("Expected tool name 'semgrep', got '%s'", report.Tool.Name)
	}

	if len(report.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(report.Findings))
	}
}

func TestGroupByFile(t *testing.T) {
	t.Parallel()

	results := []detection{
		{path: "/test/file1.go", ruleID: "rule1"},
		{path: "/test/file2.go", ruleID: "rule2"},
		{path: "/test/file1.go", ruleID: "rule3"},
	}

	grouped := groupByFile(results)

	if len(grouped) != 2 {
		t.Fatalf("Expected 2 files, got %d", len(grouped))
	}

	if len(grouped["/test/file1.go"]) != 2 {
		t.Errorf("Expected 2 results for file1.go, got %d", len(grouped["/test/file1.go"]))
	}

	if len(grouped["/test/file2.go"]) != 1 {
		t.Errorf("Expected 1 result for file2.go, got %d", len(grouped["/test/file2.go"]))
	}
}

func TestTransformFileFinding(t *testing.T) {
	t.Parallel()

	results := []detection{
		{
			ruleID:   "go.crypto.aes",
			path:     "/test/main.go",
			start:    position{15, 1},
			message:  "AES usage detected",
			severity: "warning",
			lines:    "aes.NewCipher(key)",
		},
		{
			ruleID:   "go.crypto.rsa",
			path:     "/test/main.go",
			start:    position{25, 1},
			message:  "RSA usage detected",
			severity: "info",
			lines:    "rsa.GenerateKey(...)",
		},
	}

	finding := transformFileFinding("/test/main.go", results, "/test", nil, "")

	if finding.FilePath != "main.go" {
		t.Errorf("Expected 'main.go', got '%s'", finding.FilePath)
	}

	if finding.Language != "go" {
		t.Errorf("Expected language 'go', got '%s'", finding.Language)
	}

	if len(finding.CryptographicAssets) != 2 {
		t.Fatalf("Expected 2 assets, got %d", len(finding.CryptographicAssets))
	}
}

func TestTransformToCryptographicAsset(t *testing.T) {
	t.Parallel()

	result := &detection{
		ruleID:   "python.crypto.sha256",
		start:    position{20, 5},
		message:  "SHA-256 usage",
		severity: "info",
		lines:    "hashlib.sha256(data)",
		crypto: map[string]any{
			"algorithm": "SHA-256",
			"assetType": "algorithm",
		},
	}

	asset := transformToCryptographicAsset(result, nil, "")

	if asset.StartLine != 20 {
		t.Errorf("Expected start line 20, got %d", asset.StartLine)
	}

	if asset.Match != "hashlib.sha256(data)" {
		t.Errorf("Expected match 'hashlib.sha256(data)', got '%s'", asset.Match)
	}

	if asset.Rules[0].ID != "python.crypto.sha256" {
		t.Errorf("Expected rule ID 'python.crypto.sha256', got '%s'", asset.Rules[0].ID)
	}

	if asset.Rules[0].Severity != "INFO" {
		t.Errorf("Expected severity 'INFO', got '%s'", asset.Rules[0].Severity)
	}

	if asset.Status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", asset.Status)
	}

	if asset.Metadata["algorithm"] != "SHA-256" {
		t.Errorf("Expected algorithm 'SHA-256', got '%s'", asset.Metadata["algorithm"])
	}
}

func TestTransformToCryptographicAsset_PURLPromotion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		purl string
		want string
	}{
		{name: "valid", purl: "pkg:pypi/My_Package.Name", want: "pkg:pypi/my-package-name"},
		{name: "invalid", purl: "not-a-purl", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &detection{
				ruleID: "python.crypto.hash",
				start:  position{1, 1},
				purl:   tt.purl,
			}
			asset := transformToCryptographicAsset(result, nil, "")
			if asset.PURL != tt.want {
				t.Fatalf("PURL = %q, want %q", asset.PURL, tt.want)
			}
			if _, leaked := asset.Metadata["purl"]; leaked {
				t.Fatal("rule purl leaked into generic asset metadata")
			}
		})
	}
}

func TestTransformToCryptographicAsset_NoMetadata(t *testing.T) {
	t.Parallel()

	result := &detection{
		ruleID:   "test.rule",
		start:    position{1, 1},
		message:  "Test message",
		severity: "error",
		lines:    "test code",
	}

	asset := transformToCryptographicAsset(result, nil, "")

	if asset.Rules[0].Severity != "ERROR" {
		t.Errorf("Expected severity 'ERROR', got '%s'", asset.Rules[0].Severity)
	}

	if asset.Metadata == nil {
		t.Error("Expected non-nil metadata map")
	}

	if len(asset.Metadata) != 0 {
		t.Errorf("Expected empty metadata, got %d entries", len(asset.Metadata))
	}
}

func TestCleanRuleID(t *testing.T) {
	t.Parallel()

	rulePaths := []string{
		"/Users/tester/semgrep-rules",
		"/Users/tester/.scanoss/crypto-finder/cache/rulesets/dca/latest",
	}

	t.Run("StripsRulesDirPrefix", func(t *testing.T) {
		ruleID := "Users.tester.semgrep-rules.java.crypto.aes"
		got := cleanRuleID(ruleID, rulePaths)
		want := "java.crypto.aes"
		if got != want {
			t.Errorf("cleanRuleID(%q) = %q, want %q", ruleID, got, want)
		}
	})

	t.Run("StripsCachePrefix", func(t *testing.T) {
		ruleID := "Users.tester..scanoss.crypto-finder.cache.rulesets.dca.latest.java.crypto.rsa"
		got := cleanRuleID(ruleID, rulePaths)
		want := "java.crypto.rsa"
		if got != want {
			t.Errorf("cleanRuleID(%q) = %q, want %q", ruleID, got, want)
		}
	})

	t.Run("NoMatchKeepsOriginal", func(t *testing.T) {
		ruleID := "go.crypto.sha256"
		got := cleanRuleID(ruleID, rulePaths)
		if got != ruleID {
			t.Errorf("cleanRuleID(%q) = %q, want %q", ruleID, got, ruleID)
		}
	})
}

// TestTransformToCryptographicAsset_ColumnThreading verifies that Start.Col and
// End.Col from a detection are preserved on the resulting CryptographicAsset
// as StartCol / EndCol respectively.
func TestTransformToCryptographicAsset_ColumnThreading(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		startCol  int
		endCol    int
		wantStart int
		wantEnd   int
	}{
		{
			name:      "non-zero columns are preserved",
			startCol:  5,
			endCol:    15,
			wantStart: 5,
			wantEnd:   15,
		},
		{
			name:      "zero columns pass through without error",
			startCol:  0,
			endCol:    0,
			wantStart: 0,
			wantEnd:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &detection{
				ruleID:   "java.crypto.sha3",
				start:    position{7, tt.startCol},
				end:      position{7, tt.endCol},
				lines:    "SHA3Digest digest = new SHA3Digest(256)",
				severity: "warning",
				crypto:   map[string]any{"assetType": "algorithm"},
			}

			asset := transformToCryptographicAsset(result, nil, "")

			if asset.StartCol != tt.wantStart {
				t.Errorf("StartCol = %d, want %d", asset.StartCol, tt.wantStart)
			}
			if asset.EndCol != tt.wantEnd {
				t.Errorf("EndCol = %d, want %d", asset.EndCol, tt.wantEnd)
			}
		})
	}
}

// Asked by name alone, enry answers these three with the wrong language:
// .rs -> XML, .cs -> Smalltalk, .php -> Hack. Each extension has several
// candidates and the tie is broken without looking at the file. The wrong name
// is then stored on every finding for those languages, and because "xml" is not
// an ecosystem any consumer recognizes it contributes nothing rather than
// failing loudly -- so nothing surfaces the mistake.
//
// Real files, because reading them is the whole point of the fix.
func TestDetectLanguageResolvesAmbiguousExtensions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "lib.rs",
			content: "use std::collections::HashMap;\n\npub fn build() -> HashMap<String, u32> {\n    HashMap::new()\n}\n",
			want:    "rust",
		},
		{
			name:    "Program.cs",
			content: "using System;\n\nnamespace Demo {\n    public class Program {\n        public static void Main(string[] args) { Console.WriteLine(\"hi\"); }\n    }\n}\n",
			want:    "c#",
		},
		{
			name:    "index.php",
			content: "<?php\nfunction greet($name) {\n    return \"hello \" . $name;\n}\n",
			want:    "php",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := detectLanguage(path, ""); got != tc.want {
				t.Errorf("detectLanguage(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// A C++ header and a C header share the .h extension. Telling them apart is a
// consequence of reading content, not the goal, and it is the one place the
// change alters an answer the codebase already depended on --
// reportOccurrenceKeyEcosystems keys on it. Pin both directions here so the
// pairing with that branch stays visible from this side too.
func TestDetectLanguageDistinguishesCAndCPPHeaders(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		label   string
		content string
		want    string
	}{
		{"C header", "#ifndef FOO_H\n#define FOO_H\nint add(int a, int b);\n#endif\n", "c"},
		{"C++ header", "#pragma once\n#include <string>\nclass Foo {\npublic:\n    std::string name() const;\n};\n", "c++"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "crypto.h")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := detectLanguage(path, ""); got != tc.want {
				t.Errorf("detectLanguage(%s) = %q, want %q", tc.label, got, tc.want)
			}
		})
	}
}

// An unreadable path must still answer, because a possibly-wrong language is
// more useful downstream than none. This is also what keeps the existing
// name-only table test above meaningful: it passes paths that do not exist.
func TestDetectLanguageFallsBackWhenFileIsUnreadable(t *testing.T) {
	t.Parallel()

	if got := detectLanguage(filepath.Join(t.TempDir(), "nope", "main.go"), ""); got != "go" {
		t.Errorf("detectLanguage(missing .go) = %q, want go", got)
	}
	if got := detectLanguage(filepath.Join(t.TempDir(), "nope", "file.xyz"), ""); got != "unknown" {
		t.Errorf("detectLanguage(missing .xyz) = %q, want unknown", got)
	}
}

// annotate matches a stored graph without its source tree: a file it cannot
// read takes the candidate of the cards language that matched it, the answer
// the content gives a scan, where its name alone answers another language.
func TestDetectLanguageOfAnUnreadFileFollowsTheMatchedCards(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "nope")
	for _, tc := range []struct{ name, matched, want string }{
		{"lib.rs", "rust", "rust"},
		{"index.ts", "javascript", "typescript"},
		{"main.go", "go", "go"},
		// No candidate is the matched language's: the name decides.
		{"main.go", "rust", "go"},
		{"lib.rs", "", "xml"},
	} {
		if got := detectLanguage(filepath.Join(missing, tc.name), tc.matched); got != tc.want {
			t.Errorf("detectLanguage(missing %s, matched %q) = %q, want %q", tc.name, tc.matched, got, tc.want)
		}
	}
	// Content still decides a file that can be read.
	path := filepath.Join(t.TempDir(), "lib.rs")
	if err := os.WriteFile(path, []byte("<?xml version=\"1.0\"?>\n<project></project>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectLanguage(path, "rust"); got != "xml" {
		t.Errorf("detectLanguage(XML lib.rs, matched rust) = %q, want xml", got)
	}
}

// The read is capped, so a file larger than the cap must still classify: enry's
// content strategies look at the head of the file, which is what gets read.
func TestDetectLanguageClassifiesFilesLargerThanTheSniffLimit(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "big.rs")
	body := "use std::collections::HashMap;\n\npub fn build() -> HashMap<String, u32> {\n    HashMap::new()\n}\n"
	padding := strings.Repeat("// padding to push this file past the sniff limit\n", 1000)
	if err := os.WriteFile(path, []byte(body+padding), 0o600); err != nil {
		t.Fatal(err)
	}
	if int64(len(body+padding)) <= languageSniffLimit {
		t.Fatalf("fixture is %d bytes, which does not exceed the %d-byte cap", len(body+padding), languageSniffLimit)
	}
	if got := detectLanguage(path, ""); got != "rust" {
		t.Errorf("detectLanguage(large .rs) = %q, want rust", got)
	}
}

// enry answers the empty string when it decides the bytes are binary, and it
// decides that for some legitimate sources: a generated tree-sitter parser.c,
// whose dense state tables trip the heuristic, is a real example found in the
// module cache. Reading content must never turn such a file from "c" into
// "unknown", so an empty content-informed answer falls back to the name.
func TestDetectLanguageDoesNotLoseAnAnswerToBinaryHeuristics(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "parser.c")
	// A NUL byte is enough to make enry call the content binary.
	body := []byte("#include \"parser.h\"\nstatic const uint16_t ts_parse_table[] = {\x00\x00\x00};\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if !enry.IsBinary(body) {
		t.Skip("enry no longer treats this fixture as binary; the guarded path is unreachable")
	}
	if got := detectLanguage(path, ""); got != "c" {
		t.Errorf("detectLanguage(binary-looking .c) = %q, want c", got)
	}
}

// TestTransformToInterimReport_ParameterConditionsUseParseAll pins that a
// finding's parameterCondition is parsed with paramcondition.ParseAll, the
// entry point rule entry-point synthesis also calls, so both paths ingest the
// same predicate the same way.
func TestTransformToInterimReport_ParameterConditionsUseParseAll(t *testing.T) {
	const raw = "param[0|forEncryption]~=^enc"
	report := transformToInterimReport([]detection{{
		ruleID: "fixture.java.bouncycastle.aes-init-encrypt",
		path:   "AESEngine.java",
		crypto: map[string]any{"operation": "encrypt", "parameterCondition": raw},
	}}, entities.ToolInfo{}, ".", nil, true)
	if len(report.Findings) != 1 || len(report.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("report shape = %+v, want exactly 1 finding with 1 asset", report)
	}
	want, err := paramcondition.ParseAll(raw)
	if err != nil {
		t.Fatalf("ParseAll(%q): %v", raw, err)
	}
	if got := report.Findings[0].CryptographicAssets[0].ParameterConditions; !reflect.DeepEqual(got, want) {
		t.Fatalf("report diverged from ParseAll:\nreport:   %+v\nParseAll: %+v", got, want)
	}
}
