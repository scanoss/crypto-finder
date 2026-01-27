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

package semgrep

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestResolveMetavars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		metavars map[string]entities.MetavarInfo
		want     string
	}{
		{
			name:  "Single metavar embedded in string",
			input: "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "SHA-256",
		},
		{
			name:  "Multiple metavars in string",
			input: "AES-$keySize-$mode",
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			want: "AES-256-GCM",
		},
		{
			name:  "Standalone metavar",
			input: "$ALGORITHM",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "\"AES\"",
				},
			},
			want: "AES",
		},
		{
			name:  "String without metavars",
			input: "RSA-2048",
			metavars: map[string]entities.MetavarInfo{
				"$OTHER": {
					AbstractContent: "value",
				},
			},
			want: "RSA-2048",
		},
		{
			name:  "Metavar not found - keep original",
			input: "SHA-$unknown",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "SHA-$unknown",
		},
		{
			name:  "Multiple metavars, some missing",
			input: "AES-$keySize-$mode-$unknown",
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "128",
				},
				"$mode": {
					AbstractContent: "CBC",
				},
			},
			want: "AES-128-CBC-$unknown",
		},
		{
			name:  "Empty string",
			input: "",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			want: "",
		},
		{
			name:  "Metavar with propagated value",
			input: "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "128",
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "256",
					},
				},
			},
			want: "SHA-256", // Should prefer propagated value
		},
		{
			name:  "Metavar with quotes in propagated value",
			input: "$ALGORITHM",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "\"SHA-512\"",
					},
				},
			},
			want: "SHA-512", // Should strip quotes
		},
		{
			name:     "Empty metavars map",
			input:    "SHA-$variant",
			metavars: map[string]entities.MetavarInfo{},
			want:     "SHA-$variant",
		},
		{
			name:     "Nil metavars map",
			input:    "SHA-$variant",
			metavars: nil,
			want:     "SHA-$variant",
		},
		{
			name:  "Complex pattern with multiple variations",
			input: "$algo-$size-$mode with $padding padding",
			metavars: map[string]entities.MetavarInfo{
				"$algo": {
					AbstractContent: "AES",
				},
				"$size": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
				"$padding": {
					AbstractContent: "PKCS7",
				},
			},
			want: "AES-256-GCM with PKCS7 padding",
		},
		{
			name:  "Metavar with underscore in name",
			input: "$algorithm_name-$key_size",
			metavars: map[string]entities.MetavarInfo{
				"$algorithm_name": {
					AbstractContent: "RSA",
				},
				"$key_size": {
					AbstractContent: "2048",
				},
			},
			want: "RSA-2048",
		},
		{
			name:  "Metavar with numbers in name",
			input: "$var1-$var2",
			metavars: map[string]entities.MetavarInfo{
				"$var1": {
					AbstractContent: "first",
				},
				"$var2": {
					AbstractContent: "second",
				},
			},
			want: "first-second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMetavars(tt.input, tt.metavars)
			if got != tt.want {
				t.Errorf("resolveMetavars(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetMetavarValue(t *testing.T) {
	tests := []struct {
		name     string
		metavars map[string]entities.MetavarInfo
		key      string
		want     string
	}{
		{
			name: "Metavar with AbstractContent",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "AES",
				},
			},
			key:  "$ALGORITHM",
			want: "AES",
		},
		{
			name: "Metavar with PropagatedValue",
			metavars: map[string]entities.MetavarInfo{
				"$ALGORITHM": {
					AbstractContent: "oldvalue",
					PropagatedValue: &entities.MetavarPropagatedValue{
						SvalueAbstractContent: "newvalue",
					},
				},
			},
			key:  "$ALGORITHM",
			want: "newvalue",
		},
		{
			name: "Metavar with quoted value",
			metavars: map[string]entities.MetavarInfo{
				"$MODE": {
					AbstractContent: "\"GCM\"",
				},
			},
			key:  "$MODE",
			want: "GCM",
		},
		{
			name: "Direct value without $ prefix",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "literal-value",
			want: "literal-value",
		},
		{
			name: "Empty key",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "",
			want: "",
		},
		{
			name: "Metavar not found",
			metavars: map[string]entities.MetavarInfo{
				"$ALGO": {
					AbstractContent: "value",
				},
			},
			key:  "$NOTFOUND",
			want: "",
		},
		{
			name: "Key without $ tries with and without prefix",
			metavars: map[string]entities.MetavarInfo{
				"variant": {
					AbstractContent: "256",
				},
			},
			key:  "$variant",
			want: "256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMetavarValue(tt.metavars, tt.key)
			if got != tt.want {
				t.Errorf("getMetavarValue(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestExtractCryptoMetadata(t *testing.T) {
	tests := []struct {
		name           string
		cryptoMetadata map[string]any
		metavars       map[string]entities.MetavarInfo
		wantMetadata   map[string]string
	}{
		{
			name: "String with embedded metavar",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-$variant",
				"primitive":     "hash",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
		},
		{
			name: "Multiple metavars in values",
			cryptoMetadata: map[string]any{
				"algorithmName":          "AES-$keySize",
				"mode":                   "$mode",
				"parameterSetIdentifier": "$keySize",
			},
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName":          "AES-256",
				"mode":                   "GCM",
				"parameterSetIdentifier": "256",
			},
		},
		{
			name: "Boolean value",
			cryptoMetadata: map[string]any{
				"algorithmName": "RSA",
				"certified":     true,
			},
			metavars: map[string]entities.MetavarInfo{},
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
			metavars: map[string]entities.MetavarInfo{},
			wantMetadata: map[string]string{
				"algorithmName": "AES",
				"keySize":       "256",
			},
		},
		{
			name: "Mixed types",
			cryptoMetadata: map[string]any{
				"algorithmName": "AES-$keySize-$mode",
				"primitive":     "ae",
				"keySize":       float64(256),
				"certified":     true,
			},
			metavars: map[string]entities.MetavarInfo{
				"$keySize": {
					AbstractContent: "256",
				},
				"$mode": {
					AbstractContent: "GCM",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "AES-256-GCM",
				"primitive":     "ae",
				"keySize":       "256",
				"certified":     "true",
			},
		},
		{
			name: "Literal string value",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
			metavars: map[string]entities.MetavarInfo{},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-256",
				"primitive":     "hash",
			},
		},
		{
			name:           "Empty metadata",
			cryptoMetadata: map[string]any{},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{},
		},
		{
			name: "Real example from Semgrep output",
			cryptoMetadata: map[string]any{
				"algorithmName":          "SHA-$variant",
				"api":                    "MessageDigest.getInstance",
				"assetType":              "algorithm",
				"library":                "JCA/JCE",
				"parameterSetIdentifier": "$variant",
				"primitive":              "hash",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName":          "SHA-256",
				"api":                    "MessageDigest.getInstance",
				"assetType":              "algorithm",
				"library":                "JCA/JCE",
				"parameterSetIdentifier": "256",
				"primitive":              "hash",
			},
		},
		{
			name: "Metavar not found - keeps original",
			cryptoMetadata: map[string]any{
				"algorithmName": "SHA-$unknown",
			},
			metavars: map[string]entities.MetavarInfo{
				"$variant": {
					AbstractContent: "256",
				},
			},
			wantMetadata: map[string]string{
				"algorithmName": "SHA-$unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &entities.CryptographicAsset{
				Metadata: make(map[string]string),
			}

			extractCryptoMetadata(asset, tt.cryptoMetadata, tt.metavars)

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
			got := detectLanguage(tt.filePath)
			if got != tt.want {
				t.Errorf("detectLanguage(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestTransformSemgrepCompatibleOutputToInterimFormat(t *testing.T) {
	t.Parallel()

	semgrepOutput := &entities.SemgrepOutput{
		Results: []entities.SemgrepResult{
			{
				CheckID: "go.crypto.tls.load-key-pair",
				Path:    "/test/main.go",
				Start:   entities.SemgrepLocation{Line: 10, Col: 5},
				Extra: entities.SemgrepExtra{
					Message:  "TLS certificate loading detected",
					Severity: "info",
					Lines:    "tls.LoadX509KeyPair(...)",
					Metadata: entities.SemgrepMetadata{
						Crypto: map[string]any{
							"assetType": "certificate",
							"library":   "crypto/tls",
						},
					},
				},
			},
			{
				CheckID: "go.crypto.aes",
				Path:    "/test/crypto.go",
				Start:   entities.SemgrepLocation{Line: 20, Col: 1},
				Extra: entities.SemgrepExtra{
					Message:  "AES detected",
					Severity: "warning",
					Lines:    "aes.NewCipher(key)",
					Metadata: entities.SemgrepMetadata{
						Crypto: map[string]any{
							"algorithm": "AES",
						},
					},
				},
			},
		},
	}

	toolInfo := entities.ToolInfo{
		Name:    "semgrep",
		Version: "1.0.0",
	}

	report := TransformSemgrepCompatibleOutputToInterimFormat(semgrepOutput, toolInfo, "/test", nil, false)

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

	results := []entities.SemgrepResult{
		{Path: "/test/file1.go", CheckID: "rule1"},
		{Path: "/test/file2.go", CheckID: "rule2"},
		{Path: "/test/file1.go", CheckID: "rule3"},
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

	results := []entities.SemgrepResult{
		{
			CheckID: "go.crypto.aes",
			Path:    "/test/main.go",
			Start:   entities.SemgrepLocation{Line: 15, Col: 1},
			Extra: entities.SemgrepExtra{
				Message:  "AES usage detected",
				Severity: "warning",
				Lines:    "aes.NewCipher(key)",
			},
		},
		{
			CheckID: "go.crypto.rsa",
			Path:    "/test/main.go",
			Start:   entities.SemgrepLocation{Line: 25, Col: 1},
			Extra: entities.SemgrepExtra{
				Message:  "RSA usage detected",
				Severity: "info",
				Lines:    "rsa.GenerateKey(...)",
			},
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

	if finding.TimestampUTC == "" {
		t.Error("Expected non-empty timestamp")
	}
}

func TestTransformToCryptographicAsset(t *testing.T) {
	t.Parallel()

	result := &entities.SemgrepResult{
		CheckID: "python.crypto.sha256",
		Start:   entities.SemgrepLocation{Line: 20, Col: 5},
		Extra: entities.SemgrepExtra{
			Message:  "SHA-256 usage",
			Severity: "info",
			Lines:    "hashlib.sha256(data)",
			Metadata: entities.SemgrepMetadata{
				Crypto: map[string]any{
					"algorithm": "SHA-256",
					"assetType": "algorithm",
				},
			},
			Metavars: map[string]entities.MetavarInfo{},
		},
	}

	asset := transformToCryptographicAsset(result, nil, "")

	if asset.MatchType != "semgrep" {
		t.Errorf("Expected match type 'semgrep', got '%s'", asset.MatchType)
	}

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

func TestTransformToCryptographicAsset_NoMetadata(t *testing.T) {
	t.Parallel()

	result := &entities.SemgrepResult{
		CheckID: "test.rule",
		Start:   entities.SemgrepLocation{Line: 1, Col: 1},
		Extra: entities.SemgrepExtra{
			Message:  "Test message",
			Severity: "error",
			Lines:    "test code",
			Metadata: entities.SemgrepMetadata{
				Crypto: nil,
			},
		},
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
