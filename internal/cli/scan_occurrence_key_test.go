// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
	"github.com/scanoss/crypto-finder/internal/output"
)

func TestPrepareReportOccurrenceKeys_UsesParserAnchorsAndExportsThem(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "Crypto.java")
	javaRuntime, err := javaruntime.NewConfig("auto", nil)
	if err != nil {
		t.Fatal(err)
	}

	prepare := func(source string, line int) string {
		t.Helper()
		if err := os.WriteFile(filePath, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		report := &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: filePath,
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: line, EndLine: line, StartCol: 9, EndCol: 35,
			}},
		}}}
		result, err := prepareReportOccurrenceKeys(dir, report, []string{"java"}, javaRuntime, false, "", nil)
		if err != nil {
			t.Fatalf("prepareReportOccurrenceKeys: %v", err)
		}
		if result.CallGraph.JavaPlatformSignatures != nil {
			t.Fatal("report-only occurrence keys must not run Java type resolution")
		}
		key := report.Findings[0].CryptographicAssets[0].OccurrenceKey
		if key == "" {
			t.Fatal("report-only finding omitted occurrence_key")
		}

		outputPath := filepath.Join(t.TempDir(), "findings.json")
		if err := output.NewJSONWriter().Write(report, outputPath); err != nil {
			t.Fatalf("write report: %v", err)
		}
		encoded, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		var exported entities.InterimReport
		if err := json.Unmarshal(encoded, &exported); err != nil {
			t.Fatal(err)
		}
		if got := exported.Findings[0].CryptographicAssets[0].OccurrenceKey; got != key {
			t.Fatalf("exported occurrence_key = %q, want %q", got, key)
		}
		return key
	}

	key := prepare(`package com.example;
class Crypto {
  void run() {
    Cipher.getInstance("AES");
  }
}
`, 4)
	if got := prepare(`package com.example;
class Crypto {

  void run() {
    // formatting-only change
    Cipher.getInstance("AES");
  }
}
`, 6); got != key {
		t.Fatalf("formatting-only key = %q, want %q", got, key)
	}
	if got := prepare(`package com.example;
class Crypto {
  void run() {
    if (enabled) {
      Cipher.getInstance("AES");
    }
  }
}
`, 5); got == key {
		t.Fatalf("structural-change key = %q, want a new key", got)
	}
}
