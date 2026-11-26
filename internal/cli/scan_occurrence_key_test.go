// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/javaruntime"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/output"
)

func resolvedReportForOutput(t testing.TB, report *entities.InterimReport) *oid.ResolvedReport {
	t.Helper()
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatalf("prepare report: %v", err)
	}
	return prepared.ReportClone()
}

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
		result := prepareReportOccurrenceKeys(nil, dir, report, []string{"java"}, javaRuntime, false, "", nil, nil)
		if result.CallGraph.JavaPlatformSignatures != nil {
			t.Fatal("report-only occurrence keys must not run Java type resolution")
		}
		key := report.Findings[0].CryptographicAssets[0].OccurrenceKey
		if key == "" {
			t.Fatal("report-only finding omitted occurrence_key")
		}

		outputPath := filepath.Join(t.TempDir(), "findings.json")
		if err := output.NewJSONWriter().WriteResolved(resolvedReportForOutput(t, report), outputPath); err != nil {
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

func TestPrepareReportOccurrenceKeys_DegradesOnSourceAnchorFailure(t *testing.T) {
	javaRuntime, err := javaruntime.NewConfig("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "missing/Crypto.java",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 1, EndLine: 1}},
	}}}

	result := prepareReportOccurrenceKeys(nil, filepath.Join(t.TempDir(), "missing"), report, []string{"java"}, javaRuntime, false, "", nil, nil)
	if result != nil || report.Findings[0].CryptographicAssets[0].OccurrenceKey != "" {
		t.Fatal("source-anchor failure must preserve report output without an occurrence_key")
	}
	if err := output.NewJSONWriter().WriteResolved(resolvedReportForOutput(t, report), filepath.Join(t.TempDir(), "findings.json")); err != nil {
		t.Fatalf("write report after source-anchor failure: %v", err)
	}
}

func TestPrepareReportOccurrenceKeys_AssignsKeyToTopLevelCall(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "crypto.py")
	if err := os.WriteFile(filePath, []byte("import hashlib\nhashlib.sha256(data)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	javaRuntime, err := javaruntime.NewConfig("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: filePath, Language: "python",
		CryptographicAssets: []entities.CryptographicAsset{{StartLine: 2, EndLine: 2, StartCol: 1, EndCol: 20}},
	}}}

	result := prepareReportOccurrenceKeys(nil, dir, report, []string{"python"}, javaRuntime, false, "", nil, nil)
	if result == nil || result.CallGraph == nil {
		t.Fatal("report-only enrichment must build source anchors")
	}
	if got := report.Findings[0].CryptographicAssets[0].OccurrenceKey; got == "" {
		t.Fatal("top-level report finding omitted occurrence_key")
	}
}

func TestPrepareReportOccurrenceKeys_EnrichesEveryReportedLanguage(t *testing.T) {
	dir := t.TempDir()
	javaPath := filepath.Join(dir, "Crypto.java")
	pythonPath := filepath.Join(dir, "crypto.py")
	for path, source := range map[string]string{
		javaPath: `package com.example;
class Crypto {
  void run() {
    Cipher.getInstance("AES");
  }
}

`,
		pythonPath: `def run():
    hashlib.sha256(data)
`,
	} {
		if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	javaRuntime, err := javaruntime.NewConfig("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{
		{FilePath: javaPath, Language: "java", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 4, EndLine: 4, StartCol: 5, EndCol: 30}}},
		{FilePath: pythonPath, Language: "python", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 2, EndLine: 2, StartCol: 5, EndCol: 25}}},
	}}

	result := prepareReportOccurrenceKeys(nil, dir, report, []string{"java", "python"}, javaRuntime, false, "", nil, nil)
	if result == nil || result.CallGraph == nil {
		t.Fatal("report-only enrichment must build source anchors")
	}
	outputPath := filepath.Join(t.TempDir(), "findings.json")
	if err := output.NewJSONWriter().WriteResolved(resolvedReportForOutput(t, report), outputPath); err != nil {
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
	for _, finding := range exported.Findings {
		if got := finding.CryptographicAssets[0].OccurrenceKey; got == "" {
			t.Fatalf("%s occurrence_key omitted", finding.Language)
		}
	}
}

func TestPrepareReportOccurrenceKeys_EnrichesMixedCAndCPPFiles(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "crypto.c")
	cppPath := filepath.Join(dir, "crypto.cpp")
	for path, source := range map[string]string{
		cPath: `void run(void) {
  EVP_sha256();
}
`,
		cppPath: `class Crypto {};
void run() {
  EVP_sha512();
}
`,
	} {
		if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	javaRuntime, err := javaruntime.NewConfig("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{
		{FilePath: cPath, Language: "c", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 2, EndLine: 2, StartCol: 3, EndCol: 15}}},
		{FilePath: cppPath, Language: "c", CryptographicAssets: []entities.CryptographicAsset{{StartLine: 3, EndLine: 3, StartCol: 3, EndCol: 15}}},
	}}

	result := prepareReportOccurrenceKeys(nil, dir, report, []string{"c"}, javaRuntime, false, "", nil, nil)
	if result == nil || len(result.OccurrenceAnchors) != 2 {
		t.Fatalf("occurrence anchors = %d, want both C and C++ declarations", len(result.OccurrenceAnchors))
	}
	for _, ecosystem := range []string{"c\x00", ecosystemCPP + "\x00"} {
		found := false
		for key := range result.OccurrenceAnchors {
			if strings.HasPrefix(key, ecosystem) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q-qualified occurrence anchor", strings.TrimSuffix(ecosystem, "\x00"))
		}
	}
	for _, finding := range report.Findings {
		if got := finding.CryptographicAssets[0].OccurrenceKey; got == "" {
			t.Fatalf("%s occurrence_key omitted", filepath.Base(finding.FilePath))
		}
	}
}

func TestOccurrenceKeyAnchorsReuseTheScanGraph(t *testing.T) {
	dir := t.TempDir()
	decl := &callgraph.FunctionDecl{}
	graphs := newGraphStore(dir, "")
	graphs.keep(dir, "go", &engine.DepScanResult{
		Ecosystem: "go",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{"example.com/app.Encrypt": decl}},
	})

	result := addReportOccurrenceKeyAnchors(graphs, dir, &entities.InterimReport{}, "go", javaruntime.Config{}, false, "", nil, nil)

	if result == nil || result.OccurrenceAnchors[occurrenceAnchorKey("go", "example.com/app.Encrypt")] != decl {
		t.Fatalf("anchors = %v, want the declarations of the graph the scan already built for the target", result)
	}
}

// A scan without --export-callgraph or --export-graph-fragment reaches the
// Rust foreign-receiver filter with no graph of its own: the anchors build
// supplies it, from the typed graph the cards scan kept or, when there is
// none, from a source-only build. The Rust parser types a receiver the crate
// declares in both, so both drop the consumer's own `own.sign(..)` and keep
// the crate's `key.sign(..)`, and taking the kept graph changes no finding.
func TestPrepareReportOccurrenceKeys_RustForeignReceiverWithoutExport(t *testing.T) {
	const src = `use fakesig::SigningKey;

pub struct ConsumerOwnType;

impl ConsumerOwnType {
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        msg.to_vec()
    }
}

pub fn own(msg: &[u8]) -> Vec<u8> {
    let own = ConsumerOwnType;
    own.sign(msg)
}

pub fn real(key: &SigningKey, msg: &[u8]) {
    let _sig = key.sign(msg);
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname = \"leakprobe\"\nversion = \"0.1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "lib.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	assetAt := func(needle string) entities.CryptographicAsset {
		for i, line := range strings.Split(src, "\n") {
			if col := strings.Index(line, needle); col >= 0 {
				return entities.CryptographicAsset{
					StartLine: i + 1, EndLine: i + 1, StartCol: col + 1, EndCol: col + 1 + len(needle),
					Rules: []entities.RuleInfo{{ID: "rust.fakesig.sign", Message: "detected", Severity: "INFO"}},
				}
			}
		}
		t.Fatalf("%q not in source", needle)
		return entities.CryptographicAsset{}
	}
	scan := func(t *testing.T, graphs *graphStore) []int {
		t.Helper()
		report := &entities.InterimReport{Findings: []entities.Finding{
			{FilePath: "src/lib.rs", Language: "rust", CryptographicAssets: []entities.CryptographicAsset{assetAt("own.sign(msg)")}},
			{FilePath: "src/lib.rs", Language: "rust", CryptographicAssets: []entities.CryptographicAsset{assetAt("key.sign(msg)")}},
		}}
		prepareReportOccurrenceKeys(graphs, dir, report, []string{"rust"}, javaruntime.Config{}, false, "", nil, nil)
		var lines []int
		for _, finding := range report.Findings {
			for _, asset := range finding.CryptographicAssets {
				lines = append(lines, asset.StartLine)
			}
		}
		return lines
	}

	t.Run("source-only anchors", func(t *testing.T) {
		if got := scan(t, newGraphStore(dir, "")); len(got) != 1 || got[0] != 17 {
			t.Fatalf("kept asset lines = %v, want [17]", got)
		}
	})
	t.Run("graph the cards scan kept", func(t *testing.T) {
		graphs := newGraphStore(dir, "")
		if _, err := buildStandaloneCallGraphResultForEcosystem(graphs, dir, &entities.InterimReport{}, "rust", javaruntime.Config{}, false, "", nil, true); err != nil {
			t.Fatal(err)
		}
		if _, ok := graphs.load(dir, "rust", nil); !ok {
			t.Fatal("the typed graph was not kept for the target")
		}
		if got := scan(t, graphs); len(got) != 1 || got[0] != 17 {
			t.Fatalf("kept asset lines = %v, want [17]", got)
		}
	})
}
