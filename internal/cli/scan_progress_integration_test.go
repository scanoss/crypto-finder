//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestScanProgressWritesJSONLToStderr(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), dir)
	cmd.Env = progressTestEnv(dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr.String())
	}

	var findings map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &findings); err != nil {
		t.Fatalf("findings output is not JSON: %q: %v", stdout.String(), err)
	}

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	want := []string{
		"scan:started",
		"detection:started",
		"rules:started",
		"rules:completed",
		"detection:completed",
		"dependencies:skipped",
		"occurrence_keys:started",
		"occurrence_keys:completed",
		"oid_projection:started",
		"oid_projection:completed",
		"export:skipped",
		"output:started",
		"output:completed",
		"scan:completed",
	}
	if len(lines) != len(want) {
		t.Fatalf("progress event count = %d, want %d:\n%s", len(lines), len(want), stderr.String())
	}
	for i, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("stderr contains non-JSON progress output %q: %v", line, err)
		}
		if event["event"] != "scan_progress" {
			t.Fatalf("unexpected stderr event: %#v", event)
		}
		if got := event["phase"].(string) + ":" + event["status"].(string); got != want[i] {
			t.Fatalf("event %d = %q, want %q", i, got, want[i])
		}
		if event["status"] != "started" && event["status"] != "skipped" {
			if _, ok := event["duration_ms"].(float64); !ok {
				t.Fatalf("terminal event lacks duration_ms: %#v", event)
			}
		}
	}
}

func TestScanProgressRejectsExplicitTextErrorsAsJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}

	binary := buildProgressCryptoFinder(t)
	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "text", "scan", "--progress", "--no-remote-rules", "--rules", "rule.yaml", t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("scan succeeded with incompatible --error-format=text")
	}

	var payload map[string]any
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("expected structured JSON failure, got %q: %v", stderr.String(), err)
	}
	if payload["code"] != "invalid_arguments" {
		t.Fatalf("failure payload = %#v", payload)
	}
}

func TestScanProgressPreflightFailureEmitsOnlyStructuredError(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}

	binary := buildProgressCryptoFinder(t)
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--max-stale-age", "not-a-duration", t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("scan succeeded with invalid --max-stale-age")
	}

	var payload map[string]any
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("expected one structured JSON error without progress events, got %q: %v", stderr.String(), err)
	}
	if payload["code"] != "invalid_arguments" {
		t.Fatalf("failure payload = %#v", payload)
	}
}

func TestScanProgressJavaRuntimeFailureDoesNotStartCallgraph(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "Main.java"), "class Main {}\n")
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--java-jdk-home", "invalid", "--export-callgraph", filepath.Join(dir, "callgraph.json"), dir)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("scan succeeded with an invalid Java runtime configuration")
	}

	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("stderr contains non-JSON output %q: %v", line, err)
		}
		if event["event"] == "scan_progress" && event["phase"] == "callgraph" {
			t.Fatalf("Java runtime failure emitted callgraph progress: %s", stderr.String())
		}
	}
}

// A Java tree with no root pom.xml or Gradle build file is the repro for
// scanoss/crypto-finder#391: detection succeeds, then the dependency phase
// aborted the whole scan with java_build_tool_unknown and wrote no output.
func TestScanProgressAbsentDependencyManifestSkipsAndKeepsOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	const ruleID = "java.crypto.aes-cipher"
	const matched = `Cipher.getInstance("AES/GCM/NoPadding")`
	const sourceRel = "services/payments/src/Use.java"
	binary := buildProgressCryptoFinder(t)

	cases := []struct {
		name string
		// target is the path passed on the command line, relative to the
		// repository root the case builds.
		target string
		// pom writes a Maven manifest into the source file's own directory,
		// which is the shape that makes the containing directory look
		// resolvable while the file path the resolver receives is not.
		pom bool
		// wantPath is the finding's reported file_path, asserted only for the
		// directory target. A file target reports a path unrelated to this
		// skip, so that case asserts the finding and its rule alone.
		wantPath string
	}{
		{name: "directory target with no manifest anywhere", target: ".", wantPath: sourceRel},
		{name: "file target beside a manifest it cannot be resolved from", target: sourceRel, pom: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "repo")
			source := filepath.Join(root, filepath.FromSlash(sourceRel))
			if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, source, "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+matched+"; } }\n")
			if tc.pom {
				writeFile(t, filepath.Join(filepath.Dir(source), "pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>x</artifactId><version>1.0</version></project>\n")
			}
			writeFile(t, filepath.Join(dir, "rule.yaml"), "rules:\n  - id: "+ruleID+"\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: $X\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n")
			results, err := json.Marshal(map[string]any{
				"errors": []any{},
				"results": []map[string]any{{
					"check_id": ruleID,
					"path":     source,
					"start":    map[string]int{"line": 2, "col": 43},
					"end":      map[string]int{"line": 2, "col": 43 + len(matched)},
					"extra": map[string]any{
						"message": "aes cipher", "severity": "INFO", "lines": matched,
						"metadata": map[string]any{"crypto": map[string]any{"assetType": "algorithm", "algorithmFamily": "AES", "algorithmPrimitive": "block-cipher"}},
					},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "opengrep.json"), string(results))
			writeProgressOpenGrepWithResults(t, filepath.Join(dir, "opengrep"), filepath.Join(dir, "opengrep.json"))
			output := filepath.Join(dir, "findings.json")
			target := filepath.Join(root, filepath.FromSlash(tc.target))

			cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--scan-dependencies", "--output", output, target)
			cmd.Env = progressTestEnv(dir)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("scan with --scan-dependencies and no resolvable manifest exited non-zero: %v\nstderr:\n%s", err, stderr.String())
			}

			// Only scan_progress events are read: a finding makes the callgraph
			// inference print a plain-text stats line to stderr through the stdlib
			// logger, which is not part of the progress stream under test here.
			var events []map[string]any
			for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err != nil || event["event"] != "scan_progress" {
					continue
				}
				events = append(events, event)
			}
			want := []string{
				"scan:started",
				"detection:started",
				"rules:started",
				"rules:completed",
				"detection:completed",
				"dependencies:started",
				"dependencies:skipped",
				"occurrence_keys:started",
				"occurrence_keys:completed",
				"oid_projection:started",
				"oid_projection:completed",
				"export:skipped",
				"output:started",
				"output:completed",
				"scan:completed",
			}
			if len(events) != len(want) {
				t.Fatalf("progress event count = %d, want %d:\n%s", len(events), len(want), stderr.String())
			}
			for i, event := range events {
				got := event["phase"].(string) + ":" + event["status"].(string)
				if got != want[i] {
					t.Fatalf("event %d = %q, want %q", i, got, want[i])
				}
				if got != "dependencies:skipped" {
					continue
				}
				details, _ := event["details"].(map[string]any)
				if reason := details["reason"]; reason != "manifest_absent" {
					t.Fatalf("dependencies:skipped reason = %v, want manifest_absent: %#v", reason, event)
				}
			}

			raw, err := os.ReadFile(output)
			if err != nil {
				t.Fatalf("interim output was not written: %v", err)
			}
			var report entities.InterimReport
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("interim output is not JSON: %v\n%s", err, raw)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("findings = %d, want the 1 finding detection produced:\n%s", len(report.Findings), raw)
			}
			finding := report.Findings[0]
			if tc.wantPath != "" && !strings.HasSuffix(filepath.ToSlash(finding.FilePath), tc.wantPath) {
				t.Fatalf("finding file_path = %q, want suffix %q", finding.FilePath, tc.wantPath)
			}
			if len(finding.CryptographicAssets) == 0 || len(finding.CryptographicAssets[0].Rules) == 0 || finding.CryptographicAssets[0].Rules[0].ID != ruleID {
				t.Fatalf("finding does not carry rule %s:\n%s", ruleID, raw)
			}
		})
	}
}

// The #533 discovery of module roots below a manifest-less scan root composes
// with the #391 manifest_absent skip over one tree, where the resolver cannot
// read the scan root yet a module root below it is resolvable. The skip must
// lose that composition, or the downward discovery never runs.
func TestScanProgressModuleRootBelowScanRootRunsDependencyPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	const ruleID = "java.crypto.aes-cipher"
	const matched = `Cipher.getInstance("AES/GCM/NoPadding")`
	const moduleRel = "services/ledger"
	const sourceRel = moduleRel + "/src/Use.java"

	dir := t.TempDir()
	root := filepath.Join(dir, "repo")
	source := filepath.Join(root, filepath.FromSlash(sourceRel))
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+matched+"; } }\n")
	// The only manifest sits below the scan root, and it declares neither
	// <dependencies> nor <modules>, so MavenResolver returns on that fast path
	// without invoking mvn. This case needs no Maven, no JDK and no network.
	writeFile(t, filepath.Join(root, filepath.FromSlash(moduleRel), "pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>ledger</artifactId><version>1.0</version></project>\n")
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules:\n  - id: "+ruleID+"\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: $X\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n")
	results, err := json.Marshal(map[string]any{
		"errors": []any{},
		"results": []map[string]any{{
			"check_id": ruleID,
			"path":     source,
			"start":    map[string]int{"line": 2, "col": 43},
			"end":      map[string]int{"line": 2, "col": 43 + len(matched)},
			"extra": map[string]any{
				"message": "aes cipher", "severity": "INFO", "lines": matched,
				"metadata": map[string]any{"crypto": map[string]any{"assetType": "algorithm", "algorithmFamily": "AES", "algorithmPrimitive": "block-cipher"}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "opengrep.json"), string(results))
	writeProgressOpenGrepWithResults(t, filepath.Join(dir, "opengrep"), filepath.Join(dir, "opengrep.json"))
	output := filepath.Join(dir, "findings.json")
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--scan-dependencies", "--output", output, root)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan with --scan-dependencies and a module root below the scan root exited non-zero: %v\nstderr:\n%s", err, stderr.String())
	}

	// Only scan_progress events are read: a finding makes the callgraph
	// inference print a plain-text stats line to stderr through the stdlib
	// logger, which is not part of the progress stream under test here.
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil || event["event"] != "scan_progress" {
			continue
		}
		events = append(events, event)
	}
	for _, event := range events {
		if event["phase"] != "dependencies" || event["status"] != "skipped" {
			continue
		}
		details, _ := event["details"].(map[string]any)
		if details["reason"] == "manifest_absent" {
			t.Fatalf("manifest_absent skipped the dependency phase although %s below the scan root is a resolvable module root: %#v", moduleRel, event)
		}
	}
	want := []string{
		"scan:started",
		"detection:started",
		"rules:started",
		"rules:completed",
		"detection:completed",
		"dependencies:started",
		"dependencies:completed",
		"occurrence_keys:started",
		"occurrence_keys:completed",
		"oid_projection:started",
		"oid_projection:completed",
		"export:skipped",
		"output:started",
		"output:completed",
		"scan:completed",
	}
	if len(events) != len(want) {
		t.Fatalf("progress event count = %d, want %d:\n%s", len(events), len(want), stderr.String())
	}
	for i, event := range events {
		if got := event["phase"].(string) + ":" + event["status"].(string); got != want[i] {
			t.Fatalf("event %d = %q, want %q", i, got, want[i])
		}
	}

	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("interim output was not written: %v", err)
	}
	var report entities.InterimReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("interim output is not JSON: %v\n%s", err, raw)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want the 1 finding detection produced:\n%s", len(report.Findings), raw)
	}
	finding := report.Findings[0]
	if !strings.HasSuffix(filepath.ToSlash(finding.FilePath), sourceRel) {
		t.Fatalf("finding file_path = %q, want suffix %q", finding.FilePath, sourceRel)
	}
	if len(finding.CryptographicAssets) == 0 || len(finding.CryptographicAssets[0].Rules) == 0 || finding.CryptographicAssets[0].Rules[0].ID != ruleID {
		t.Fatalf("finding does not carry rule %s:\n%s", ruleID, raw)
	}
}

// The passes between the dependency phase and the written report used to run
// with no progress events, so on a large target the reported phases accounted
// for less than half of the scan's wall time. Each pass is reported as a child
// of the phase it runs inside: the scan, or the export that built its graph.
func TestScanProgressReportsEveryPassBeforeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	const ruleID = "java.crypto.aes-cipher"
	const matched = `Cipher.getInstance("AES/GCM/NoPadding")`
	binary := buildProgressCryptoFinder(t)

	cases := []struct {
		name string
		// fixture writes the target below root and returns the extra scan flags.
		fixture func(t *testing.T, dir, root string) []string
		want    []string
	}{
		{
			name: "findings report only",
			fixture: func(t *testing.T, dir, root string) []string {
				writeJavaFindingFixture(t, dir, root, ruleID, matched)
				return nil
			},
			want: []string{
				"/scan:started",
				"scan/detection:started",
				"scan/rules:started",
				"scan/rules:completed",
				"scan/detection:completed",
				"scan/dependencies:skipped",
				"scan/occurrence_keys:started",
				"scan/occurrence_keys:completed",
				"scan/oid_projection:started",
				"scan/oid_projection:completed",
				"scan/export:skipped",
				"scan/output:started",
				"scan/output:completed",
				"/scan:completed",
			},
		},
		{
			name: "callgraph export builds its own graph",
			fixture: func(t *testing.T, dir, root string) []string {
				writeJavaFindingFixture(t, dir, root, ruleID, matched)
				return []string{"--export-callgraph", filepath.Join(dir, "callgraph.json")}
			},
			want: []string{
				"/scan:started",
				"scan/detection:started",
				"scan/rules:started",
				"scan/rules:completed",
				"scan/detection:completed",
				"scan/dependencies:skipped",
				"scan/export:started",
				"export/callgraph:started",
				"export/callgraph:completed",
				"export/entry_points:started",
				"export/entry_points:completed",
				"export/conditioned_findings:started",
				"export/conditioned_findings:completed",
				"export/finding_ids:started",
				"export/finding_ids:completed",
				"export/occurrence_keys:started",
				"export/occurrence_keys:completed",
				"export/oid_projection:started",
				"export/oid_projection:completed",
				"scan/export:completed",
				"scan/output:started",
				"scan/output:completed",
				"/scan:completed",
			},
		},
		{
			name: "dependency scan builds the graph",
			fixture: func(t *testing.T, dir, root string) []string {
				writeNodeDependencyFixture(t, dir, root)
				return []string{"--scan-dependencies"}
			},
			// The passes after the dependency phase add assets, so their
			// finding ids are assigned even when no export asks for them.
			want: []string{
				"/scan:started",
				"scan/detection:started",
				"scan/rules:started",
				"scan/rules:completed",
				"scan/detection:completed",
				"scan/dependencies:started",
				"dependencies/callgraph:started",
				"dependencies/callgraph:completed",
				"scan/dependencies:completed",
				"scan/entry_points:started",
				"scan/entry_points:completed",
				"scan/conditioned_findings:started",
				"scan/conditioned_findings:completed",
				"scan/finding_ids:started",
				"scan/finding_ids:completed",
				"scan/occurrence_keys:started",
				"scan/occurrence_keys:completed",
				"scan/oid_projection:started",
				"scan/oid_projection:completed",
				"scan/export:skipped",
				"scan/output:started",
				"scan/output:completed",
				"/scan:completed",
			},
		},
		{
			name: "dependency scan graph feeds a requested export",
			fixture: func(t *testing.T, dir, root string) []string {
				writeNodeDependencyFixture(t, dir, root)
				return []string{"--scan-dependencies", "--export-callgraph", filepath.Join(dir, "callgraph.json")}
			},
			want: []string{
				"/scan:started",
				"scan/detection:started",
				"scan/rules:started",
				"scan/rules:completed",
				"scan/detection:completed",
				"scan/dependencies:started",
				"dependencies/callgraph:started",
				"dependencies/callgraph:completed",
				"scan/dependencies:completed",
				"scan/entry_points:started",
				"scan/entry_points:completed",
				"scan/conditioned_findings:started",
				"scan/conditioned_findings:completed",
				"scan/finding_ids:started",
				"scan/finding_ids:completed",
				"scan/occurrence_keys:started",
				"scan/occurrence_keys:completed",
				"scan/oid_projection:started",
				"scan/oid_projection:completed",
				"scan/export:started",
				"scan/export:completed",
				"scan/output:started",
				"scan/output:completed",
				"/scan:completed",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "repo")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			flags := tc.fixture(t, dir, root)
			output := filepath.Join(dir, "findings.json")
			args := append([]string{"scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--output", output}, flags...)
			cmd := exec.CommandContext(t.Context(), binary, append(args, root)...)
			cmd.Env = progressTestEnv(dir)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("scan: %v\nstderr:\n%s", err, stderr.String())
			}

			got := progressTransitions(t, stderr.String())
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("progress transitions:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
			if _, err := os.Stat(output); err != nil {
				t.Fatalf("findings report was not written: %v", err)
			}
		})
	}
}

// A rule that times out leaves its file's findings out. The scan still
// succeeds, and the progress stream counts the cut-short files of the
// primary scan and the dependencies whose scan was cut short.
func TestScanProgressCountsScansCutShortByTimeouts(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	root := filepath.Join(dir, "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeNodeDependencyFixture(t, dir, root)
	timedOut := filepath.Join(root, "node_modules", "dep", "index.js")
	results, err := json.Marshal(map[string]any{
		"results": []any{},
		"errors": []map[string]any{{
			"code": 2, "level": "warn", "type": "Timeout", "rule_id": "fixture",
			"message": "Timeout when running fixture on " + timedOut + ":\n ", "path": timedOut,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "opengrep.json"), string(results))
	writeProgressOpenGrepWithResults(t, filepath.Join(dir, "opengrep"), filepath.Join(dir, "opengrep.json"))
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--scan-dependencies", "--output", filepath.Join(dir, "findings.json"), root)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("a scan with timed-out files exited non-zero: %v\nstderr:\n%s", err, stderr.String())
	}

	progressTransitions(t, stderr.String())
	details := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil || event["event"] != "scan_progress" {
			continue
		}
		if counts, ok := event["details"].(map[string]any); ok {
			details[event["phase"].(string)] = counts
		}
	}
	if got := details["detection"]["files_incomplete"]; got != float64(1) {
		t.Errorf("detection files_incomplete = %v, want 1: %v", got, details["detection"])
	}
	if got := details["dependencies"]["deps_incomplete"]; got != float64(1) {
		t.Errorf("dependencies deps_incomplete = %v, want 1: %v", got, details["dependencies"])
	}
}

// A pass that fails closes as failed, and the scan after it, before the
// structured error payload.
func TestScanProgressFailedPassClosesScanAsFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	binary := buildProgressCryptoFinder(t)

	// An existing directory cannot be replaced by the findings report.
	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), "--output", t.TempDir(), dir)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("scan succeeded although its report could not be written")
	}

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	transitions := progressTransitions(t, strings.Join(lines[:len(lines)-1], "\n"))
	tail := strings.Join(transitions[len(transitions)-3:], "\n")
	if want := "scan/output:started\nscan/output:failed\n/scan:failed"; tail != want {
		t.Fatalf("last progress transitions:\n%s\nwant:\n%s", tail, want)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &payload); err != nil {
		t.Fatalf("last stderr line is not the structured error: %q: %v", lines[len(lines)-1], err)
	}
	if payload["code"] != "output_write_failed" {
		t.Fatalf("failure payload = %#v, want output_write_failed", payload)
	}
}

// progressTransitions reads the scan_progress events on stderr, checks each
// against the published schema and its terminal duration, and returns them as
// "parent/phase:status".
func progressTransitions(t *testing.T, stderr string) []string {
	t.Helper()
	schema, err := filepath.Abs(filepath.Join("..", "..", "schemas", "scan-progress-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	transitions := make([]string, 0, len(lines))
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil || event["event"] != "scan_progress" {
			continue
		}
		result, err := gojsonschema.Validate(gojsonschema.NewReferenceLoader("file://"+schema), gojsonschema.NewStringLoader(line))
		if err != nil {
			t.Fatalf("validate progress event: %v", err)
		}
		if !result.Valid() {
			t.Fatalf("progress event %s violates the published schema: %v", line, result.Errors())
		}
		status, _ := event["status"].(string)
		terminal := status == "completed" || status == "failed" || status == "canceled"
		if _, timed := event["duration_ms"].(float64); terminal && !timed {
			t.Fatalf("terminal progress event lacks duration_ms: %s", line)
		}
		parent, _ := event["parent_phase"].(string)
		transitions = append(transitions, parent+"/"+event["phase"].(string)+":"+status)
	}
	return transitions
}

// writeJavaFindingFixture writes one Java source under root with an AES finding
// that the stub scanner replays, and the rule that names it.
func writeJavaFindingFixture(t *testing.T, dir, root, ruleID, matched string) {
	t.Helper()
	source := filepath.Join(root, "src", "Use.java")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+matched+"; } }\n")
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules:\n  - id: "+ruleID+"\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: $X\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n")
	results, err := json.Marshal(map[string]any{
		"errors": []any{},
		"results": []map[string]any{{
			"check_id": ruleID,
			"path":     source,
			"start":    map[string]int{"line": 2, "col": 43},
			"end":      map[string]int{"line": 2, "col": 43 + len(matched)},
			"extra": map[string]any{
				"message": "aes cipher", "severity": "INFO", "lines": matched,
				"metadata": map[string]any{"crypto": map[string]any{"assetType": "algorithm", "algorithmFamily": "AES", "algorithmPrimitive": "block-cipher"}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "opengrep.json"), string(results))
	writeProgressOpenGrepWithResults(t, filepath.Join(dir, "opengrep"), filepath.Join(dir, "opengrep.json"))
}

// writeNodeDependencyFixture writes a Node package whose one dependency is
// already installed, so the dependency phase resolves it and builds a graph
// without a network or an npm install.
func writeNodeDependencyFixture(t *testing.T, dir, root string) {
	t.Helper()
	dep := filepath.Join(root, "node_modules", "dep")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}},"node_modules/dep":{"version":"1.0.0"}}}`)
	writeFile(t, filepath.Join(root, "index.js"), "const dep = require('dep');\ndep.run();\n")
	writeFile(t, filepath.Join(dep, "package.json"), `{"name":"dep","version":"1.0.0","main":"index.js"}`)
	writeFile(t, filepath.Join(dep, "index.js"), "exports.run = function run() { return 1; };\n")
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
}

func writeProgressOpenGrep(t *testing.T, path string) {
	t.Helper()
	writeProgressOpenGrepScript(t, path, `printf '%s\n' '{"results":[],"errors":[]}'`)
}

// writeProgressOpenGrepWithResults stubs opengrep with a script that replays
// the JSON at resultsPath for every scan invocation.
func writeProgressOpenGrepWithResults(t *testing.T, path, resultsPath string) {
	t.Helper()
	writeProgressOpenGrepScript(t, path, `cat '`+resultsPath+`'`)
}

func writeProgressOpenGrepScript(t *testing.T, path, scanCommand string) {
	t.Helper()
	writeFile(t, path, `#!/bin/sh
case "$1:$2" in
  --version:*) echo 1.12.1; exit 0 ;;
  scan:--help|--help:*) exit 0 ;;
esac
`+scanCommand+`
`)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func progressTestEnv(dir string) []string {
	env := os.Environ()
	for i, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + strings.TrimPrefix(entry, "PATH=")
		}
	}
	return append(env, "HOME="+dir)
}

func buildProgressCryptoFinder(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "crypto-finder")
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", binary, "./cmd/crypto-finder")
	cmd.Dir = filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build crypto-finder: %v\n%s", err, output)
	}
	return binary
}
