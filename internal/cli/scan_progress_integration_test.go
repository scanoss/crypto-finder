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
		"export:skipped",
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
				"export:skipped",
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
