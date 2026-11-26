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
	writeJavaFindingFixture(t, dir, dir)
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
	writeJavaFindingFixture(t, dir, dir)
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
			writeCardsRule(t, dir, ruleID, matched)
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
				if ecosystem := details["ecosystem"]; ecosystem != "java" {
					t.Fatalf("dependencies:skipped ecosystem = %v, want java: %#v", ecosystem, event)
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

// The passes between the dependency phase and the written report used to run
// with no progress events, so on a large target the reported phases accounted
// for less than half of the scan's wall time. Each pass is reported as a child
// of the phase it runs inside: the scan, or the export that built its graph.
func TestScanProgressReportsEveryPassBeforeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

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
				writeJavaFindingFixture(t, dir, root)
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
				writeJavaFindingFixture(t, dir, root)
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

// A pass that fails closes as failed, and the scan after it, before the
// structured error payload.
func TestScanProgressFailedPassClosesScanAsFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	writeJavaFindingFixture(t, dir, dir)
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

// The progress tests detect one AES cipher with the cards detector.
const (
	progressRuleID  = "java.crypto.aes-cipher"
	progressMatched = `Cipher.getInstance("AES/GCM/NoPadding")`
)

// writeJavaFindingFixture writes a Java source under root whose one call the
// rule.yaml it writes in dir detects.
func writeJavaFindingFixture(t *testing.T, dir, root string) {
	t.Helper()
	source := filepath.Join(root, "src", "Use.java")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "import javax.crypto.Cipher;\nclass Use { void run() throws Exception { "+progressMatched+"; } }\n")
	writeCardsRule(t, dir, progressRuleID, progressMatched)
}

// writeCardsRule writes dir/rule.yaml: one rule the cards detector compiles,
// matching matched, a call on javax.crypto.
func writeCardsRule(t *testing.T, dir, ruleID, matched string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules:\n  - id: "+ruleID+"\n    message: aes cipher\n    severity: INFO\n    languages: [java]\n    pattern: javax.crypto."+matched+"\n    metadata:\n      crypto:\n        assetType: algorithm\n        algorithmFamily: AES\n        algorithmPrimitive: block-cipher\n")
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
