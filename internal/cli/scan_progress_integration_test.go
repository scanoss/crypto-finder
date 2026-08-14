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

func writeProgressOpenGrep(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, `#!/bin/sh
case "$1:$2" in
  --version:*) echo 1.12.1; exit 0 ;;
  scan:--help|--help:*) exit 0 ;;
esac
printf '%s\n' '{"results":[],"errors":[]}'
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
