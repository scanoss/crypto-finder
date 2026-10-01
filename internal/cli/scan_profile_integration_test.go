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
	"strings"
	"testing"
)

func TestScanProfileFlagsWritePprofProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	dir := t.TempDir()
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	cpuProfile := filepath.Join(dir, "cpu.pprof")
	memProfile := filepath.Join(dir, "mem.pprof")
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"),
		"--cpuprofile", cpuProfile, "--memprofile", memProfile, "--output", filepath.Join(dir, "findings.json"), dir)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr.String())
	}

	// pprof -raw prints the sample types it decoded, which tells a CPU profile
	// from a heap profile.
	for path, sampleType := range map[string]string{cpuProfile: "cpu/nanoseconds", memProfile: "inuse_space/bytes"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("profile %s was not written: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("profile %s is empty", path)
		}
		raw, err := exec.CommandContext(t.Context(), "go", "tool", "pprof", "-raw", path).CombinedOutput()
		if err != nil {
			t.Fatalf("go tool pprof cannot read %s: %v\n%s", path, err, raw)
		}
		if !strings.Contains(string(raw), sampleType) {
			t.Fatalf("profile %s has no %s samples:\n%s", path, sampleType, raw)
		}
	}

	help, err := exec.CommandContext(t.Context(), binary, "scan", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("scan --help: %v\n%s", err, help)
	}
	if strings.Contains(string(help), "--cpuprofile") || strings.Contains(string(help), "--memprofile") {
		t.Fatalf("scan --help lists the diagnostic profile flags:\n%s", help)
	}
}

// A heap profile that cannot be written fails the scan, and the progress stream
// closes the scan as failed before the structured error, as for any failure.
func TestScanProfileWriteFailureClosesScanAsFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("needs /dev/full to make the heap profile write fail")
	}

	dir := t.TempDir()
	writeProgressOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	binary := buildProgressCryptoFinder(t)

	cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"),
		"--memprofile", "/dev/full", "--output", filepath.Join(dir, "findings.json"), dir)
	cmd.Env = progressTestEnv(dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("scan succeeded although its heap profile could not be written")
	}

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	transitions := progressTransitions(t, strings.Join(lines[:len(lines)-1], "\n"))
	if last := transitions[len(transitions)-1]; last != "/scan:failed" {
		t.Fatalf("last progress transition = %q, want /scan:failed:\n%s", last, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &payload); err != nil {
		t.Fatalf("last stderr line is not the structured error: %q: %v", lines[len(lines)-1], err)
	}
	if payload["code"] != "output_write_failed" {
		t.Fatalf("failure payload = %#v, want output_write_failed", payload)
	}
}

// A profile path that cannot be created fails before the scan starts, so a
// long scan never runs to its end only to lose the profile it was asked for.
func TestScanProfileUnwritablePathFailsBeforeScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	binary := buildProgressCryptoFinder(t)

	for _, flag := range []string{"--cpuprofile", "--memprofile"} {
		t.Run(flag, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, "scan", "--progress", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"),
				flag, filepath.Join(dir, "missing", "profile.pprof"), dir)
			cmd.Env = progressTestEnv(dir)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				t.Fatalf("scan succeeded with an unwritable %s path", flag)
			}

			var payload map[string]any
			if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
				t.Fatalf("expected one structured JSON error without progress events, got %q: %v", stderr.String(), err)
			}
			if payload["code"] != "output_write_failed" || payload["stage"] != "output" {
				t.Fatalf("failure payload = %#v, want output_write_failed at stage output", payload)
			}
		})
	}
}
