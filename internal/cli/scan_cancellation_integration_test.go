//go:build !windows

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/failure"
)

func TestScanCancellationTerminatesScannerProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	binary := filepath.Join(t.TempDir(), "crypto-finder")
	build := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", binary, "../../cmd/crypto-finder")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build crypto-finder: %v\n%s", err, output)
	}

	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			runCancelledScan(t, binary, signal)
		})
	}
}

func TestScanCancellationTerminatesScannerInitializationProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI and external scanner process")
	}

	binary := filepath.Join(t.TempDir(), "crypto-finder")
	build := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", binary, "../../cmd/crypto-finder")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build crypto-finder: %v\n%s", err, output)
	}

	dir := t.TempDir()
	childPIDFile := filepath.Join(dir, "child.pid")
	writeFakeOpenGrepInitializationProbe(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")

	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "scan", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), dir)
	cmd.Env = scanCancellationEnv(dir, childPIDFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start scan: %v", err)
	}

	childPID := waitForChildPID(t, childPIDFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("canceled scan exited successfully")
	}

	var payload failure.Payload
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("decode cancellation error %q: %v", stderr.String(), err)
	}
	if payload.Code != failure.CodeScannerCancelled || payload.Stage != failure.StageScan {
		t.Fatalf("cancellation payload = %#v, want scanner_canceled at scan stage", payload)
	}
	waitForProcessExit(t, childPID)
}

func runCancelledScan(t *testing.T, binary string, signal syscall.Signal) {
	t.Helper()

	dir := t.TempDir()
	childPIDFile := filepath.Join(dir, "child.pid")
	writeFakeOpenGrep(t, filepath.Join(dir, "opengrep"))
	writeFile(t, filepath.Join(dir, "rule.yaml"), "rules: []\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")

	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "scan", "--no-remote-rules", "--rules", filepath.Join(dir, "rule.yaml"), dir)
	cmd.Env = scanCancellationEnv(dir, childPIDFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start scan: %v", err)
	}

	childPID := waitForChildPID(t, childPIDFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	if err := cmd.Process.Signal(signal); err != nil {
		t.Fatalf("send %s: %v", signal, err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("canceled scan exited successfully")
	}

	var payload failure.Payload
	if err := json.Unmarshal(stderr.Bytes(), &payload); err != nil {
		t.Fatalf("decode cancellation error %q: %v", stderr.String(), err)
	}
	if payload.Code != failure.CodeScannerCancelled || payload.Stage != failure.StageScan {
		t.Fatalf("cancellation payload = %#v, want scanner_canceled at scan stage", payload)
	}

	waitForProcessExit(t, childPID)
}

func scanCancellationEnv(dir, childPIDFile string) []string {
	env := os.Environ()
	for i, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + strings.TrimPrefix(entry, "PATH=")
		}
	}
	return append(env, "CHILD_PID_FILE="+childPIDFile, "HOME="+dir)
}

func writeFakeOpenGrep(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, `#!/bin/sh
case "$1:$2" in
  --version:*) echo 1.12.1; exit 0 ;;
  scan:--help|--help:*) exit 0 ;;
esac
(
  trap '' INT TERM
  while :; do sleep 1; done
) &
echo $! > "$CHILD_PID_FILE"
wait
`)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("make fake opengrep executable: %v", err)
	}
}

func writeFakeOpenGrepInitializationProbe(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, `#!/bin/sh
case "$1:$2" in
  --version:*)
    (
      trap '' INT TERM
      while :; do sleep 1; done
    ) &
    echo $! > "$CHILD_PID_FILE"
    wait
    ;;
  scan:--help|--help:*) exit 0 ;;
esac
`)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("make fake opengrep executable: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func waitForChildPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(contents)))
			if parseErr != nil {
				t.Fatalf("parse child pid %q: %v", contents, parseErr)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read child pid: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scanner did not start its child process")
	return 0
}

func waitForProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		terminated, currentState, err := processTerminated(t.Context(), pid)
		if err != nil {
			t.Fatalf("inspect scanner child process %d: %v", pid, err)
		}
		if terminated {
			return
		}
		state = currentState
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scanner child process %d remained alive after cancellation (state %q)", pid, state)
}

func processTerminated(ctx context.Context, pid int) (bool, string, error) {
	output, err := exec.CommandContext(ctx, "ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return true, "", nil
		}
		return false, "", fmt.Errorf("run ps: %w", err)
	}

	state := strings.TrimSpace(string(output))
	return strings.HasPrefix(state, "Z"), state, nil
}
