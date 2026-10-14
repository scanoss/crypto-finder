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

package opengrep

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil { // #nosec G306 -- Test executable.
		t.Fatal(err)
	}
}

// TestEngineFingerprintKeysOnContentNotPath pins what the dependency
// findings cache keys the engine on in CLI mode: identical builds installed
// in different places (or reached through a symlink on PATH) fingerprint
// the same, a different build at the same path does not.
func TestEngineFingerprintKeysOnContentNotPath(t *testing.T) {
	fingerprint := func(path string) string {
		t.Helper()
		got, err := (&Scanner{executablePath: path, mode: scanner.OpengrepModeCLI}).EngineFingerprint(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	dir := t.TempDir()
	machineA := filepath.Join(dir, "a", "bin", "opengrep")
	machineB := filepath.Join(dir, "b", "opt", "opengrep")
	writeExecutable(t, machineA, "engine build 1")
	writeExecutable(t, machineB, "engine build 1")
	link := filepath.Join(dir, "home", ".local", "bin", "opengrep")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(machineA, link); err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("%x", sha256.Sum256([]byte("engine build 1")))
	for _, path := range []string{machineA, machineB, link} {
		if got := fingerprint(path); got != want {
			t.Fatalf("fingerprint(%s) = %s, want content digest %s", path, got, want)
		}
	}

	// Another build at the same path: the memo must not serve the old digest.
	writeExecutable(t, machineA, "engine build 2")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(machineA, later, later); err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(link); got == want {
		t.Fatal("a different build at the same path must change the fingerprint")
	}
}

// TestEngineFingerprintNamesTheEngineThatRuns pins that a core-mode
// fingerprint is the opengrep-core binary the scan will run, found as the
// scan finds it (CoreBinaryEnv, else one beside the CLI), and the CLI's
// digest whenever core mode will fall back to the CLI before scanning.
func TestEngineFingerprintNamesTheEngineThatRuns(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "bin", "opengrep")
	writeExecutable(t, cli, "cli build")
	cliDigest := fmt.Sprintf("%x", sha256.Sum256([]byte("cli build")))
	besideCLI := filepath.Join(dir, "bin", "opengrep-core")
	writeExecutable(t, besideCLI, "core beside cli")
	named := filepath.Join(dir, "elsewhere", "opengrep-core")
	writeExecutable(t, named, "core named by env")
	coreDigest := func(content string) string {
		return coreFingerprintPrefix + fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	}

	// Only the test's binaries report the CLI's version: a real
	// opengrep-core in this host's cache must not be picked up.
	original := coreCommandOutput
	t.Cleanup(func() { coreCommandOutput = original })
	coreCommandOutput = func(_ context.Context, path string) ([]byte, error) {
		if path == besideCLI || path == named {
			return []byte("opengrep-core version: 1.30.2\n"), nil
		}
		return nil, errors.New("not a test binary")
	}
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "xdg-cache"))
	coreBinaries.Range(func(key, _ any) bool { coreBinaries.Delete(key); return true })

	fingerprint := func(version string, mode scanner.OpengrepMode) string {
		t.Helper()
		got, err := (&Scanner{executablePath: cli, version: version, mode: mode}).EngineFingerprint(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Setenv(CoreBinaryEnv, "")
	if got := fingerprint("1.30.2", scanner.OpengrepModeCore); got != coreDigest("core beside cli") {
		t.Errorf("core mode runs the opengrep-core beside the CLI, fingerprint = %s, want %s", got, coreDigest("core beside cli"))
	}
	if got := fingerprint("1.30.2", scanner.OpengrepModeCLI); got != cliDigest {
		t.Errorf("CLI mode fingerprint = %s, want the CLI's digest %s", got, cliDigest)
	}
	if got := fingerprint("1.29.0", scanner.OpengrepModeCore); got != cliDigest {
		t.Errorf("an unverified version runs the CLI, fingerprint = %s, want %s", got, cliDigest)
	}

	t.Setenv(CoreBinaryEnv, named)
	if got := fingerprint("1.30.2", scanner.OpengrepModeCore); got != coreDigest("core named by env") {
		t.Errorf("%s names the core that runs, fingerprint = %s, want %s", CoreBinaryEnv, got, coreDigest("core named by env"))
	}
	if got := fingerprint("1.30.2", scanner.OpengrepModeCLI); got != cliDigest {
		t.Errorf("the CLI ignores %s, fingerprint = %s, want %s", CoreBinaryEnv, got, cliDigest)
	}

	t.Setenv(CoreBinaryEnv, filepath.Join(dir, "missing"))
	if got := fingerprint("1.30.2", scanner.OpengrepModeCore); got != cliDigest {
		t.Errorf("with no usable core the scan runs the CLI, fingerprint = %s, want %s", got, cliDigest)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t.Setenv(CoreBinaryEnv, filepath.Join(dir, "unprobed", "opengrep-core"))
	writeExecutable(t, filepath.Join(dir, "unprobed", "opengrep-core"), "x")
	coreCommandOutput = func(ctx context.Context, _ string) ([]byte, error) { return nil, ctx.Err() }
	if _, err := (&Scanner{executablePath: cli, version: "1.30.2", mode: scanner.OpengrepModeCore}).EngineFingerprint(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled probe must fail the fingerprint, got %v", err)
	}
}
