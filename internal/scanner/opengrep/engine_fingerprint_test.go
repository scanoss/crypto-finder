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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

// TestEngineFingerprintKeysOnContentNotPath pins what the dependency
// findings cache keys the engine on: identical builds installed in
// different places (or reached through a symlink on PATH) fingerprint the
// same, a different build at the same path does not, and core mode adds
// the opengrep-core binary CoreBinaryEnv names.
func TestEngineFingerprintKeysOnContentNotPath(t *testing.T) {
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil { // #nosec G306 -- Test executable.
			t.Fatal(err)
		}
	}
	fingerprint := func(path string, mode scanner.OpengrepMode) string {
		t.Helper()
		got, err := (&Scanner{executablePath: path, mode: mode}).EngineFingerprint()
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	dir := t.TempDir()
	machineA := filepath.Join(dir, "a", "bin", "opengrep")
	machineB := filepath.Join(dir, "b", "opt", "opengrep")
	write(machineA, "engine build 1")
	write(machineB, "engine build 1")
	link := filepath.Join(dir, "home", ".local", "bin", "opengrep")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(machineA, link); err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("%x", sha256.Sum256([]byte("engine build 1")))
	for _, path := range []string{machineA, machineB, link} {
		if got := fingerprint(path, scanner.OpengrepModeCLI); got != want {
			t.Fatalf("fingerprint(%s) = %s, want content digest %s", path, got, want)
		}
	}

	// Another build at the same path: the memo must not serve the old digest.
	write(machineA, "engine build 2")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(machineA, later, later); err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(link, scanner.OpengrepModeCLI); got == want {
		t.Fatal("a different build at the same path must change the fingerprint")
	}

	core := filepath.Join(dir, "core", "opengrep-core")
	write(core, "core build")
	t.Setenv(CoreBinaryEnv, core)
	if got := fingerprint(machineB, scanner.OpengrepModeCLI); got != want {
		t.Fatalf("the CLI ignores %s, so it must not change the fingerprint: %s", CoreBinaryEnv, got)
	}
	coreWant := want + "+core:" + fmt.Sprintf("%x", sha256.Sum256([]byte("core build")))
	if got := fingerprint(machineB, scanner.OpengrepModeCore); got != coreWant {
		t.Fatalf("core mode fingerprint = %s, want %s", got, coreWant)
	}
	t.Setenv(CoreBinaryEnv, filepath.Join(dir, "missing"))
	if _, err := (&Scanner{executablePath: machineB, mode: scanner.OpengrepModeCore}).EngineFingerprint(); err == nil {
		t.Fatal("an unreadable core binary must fail the fingerprint, which disables caching")
	}
}
