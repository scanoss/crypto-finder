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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package opengrep_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

// Each factory stands for one crypto-finder process; the probe cache
// directory is what carries probe results between them.
func TestProbeCacheSkipsProbesAcrossProcesses(t *testing.T) {
	dir, exe := discoveryFixture(t)
	cacheDir := filepath.Join(t.TempDir(), "opengrep-probes")
	config := scanner.Config{ExecutablePath: exe}
	for range 3 {
		adapter := initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config)
		discoveryScan(t, adapter, dir)
		if adapter.GetInfo().Version != "1.29.0" {
			t.Fatal(adapter.GetInfo())
		}
	}
	if got := discoveryCounts(t, dir); got != "version=1 help=1 scan=3" {
		t.Fatalf("want one probe of each kind for three processes, got %s", got)
	}
	assertProbeEntries(t, cacheDir, 2)
	// Without a cache directory every process probes, as before.
	discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(), config), dir)
	if got := discoveryCounts(t, dir); got != "version=2 help=2 scan=4" {
		t.Fatal(got)
	}
}

func TestProbeCacheNeverReusesAnotherBinary(t *testing.T) {
	dir, exe := discoveryFixture(t)
	cacheDir := t.TempDir()
	config := scanner.Config{ExecutablePath: exe}
	discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
	// Same size, path and modification time: only the bytes differ.
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte(strings.ReplaceAll(string(data), "1.29.0", "1.30.0")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(exe, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	adapter := initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config)
	discoveryScan(t, adapter, dir)
	if adapter.GetInfo().Version != "1.30.0" {
		t.Fatalf("updated binary reported %q", adapter.GetInfo().Version)
	}
	if got := discoveryCounts(t, dir); got != "version=2 help=2 scan=2" {
		t.Fatal(got)
	}
	assertProbeEntries(t, cacheDir, 4)
}

func TestProbeCacheFallsBackToProbing(t *testing.T) {
	for _, damage := range []string{"corrupt", "invalid-version", "unwritable"} {
		t.Run(damage, func(t *testing.T) {
			dir, exe := discoveryFixture(t)
			cacheDir := filepath.Join(t.TempDir(), "probes")
			config := scanner.Config{ExecutablePath: exe}
			if damage == "unwritable" {
				// A file where the directory should be: nothing persists.
				if err := os.WriteFile(cacheDir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
			if damage != "unwritable" {
				entries, err := filepath.Glob(filepath.Join(cacheDir, "*.json"))
				if err != nil || len(entries) != 2 {
					t.Fatalf("entries %v, %v", entries, err)
				}
				for _, entry := range entries {
					content := "{not json"
					if damage == "invalid-version" {
						data, readErr := os.ReadFile(entry)
						if readErr != nil {
							t.Fatal(readErr)
						}
						content = strings.ReplaceAll(string(data), `"1.29.0`, `"not-a-version`)
					}
					if err := os.WriteFile(entry, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			adapter := initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config)
			discoveryScan(t, adapter, dir)
			if adapter.GetInfo().Version != "1.29.0" {
				t.Fatal(adapter.GetInfo())
			}
			want := "version=2 help=2 scan=2"
			if damage == "invalid-version" {
				// The help entry was still intact.
				want = "version=2 help=1 scan=2"
			}
			if got := discoveryCounts(t, dir); got != want {
				t.Fatal(got)
			}
			if damage != "unwritable" {
				// The probe rewrote the damaged entries, so a third process
				// probes nothing.
				discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
				if got := discoveryCounts(t, dir); got != strings.Replace(want, "scan=2", "scan=3", 1) {
					t.Fatal(got)
				}
			}
		})
	}
}

// A help text from the --help fallback answers this process only: the
// preferred `scan --help` may have failed for a transient reason.
func TestProbeCacheKeepsHelpFallbackInProcess(t *testing.T) {
	dir, exe := discoveryFixture(t)
	cacheDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "preferred-fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config := scanner.Config{ExecutablePath: exe}
	discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
	assertProbeEntries(t, cacheDir, 1)
	if err := os.Remove(filepath.Join(dir, "preferred-fail")); err != nil {
		t.Fatal(err)
	}
	discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
	if got := discoveryCounts(t, dir); got != "version=1 help=3 scan=2" {
		t.Fatal(got)
	}
	data, err := os.ReadFile(filepath.Join(dir, "help-order"))
	if err != nil || string(data) != "scan\n--help\nscan\n" {
		t.Fatalf("help order %q, %v", data, err)
	}
	assertProbeEntries(t, cacheDir, 2)
}

func TestProbeCacheConcurrentProcesses(t *testing.T) {
	dir, exe := discoveryFixture(t)
	cacheDir := t.TempDir()
	config := scanner.Config{ExecutablePath: exe}
	var done sync.WaitGroup
	for range 8 {
		done.Add(1)
		go func() {
			defer done.Done()
			adapter := opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir))()
			if err := adapter.Initialize(t.Context(), config); err != nil {
				t.Error(err)
				return
			}
			discoveryScan(t, adapter, dir)
			if adapter.GetInfo().Version != "1.29.0" {
				t.Error(adapter.GetInfo())
			}
		}()
	}
	done.Wait()
	assertProbeEntries(t, cacheDir, 2)
	before := discoveryCounts(t, dir)
	discoveryScan(t, initializedDiscovery(t, opengrep.NewScannerFactory(opengrep.WithProbeCacheDir(cacheDir)), config), dir)
	after := discoveryCounts(t, dir)
	if strings.Fields(before)[0] != strings.Fields(after)[0] || strings.Fields(before)[1] != strings.Fields(after)[1] {
		t.Fatalf("probed again after concurrent writers: %s then %s", before, after)
	}
}

// assertProbeEntries checks the directory holds want complete entries and no
// temporary file left behind by a writer.
func assertProbeEntries(t *testing.T, cacheDir string, want int) {
	t.Helper()
	files, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, file.Name())
	}
	entries, err := filepath.Glob(filepath.Join(cacheDir, "*.json"))
	if err != nil || len(entries) != want || len(names) != want {
		t.Fatalf("want %d probe entries, got %v", want, names)
	}
}
