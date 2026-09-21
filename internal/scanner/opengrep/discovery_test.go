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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

func TestFactoryReusesDiscoveryWithoutReusingInvocations(t *testing.T) {
	dir, exe := discoveryFixture(t)
	factory := opengrep.NewScannerFactory()
	var done sync.WaitGroup
	for i := range 4 {
		done.Add(1)
		go func() {
			defer done.Done()
			adapter := factory()
			config := scanner.Config{ExecutablePath: exe, WorkDir: dir, Env: map[string]string{"TOKEN": string(rune('a' + i))}, ExtraArgs: []string{"--token", string(rune('a' + i))}}
			if err := adapter.Initialize(t.Context(), config); err != nil {
				t.Error(err)
				return
			}
			discoveryScan(t, adapter, dir)
		}()
	}
	done.Wait()
	if got := discoveryCounts(t, dir); got != "version=1 help=1 scan=4" {
		t.Fatalf("want one discovery and four configured scans, got %s", got)
	}
	// A new run must not inherit discovery from a prior factory.
	adapter := initializedDiscovery(t, opengrep.NewScannerFactory(), scanner.Config{ExecutablePath: exe})
	discoveryScan(t, adapter, dir)
	if got := discoveryCounts(t, dir); got != "version=2 help=2 scan=5" {
		t.Fatal(got)
	}
}

func discoveryFixture(t *testing.T) (string, string) {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires POSIX scanner fixture subprocesses")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "opengrep")
	script := `#!/bin/sh
root="$(dirname "$0")"
case "$1" in
 --version) echo version >> "$root/log"; [ ! -s "$root/fail-version" ] || { cat "$root/fail-version"; exit 0; }; [ ! -f "$root/fail-version" ] || exit 2; [ ! -f "$root/block-version" ] || sleep 10; echo "${DISCOVERY_VERSION:-1.29.0}"; exit 0;;
 scan|--help) echo help >> "$root/log"; echo "$1" >> "$root/help-order"; [ ! -f "$root/block-help" ] || sleep 10; [ ! -f "$root/fail-help" ] || exit 2; if [ "$1" = scan ] && [ -f "$root/preferred-fail" ]; then exit 2; fi; if [ -f "$root/legacy-help" ]; then echo 'legacy help'; else echo '--x-ignore-semgrepignore-files'; fi; exit 0;;
esac
[ -z "$TOKEN" ] || { [ "$PWD" = "$root" ] && case "$*" in *"--token $TOKEN"*) true;; *) false;; esac; } || exit 2
case "$EXPECT_CONTROL:$*" in
 modern:*--x-ignore-semgrepignore-files*) true;;
 legacy:*--experimental*--semgrepignore-filename\ .crypto-finder-no-semgrepignore*) true;;
 :*) true;;
 *) exit 2;;
esac
echo scan >> "$root/log"
printf '%s\n' '{"version":"1.29.0","results":[],"errors":[]}'
`
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, exe
}

func discoveryScan(t *testing.T, adapter scanner.Scanner, dir string) {
	t.Helper()
	report, err := adapter.Scan(t.Context(), dir, []string{"rules.yaml"}, entities.ToolInfo{Name: "fixture", Version: "1"})
	if err != nil || report == nil || len(report.Findings) != 0 {
		t.Errorf("scan: %#v, %v", report, err)
	}
}

func discoveryCounts(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("version=%d help=%d scan=%d", strings.Count(string(data), "version\n"), strings.Count(string(data), "help\n"), strings.Count(string(data), "scan\n"))
}

func TestDiscoveryIdentityInvalidation(t *testing.T) {
	for _, change := range []string{"bytes", "environment", "cwd", "PATH"} {
		t.Run(change, func(t *testing.T) {
			dir, exe := discoveryFixture(t)
			factory := opengrep.NewScannerFactory()
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			config := scanner.Config{}
			first := initializedDiscovery(t, factory, config)
			discoveryScan(t, first, dir)
			expected := "1.29.0"
			switch change {
			case "bytes":
				data, _ := os.ReadFile(exe)
				info, _ := os.Stat(exe)
				if err := os.WriteFile(exe, []byte(strings.ReplaceAll(string(data), "1.29.0", "1.30.0")), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(exe, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
				expected = "1.30.0"
			case "environment":
				t.Setenv("DISCOVERY_VERSION", "1.30.0")
				expected = "1.30.0"
			case "cwd":
				t.Chdir(dir)
			case "PATH":
				other, _ := discoveryFixture(t)
				t.Setenv("PATH", other+string(os.PathListSeparator)+os.Getenv("PATH"))
				dir = other
			}
			second := initializedDiscovery(t, factory, config)
			discoveryScan(t, second, dir)
			if second.GetInfo().Version != expected {
				t.Fatal(second.GetInfo())
			}
			want := "version=2 help=2 scan=2"
			if change == "PATH" {
				want = "version=1 help=1 scan=1"
			}
			if got := discoveryCounts(t, dir); got != want {
				t.Fatal(got)
			}
		})
	}
}

func TestVersionDiscoveryCancellationAndRetry(t *testing.T) {
	dir, exe := discoveryFixture(t)
	factory := opengrep.NewScannerFactory()
	config := scanner.Config{ExecutablePath: exe}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := factory().Initialize(canceled, config); !errors.Is(err, context.Canceled) {
		t.Fatalf("cold canceled: %v", err)
	}
	block := filepath.Join(dir, "block-version")
	if err := os.WriteFile(block, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerCtx, ownerCancel := context.WithCancel(t.Context())
	defer ownerCancel()
	result := make(chan error, 1)
	go func() { result <- factory().Initialize(ownerCtx, config) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, _ := os.ReadFile(filepath.Join(dir, "log"))
		if strings.Contains(string(data), "version\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("version probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
	waiterCtx, waiterCancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer waiterCancel()
	if err := factory().Initialize(waiterCtx, config); err == nil {
		t.Fatal("waiting cancellation was ignored")
	}
	if got := discoveryCounts(t, dir); got != "version=1 help=0 scan=0" {
		t.Fatal(got)
	}
	ownerCancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner canceled: %v", err)
	}
	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	adapter := initializedDiscovery(t, factory, config)
	discoveryScan(t, adapter, dir)
	if err := factory().Initialize(canceled, config); !errors.Is(err, context.Canceled) {
		t.Fatalf("warm canceled: %v", err)
	}
	if _, err := adapter.Scan(canceled, dir, []string{"rules.yaml"}, entities.ToolInfo{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("warm Scan canceled: %v", err)
	}
	if got := discoveryCounts(t, dir); got != "version=2 help=1 scan=1" {
		t.Fatal(got)
	}
}

func TestVersionDiscoveryFailuresRemainRetryableAndValidated(t *testing.T) {
	for _, output := range []string{"", "malformed"} {
		t.Run(output, func(t *testing.T) {
			dir, exe := discoveryFixture(t)
			factory := opengrep.NewScannerFactory()
			config := scanner.Config{ExecutablePath: exe}
			fail := filepath.Join(dir, "fail-version")
			if err := os.WriteFile(fail, []byte(output), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := factory().Initialize(t.Context(), config); err == nil {
				t.Fatal("version probe failure was ignored")
			}
			if err := os.Remove(fail); err != nil {
				t.Fatal(err)
			}
			adapter := initializedDiscovery(t, factory, config)
			discoveryScan(t, adapter, dir)
			if got := discoveryCounts(t, dir); got != "version=2 help=1 scan=1" {
				t.Fatal(got)
			}
			t.Setenv("DISCOVERY_VERSION", "1.0.0")
			for range 2 {
				if err := factory().Initialize(t.Context(), config); err == nil {
					t.Fatal("minimum-version validation was bypassed")
				}
			}
			if got := discoveryCounts(t, dir); got != "version=3 help=1 scan=1" {
				t.Fatal(got)
			}
		})
	}
}

func initializedDiscovery(t *testing.T, factory func() scanner.Scanner, config scanner.Config) scanner.Scanner {
	t.Helper()
	adapter := factory()
	if err := adapter.Initialize(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	return adapter
}
