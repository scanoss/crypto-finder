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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

func TestHelpDiscoveryPreservesFallbackAndRetriesFailures(t *testing.T) {
	for _, mode := range []string{"modern", "legacy-help", "preferred-fail", "fail-help"} {
		t.Run(mode, func(t *testing.T) {
			dir, exe := discoveryFixture(t)
			factory := opengrep.NewScannerFactory()
			if mode != "modern" {
				if err := os.WriteFile(filepath.Join(dir, mode), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			control := "modern"
			if mode == "legacy-help" || mode == "fail-help" {
				control = "legacy"
			}
			adapter := initializedDiscovery(t, factory, scanner.Config{ExecutablePath: exe, Env: map[string]string{"EXPECT_CONTROL": control}})
			discoveryScan(t, adapter, dir)
			if mode == "fail-help" {
				if err := os.Remove(filepath.Join(dir, mode)); err != nil {
					t.Fatal(err)
				}
				adapter = initializedDiscovery(t, factory, scanner.Config{ExecutablePath: exe, Env: map[string]string{"EXPECT_CONTROL": "modern"}})
			}
			discoveryScan(t, adapter, dir)
			want := "version=1 help=1 scan=2"
			order := "scan\n"
			if mode == "preferred-fail" {
				want = "version=1 help=2 scan=2"
				order = "scan\n--help\n"
			}
			if mode == "fail-help" {
				want = "version=1 help=3 scan=3"
				order = "scan\n--help\nscan\n"
				discoveryScan(t, adapter, dir)
			}
			if got := discoveryCounts(t, dir); got != want {
				t.Fatal(got)
			}
			data, err := os.ReadFile(filepath.Join(dir, "help-order"))
			if err != nil || string(data) != order {
				t.Fatalf("help order %q, %v", data, err)
			}
		})
	}
}

func TestHelpDiscoveryCancellationAndRetry(t *testing.T) {
	dir, exe := discoveryFixture(t)
	factory := opengrep.NewScannerFactory()
	config := scanner.Config{ExecutablePath: exe}
	adapter := initializedDiscovery(t, factory, config)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	scan := func(ctx context.Context, adapter scanner.Scanner) error {
		_, err := adapter.Scan(ctx, dir, []string{"rules.yaml"}, entities.ToolInfo{})
		return err
	}
	if err := scan(canceled, adapter); !errors.Is(err, context.Canceled) {
		t.Fatalf("cold canceled: %v", err)
	}
	if got := discoveryCounts(t, dir); got != "version=1 help=0 scan=0" {
		t.Fatal(got)
	}
	block := filepath.Join(dir, "block-help")
	if err := os.WriteFile(block, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerCtx, ownerCancel := context.WithCancel(t.Context())
	defer ownerCancel()
	result := make(chan error, 1)
	go func() { result <- scan(ownerCtx, adapter) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, _ := os.ReadFile(filepath.Join(dir, "log"))
		if strings.Contains(string(data), "help\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("help probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
	waiterCtx, waiterCancel := context.WithCancel(t.Context())
	defer waiterCancel()
	timer := time.AfterFunc(20*time.Millisecond, waiterCancel)
	defer timer.Stop()
	if err := scan(waiterCtx, initializedDiscovery(t, factory, config)); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter canceled: %v", err)
	}
	if got := discoveryCounts(t, dir); got != "version=1 help=1 scan=0" {
		t.Fatal(got)
	}
	ownerCancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner canceled: %v", err)
	}
	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	discoveryScan(t, adapter, dir)
	if err := scan(canceled, adapter); !errors.Is(err, context.Canceled) {
		t.Fatalf("warm canceled: %v", err)
	}
	discoveryScan(t, adapter, dir)
	if got := discoveryCounts(t, dir); got != "version=1 help=2 scan=2" {
		t.Fatal(got)
	}
}
