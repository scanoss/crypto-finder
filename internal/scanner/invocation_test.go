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
package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

func TestScannerOwnsInvocationConfiguration(t *testing.T) {
	for _, tc := range invocationAdapters() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := invocationConfig(t, 0, false)
			adapter := tc.newScanner()
			if err := adapter.Initialize(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			cfg.Env["INVOCATION_ID"] = "changed"
			cfg.ExtraArgs[1] = "changed"
			cfg.SkipPatterns[0] = "changed"
			assertInvocationReport(t, adapter, cfg.WorkDir, 1)
		})
	}
}

type invocationAdapter struct {
	name       string
	newScanner func() scanner.Scanner
}

func invocationAdapters() []invocationAdapter {
	return []invocationAdapter{
		{opengrep.ScannerName, func() scanner.Scanner { return opengrep.NewScanner() }},
		{semgrep.ScannerName, func() scanner.Scanner { return semgrep.NewScanner() }},
	}
}

func invocationConfig(t *testing.T, id int, interfile bool) scanner.Config {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires POSIX scanner fixture subprocesses")
	}
	dir := t.TempDir()
	token := fmt.Sprint(id)
	pro := ""
	if interfile {
		pro = "1"
	}
	// The executable rejects a different invocation's config instead of recording private state.
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
 --version) echo 1.12.1; exit 0;;
 scan|--help) echo '--x-ignore-semgrepignore-files'; exit 0;;
esac
[ "$PWD" = '%s' ] && [ "$INVOCATION_ID" = '%s' ] || exit 2
skip= extra= config= target= pro=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --exclude) shift; skip="$1";;
  --invocation-token) shift; extra="$1";;
  --config) shift; config="$1";;
  --pro) pro=1;;
 esac
 target="$1"; shift
done
[ "$skip" = 'skip-%s' ] && [ "$extra" = '%s' ] && [ "$config" = '%s/rules.yaml' ] && [ "$target" = '%s' ] || exit 2
[ "$pro" = '%s' ] || exit 2
printf '%%s\n' '{"version":"1.12.1","results":[{"check_id":"fixture.sha256","path":"%s/main.go","start":{"line":1,"col":1},"end":{"line":1,"col":8},"extra":{"message":"SHA256 fixture","severity":"INFO","lines":"hash()","metadata":{"crypto":{"assetType":"algorithm","algorithmFamily":"SHA2","primitive":"hash"}}}},{"check_id":"fixture.sha256","path":"%s/main.go","start":{"line":1,"col":1},"end":{"line":1,"col":8},"extra":{"message":"SHA256 fixture","severity":"INFO","lines":"hash()","metadata":{"crypto":{"assetType":"algorithm","algorithmFamily":"SHA2","primitive":"hash"}}}}],"errors":[]}'
`, dir, token, token, token, dir, dir, pro, dir, dir)
	exe := filepath.Join(dir, "scanner")
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return scanner.Config{
		ExecutablePath: exe, WorkDir: dir, Timeout: time.Second,
		Env: map[string]string{"INVOCATION_ID": token}, ExtraArgs: []string{"--invocation-token", token}, SkipPatterns: []string{"skip-" + token}, DisableDedup: id%2 != 0, Interfile: interfile,
	}
}

func assertInvocationReport(t *testing.T, adapter scanner.Scanner, target string, assets int) {
	t.Helper()
	report, err := adapter.Scan(t.Context(), target, []string{filepath.Join(target, "rules.yaml")}, entities.ToolInfo{Name: "fixture", Version: "1"})
	if err != nil {
		t.Errorf("Scan lost invocation configuration: %v", err)
		return
	}
	if report == nil || len(report.Findings) != 1 || report.Findings[0].FilePath != "main.go" || len(report.Findings[0].CryptographicAssets) != assets {
		t.Errorf("unexpected invocation findings: %#v", report)
		return
	}
	asset := report.Findings[0].CryptographicAssets[0]
	if asset.Metadata["assetType"] != "algorithm" || asset.Metadata["algorithmFamily"] != "SHA2" || asset.Match != "hash()" || asset.StartCol != 1 || asset.EndCol != 8 || len(asset.Rules) != 1 || asset.Rules[0].ID != "fixture.sha256" {
		t.Errorf("unexpected finding evidence: %#v", asset)
	}
}

// Each worker follows the production Registry.Get -> Initialize -> Scan contract.
func TestRegistryIsolatesScannerInvocations(t *testing.T) {
	for _, tc := range invocationAdapters() {
		t.Run(tc.name, func(t *testing.T) {
			registry := scanner.NewRegistry()
			registry.RegisterFactory(tc.name, tc.newScanner)
			const workers = 4
			adapters := make([]scanner.Scanner, workers)
			configs := make([]scanner.Config, workers)
			for i := range workers {
				configs[i] = invocationConfig(t, i, tc.name == semgrep.ScannerName && i%2 != 0)
				var err error
				adapters[i], err = registry.Get(tc.name)
				if err != nil {
					t.Fatal(err)
				}
				if err := adapters[i].Initialize(context.Background(), configs[i]); err != nil {
					t.Fatal(err)
				}
			}
			// All initializations finish before scans, making configuration leakage deterministic.
			var done sync.WaitGroup
			for i := range workers {
				done.Add(1)
				go func() {
					defer done.Done()
					assertInvocationReport(t, adapters[i], configs[i].WorkDir, 1+i%2)
					for range 4 {
						adapter, err := registry.Get(tc.name)
						if err != nil {
							t.Error(err)
							return
						}
						if err := adapter.Initialize(t.Context(), configs[i]); err != nil {
							t.Error(err)
							return
						}
						assertInvocationReport(t, adapter, configs[i].WorkDir, 1+i%2)
					}
				}()
			}
			done.Wait()
		})
	}
}
