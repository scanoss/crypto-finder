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
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

const relativeRootFixtures = "testdata/relative-root"

// realScanner initializes the adapter over the opengrep on PATH, skipping
// the test when core mode is asked for and opengrep-core is unavailable.
func realScanner(t *testing.T, config scanner.Config) *Scanner {
	t.Helper()
	checkOpengrepAvailable(t)
	s := NewScanner()
	config.Timeout = 5 * time.Minute
	if config.Jobs == 0 {
		config.Jobs = 1
	}
	if err := s.Initialize(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if config.OpengrepMode == scanner.OpengrepModeCore {
		if _, err := s.coreBinary(context.Background()); err != nil {
			t.Skipf("opengrep-core unavailable: %v", err)
		}
	}
	return s
}

// fixtureRoot copies the fixture class to <base>/<name>/fixture and returns
// <base>/<name>, the root to scan.
func fixtureRoot(t *testing.T, base, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(relativeRootFixtures, "KeyDeriver.java"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, name)
	writeTree(t, root, map[string]string{filepath.Join("fixture", "KeyDeriver.java"): string(data)})
	return root
}

// reportJSON encodes report with its findings in path order, as the
// transformer's map leaves them in no particular one.
func reportJSON(t *testing.T, report *entities.InterimReport) string {
	t.Helper()
	slices.SortFunc(report.Findings, func(a, b entities.Finding) int { return strings.Compare(a.FilePath, b.FilePath) })
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var relativeRootModes = []struct {
	name string
	mode scanner.OpengrepMode
	pf   scanner.RulePrefilter
}{
	{"cli", scanner.OpengrepModeCLI, scanner.RulePrefilterOff},
	{"core", scanner.OpengrepModeCore, scanner.RulePrefilterOff},
	{"core+imports", scanner.OpengrepModeCore, scanner.RulePrefilterImports},
}

// opengrep 1.30.2 reports the key-length taint in the fixture for some
// absolute paths of the file and not for others (about two in five
// directory names). Scanned in the root through relative paths, the result
// is the same wherever the root lies, at any name and depth, in every mode.
func TestRootRelativeScanIsStableAcrossRootLocations(t *testing.T) {
	rules, err := filepath.Abs(filepath.Join(relativeRootFixtures, "kdf.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	names := []string{"a", "bb", "ccc", "home/u1/src", "home/someone-else/w/x/y", "deps/org.example-lib/1.0", "z9", "q-q_q/r"}
	var want string
	for _, m := range relativeRootModes {
		s := realScanner(t, scanner.Config{OpengrepMode: m.mode, RulePrefilter: m.pf})
		for _, name := range names {
			report, err := s.Scan(context.Background(), fixtureRoot(t, base, name), []string{rules}, entities.ToolInfo{Name: "fixture"})
			if err != nil {
				t.Fatalf("%s %s: %v", m.name, name, err)
			}
			got := reportJSON(t, report)
			if want == "" {
				want = got
				if !strings.Contains(got, `"fixture/KeyDeriver.java"`) || !strings.Contains(got, "kdf.pbkdf2") {
					t.Fatalf("report %s: want the fixture's finding named relative to the root", got)
				}
				continue
			}
			if got != want {
				t.Errorf("%s at %s: report differs from the first root's:\n got %s\nwant %s", m.name, name, got, want)
			}
		}
	}
}

// The scan in the root reports what a scan by the target's path in
// crypto-finder's working directory reports: the same paths and the same
// rule ids, here with the rules below the working directory, where the CLI
// prefixes ids with their directory relative to it. Extra scanner
// arguments keep the latter, legacy, invocation.
func TestRootRelativeScanKeepsRuleIDsAndPaths(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(relativeRootFixtures, "kdf.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	writeTree(t, cwd, map[string]string{filepath.Join("rules", "java", "kdf.yaml"): string(data)})
	root := fixtureRoot(t, cwd, filepath.Join("work", "proj"))
	t.Chdir(cwd)
	// Relative and absolute rule paths and targets, all named from cwd.
	for _, paths := range []struct{ rules, target string }{
		{filepath.Join("rules", "java"), filepath.Join("work", "proj")},
		{filepath.Join(cwd, "rules", "java"), root},
	} {
		legacy := realScanner(t, scanner.Config{ExtraArgs: []string{"--quiet"}})
		report, err := legacy.Scan(context.Background(), paths.target, []string{paths.rules}, entities.ToolInfo{Name: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		want := reportJSON(t, report)
		if !strings.Contains(want, `"rules.java.kdf.pbkdf2"`) || !strings.Contains(want, `"fixture/KeyDeriver.java"`) {
			t.Fatalf("legacy report %s: want ids prefixed relative to cwd and paths relative to the target", want)
		}
		for _, m := range relativeRootModes {
			s := realScanner(t, scanner.Config{OpengrepMode: m.mode, RulePrefilter: m.pf})
			report, err := s.Scan(context.Background(), paths.target, []string{paths.rules}, entities.ToolInfo{Name: "fixture"})
			if err != nil {
				t.Fatal(err)
			}
			// The taint finding is the path lottery's; compare the rest.
			if got := reportJSON(t, report); stripTaint(got) != stripTaint(want) {
				t.Errorf("%s (rules %s, target %s): report differs from the legacy scan's:\n got %s\nwant %s", m.name, paths.rules, paths.target, got, want)
			}
		}
	}
}

// stripTaint drops the key-length rule's assets from an encoded report.
func stripTaint(encoded string) string {
	var report entities.InterimReport
	if err := json.Unmarshal([]byte(encoded), &report); err != nil {
		return encoded
	}
	for i := range report.Findings {
		assets := report.Findings[i].CryptographicAssets[:0]
		for j := range report.Findings[i].CryptographicAssets {
			asset := &report.Findings[i].CryptographicAssets[j]
			if len(asset.Rules) == 0 || !strings.HasSuffix(asset.Rules[0].ID, "pbkdf2-keylength") {
				assets = append(assets, *asset)
			}
		}
		report.Findings[i].CryptographicAssets = assets
	}
	data, err := json.Marshal(report)
	if err != nil {
		return encoded
	}
	return string(data)
}
