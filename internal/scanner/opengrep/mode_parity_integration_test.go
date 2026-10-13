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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules/rulejson"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/skip"
)

// mergeRulesLikeMaterializer writes the rule files below ruleDir into one
// merged-rules.yaml in a fresh directory, each id prefixed with its file's
// directory relative to ruleDir, the way the engine materializes rules for
// OpenGrep. It returns the directory to pass as the rule path.
func mergeRulesLikeMaterializer(t *testing.T, ruleDir string) string {
	t.Helper()
	var merged bytes.Buffer
	merged.WriteString("{\"rules\":[\n")
	count := 0
	err := filepath.WalkDir(ruleDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(ruleDir, path)
		if err != nil || !rulejson.LoadsAsPlainRuleFile(rel) {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		prefix := ""
		if dir := filepath.Dir(rel); dir != "." {
			prefix = strings.ReplaceAll(filepath.ToSlash(dir), "/", ".") + "."
		}
		rules, ok := rulejson.EncodeYAMLRules(data, prefix)
		if !ok {
			return fmt.Errorf("rule file %s is not mergeable", path)
		}
		for _, rule := range rules {
			if count > 0 {
				merged.WriteString(",\n")
			}
			merged.Write(rule)
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	merged.WriteString("\n]}\n")
	dir := filepath.Join(t.TempDir(), filepath.Base(ruleDir))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "merged-rules.yaml"), merged.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// findingKeys flattens a report into comparable keys: file, location, the
// sorted rule ids of the asset, its match and its metadata.
func findingKeys(t *testing.T, report *entities.InterimReport) map[string]int {
	t.Helper()
	keys := make(map[string]int)
	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[i]
			ids := make([]string, 0, len(asset.Rules))
			for _, rule := range asset.Rules {
				ids = append(ids, rule.ID)
			}
			sort.Strings(ids)
			metadata, err := json.Marshal(asset.Metadata)
			if err != nil {
				t.Fatal(err)
			}
			key := fmt.Sprintf("%s:%d-%d:%d-%d %v %q %s %s", finding.FilePath, asset.StartLine, asset.EndLine, asset.StartCol, asset.EndCol, ids, asset.Match, asset.PURL, metadata)
			keys[key]++
		}
	}
	return keys
}

func diffKeys(want, got map[string]int) (missing, extra []string) {
	for key, n := range want {
		if got[key] < n {
			missing = append(missing, key)
		}
	}
	for key, n := range got {
		if want[key] < n {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// TestModeParityOnFixtures scans each fixture directory with the CLI and
// opengrep-core, with and without the import prefilter, and requires the
// four reports to hold the same findings: same files, locations, rule ids,
// matches and metadata. The default exclusions apply, as in a project scan.
func TestModeParityOnFixtures(t *testing.T) {
	rulesDir, fixturesDir := parityPaths(t)
	ctx := context.Background()
	for _, lang := range parityLanguages(t, fixturesDir) {
		t.Run(lang, func(t *testing.T) {
			ruleDir := filepath.Join(rulesDir, lang)
			if _, err := os.Stat(ruleDir); err != nil {
				t.Skipf("no rules for %s", lang)
			}
			rulePath := mergeRulesLikeMaterializer(t, ruleDir)
			if requireModeParity(ctx, t, filepath.Join(fixturesDir, lang), rulePath) == 0 {
				t.Fatalf("%s: the CLI found nothing; the fixtures do not exercise the rules", lang)
			}
		})
	}
}

// requireModeParity scans target with the CLI and opengrep-core, with and
// without the import prefilter, fails on any finding the four reports do not
// share, and returns the CLI's finding count. The default exclusions apply,
// as in a project scan.
func requireModeParity(ctx context.Context, t *testing.T, target, rulePath string) int {
	t.Helper()
	var baseline map[string]int
	for _, combo := range []struct {
		mode scanner.OpengrepMode
		pf   scanner.RulePrefilter
	}{
		{scanner.OpengrepModeCLI, scanner.RulePrefilterOff},
		{scanner.OpengrepModeCore, scanner.RulePrefilterOff},
		{scanner.OpengrepModeCLI, scanner.RulePrefilterImports},
		{scanner.OpengrepModeCore, scanner.RulePrefilterImports},
	} {
		name := combo.mode.String() + "/" + combo.pf.String()
		s := NewScanner()
		config := scanner.Config{Jobs: 2, Timeout: 30 * time.Minute, OpengrepMode: combo.mode, RulePrefilter: combo.pf, SkipPatterns: skip.DefaultPatterns()}
		if err := s.Initialize(ctx, config); err != nil {
			t.Fatalf("%s: initialize: %v", name, err)
		}
		if combo.mode == scanner.OpengrepModeCore {
			if _, err := s.coreBinary(ctx); err != nil {
				t.Skipf("opengrep-core unavailable: %v", err)
			}
		}
		started := time.Now()
		report, err := s.Scan(ctx, target, []string{rulePath}, entities.ToolInfo{Name: "crypto-finder"})
		if err != nil {
			t.Fatalf("%s: scan: %v", name, err)
		}
		keys := findingKeys(t, report)
		t.Logf("%s %s: %d findings in %.1fs", filepath.Base(target), name, len(keys), time.Since(started).Seconds())
		if baseline == nil {
			baseline = keys
			continue
		}
		missing, extra := diffKeys(baseline, keys)
		for _, key := range missing {
			t.Errorf("%s misses %s", name, key)
		}
		for _, key := range extra {
			t.Errorf("%s adds %s", name, key)
		}
	}
	total := 0
	for _, n := range baseline {
		total += n
	}
	return total
}

// TestCoreModeHonorsNosemgrepLikeCLI pins the nosemgrep comments the CLI
// honors, by suffix of the prefixed rule id, including one that spells the
// rule file's directory: core mode must silence the same matches. It needs
// opengrep and opengrep-core 1.30.2 but no parity paths.
func TestCoreModeHonorsNosemgrepLikeCLI(t *testing.T) {
	checkOpengrepAvailable(t)
	ctx := context.Background()
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"r/sub/rules.yaml": "rules:\n- id: base.rule\n  message: m\n  severity: INFO\n  languages: [go]\n  pattern: foo()\n",
		"t/a.go": "package a\n\nfunc f() {\n\tfoo() // nosemgrep: base.rule\n\tfoo() // nosemgrep: " +
			strings.TrimSuffix(configPrefix(filepath.Join(root, "r", "sub", "rules.yaml"), mustPhysicalDir(t)), ".") +
			".base.rule\n\tfoo() // nosemgrep: rule\n\tfoo() // nosemgrep: other\n\tfoo() // nosemgrep\n\tfoo()\n}\n",
	})
	lines := func(mode scanner.OpengrepMode) []int {
		s := NewScanner()
		if err := s.Initialize(ctx, scanner.Config{Jobs: 1, OpengrepMode: mode, IncludeGitIgnored: true}); err != nil {
			t.Fatal(err)
		}
		if mode == scanner.OpengrepModeCore {
			if _, err := s.coreBinary(ctx); err != nil {
				t.Skipf("opengrep-core unavailable: %v", err)
			}
		}
		report, err := s.Scan(ctx, filepath.Join(root, "t"), []string{filepath.Join(root, "r")}, entities.ToolInfo{})
		if err != nil {
			t.Fatal(err)
		}
		var got []int
		for _, finding := range report.Findings {
			for _, asset := range finding.CryptographicAssets {
				got = append(got, asset.StartLine)
			}
		}
		sort.Ints(got)
		return got
	}
	cli, core := lines(scanner.OpengrepModeCLI), lines(scanner.OpengrepModeCore)
	if fmt.Sprint(cli) != "[7 9]" || fmt.Sprint(core) != fmt.Sprint(cli) {
		t.Errorf("unsilenced lines: cli %v, core %v, want [7 9] from both", cli, core)
	}
}

func mustPhysicalDir(t *testing.T) string {
	t.Helper()
	dir, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
