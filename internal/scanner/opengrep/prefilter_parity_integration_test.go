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
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// The parity tests below run real OpenGrep over a real ruleset and real
// fixture code. They need opengrep 1.30.2 (CLI and opengrep-core) and are
// skipped unless both paths are set:
//
//	CRYPTO_FINDER_PARITY_RULES     a Semgrep rules directory (crypto_rules/semgrep-rules)
//	CRYPTO_FINDER_PARITY_FIXTURES  a directory of per-language fixture directories
//	                               (crypto_rules/tests/integration/fixtures)
//
// CRYPTO_FINDER_PARITY_LANGUAGES optionally limits the fixture directories
// (comma-separated names).
const (
	parityRulesEnv     = "CRYPTO_FINDER_PARITY_RULES"
	parityFixturesEnv  = "CRYPTO_FINDER_PARITY_FIXTURES"
	parityLanguagesEnv = "CRYPTO_FINDER_PARITY_LANGUAGES"
)

func parityPaths(t *testing.T) (rulesDir, fixturesDir string) {
	t.Helper()
	rulesDir, fixturesDir = os.Getenv(parityRulesEnv), os.Getenv(parityFixturesEnv)
	if rulesDir == "" || fixturesDir == "" {
		t.Skipf("set %s and %s to run OpenGrep parity tests", parityRulesEnv, parityFixturesEnv)
	}
	checkOpengrepAvailable(t)
	return rulesDir, fixturesDir
}

func parityLanguages(t *testing.T, fixturesDir string) []string {
	t.Helper()
	if only := os.Getenv(parityLanguagesEnv); only != "" {
		return splitComma(only)
	}
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var langs []string
	for _, entry := range entries {
		if entry.IsDir() {
			langs = append(langs, entry.Name())
		}
	}
	return langs
}

func splitComma(value string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == ',' {
			if i > start {
				out = append(out, value[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// parityScanner initializes the adapter against the opengrep in PATH and
// requires a verified opengrep-core.
func parityScanner(ctx context.Context, t *testing.T, mode scanner.OpengrepMode, prefilterMode scanner.RulePrefilter) *Scanner {
	t.Helper()
	s := NewScanner()
	if err := s.Initialize(ctx, scanner.Config{Jobs: 2, Timeout: 30 * time.Minute, OpengrepMode: mode, RulePrefilter: prefilterMode, IncludeGitIgnored: true}); err != nil {
		t.Fatalf("initialize opengrep: %v", err)
	}
	if _, err := s.coreBinary(ctx); err != nil {
		t.Skipf("opengrep-core unavailable: %v", err)
	}
	return s
}

// TestPrefilterKeepsEveryMatchingRulePerFile is the strictest soundness
// check of the import prefilter: it runs every rule over each fixture
// directory, then asks the prefilter about every fixture file as a unit of
// its own, and fails when it would drop a rule that matched in that file.
func TestPrefilterKeepsEveryMatchingRulePerFile(t *testing.T) {
	rulesDir, fixturesDir := parityPaths(t)
	ctx := context.Background()
	s := parityScanner(ctx, t, scanner.OpengrepModeCore, scanner.RulePrefilterOff)
	cwd, err := physicalDir("")
	if err != nil {
		t.Fatal(err)
	}
	ruleset, err := loadCoreRuleset([]string{rulesDir}, cwd)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	binary, err := s.coreBinary(ctx)
	if err != nil {
		t.Skip(err)
	}
	for _, lang := range parityLanguages(t, fixturesDir) {
		t.Run(lang, func(t *testing.T) {
			dir := filepath.Join(fixturesDir, lang)
			plan, err := enumerateTargets(ctx, targetOptions{targets: []string{dir}, includeGitIgnored: true, maxTargetBytes: defaultMaxTargetBytes}, languagesOf(ruleset.rules))
			if err != nil {
				t.Fatalf("enumerate: %v", err)
			}
			rules := rulesForPlan(ruleset.rules, plan)
			out, err := s.runCore(ctx, binary, rules, plan.forLanguages(languagesOf(rules)), false, false)
			if err != nil {
				t.Fatalf("run core: %v", err)
			}
			byID := make(map[string]*coreRule, len(rules))
			for _, rule := range rules {
				byID[rule.id] = rule
			}
			matched := make(map[string]map[string]bool)
			for i := range out.Results {
				result := &out.Results[i]
				if matched[result.Path] == nil {
					matched[result.Path] = make(map[string]bool)
				}
				matched[result.Path][result.CheckID] = true
			}
			files := make([]string, 0, len(matched))
			for file := range matched {
				files = append(files, file)
			}
			sort.Strings(files)
			lost, total, keptSum := 0, 0, 0
			for _, file := range files {
				evidence := prefilter.NewEvidence()
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				evidence.AddFile(plan.analyzers[file], data)
				inputs := make([]prefilter.Rule, len(rules))
				for i, rule := range rules {
					inputs[i] = prefilter.Rule{Analyzers: rule.analyzers(), Requirement: rule.requirement()}
				}
				keep, stats := prefilter.Decide(inputs, evidence)
				keptSum += stats.Kept
				for i, rule := range rules {
					if !matched[file][rule.id] {
						continue
					}
					total++
					if !keep[i] {
						lost++
						t.Errorf("prefilter drops %s, which matches in %s", rule.id, file)
					}
				}
			}
			t.Logf("%s: %d rules, %d results in %d files, %d (rule,file) matches, %d lost; prefilter keeps %.1f rules per file on average",
				lang, len(rules), len(out.Results), len(files), total, lost, float64(keptSum)/float64(max(1, len(files))))
		})
	}
}

// rulesForPlan keeps the rules with a language some target has.
func rulesForPlan(rules []*coreRule, plan *targetPlan) []*coreRule {
	present := make(map[string]bool)
	for _, target := range plan.targets {
		present[target.analyzer] = true
	}
	var kept []*coreRule
	for _, rule := range rules {
		for _, lang := range rule.langs {
			if present[lang.id] {
				kept = append(kept, rule)
				break
			}
		}
	}
	return kept
}
