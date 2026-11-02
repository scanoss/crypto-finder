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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

// The committed budget file and checker must agree. This is the test that
// keeps budgets.json honest as budgets.sh changes.
func TestCommittedBudgetsAreHonest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--root", repoRoot}, &stdout, &stderr); code != 0 {
		t.Fatalf("budgetcheck exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
}

const goodScript = "#!/usr/bin/env bash\nMETRICS=(binary_size_bytes startup_help_ms)\n"

const goodBudgets = `{
  "measured": {"date": "2026-11-02", "commit": "abc", "machine": "test box", "method": "three runs"},
  "budgets": {
    "binary_size_bytes": {"kind": "deterministic", "unit": "bytes", "measured": 1000, "limit": 1100, "why": "measured plus 10%"},
    "startup_help_ms": {"kind": "noisy", "unit": "ms", "measured": 15, "limit": 250, "why": "loose"}
  },
  "tracked": {"ci_test_suite_seconds": {"median": 505.5}}
}`

func TestCheck(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		budgets  string
		problems []string // substrings, one per expected problem, in order
	}{
		{name: "honest file passes", script: goodScript, budgets: goodBudgets},
		{
			name:    "renamed metric in the checker",
			script:  strings.Replace(goodScript, "startup_help_ms", "startup_usage_ms", 1),
			budgets: goodBudgets,
			problems: []string{
				"metric startup_usage_ms: budgets.sh measures it but budgets.json has no budget",
				"budget startup_help_ms: budgets.sh does not measure it",
			},
		},
		{
			name:    "renamed budget key",
			script:  goodScript,
			budgets: strings.Replace(goodBudgets, `"binary_size_bytes": {`, `"binary_size": {`, 1),
			problems: []string{
				"metric binary_size_bytes: budgets.sh measures it but budgets.json has no budget",
				"budget binary_size: budgets.sh does not measure it",
			},
		},
		{
			name:     "missing why",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"why": "loose"`, `"why": " "`, 1),
			problems: []string{"budget startup_help_ms: limit 250 has no why"},
		},
		{
			name:     "deterministic limit loosened without re-measuring",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"limit": 1100`, `"limit": 1500`, 1),
			problems: []string{"budget binary_size_bytes: limit 1500 is over its measured 1000 plus 10% (1100)"},
		},
		{
			name:     "limit below its measurement",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"limit": 250`, `"limit": 10`, 1),
			problems: []string{"budget startup_help_ms: limit 10 is below its measured 15"},
		},
		{
			name:     "unknown kind",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"kind": "noisy"`, `"kind": "fast"`, 1),
			problems: []string{`budget startup_help_ms: kind "fast" is neither`},
		},
		{
			name:     "misspelled field",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"why": "loose"`, `"wy": "loose"`, 1),
			problems: []string{`unknown field "wy"`},
		},
		{
			name:     "unmeasured file",
			script:   goodScript,
			budgets:  strings.Replace(goodBudgets, `"machine": "test box"`, `"machine": ""`, 1),
			problems: []string{"measured.machine is empty"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.script, tt.budgets)
			problems, err := check(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != len(tt.problems) {
				t.Fatalf("problems = %q, want %d matching %q", problems, len(tt.problems), tt.problems)
			}
			for i, want := range tt.problems {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, problems[i], want)
				}
			}
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	broken := writeTree(t, goodScript, strings.Replace(goodBudgets, `"why": "loose"`, `"why": ""`, 1))
	noMetrics := writeTree(t, "#!/usr/bin/env bash\n", goodBudgets)
	for _, tt := range []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"problems exit 1", []string{"--root", broken}, 1, "FAIL budget startup_help_ms: limit 250 has no why"},
		{"no METRICS line exits 2", []string{"--root", noMetrics}, 2, "exactly one METRICS=(...) line"},
		{"stray argument exits 2", []string{"extra"}, 2, "usage"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tt.code, stdout.String(), stderr.String())
			}
			if out := stdout.String() + stderr.String(); !strings.Contains(out, tt.out) {
				t.Errorf("output %q does not contain %q", out, tt.out)
			}
		})
	}
}

func writeTree(t *testing.T, script, budgets string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range map[string]string{scriptPath: script, budgetsPath: budgets} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
