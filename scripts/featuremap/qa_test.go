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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSelectFeatures(t *testing.T) {
	tests := []struct {
		name         string
		changed      []string
		limit        int
		chosen, left []string
	}{
		{"a mapped path selects its feature", []string{"internal/scanner/opengrep/run.go"}, 5, []string{"scan"}, nil},
		{"docs and tests select none", []string{"README.md", "internal/scanner/x_test.go", "testdata/rules/a.yaml"}, 5, nil, nil},
		{
			"over the cap the rest are named, not driven",
			[]string{"internal/callgraph/builder.go", "internal/dependency/go/mod.go", "internal/cli/scan.go"},
			2,
			[]string{"reachability", "reachability-dependencies"},
			[]string{"scan"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chosen, left := selectFeatures(prFeatures, tt.changed, tt.limit)
			if !slices.Equal(chosen, tt.chosen) || !slices.Equal(left, tt.left) {
				t.Errorf("selectFeatures = %q, %q; want %q, %q", chosen, left, tt.chosen, tt.left)
			}
		})
	}
}

// TestSelectCommand runs `select` over a real git range, with the map of a
// temporary repository.
func TestSelectCommand(t *testing.T) {
	root := t.TempDir()
	gitT(t, root, "init", "-q", "-b", "main")
	writeFile(t, root, filepath.Join(featureDir, "scan.md"), goodFeature)
	writeFile(t, root, filepath.Join(featureDir, "convert.md"), strings.Replace(goodFeature, "internal/scanner/**", "internal/converter/**", 1))
	writeFile(t, root, "README.md", "x\n")
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "base")
	writeFile(t, root, "internal/scanner/run.go", "package scanner\n")
	writeFile(t, root, "internal/converter/c.go", "package converter\n")
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "change")
	writeFile(t, root, "README.md", "y\n")
	gitT(t, root, "commit", "-q", "-am", "docs")

	tests := []struct {
		name            string
		base, head, max string
		stdout, stderr  string
	}{
		{"a merge touching two features", "HEAD~2", "HEAD~1", "5", "convert scan\n", ""},
		{"a docs-only merge prints an empty line", "HEAD~1", "HEAD", "5", "\n", ""},
		{"over the cap", "HEAD~2", "HEAD~1", "1", "convert\n", "not driven this run (over --max 1): scan\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut strings.Builder
			code := run([]string{"select", "--root", root, "--base", tt.base, "--head", tt.head, "--max", tt.max}, &out, &errOut)
			if code != 0 || out.String() != tt.stdout || errOut.String() != tt.stderr {
				t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q, %q", code, out.String(), errOut.String(), tt.stdout, tt.stderr)
			}
		})
	}
	var out, errOut strings.Builder
	if code := run([]string{"select", "--root", root, "--base", "HEAD~1", "--head", "HEAD", "--max", "0"}, &out, &errOut); code != 2 {
		t.Errorf("--max 0: exit %d, want 2", code)
	}
}

// The shapes below are trimmed from real `claude -p --output-format json
// --json-schema` runs of Claude Code 2.1.312 on the scan feature.
const (
	resultPass = `{"type":"result","subtype":"success","is_error":false,"num_turns":14,"duration_ms":32852,"total_cost_usd":0.014,"result":"done",` +
		`"structured_output":{"features":[{"id":"scan","verdict":"pass","summary":"run.sh scan returned VERDICT: PASS (14 passed, 0 failed)"}]},` +
		`"usage":{"input_tokens":20,"output_tokens":3000,"cache_read_input_tokens":498042,"cache_creation_input_tokens":32616}}`
	resultFail = `{"type":"result","subtype":"success","is_error":false,"num_turns":20,"duration_ms":45074,` +
		`"structured_output":{"features":[{"id":"scan","verdict":"fail","summary":"--fail-on-findings exited 0 | want 1"}]}}`
	resultTurnCap    = `{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":4,"duration_ms":8570,"structured_output":null}`
	resultBadVerdict = `{"subtype":"success","num_turns":3,"structured_output":{"features":[{"id":"scan","verdict":"ok","summary":"x"}]}}`
)

func TestParseQAResult(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		readErr  error
		verdicts string
		notices  []string
	}{
		{
			name:     "a verdict",
			raw:      resultPass,
			verdicts: `{"features":[{"id":"scan","verdict":"pass","summary":"run.sh scan returned VERDICT: PASS (14 passed, 0 failed)"}]}`,
			notices:  []string{"::notice::agent: success, 14 turns, 32s"},
		},
		{
			name:     "a fail keeps its summary",
			raw:      resultFail,
			verdicts: `{"features":[{"id":"scan","verdict":"fail","summary":"--fail-on-findings exited 0 | want 1"}]}`,
			notices:  []string{"::notice::agent: success, 20 turns, 45s"},
		},
		{
			name:     "a turn-capped run is no verdict",
			raw:      resultTurnCap,
			verdicts: "{}",
			notices:  []string{"::notice::agent: error_max_turns, 4 turns, 8s", "::error::agent: error_max_turns", "::error::agent: no verdict in the result"},
		},
		{
			name:     "a missing file is no verdict",
			readErr:  os.ErrNotExist,
			verdicts: "{}",
			notices:  []string{"::error::agent: no result file: file does not exist"},
		},
		{
			name:     "malformed output is no verdict",
			raw:      "Error: unknown option --json-schema\n",
			verdicts: "{}",
			notices:  []string{"::error::agent: result is not JSON"},
		},
		{
			name:     "a verdict outside the schema is no verdict",
			raw:      resultBadVerdict,
			verdicts: "{}",
			notices:  []string{"::notice::agent: success, 3 turns, 0s", `::error::agent: feature "scan" has verdict "ok"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputs, notices := parseQAResult([]byte(tt.raw), tt.readErr)
			if len(outputs) != 2 || outputs[0] != "structured_output="+tt.verdicts || !strings.HasPrefix(outputs[1], "usage=") {
				t.Errorf("outputs = %q, want structured_output=%s then usage=", outputs, tt.verdicts)
			}
			if len(notices) != len(tt.notices) {
				t.Fatalf("notices = %q, want %q", notices, tt.notices)
			}
			for i, want := range tt.notices {
				if !strings.HasPrefix(notices[i], want) {
					t.Errorf("notice %d = %q, want prefix %q", i, notices[i], want)
				}
			}
		})
	}
	outputs, _ := parseQAResult([]byte(resultPass), nil)
	if want := `usage={"cost_usd":0.014,"duration_ms":32852,"tokens":{"input_tokens":20,"output_tokens":3000,"cache_read_input_tokens":498042,"cache_creation_input_tokens":32616},"turns":14}`; outputs[1] != want {
		t.Errorf("usage = %s, want %s", outputs[1], want)
	}
}

func TestQAResultCommandAlwaysSucceeds(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"qa-result", "--file", filepath.Join(t.TempDir(), "none.json")}, &out, &errOut); code != 0 {
		t.Errorf("missing file: exit %d, want 0 (the report job fails, after the evidence uploads)", code)
	}
	if !strings.HasPrefix(out.String(), "structured_output={}\n") {
		t.Errorf("stdout = %q", out.String())
	}
	if code := run([]string{"qa-result"}, &out, &errOut); code != 2 {
		t.Errorf("no --file: exit %d, want 2", code)
	}
}
