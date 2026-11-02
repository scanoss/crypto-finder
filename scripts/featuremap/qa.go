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
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// selectFeatures splits the features a change touched into the ones one run
// drives (at most limit, in id order) and the rest.
func selectFeatures(features []feature, changed []string, limit int) (chosen, left []string) {
	ids := sortedKeys(touched(features, changed))
	if len(ids) <= limit {
		return ids, nil
	}
	return ids[:limit], ids[limit:]
}

// runSelect prints, space-separated, the features the diff from base to head
// touched, with the same matching check-pr uses. Over limit, the rest are named
// on stderr and not printed, so one large merge cannot run up the agent's turns.
func runSelect(root, base, head string, limit int, stdout, stderr *printer) error {
	if base == "" || head == "" || limit < 1 {
		return fmt.Errorf("%w: select needs --base, --head and a --max of at least 1", errUsage)
	}
	features, err := loadRepoFeatures(root)
	if err != nil {
		return err
	}
	changed, err := changedFiles(root, base, head)
	if err != nil {
		return err
	}
	chosen, left := selectFeatures(features, changed, limit)
	if len(left) > 0 {
		stderr.printf("not driven this run (over --max %d): %s\n", limit, strings.Join(left, " "))
	}
	stdout.println(strings.Join(chosen, " "))
	return nil
}

// agentResult is the part of `claude -p --output-format json` the QA reads.
type agentResult struct {
	Subtype          string          `json:"subtype"`
	IsError          bool            `json:"is_error"`
	NumTurns         int             `json:"num_turns"`
	DurationMS       int64           `json:"duration_ms"`
	TotalCostUSD     float64         `json:"total_cost_usd"`
	Result           string          `json:"result"`
	StructuredOutput json.RawMessage `json:"structured_output"`
	Usage            agentUsage      `json:"usage"`
}

// agentUsage is the token count of one run. cost_usd beside it is Claude
// Code's own list-price estimate; the subscription seat bills nothing per run.
type agentUsage struct {
	Input         int `json:"input_tokens"`
	Output        int `json:"output_tokens"`
	CacheRead     int `json:"cache_read_input_tokens"`
	CacheCreation int `json:"cache_creation_input_tokens"`
}

// qaVerdicts is the --json-schema shape the agent answers in.
type qaVerdicts struct {
	Features []struct {
		ID      string `json:"id"`
		Verdict string `json:"verdict"`
		Summary string `json:"summary"`
	} `json:"features"`
}

// parseQAResult turns the agent's output file into GITHUB_OUTPUT lines (the
// verdicts, "{}" when there are none, and the agent's usage) plus notices for
// the log. A missing or malformed file, a turn-capped run and an answer outside
// the schema all yield "{}", which the report job fails on.
func parseQAResult(raw []byte, readErr error) (outputs, notices []string) {
	verdicts, usage, notices := readQAResult(raw, readErr)
	return []string{"structured_output=" + verdicts, "usage=" + usage}, notices
}

func readQAResult(raw []byte, readErr error) (verdicts, usage string, notices []string) {
	verdicts, usage = "{}", "{}"
	if readErr != nil {
		return verdicts, usage, []string{"::error::agent: no result file: " + readErr.Error()}
	}
	var r agentResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return verdicts, usage, []string{"::error::agent: result is not JSON: " + err.Error()}
	}
	notices = append(notices, fmt.Sprintf("::notice::agent: %s, %d turns, %ds", r.Subtype, r.NumTurns, r.DurationMS/1000))
	if r.IsError {
		why := r.Result
		if why == "" {
			why = r.Subtype
		}
		notices = append(notices, "::error::agent: "+truncate(why, 500))
	}
	if u, err := json.Marshal(map[string]any{"turns": r.NumTurns, "duration_ms": r.DurationMS, "cost_usd": r.TotalCostUSD, "tokens": r.Usage}); err == nil {
		usage = string(u)
	}
	var v qaVerdicts
	if len(r.StructuredOutput) == 0 || json.Unmarshal(r.StructuredOutput, &v) != nil || len(v.Features) == 0 {
		return verdicts, usage, append(notices, "::error::agent: no verdict in the result")
	}
	for _, f := range v.Features {
		switch f.Verdict {
		case "pass", "fail", "unreachable":
		default:
			return verdicts, usage, append(notices, fmt.Sprintf("::error::agent: feature %q has verdict %q", f.ID, f.Verdict))
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return verdicts, usage, append(notices, "::error::agent: "+err.Error())
	}
	return string(b), usage, notices
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// runQAResult prints parseQAResult's outputs on stdout (for GITHUB_OUTPUT) and
// its notices on stderr. Given a --file, it succeeds: a missing verdict is the report
// job's failure, so the evidence still uploads.
func runQAResult(file string, stdout, stderr *printer) error {
	if file == "" {
		return fmt.Errorf("%w: qa-result needs --file", errUsage)
	}
	raw, err := os.ReadFile(file) // #nosec G703 -- CI helper; the result file is a flag
	outputs, notices := parseQAResult(raw, err)
	for _, n := range notices {
		stderr.println(n)
	}
	for _, o := range outputs {
		stdout.println(o)
	}
	return nil
}
