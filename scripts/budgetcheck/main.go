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

// Command budgetcheck keeps the verify skill's budget file honest. It reads
// .claude/skills/verify/budgets.json and the METRICS list of
// .claude/skills/verify/scripts/budgets.sh, and never runs a measurement.
//
// Usage (from the repository root):
//
//	go run ./scripts/budgetcheck [--root DIR]
//
// It fails when:
//   - a budget names a key budgets.sh does not measure, or budgets.sh
//     measures a key with no budget;
//   - a budget has no why, no unit, an unknown kind or field, or a measured
//     value that is not positive;
//   - a limit is below its measured value (the budget is already broken);
//   - a deterministic limit is more than 10% over its measured value: a
//     deterministic quantity is loosened by re-measuring it, not by raising
//     the limit alone;
//   - the file does not say when, on what machine and how it was measured.
//
// It exits 0 when the file is honest, 1 listing every problem, and 2 on a
// usage error or an unreadable file.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	budgetsPath = ".claude/skills/verify/budgets.json"
	scriptPath  = ".claude/skills/verify/scripts/budgets.sh"
)

// Kinds of quantity. A deterministic one is the same on every run of one
// build; a noisy one is a timing or a memory peak.
const (
	kindDeterministic = "deterministic"
	kindNoisy         = "noisy"
)

// deterministicHeadroom is how far over its measured value a deterministic
// limit may sit: the measured maximum plus about 10%.
const deterministicHeadroom = 1.10

type budgetFile struct {
	Measured measurement                `json:"measured"`
	Budgets  map[string]budget          `json:"budgets"`
	Tracked  map[string]json.RawMessage `json:"tracked"`
}

type measurement struct {
	Date    string `json:"date"`
	Commit  string `json:"commit"`
	Machine string `json:"machine"`
	Method  string `json:"method"`
}

type budget struct {
	Kind     string `json:"kind"`
	Unit     string `json:"unit"`
	Measured int64  `json:"measured"`
	Limit    int64  `json:"limit"`
	Why      string `json:"why"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("budgetcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository root")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return emit(stderr, 2, "usage: budgetcheck [--root DIR]\n")
	}
	problems, err := check(*root)
	if err != nil {
		return emit(stderr, 2, err.Error()+"\n")
	}
	if len(problems) > 0 {
		var out strings.Builder
		for _, p := range problems {
			out.WriteString("FAIL " + p + "\n")
		}
		return emit(stdout, 1, out.String())
	}
	return emit(stdout, 0, fmt.Sprintf("ok: %s matches the metrics of %s\n", budgetsPath, scriptPath))
}

// emit writes text and returns code; output that could not be written turns a
// success into a failure.
func emit(w io.Writer, code int, text string) int {
	if _, err := io.WriteString(w, text); err != nil && code == 0 {
		return 1
	}
	return code
}

// check reads both files under root and returns every problem found.
func check(root string) ([]string, error) {
	script, err := os.ReadFile(filepath.Join(root, scriptPath))
	if err != nil {
		return nil, fmt.Errorf("budgetcheck: read the checker: %w", err)
	}
	metrics, err := scriptMetrics(script)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(root, budgetsPath))
	if err != nil {
		return nil, fmt.Errorf("budgetcheck: read the budget file: %w", err)
	}
	var file budgetFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return []string{fmt.Sprintf("%s: %v", budgetsPath, err)}, nil
	}
	return validate(file, metrics), nil
}

var metricsLine = regexp.MustCompile(`(?m)^METRICS=\(([^)]*)\)$`)

// scriptMetrics returns the keys of the one METRICS=(...) line of budgets.sh.
func scriptMetrics(script []byte) ([]string, error) {
	lines := metricsLine.FindAllSubmatch(script, -1)
	if len(lines) != 1 {
		return nil, fmt.Errorf("budgetcheck: %s needs exactly one METRICS=(...) line, found %d", scriptPath, len(lines))
	}
	metrics := strings.Fields(string(lines[0][1]))
	if len(metrics) == 0 {
		return nil, errors.New("budgetcheck: METRICS in " + scriptPath + " is empty")
	}
	return metrics, nil
}

func validate(file budgetFile, metrics []string) []string {
	var problems []string
	m := file.Measured
	if _, err := time.Parse(time.DateOnly, m.Date); err != nil {
		problems = append(problems, fmt.Sprintf("measured.date %q is not a YYYY-MM-DD date", m.Date))
	}
	for _, field := range []struct{ name, value string }{{"commit", m.Commit}, {"machine", m.Machine}, {"method", m.Method}} {
		if strings.TrimSpace(field.value) == "" {
			problems = append(problems, "measured."+field.name+" is empty: say what the budgets were measured on and how")
		}
	}

	for _, key := range metrics {
		if _, ok := file.Budgets[key]; !ok {
			problems = append(problems, fmt.Sprintf("metric %s: budgets.sh measures it but budgets.json has no budget", key))
		}
	}
	keys := make([]string, 0, len(file.Budgets))
	for key := range file.Budgets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b := file.Budgets[key]
		if !slices.Contains(metrics, key) {
			problems = append(problems, fmt.Sprintf("budget %s: budgets.sh does not measure it", key))
		}
		problems = append(problems, validateBudget(key, b)...)
	}
	return problems
}

func validateBudget(key string, b budget) []string {
	var problems []string
	if strings.TrimSpace(b.Why) == "" {
		problems = append(problems, fmt.Sprintf("budget %s: limit %d has no why", key, b.Limit))
	}
	if strings.TrimSpace(b.Unit) == "" {
		problems = append(problems, fmt.Sprintf("budget %s: no unit", key))
	}
	if b.Measured <= 0 {
		problems = append(problems, fmt.Sprintf("budget %s: measured %d is not a measurement", key, b.Measured))
		return problems
	}
	if b.Limit < b.Measured {
		problems = append(problems, fmt.Sprintf("budget %s: limit %d is below its measured %d, so every run breaks it", key, b.Limit, b.Measured))
	}
	switch b.Kind {
	case kindDeterministic:
		if most := int64(math.Ceil(float64(b.Measured) * deterministicHeadroom)); b.Limit > most {
			problems = append(problems, fmt.Sprintf("budget %s: limit %d is over its measured %d plus 10%% (%d); re-measure instead of loosening it", key, b.Limit, b.Measured, most))
		}
	case kindNoisy:
	default:
		problems = append(problems, fmt.Sprintf("budget %s: kind %q is neither %s nor %s", key, b.Kind, kindDeterministic, kindNoisy))
	}
	return problems
}
