// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type anchorScalingCase struct {
	name  string
	file  string
	parse func(path string) error
	// source renders a file with n sibling statements, each holding one call.
	source func(n int) string
}

func anchorScalingCases() []anchorScalingCase {
	parseGo := func(path string) error {
		_, err := NewGoParser().ParseFile(path, "example.com/gen")
		return err
	}
	parseDir := func(p Parser) func(string) error {
		return func(path string) error {
			_, err := p.ParseDirectory(filepath.Dir(path), "gen")
			return err
		}
	}
	repeat := func(n int, line func(i int) string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(line(i))
		}
		return b.String()
	}
	return []anchorScalingCase{
		{
			name:  "go_package_var_initializers",
			file:  "gen.go",
			parse: parseGo,
			source: func(n int) string {
				return "package gen\n\nfunc mk(int) int { return 0 }\n\n" + repeat(n, func(i int) string {
					return fmt.Sprintf("var v%d = mk(%d)\n", i, i)
				})
			},
		},
		{
			name:  "go_function_body",
			file:  "gen.go",
			parse: parseGo,
			source: func(n int) string {
				return "package gen\n\nfunc mk(int) int { return 0 }\n\nfunc big() {\n" + repeat(n, func(i int) string {
					return fmt.Sprintf("\tmk(%d)\n", i)
				}) + "}\n"
			},
		},
		{
			name:  "python_module_statements",
			file:  "gen.py",
			parse: parseDir(NewPythonParser()),
			source: func(n int) string {
				return "def mk(x):\n    return x\n\n" + repeat(n, func(i int) string {
					return fmt.Sprintf("mk(%d)\n", i)
				})
			},
		},
		{
			name:  "javascript_program_statements",
			file:  "gen.js",
			parse: parseDir(NewNodeParser()),
			source: func(n int) string {
				return "function mk(x) { return x; }\n" + repeat(n, func(i int) string {
					return fmt.Sprintf("mk(%d);\n", i)
				})
			},
		},
	}
}

// bestParseTime parses a freshly generated file a few times and keeps the
// fastest run, so one descheduled run on a loaded host cannot fail the test.
func bestParseTime(t *testing.T, c anchorScalingCase, n int) time.Duration {
	t.Helper()
	path := filepath.Join(t.TempDir(), c.file)
	if err := os.WriteFile(path, []byte(c.source(n)), 0o600); err != nil {
		t.Fatal(err)
	}
	best := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		if err := c.parse(path); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		best = min(best, time.Since(start))
	}
	return best
}

// TestCallAnchorsScaleLinearlyWithSiblingStatements pins the cost of call
// anchoring in files with many sibling statements (generated code: ccgo's
// modernc.org/libc has ~11k package-level declarations and ~84k calls in
// variable initializers). Linear work grows about 4x when the statement count
// grows 4x; a per-call scan of the siblings grows about 16x.
func TestCallAnchorsScaleLinearlyWithSiblingStatements(t *testing.T) {
	// Wall-clock ratios are not stable on shared CI runners under -race and
	// coverage (a 4x input measured 8.8x there), so this runs on demand.
	// TestCallAnchorsMatchReferenceWalk guards the anchors themselves.
	if os.Getenv("CRYPTO_FINDER_ANCHOR_SCALING") == "" {
		t.Skip("set CRYPTO_FINDER_ANCHOR_SCALING=1 to run the anchor scaling timing test")
	}
	const small, large = 2000, 8000
	for _, c := range anchorScalingCases() {
		t.Run(c.name, func(t *testing.T) {
			bestParseTime(t, c, 50)
			smallTime := bestParseTime(t, c, small)
			largeTime := bestParseTime(t, c, large)
			ratio := float64(largeTime) / float64(smallTime)
			t.Logf("n=%d %v, n=%d %v, ratio %.1f", small, smallTime, large, largeTime, ratio)
			if ratio > 8 {
				t.Fatalf("parse time grew %.1fx for 4x more sibling statements (n=%d %v, n=%d %v); want near-linear growth", ratio, small, smallTime, large, largeTime)
			}
		})
	}
}
