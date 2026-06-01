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

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/skip"
)

// TestBuildSkipPatterns covers the buildSkipPatterns helper across all spec scenarios.
func TestBuildSkipPatterns(t *testing.T) {
	t.Parallel()

	// -----------------------------------------------------------------------
	// Phase 2.2 baseline — current behavior (no flags, no scanoss.json)
	// -----------------------------------------------------------------------

	t.Run("defaultsOnly_noFlags", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		patterns, label := buildSkipPatterns(dir, false, nil)

		// Must contain all DefaultSkippedDirs entries
		for _, want := range skip.DefaultSkippedDirs {
			if !sliceContains(patterns, want) {
				t.Errorf("expected %q in patterns, not found. patterns=%v", want, patterns)
			}
		}

		// sourceLabel must mention both source names
		if !strings.Contains(label, "defaults") {
			t.Errorf("sourceLabel %q does not contain \"defaults\"", label)
		}
		if !strings.Contains(label, "scanoss.json") {
			t.Errorf("sourceLabel %q does not contain \"scanoss.json\"", label)
		}
	})

	// -----------------------------------------------------------------------
	// Phase 3.x — noDefaults flag
	// -----------------------------------------------------------------------

	t.Run("noDefaults", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		patterns, _ := buildSkipPatterns(dir, true, nil)

		// With no scanoss.json and noDefaults=true, result must be empty
		if len(patterns) != 0 {
			t.Errorf("expected empty patterns with noDefaults=true and no scanoss.json, got %v", patterns)
		}
	})

	t.Run("excludeOnly", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		// "vendor" is already in DefaultSkippedDirs, so dedup removes duplicate
		// "custom" is new
		patterns, _ := buildSkipPatterns(dir, false, []string{"vendor", "custom"})

		// Must still contain all DefaultSkippedDirs entries
		for _, want := range skip.DefaultSkippedDirs {
			if !sliceContains(patterns, want) {
				t.Errorf("expected %q in patterns, not found", want)
			}
		}
		// Must contain user-supplied "custom" pattern
		if !sliceContains(patterns, "custom") {
			t.Errorf("expected \"custom\" in patterns, not found. patterns=%v", patterns)
		}
	})

	t.Run("noDefaultsPlusExcludes", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		patterns, _ := buildSkipPatterns(dir, true, []string{"docs", "build"})

		if !sliceContains(patterns, "docs") {
			t.Errorf("expected \"docs\" in patterns, not found. patterns=%v", patterns)
		}
		if !sliceContains(patterns, "build") {
			t.Errorf("expected \"build\" in patterns, not found. patterns=%v", patterns)
		}

		// Must NOT contain DefaultSkippedDirs entries that were not in userExcludes
		for _, def := range skip.DefaultSkippedDirs {
			if def == "docs" || def == "build" {
				continue // overlap — appear because user asked for them
			}
			if sliceContains(patterns, def) {
				t.Errorf("unexpected DefaultSkippedDirs entry %q in noDefaults result. patterns=%v", def, patterns)
			}
		}
	})

	t.Run("whitespaceExcludesDropped", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		patterns, _ := buildSkipPatterns(dir, true, []string{"", "  ", "docs"})

		if len(patterns) != 1 || patterns[0] != "docs" {
			t.Errorf("expected exactly [\"docs\"], got %v", patterns)
		}
	})

	// -----------------------------------------------------------------------
	// Phase 4.1 — truth table (R4) — compose buildSkipPatterns + applyTestSkipPatterns
	// -----------------------------------------------------------------------

	t.Run("truthTable", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		type row struct {
			name           string
			noDefaults     bool
			includeTests   bool
			wantDirEntry   string // entry that SHOULD be present (from DefaultSkippedDirs)
			wantDirAbsent  string // entry that MUST be absent (DefaultSkippedDirs when noDefaults)
			wantTestEntry  string // test pattern that SHOULD be present when !includeTests
			wantTestAbsent string // test pattern that MUST be absent when includeTests
		}

		rows := []row{
			// T4d: -N=false, -T=false — full defaults
			{
				name:          "noDefaultsFalseIncludeTestsFalse",
				noDefaults:    false,
				includeTests:  false,
				wantDirEntry:  "node_modules",
				wantTestEntry: "test/",
			},
			// T4a: -N=false, -T=true — dirs kept, test patterns removed
			{
				name:           "noDefaultsFalseIncludeTestsTrue",
				noDefaults:     false,
				includeTests:   true,
				wantDirEntry:   "node_modules",
				wantTestAbsent: "test/",
			},
			// T4b: -N=true, -T=false — dirs removed, test patterns kept
			{
				name:          "noDefaultsTrueIncludeTestsFalse",
				noDefaults:    true,
				includeTests:  false,
				wantDirAbsent: "docs",
				wantTestEntry: "test/",
			},
			// T4c: -N=true, -T=true — both empty
			{
				name:           "noDefaultsTrueIncludeTestsTrue",
				noDefaults:     true,
				includeTests:   true,
				wantDirAbsent:  "docs",
				wantTestAbsent: "test/",
			},
		}

		for _, r := range rows {
			r := r
			t.Run(r.name, func(t *testing.T) {
				t.Parallel()

				patterns, _ := buildSkipPatterns(dir, r.noDefaults, nil)
				effective := applyTestSkipPatterns(patterns, r.includeTests)

				if r.wantDirEntry != "" && !sliceContains(effective, r.wantDirEntry) {
					t.Errorf("[%s] expected dir entry %q in effective patterns. got=%v", r.name, r.wantDirEntry, effective)
				}
				if r.wantDirAbsent != "" && sliceContains(effective, r.wantDirAbsent) {
					t.Errorf("[%s] unexpected dir entry %q in effective patterns (should be absent). got=%v", r.name, r.wantDirAbsent, effective)
				}
				if r.wantTestEntry != "" && !sliceContains(effective, r.wantTestEntry) {
					t.Errorf("[%s] expected test pattern %q in effective patterns. got=%v", r.name, r.wantTestEntry, effective)
				}
				if r.wantTestAbsent != "" && sliceContains(effective, r.wantTestAbsent) {
					t.Errorf("[%s] unexpected test pattern %q in effective patterns (should be absent). got=%v", r.name, r.wantTestAbsent, effective)
				}
			})
		}
	})

	// -----------------------------------------------------------------------
	// Phase 4.2 — dedup and co-existence (R6, R9, R10)
	// -----------------------------------------------------------------------

	t.Run("duplicateExcludesDeduped", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		// noDefaults=true so only userExcludes contribute
		patterns, _ := buildSkipPatterns(dir, true, []string{"mydir", "mydir"})

		// "mydir" must appear exactly once after MultiSource dedup
		count := 0
		for _, p := range patterns {
			if p == "mydir" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected \"mydir\" exactly once, got %d occurrences. patterns=%v", count, patterns)
		}
	})

	t.Run("scanossConfigPlusCLIExclude", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		// Write a minimal scanoss.json with pattern "foo"
		scanossJSON := `{"settings":{"skip":{"patterns":{"scanning":["foo"]}}}}`
		if err := os.WriteFile(filepath.Join(dir, "scanoss.json"), []byte(scanossJSON), 0o600); err != nil {
			t.Fatalf("write scanoss.json: %v", err)
		}

		patterns, _ := buildSkipPatterns(dir, true, []string{"bar"})

		if !sliceContains(patterns, "foo") {
			t.Errorf("expected \"foo\" (from scanoss.json) in patterns. got=%v", patterns)
		}
		if !sliceContains(patterns, "bar") {
			t.Errorf("expected \"bar\" (from --exclude) in patterns. got=%v", patterns)
		}

		// No duplicates
		seen := make(map[string]int)
		for _, p := range patterns {
			seen[p]++
		}
		for p, cnt := range seen {
			if cnt > 1 {
				t.Errorf("duplicate pattern %q appears %d times", p, cnt)
			}
		}
	})

	t.Run("emptyExcludeDropped", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		patterns, _ := buildSkipPatterns(dir, true, []string{""})

		for _, p := range patterns {
			if strings.TrimSpace(p) == "" {
				t.Errorf("found empty/whitespace pattern in output: %q. patterns=%v", p, patterns)
			}
		}
	})

	// -----------------------------------------------------------------------
	// Phase 4.3 — fallback regression (R8)
	// -----------------------------------------------------------------------

	t.Run("scanossConfigLoadError", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		// Write malformed scanoss.json to trigger a load error
		if err := os.WriteFile(filepath.Join(dir, "scanoss.json"), []byte("this is not json {{{"), 0o600); err != nil {
			t.Fatalf("write malformed scanoss.json: %v", err)
		}

		t.Run("noDefaultsTrue_fallbackEmpty", func(t *testing.T) {
			patterns, _ := buildSkipPatterns(dir, true, nil)

			// With noDefaults=true and load error, fallback must NOT contain DefaultSkippedDirs
			for _, p := range patterns {
				for _, def := range skip.DefaultSkippedDirs {
					if p == def {
						t.Errorf("unexpected DefaultSkippedDirs entry %q in fallback when noDefaults=true", p)
					}
				}
			}
		})

		t.Run("noDefaultsFalse_fallbackHasDefaults", func(t *testing.T) {
			patterns, _ := buildSkipPatterns(dir, false, nil)

			// With noDefaults=false and load error, fallback must include DefaultSkippedDirs
			for _, want := range skip.DefaultSkippedDirs {
				if !sliceContains(patterns, want) {
					t.Errorf("expected DefaultSkippedDirs entry %q in fallback when noDefaults=false", want)
				}
			}
		})

		t.Run("userExcludesMergedIntoFallback", func(t *testing.T) {
			patterns, _ := buildSkipPatterns(dir, true, []string{"custom"})

			if !sliceContains(patterns, "custom") {
				t.Errorf("expected \"custom\" in fallback even with load error. got=%v", patterns)
			}
		})
	})
}

// TestBuildSkipPatterns_WarnEmission tests warn log emission for R7/NF1.
// This test is intentionally NOT parallelized because it replaces the
// zerolog/log package-level Logger, which is not safe to swap under races.
func TestBuildSkipPatterns_WarnEmission(t *testing.T) {
	dir := t.TempDir()

	t.Run("noDefaultsTrue_emitsWarn", func(t *testing.T) {
		var buf bytes.Buffer
		captureLogger := zerolog.New(&buf).Level(zerolog.WarnLevel)

		old := zlog.Logger
		zlog.Logger = captureLogger
		defer func() { zlog.Logger = old }()

		buildSkipPatterns(dir, true, nil)

		output := buf.String()
		warnCount := countWarnLines(t, output, "Default directory exclusions are disabled")
		if warnCount != 1 {
			t.Errorf("expected exactly 1 warn containing %q, got %d. full output:\n%s",
				"Default directory exclusions are disabled", warnCount, output)
		}
	})

	t.Run("noDefaultsFalse_noWarn", func(t *testing.T) {
		var buf bytes.Buffer
		captureLogger := zerolog.New(&buf).Level(zerolog.WarnLevel)

		old := zlog.Logger
		zlog.Logger = captureLogger
		defer func() { zlog.Logger = old }()

		buildSkipPatterns(dir, false, nil)

		output := buf.String()
		warnCount := countWarnLines(t, output, "Default directory exclusions are disabled")
		if warnCount != 0 {
			t.Errorf("expected 0 warns containing %q when noDefaults=false, got %d. output:\n%s",
				"Default directory exclusions are disabled", warnCount, output)
		}
	})
}

// countWarnLines counts log lines at warn level whose "message" field contains substr.
// zerolog emits JSON lines by default; each line is one log entry.
func countWarnLines(t *testing.T, output, substr string) int {
	t.Helper()
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// If not JSON, try plain-text match (just in case logger format changed)
			if strings.Contains(line, "warn") && strings.Contains(line, substr) {
				count++
			}
			continue
		}
		level, _ := entry["level"].(string)
		msg, _ := entry["message"].(string)
		if level == "warn" && strings.Contains(msg, substr) {
			count++
		}
	}
	return count
}
