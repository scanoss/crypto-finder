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

package deadcode

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFindDeadRegions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		file     string
		expected []Region
	}{
		{
			name: "simple #if 0 block",
			file: "dead_code.c",
			expected: []Region{
				{StartLine: 9, EndLine: 14},
				{StartLine: 21, EndLine: 26},
			},
		},
		{
			name: "nested #if inside #if 0",
			file: "nested_dead_code.c",
			expected: []Region{
				{StartLine: 9, EndLine: 24},
			},
		},
		{
			name: "#if 0 with #else — dead region stops at #else",
			file: "if0_else.c",
			expected: []Region{
				{StartLine: 4, EndLine: 9},
			},
		},
		{
			name: "all statically-false variants",
			file: "variants.c",
			expected: []Region{
				{StartLine: 7, EndLine: 10},  // #if (0)
				{StartLine: 15, EndLine: 18}, // #if 0x0
				{StartLine: 23, EndLine: 26}, // #if 00
				{StartLine: 31, EndLine: 34}, // #if !1
				{StartLine: 39, EndLine: 42}, // #if 0 && FEATURE_ENABLED
			},
		},
		{
			name:     "no dead code — #ifdef and #if 0x1 are not statically false",
			file:     "no_dead_code.c",
			expected: []Region{},
		},
	}

	testdataDir := filepath.Join("..", "..", "testdata", "code", "c")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filePath := filepath.Join(testdataDir, tt.file)
			regions, err := FindDeadRegions(filePath)
			if err != nil {
				t.Fatalf("FindDeadRegions(%s) returned error: %v", tt.file, err)
			}

			if len(regions) != len(tt.expected) {
				t.Fatalf("expected %d regions, got %d: %+v", len(tt.expected), len(regions), regions)
			}

			for i, r := range regions {
				if r.StartLine != tt.expected[i].StartLine || r.EndLine != tt.expected[i].EndLine {
					t.Errorf("region[%d]: expected {%d, %d}, got {%d, %d}",
						i, tt.expected[i].StartLine, tt.expected[i].EndLine, r.StartLine, r.EndLine)
				}
			}
		})
	}
}

func TestFindDeadRegions_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := FindDeadRegions("/nonexistent/file.c")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestIsStaticallyFalse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expr     string
		expected bool
	}{
		// True — statically false expressions
		{"0", true},
		{"00", true},
		{"000", true},
		{"0x0", true},
		{"0X0", true},
		{"0x00", true},
		{"(0)", true},
		{"((0))", true},
		{"!1", true},
		{"! 1", true},
		{"0 && FEATURE", true},
		{"0&&ANYTHING", true},
		{"0 // comment", true},
		{"0 /* comment */", true},

		// False — NOT statically false
		{"1", false},
		{"0x1", false},
		{"0x0F", false},
		{"01", false},         // octal 1
		{"0 || MACRO", false}, // could be true
		{"!0", false},
		{"DEFINED", false},
		{"", false},
		{"1 && 0", false}, // would need full evaluation
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			t.Parallel()
			if got := isStaticallyFalse(tt.expr); got != tt.expected {
				t.Errorf("isStaticallyFalse(%q) = %v, want %v", tt.expr, got, tt.expected)
			}
		})
	}
}

func TestIsInsideDeadRegion(t *testing.T) {
	t.Parallel()

	regions := []Region{
		{StartLine: 10, EndLine: 20},
		{StartLine: 30, EndLine: 40},
	}

	tests := []struct {
		name      string
		startLine int
		endLine   int
		expected  bool
	}{
		{"fully inside first region", 12, 15, true},
		{"at boundary of first region", 10, 20, true},
		{"start inside, end outside", 15, 25, false},
		{"fully outside between regions", 22, 28, false},
		{"fully inside second region", 32, 38, true},
		{"before all regions", 1, 5, false},
		{"after all regions", 45, 50, false},
		{"single line inside", 15, 15, true},
		{"single line outside", 25, 25, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsInsideDeadRegion(regions, tt.startLine, tt.endLine); got != tt.expected {
				t.Errorf("IsInsideDeadRegion(%d, %d) = %v, want %v",
					tt.startLine, tt.endLine, got, tt.expected)
			}
		})
	}
}

func TestFindDeadRegions_WhitespaceVariations(t *testing.T) {
	t.Parallel()

	content := `line 1
  #  if  0
dead code
  #  endif
line 5
`
	tmpFile := filepath.Join(t.TempDir(), "whitespace.c")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	regions, err := FindDeadRegions(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(regions) != 1 {
		t.Fatalf("expected 1 region, got %d: %+v", len(regions), regions)
	}
	if regions[0].StartLine != 2 || regions[0].EndLine != 4 {
		t.Errorf("expected {2, 4}, got {%d, %d}", regions[0].StartLine, regions[0].EndLine)
	}
}

func TestFindDeadRegions_If0ElseElif(t *testing.T) {
	t.Parallel()

	content := `line 1
#if 0
dead
#elif SOMETHING
live elif
#else
live else
#endif
line 9
`
	tmpFile := filepath.Join(t.TempDir(), "elif.c")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	regions, err := FindDeadRegions(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(regions) != 1 {
		t.Fatalf("expected 1 region, got %d: %+v", len(regions), regions)
	}
	// Dead region: #if 0 (line 2) to #elif (line 4)
	if regions[0].StartLine != 2 || regions[0].EndLine != 4 {
		t.Errorf("expected {2, 4}, got {%d, %d}", regions[0].StartLine, regions[0].EndLine)
	}
}

// The conditionals RegionDirectives keeps give DeadRegionsOfLines the
// regions FindDeadRegions finds in the whole file, whatever other lines of
// the file come with them: a fragment holds them beside the lines of its
// call sites, among them conditionals of the file's live code and of blocks
// nested in a dead one.
func TestRegionDirectivesRebuildTheRegions(t *testing.T) {
	t.Parallel()

	testdataDir := filepath.Join("..", "..", "testdata", "code", "c")
	for _, file := range []string{"dead_code.c", "nested_dead_code.c", "if0_else.c", "variants.c", "no_dead_code.c"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(testdataDir, file)
			want, err := FindDeadRegions(path)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fileLines := strings.Split(string(data), "\n")
			kept := RegionDirectives(fileLines)
			if got := DeadRegionsOfLines(kept); !slices.Equal(got, want) {
				t.Fatalf("regions of the kept lines = %+v, want %+v", got, want)
			}
			// Every other line along with them: each conditional, then all.
			withConditionals := maps.Clone(kept)
			if withConditionals == nil {
				withConditionals = map[int]string{}
			}
			all := map[int]string{}
			for i, line := range fileLines {
				all[i+1] = line
				if isConditional(line) {
					withConditionals[i+1] = line
				}
			}
			for name, lines := range map[string]map[int]string{"conditionals": withConditionals, "all": all} {
				if got := DeadRegionsOfLines(lines); !slices.Equal(got, want) {
					t.Errorf("regions of %s = %+v, want %+v", name, got, want)
				}
			}
		})
	}
}

// A block nested in a dead one closes the region only with its own
// conditionals: kept without them, its #else would end the region early.
func TestRegionDirectivesKeepNestedConditionals(t *testing.T) {
	t.Parallel()

	fileLines := []string{
		"#if 0",          // 1
		"#ifdef FEATURE", // 2
		"call(a,",        // 3
		"#else",          // 4
		"  b);",          // 5
		"#endif",         // 6
		"dead();",        // 7
		"#endif",         // 8
		"live();",        // 9
	}
	kept := RegionDirectives(fileLines)
	for _, n := range []int{1, 2, 4, 6, 8} {
		if kept[n] != fileLines[n-1] {
			t.Errorf("line %d not kept: %v", n, kept)
		}
	}
	// A fragment holds lines 3-5 of the call; with 2 kept, 4 does not close.
	lines := maps.Clone(kept)
	lines[3], lines[5] = fileLines[2], fileLines[4]
	if got, want := DeadRegionsOfLines(lines), []Region{{StartLine: 1, EndLine: 8}}; !slices.Equal(got, want) {
		t.Fatalf("regions = %+v, want %+v", got, want)
	}
}
