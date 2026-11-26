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

// Package deadcode detects and filters cryptographic findings that fall inside
// C/C++ preprocessor dead code blocks (e.g., #if 0 ... #endif).
package deadcode

import (
	"bufio"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// Region represents a contiguous block of dead code delimited by preprocessor directives.
type Region struct {
	StartLine int // line number of the #if 0 directive
	EndLine   int // line number of the matching #endif (or #else/#elif at depth 1)
}

// Compiled regexes for preprocessor directive detection.
var (
	reIfDirective = regexp.MustCompile(`^\s*#\s*if\s+(.+)`)
	reIfdef       = regexp.MustCompile(`^\s*#\s*if(?:n?def)\b`)
	reElif        = regexp.MustCompile(`^\s*#\s*elif\b`)
	reElse        = regexp.MustCompile(`^\s*#\s*else\b`)
	reEndif       = regexp.MustCompile(`^\s*#\s*endif\b`)

	// Patterns for statically-false expression evaluation.
	reLiteralZero  = regexp.MustCompile(`^0+$`)
	reHexZero      = regexp.MustCompile(`^0[xX]0+$`)
	reNotOne       = regexp.MustCompile(`^!\s*1$`)
	reShortCircuit = regexp.MustCompile(`^0\s*&&`)
)

// isStaticallyFalse evaluates whether a preprocessor #if expression is
// statically determinable as false (zero). It handles:
//   - #if 0, #if 00 (decimal/octal zero)
//   - #if 0x0, #if 0X00 (hex zero)
//   - #if (0), #if ((0)) (parenthesized zero)
//   - #if !1 (logical NOT of 1)
//   - #if 0 && <anything> (short-circuit, always false)
func isStaticallyFalse(expr string) bool {
	expr = stripTrailingComment(expr)
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}

	// Check short-circuit first (before stripping parens): 0 && <anything>
	if reShortCircuit.MatchString(expr) {
		return true
	}

	// Strip outer parentheses: (0) → 0, ((0)) → 0
	expr = stripOuterParens(expr)

	if reLiteralZero.MatchString(expr) {
		return true
	}
	if reHexZero.MatchString(expr) {
		return true
	}
	if reNotOne.MatchString(expr) {
		return true
	}

	return false
}

// stripTrailingComment removes C-style trailing comments from an expression.
// "0 // comment" → "0", "0 /* comment */" → "0".
func stripTrailingComment(s string) string {
	if idx := strings.Index(s, "//"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "/*"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// stripOuterParens removes balanced outer parentheses: ((0)) → 0.
func stripOuterParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		inner := s[1 : len(s)-1]
		// Verify the parens are actually matching (not "(a)+(b)")
		depth := 0
		balanced := true
		for _, ch := range inner {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					balanced = false
				}
			}
		}
		if !balanced || depth != 0 {
			break
		}
		s = strings.TrimSpace(inner)
	}
	return s
}

// FindDeadRegions scans a C/C++ file and returns all preprocessor dead code regions.
// A dead region is a block of code inside a statically-false #if expression
// (e.g., #if 0) up to its matching #endif, #else, or #elif.
func FindDeadRegions(filePath string) ([]Region, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn().Err(cerr).Str("file", filePath).Msg("Failed to close file")
		}
	}()

	var t regionTracker
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		t.line(lineNum, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return t.regions, nil
}

// DeadRegionsOfLines returns the dead regions of a file known by some of its
// lines (line number to text), as FindDeadRegions finds them in the whole
// file when the lines hold every directive RegionDirectives keeps. A line
// not listed reads as code.
func DeadRegionsOfLines(lines map[int]string) []Region {
	var t regionTracker
	for _, n := range slices.Sorted(maps.Keys(lines)) {
		t.line(n, lines[n])
	}
	return t.regions
}

// RegionDirectives returns, of a file's lines (fileLines[0] is line 1), the
// preprocessor conditionals written inside its dead regions, by line
// number: the opening statically-false #if, the conditionals nested in it
// and the line that closes the region. DeadRegionsOfLines finds the same
// regions from them, whatever other lines of the file it is given.
func RegionDirectives(fileLines []string) map[int]string {
	var t regionTracker
	for i, line := range fileLines {
		t.line(i+1, line)
	}
	if len(t.regions) == 0 {
		return nil
	}
	out := make(map[int]string)
	for _, r := range t.regions {
		for n := r.StartLine; n <= r.EndLine && n <= len(fileLines); n++ {
			if line := fileLines[n-1]; isConditional(line) {
				out[n] = line
			}
		}
	}
	return out
}

// isConditional reports a preprocessor conditional line: #if, #ifdef,
// #ifndef, #elif, #else or #endif.
func isConditional(line string) bool {
	return matchesIfFamily(line) || reElif.MatchString(line) || reElse.MatchString(line) || reEndif.MatchString(line)
}

// regionTracker follows a file's lines in order and collects its dead
// regions.
type regionTracker struct {
	regions   []Region
	deadStart int
	deadDepth int
}

// line reads line lineNum of the file.
func (t *regionTracker) line(lineNum int, line string) {
	if t.deadDepth > 0 {
		t.deadDepth, t.regions = trackDeadBlock(line, t.deadDepth, t.deadStart, lineNum, t.regions)
		return
	}
	// Live code — check for statically-false #if directives.
	if reIfdef.MatchString(line) {
		// #ifdef / #ifndef are not statically evaluable — skip.
		return
	}
	if m := reIfDirective.FindStringSubmatch(line); len(m) > 1 && isStaticallyFalse(m[1]) {
		t.deadStart = lineNum
		t.deadDepth = 1
	}
}

// trackDeadBlock processes a single line while inside a dead code block,
// tracking nesting depth and closing the region when appropriate.
func trackDeadBlock(line string, deadDepth, deadStart, lineNum int, regions []Region) (int, []Region) {
	switch {
	case matchesIfFamily(line):
		deadDepth++
	case reElif.MatchString(line) || reElse.MatchString(line):
		if deadDepth == 1 {
			// The #else/#elif branch of the outermost #if 0 IS compiled.
			regions = append(regions, Region{StartLine: deadStart, EndLine: lineNum})
			deadDepth = 0
		}
	case reEndif.MatchString(line):
		deadDepth--
		if deadDepth == 0 {
			regions = append(regions, Region{StartLine: deadStart, EndLine: lineNum})
		}
	}
	return deadDepth, regions
}

// matchesIfFamily returns true if the line is any #if, #ifdef, or #ifndef directive.
func matchesIfFamily(line string) bool {
	return reIfDirective.MatchString(line) || reIfdef.MatchString(line)
}

// IsInsideDeadRegion checks whether a line range [startLine, endLine] falls
// entirely within any dead code region.
func IsInsideDeadRegion(regions []Region, startLine, endLine int) bool {
	for _, r := range regions {
		if startLine >= r.StartLine && endLine <= r.EndLine {
			return true
		}
	}
	return false
}
