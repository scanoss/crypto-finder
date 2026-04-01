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
	"os"
	"regexp"
	"strings"
)

// Region represents a contiguous block of dead code delimited by preprocessor directives.
type Region struct {
	StartLine int // line number of the #if 0 directive
	EndLine   int // line number of the matching #endif (or #else/#elif at depth 1)
}

// Compiled regexes for preprocessor directive detection.
var (
	reIfDirective = regexp.MustCompile(`^\s*#\s*if\s+(.+)`)
	reIfdef       = regexp.MustCompile(`^\s*#\s*if(?:def|ndef)\b`)
	reElif        = regexp.MustCompile(`^\s*#\s*elif\b`)
	reElse        = regexp.MustCompile(`^\s*#\s*else\b`)
	reEndif       = regexp.MustCompile(`^\s*#\s*endif\b`)

	// Patterns for statically-false expression evaluation.
	reLiteralZero = regexp.MustCompile(`^0+$`)
	reHexZero     = regexp.MustCompile(`^0[xX]0+$`)
	reNotOne      = regexp.MustCompile(`^!\s*1$`)
	reShortCircut = regexp.MustCompile(`^0\s*&&`)
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
	if reShortCircut.MatchString(expr) {
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
// "0 // comment" → "0", "0 /* comment */" → "0"
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
	defer f.Close()

	var regions []Region
	var deadStart int
	deadDepth := 0

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if deadDepth > 0 {
			// Inside a dead code block — track nesting.
			if matchesIfFamily(line) {
				deadDepth++
			} else if reElif.MatchString(line) || reElse.MatchString(line) {
				if deadDepth == 1 {
					// The #else/#elif branch of the outermost #if 0 IS compiled.
					regions = append(regions, Region{StartLine: deadStart, EndLine: lineNum})
					deadDepth = 0
				}
			} else if reEndif.MatchString(line) {
				deadDepth--
				if deadDepth == 0 {
					regions = append(regions, Region{StartLine: deadStart, EndLine: lineNum})
				}
			}
		} else {
			// Live code — check for statically-false #if directives.
			if reIfdef.MatchString(line) {
				// #ifdef / #ifndef are not statically evaluable — skip.
				continue
			}
			if m := reIfDirective.FindStringSubmatch(line); m != nil {
				if isStaticallyFalse(m[1]) {
					deadStart = lineNum
					deadDepth = 1
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return regions, nil
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
