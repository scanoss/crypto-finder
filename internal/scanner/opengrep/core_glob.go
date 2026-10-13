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
	"strings"
)

// excludeMatcher applies --exclude patterns the way the opengrep CLI does:
// each pattern P becomes the wcmatch globs **/P and **/P/** (GLOBSTAR and
// DOTGLOB), matched against the whole path string the CLI holds, absolute
// or relative as the target was given.
type excludeMatcher struct {
	globs [][]string
}

func newExcludeMatcher(patterns []string) *excludeMatcher {
	m := &excludeMatcher{}
	for _, pattern := range patterns {
		m.globs = append(m.globs, splitGlob("**/"+pattern), splitGlob("**/"+pattern+"/**"))
	}
	return m
}

// matches reports whether some pattern matches path.
func (m *excludeMatcher) matches(path string) bool {
	segments := strings.Split(path, "/")
	for _, glob := range m.globs {
		if matchSegments(glob, segments) {
			return true
		}
	}
	return false
}

// splitGlob splits a glob into segments, folding repeated slashes as
// wcmatch does. A trailing slash leaves an empty last segment, which only a
// path ending in a slash matches: never a file path.
func splitGlob(glob string) []string {
	for strings.Contains(glob, "//") {
		glob = strings.ReplaceAll(glob, "//", "/")
	}
	return strings.Split(glob, "/")
}

// matchSegments matches glob segments against path segments; a ** segment
// stands for any number of path segments, the empty root of an absolute
// path included.
func matchSegments(glob, path []string) bool {
	if len(glob) == 0 {
		return len(path) == 0
	}
	if glob[0] == "**" {
		for i := 0; i <= len(path); i++ {
			if i > 0 && isDotDir(path[i-1]) {
				return false
			}
			if matchSegments(glob[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if !matchSegment(glob[0], path[0]) {
		return false
	}
	return matchSegments(glob[1:], path[1:])
}

func isDotDir(segment string) bool {
	return segment == "." || segment == ".."
}

// matchSegment is fnmatch for one segment: * and ? never cross a slash,
// [...] and [!...] or [^...] are classes and a backslash escapes. Wildcards
// match leading dots (DOTGLOB) but never the . and .. segments.
func matchSegment(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if isDotDir(name) {
		return false
	}
	return fnmatch(pattern, name)
}

func fnmatch(pattern, name string) bool {
	p, n := 0, 0
	starP, starN := -1, -1
	for n < len(name) {
		if p < len(pattern) && pattern[p] == '*' {
			for p < len(pattern) && pattern[p] == '*' {
				p++
			}
			starP, starN = p, n
			continue
		}
		if width, ok := matchOne(pattern, p, name[n]); ok {
			p += width
			n++
			continue
		}
		if starP < 0 {
			return false
		}
		starN++
		p, n = starP, starN
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matchOne matches the pattern element at p, other than *, against c and
// returns its width in the pattern.
func matchOne(pattern string, p int, c byte) (int, bool) {
	if p >= len(pattern) {
		return 0, false
	}
	switch pattern[p] {
	case '?':
		return 1, true
	case '[':
		if end, ok := classMatch(pattern, p, c); end > 0 {
			return end - p, ok
		}
		// An unterminated class is a literal bracket.
		return 1, c == '['
	case '\\':
		if p+1 < len(pattern) {
			return 2, pattern[p+1] == c
		}
		return 1, c == '\\'
	default:
		return 1, pattern[p] == c
	}
}

// classMatch reads the class starting at pattern[start] == '[' and reports
// the index after it (0 when unterminated) and whether c is in it.
func classMatch(pattern string, start int, c byte) (int, bool) {
	i := start + 1
	negate := false
	if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
		negate = true
		i++
	}
	matched := false
	first := true
	for i < len(pattern) && (first || pattern[i] != ']') {
		first = false
		lo := pattern[i]
		if lo == '\\' && i+1 < len(pattern) {
			i++
			lo = pattern[i]
		}
		hi := lo
		if i+2 < len(pattern) && pattern[i+1] == '-' && pattern[i+2] != ']' {
			hi = pattern[i+2]
			i += 2
		}
		if lo <= c && c <= hi {
			matched = true
		}
		i++
	}
	if i >= len(pattern) {
		return 0, false
	}
	return i + 1, matched != negate
}
