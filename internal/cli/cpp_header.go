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
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// cppHeaderCode matches what only C++ code writes: a namespace or class
// declaration, a template, or a name qualified with `::`. It reads code with
// comments and literals blanked (cppHeaderText), so a C header that says
// "global namespace" or "this class of" in a comment, or holds the
// clobber list of an inline asm (`::: "memory"`), stays C; and without the
// branches a `__cplusplus` test selects (cppOnlyBlanked), so a C header that
// also serves C++ (`#if defined(__cplusplus)` then `template <class T>`)
// stays C too.
var cppHeaderCode = regexp.MustCompile(`\bnamespace\s+[A-Za-z_{]|\bclass\s+[A-Za-z_]\w*\s*[:{;]|\btemplate\s*<|[A-Za-z_]\w*\s*::\s*[A-Za-z_~]`)

func isCPPHeader(path string) bool {
	if strings.ToLower(filepath.Ext(path)) != ".h" {
		return false
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return cppHeaderCode.Match(cppOnlyBlanked(cppHeaderText(contents)))
}

// cppOnlyBlanked blanks the lines of the branches only a C++ compiler reads:
// from a conditional that tests __cplusplus (`#ifdef __cplusplus`,
// `#if defined(__cplusplus) && ...`) to its #else, #elif or #endif, and the
// #else branch of a negated test (`#ifndef __cplusplus`,
// `#if !defined(__cplusplus)`), nested conditionals included.
func cppOnlyBlanked(text []byte) []byte {
	lines := bytes.Split(text, []byte("\n"))
	var s cppBranches
	for i, line := range lines {
		if s.blank(line) {
			lines[i] = bytes.Repeat([]byte(" "), len(line))
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

// cppBranches follows the conditionals of a header line by line.
type cppBranches struct {
	depth     int
	blankFrom int // depth of the C++-only branch being blanked, 0 when none
	elseAt    int // depth of a negated test whose #else is C++-only, 0 when none
}

// blank reports whether line, a line of a C++-only branch, is to be blanked.
func (s *cppBranches) blank(line []byte) bool {
	directive, rest := cppDirective(line)
	switch directive {
	case "if", "ifdef", "ifndef":
		s.depth++
		if s.blankFrom != 0 || s.elseAt != 0 || !bytes.Contains(rest, []byte("__cplusplus")) {
			break
		}
		if directive == "ifndef" || cppNegated(rest) {
			s.elseAt = s.depth
			break
		}
		s.blankFrom = s.depth
		return false
	case "elif", "else":
		if s.blankFrom == s.depth {
			s.blankFrom = 0
		} else if s.elseAt == s.depth && directive == "else" {
			s.elseAt, s.blankFrom = 0, s.depth
			return false
		}
	case "endif":
		if s.blankFrom == s.depth {
			s.blankFrom = 0
		}
		if s.elseAt == s.depth {
			s.elseAt = 0
		}
		s.depth--
	}
	return s.blankFrom != 0
}

// cppDirective splits a preprocessor line into its directive and the rest.
func cppDirective(line []byte) (string, []byte) {
	s := bytes.TrimLeft(line, " \t")
	if len(s) == 0 || s[0] != '#' {
		return "", nil
	}
	s = bytes.TrimLeft(s[1:], " \t")
	end := 0
	for end < len(s) && (s[end] >= 'a' && s[end] <= 'z') {
		end++
	}
	return string(s[:end]), s[end:]
}

// cppNegated reports a test that holds when __cplusplus is not defined.
func cppNegated(rest []byte) bool {
	compact := bytes.ReplaceAll(bytes.ReplaceAll(rest, []byte(" "), nil), []byte("\t"), nil)
	return bytes.Contains(compact, []byte("!defined(__cplusplus)")) || bytes.Contains(compact, []byte("!defined__cplusplus")) ||
		bytes.Contains(compact, []byte("!__cplusplus"))
}

// cppHeaderText returns src with comments, string literals and character
// literals replaced by spaces, newlines kept.
func cppHeaderText(src []byte) []byte {
	out := bytes.Clone(src)
	for i := 0; i < len(src); {
		i = blankCommentOrLiteral(src, out, i)
	}
	return out
}

// blankCommentOrLiteral blanks in out the comment or literal that starts at
// src[i], if one does, and returns the index after it.
func blankCommentOrLiteral(src, out []byte, i int) int {
	stop := i + 1
	switch {
	case bytes.HasPrefix(src[i:], []byte("//")):
		stop = len(src)
		if end := bytes.IndexByte(src[i:], '\n'); end >= 0 {
			stop = i + end
		}
	case bytes.HasPrefix(src[i:], []byte("/*")):
		stop = len(src)
		if end := bytes.Index(src[i+2:], []byte("*/")); end >= 0 {
			stop = i + 2 + end + 2
		}
	case src[i] == '"' || src[i] == '\'':
		stop = literalEnd(src, i)
	default:
		return stop
	}
	for k := i; k < stop; k++ {
		if out[k] != '\n' {
			out[k] = ' '
		}
	}
	return stop
}

// literalEnd returns the index after the string or character literal that
// starts at src[i], or the end of its line when it is not closed.
func literalEnd(src []byte, i int) int {
	quote := src[i]
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case quote:
			return j + 1
		case '\n':
			return j
		}
	}
	return len(src)
}
