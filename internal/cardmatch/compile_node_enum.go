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

package cardmatch

// enumRegex: the strings a metavariable-regex accepts, when they are a short
// finite list. The node rule generators write module and member names as
// regexes (`^["']?(?:node:)?crypto["']?$`, `^(hash|verify)$`); the compiler
// turns those into module lists and fixed paths.

import (
	"regexp/syntax"
	"sort"
)

const (
	enumMax      = 400 // most strings a regex may stand for
	enumClassMax = 20  // most characters a character class may stand for
)

// enumPart is one string being built, and whether the regex's end anchor was
// passed (nothing may follow it).
type enumPart struct {
	s     string
	ended bool
}

// enumRegex lists the strings a regex accepts with Python's re.match (anchored
// at the start only), when it is built of literals, small character classes,
// alternation, optional parts and bounded repeats (which Simplify writes as
// optional parts), and every alternative ends in an end anchor. ok is false otherwise, or past max strings.
func enumRegex(rx string, maxStrings int) (values []string, ok bool) {
	re, err := syntax.Parse(rx, syntax.Perl)
	if err != nil {
		return nil, false
	}
	parts, ok := enumWalk(re.Simplify(), []enumPart{{}}, maxStrings)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if !p.ended {
			return nil, false // a prefix match: anything may follow
		}
		if !seen[p.s] {
			seen[p.s] = true
			values = append(values, p.s)
		}
	}
	sort.Strings(values)
	return values, len(values) > 0
}

func enumAppend(in []enumPart, alts []string, maxStrings int) ([]enumPart, bool) {
	var out []enumPart
	for _, p := range in {
		if p.ended {
			continue // a character after the end anchor never matches
		}
		for _, a := range alts {
			out = append(out, enumPart{s: p.s + a})
		}
	}
	return out, len(out) <= maxStrings
}

func enumWalk(re *syntax.Regexp, in []enumPart, maxStrings int) ([]enumPart, bool) {
	switch re.Op { //nolint:exhaustive // every other operator stands for unboundedly many strings
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpBeginText:
		return in, true
	case syntax.OpEndLine, syntax.OpEndText:
		out := make([]enumPart, len(in))
		for i, p := range in {
			out[i] = enumPart{s: p.s, ended: true}
		}
		return out, true
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil, false
		}
		return enumAppend(in, []string{string(re.Rune)}, maxStrings)
	case syntax.OpCharClass:
		alts, ok := enumClass(re)
		if !ok {
			return nil, false
		}
		return enumAppend(in, alts, maxStrings)
	case syntax.OpCapture:
		return enumWalk(re.Sub[0], in, maxStrings)
	case syntax.OpConcat:
		out := in
		for _, sub := range re.Sub {
			var ok bool
			if out, ok = enumWalk(sub, out, maxStrings); !ok {
				return nil, false
			}
		}
		return out, true
	case syntax.OpAlternate, syntax.OpQuest:
		return enumUnion(re, in, maxStrings)
	}
	return nil, false
}

// enumClass lists a small character class.
func enumClass(re *syntax.Regexp) ([]string, bool) {
	var alts []string
	for i := 0; i+1 < len(re.Rune); i += 2 {
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			alts = append(alts, string(r))
			if len(alts) > enumClassMax {
				return nil, false
			}
		}
	}
	return alts, true
}

// enumUnion is an alternation's strings, or an optional part's (the part,
// or nothing).
func enumUnion(re *syntax.Regexp, in []enumPart, maxStrings int) ([]enumPart, bool) {
	var out []enumPart
	if re.Op == syntax.OpQuest {
		out = append(out, in...)
	}
	for _, sub := range re.Sub {
		alt, ok := enumWalk(sub, in, maxStrings)
		if !ok {
			return nil, false
		}
		out = append(out, alt...)
	}
	return out, len(out) <= maxStrings
}
