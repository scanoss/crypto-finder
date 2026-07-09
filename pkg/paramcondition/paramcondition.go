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

// Package paramcondition parses the crypto-rules parameterCondition grammar
// (`param[<selector>]<op><value>`) into a structured, JSON-serializable form.
//
// This package is dependency-free (stdlib only) by design: it is the single
// shared grammar used by rule-load validation (internal/rules), both
// ingestion paths (internal/scanner/semgrep, internal/engine), and the
// public findings envelope (pkg/graphfrag) — the last of which must stay
// free of internal/ imports to remain usable from outside this module.
package paramcondition

import (
	"fmt"
	"strconv"
	"strings"
)

// Operator is the comparison operator a predicate applies to its selected
// argument: exact string equality or regex match.
type Operator string

// Match indicates whether a predicate compares the argument's runtime value
// or its static type.
type Match string

const (
	// OpExact is the "==" operator: exact string equality.
	OpExact Operator = "=="
	// OpRegex is the "~=" operator: regex match.
	OpRegex Operator = "~="

	// MatchValue means the predicate compares the argument's value (default).
	MatchValue Match = "value"
	// MatchType means the predicate compares the argument's static type,
	// signaled by the ":type" suffix on the selector.
	MatchType Match = "type"
)

// paramPrefix is the literal grammar token every predicate must start with.
const paramPrefix = "param["

// Selector identifies which call argument a predicate binds to. Pointers are
// used (rather than a sentinel value) so the JSON shape renders an explicit
// null for the unused half of the binding: {"index":0,"name":null}.
type Selector struct {
	// Index is the 0-based positional argument index. Nil when the selector
	// is keyword-only.
	Index *int `json:"index"`
	// Name is the keyword/parameter name. Nil when the selector is
	// positional-only.
	Name *string `json:"name"`
}

// Condition is one parsed parameterCondition predicate.
type Condition struct {
	// Raw preserves the exact source substring this Condition was parsed
	// from, trimmed of surrounding whitespace.
	Raw string `json:"raw"`
	// Selector is the argument binding (positional, keyword, or both).
	Selector Selector `json:"selector"`
	// Operator is the comparison operator ("==" or "~=").
	Operator Operator `json:"operator"`
	// Match indicates whether Value compares against the argument's value
	// or its static type.
	Match Match `json:"match"`
	// Value is the comparison operand, taken verbatim from the source
	// (may itself contain "]", "==", commas, or regex metacharacters).
	Value string `json:"value"`
}

// ParseError describes why a parameterCondition predicate failed to parse.
// Raw is the exact input that failed; Reason is a short, human-readable
// explanation. Callers that need the offending rule id (e.g. rule-load
// validation) attach it separately when wrapping this error.
type ParseError struct {
	Raw    string
	Reason string
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	return fmt.Sprintf("invalid parameterCondition %q: %s", e.Raw, e.Reason)
}

// operatorToken pairs a grammar operator token with the Operator/Match it
// resolves to. Order matters: ":type==" and ":type~=" MUST be tested before
// their bare "==" / "~=" counterparts since both share the "==" / "~=" tail.
var operatorTokens = []struct {
	token    string
	operator Operator
	match    Match
}{
	{token: ":type==", operator: OpExact, match: MatchType},
	{token: ":type~=", operator: OpRegex, match: MatchType},
	{token: "==", operator: OpExact, match: MatchValue},
	{token: "~=", operator: OpRegex, match: MatchValue},
}

// Parse converts a single parameterCondition predicate string
// (`param[<selector>]<op><value>`) into a structured Condition.
//
// The selector is anchored on the FIRST "]" after "param[" — selectors never
// contain "]", so this reliably closes the selector even when Value itself
// contains "]" (e.g. a regex). The operator is matched at the start of the
// remainder against the longest/most-specific token first, so ":type=="
// is never mistaken for a bare "==". Value is everything after the matched
// operator token, taken verbatim.
func Parse(raw string) (Condition, error) {
	trimmed := strings.TrimSpace(raw)

	if !strings.HasPrefix(trimmed, paramPrefix) {
		return Condition{}, &ParseError{Raw: trimmed, Reason: "missing param[ prefix"}
	}

	afterPrefix := trimmed[len(paramPrefix):]
	closeIdx := strings.IndexByte(afterPrefix, ']')
	if closeIdx < 0 {
		return Condition{}, &ParseError{Raw: trimmed, Reason: "missing closing ]"}
	}

	selector, err := parseSelector(afterPrefix[:closeIdx])
	if err != nil {
		return Condition{}, &ParseError{Raw: trimmed, Reason: err.Error()}
	}

	operator, match, value, err := parseOperatorAndValue(afterPrefix[closeIdx+1:])
	if err != nil {
		return Condition{}, &ParseError{Raw: trimmed, Reason: err.Error()}
	}

	return Condition{
		Raw:      trimmed,
		Selector: selector,
		Operator: operator,
		Match:    match,
		Value:    value,
	}, nil
}

// ParseAll splits a comma-joined parameterCondition string into its
// individual predicates and parses each one.
//
// A comma is a predicate separator ONLY when immediately followed by a new
// "param[" selector; a comma anywhere else (inside a regex or FQN value) is
// part of that value. This is unambiguous because every predicate MUST
// begin with the literal "param[": splitting on every occurrence of that
// literal and trimming one trailing separator comma off each slice
// recovers the original predicates without ever inspecting value content.
func ParseAll(raw string) ([]Condition, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	starts := indexAll(trimmed, paramPrefix)
	if len(starts) == 0 {
		return nil, &ParseError{Raw: trimmed, Reason: "no param[ predicate found"}
	}
	if starts[0] != 0 {
		return nil, &ParseError{Raw: trimmed, Reason: fmt.Sprintf("unexpected leading text %q before first param[ predicate", trimmed[:starts[0]])}
	}

	conditions := make([]Condition, 0, len(starts))
	for i, start := range starts {
		end := len(trimmed)
		hasNext := i+1 < len(starts)
		if hasNext {
			end = starts[i+1]
		}

		segment := trimmed[start:end]
		if hasNext {
			// The comma separator is mandatory between predicates. TrimSuffix
			// alone would silently accept concatenated predicates and truncate
			// the first value — defeating the rule-load fail-fast gate.
			segment = strings.TrimRight(segment, " \t\n")
			withoutComma := strings.TrimSuffix(segment, ",")
			if withoutComma == segment {
				return nil, &ParseError{Raw: trimmed, Reason: "missing ',' separator before next param[ predicate"}
			}
			segment = strings.TrimRight(withoutComma, " \t\n")
		}

		cond, err := Parse(segment)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, cond)
	}

	return conditions, nil
}

// parseSelector parses the text between "param[" and its closing "]".
//
//   - "idx|name" (contains "|"): dual binding. The left side must be a
//     non-negative integer (Index); the right side must be non-empty (Name).
//   - all-digits: positional selector (Index only).
//   - anything else: keyword selector (Name only).
func parseSelector(s string) (Selector, error) {
	if s == "" {
		return Selector{}, fmt.Errorf("empty selector")
	}

	if pipeIdx := strings.IndexByte(s, '|'); pipeIdx >= 0 {
		left := s[:pipeIdx]
		right := s[pipeIdx+1:]
		if right == "" {
			return Selector{}, fmt.Errorf("empty name in dual-binding selector %q", s)
		}
		idx, err := strconv.Atoi(left)
		if err != nil || idx < 0 {
			return Selector{}, fmt.Errorf("dual-binding selector requires a non-negative index, got %q", left)
		}
		return Selector{Index: &idx, Name: &right}, nil
	}

	if isAllDigits(s) {
		idx, err := strconv.Atoi(s)
		if err != nil {
			return Selector{}, fmt.Errorf("invalid numeric selector %q", s)
		}
		return Selector{Index: &idx}, nil
	}

	name := s
	return Selector{Name: &name}, nil
}

// parseOperatorAndValue matches the longest/most-specific operator token at
// the start of remainder and returns the resolved Operator, Match, and the
// verbatim Value that follows it.
func parseOperatorAndValue(remainder string) (Operator, Match, string, error) {
	for _, ot := range operatorTokens {
		if !strings.HasPrefix(remainder, ot.token) {
			continue
		}
		value := remainder[len(ot.token):]
		if value == "" {
			return "", "", "", fmt.Errorf("empty value")
		}
		return ot.operator, ot.match, value, nil
	}
	return "", "", "", fmt.Errorf("unknown operator in %q", remainder)
}

// isAllDigits reports whether s is non-empty and consists solely of ASCII
// digits (used to distinguish a positional index from a keyword name).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// indexAll returns the start index of every non-overlapping occurrence of
// sub within s, in order.
func indexAll(s, sub string) []int {
	var idxs []int
	offset := 0
	for {
		i := strings.Index(s[offset:], sub)
		if i < 0 {
			break
		}
		idxs = append(idxs, offset+i)
		offset += i + len(sub)
	}
	return idxs
}
