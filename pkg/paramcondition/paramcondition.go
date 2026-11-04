// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package paramcondition parses the crypto-rules parameterCondition grammar
// (`param[<selector>]<op><value>`) into a structured, JSON-serializable form.
//
// It forwards to github.com/scanoss/static-engine/paramcondition, which holds
// the implementation; the names here are aliases so both paths share one type.
package paramcondition

import engineparamcondition "github.com/scanoss/static-engine/paramcondition"

type (
	// Operator is the comparison operator a predicate applies to its selected
	// argument: exact string equality or regex match.
	Operator = engineparamcondition.Operator
	// Match indicates whether a predicate compares the argument's runtime value
	// or its static type.
	Match = engineparamcondition.Match
	// Selector identifies which call argument a predicate binds to.
	Selector = engineparamcondition.Selector
	// Condition is one parsed parameterCondition predicate.
	Condition = engineparamcondition.Condition
	// ParseError describes why a parameterCondition predicate failed to parse.
	ParseError = engineparamcondition.ParseError
)

const (
	// OpExact is the "==" operator: exact string equality.
	OpExact = engineparamcondition.OpExact
	// OpRegex is the "~=" operator: regex match.
	OpRegex = engineparamcondition.OpRegex

	// MatchValue means the predicate compares the argument's value (default).
	MatchValue = engineparamcondition.MatchValue
	// MatchType means the predicate compares the argument's static type,
	// signaled by the ":type" suffix on the selector.
	MatchType = engineparamcondition.MatchType
)

// Parse converts a single parameterCondition predicate string
// (`param[<selector>]<op><value>`) into a structured Condition.
func Parse(raw string) (Condition, error) {
	return engineparamcondition.Parse(raw)
}

// ParseAll splits a comma-joined parameterCondition string into its
// individual predicates and parses each one.
func ParseAll(raw string) ([]Condition, error) {
	return engineparamcondition.ParseAll(raw)
}
