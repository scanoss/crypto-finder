// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package conditioned

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/scanoss/reach/paramcondition"
)

// Rule is one conditioned rule of a ruleset in the form a catalog is sent
// and stored in: what a scan reads off the rule file (internal/engine
// LoadRuleCryptoMetadata) to specialize a finding on a call the rule names.
type Rule struct {
	ID       string `json:"id"`
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Symbols are the API symbols the rule's patterns call
	// ("javax.crypto.SecretKeyFactory.getInstance").
	Symbols []string `json:"symbols"`
	// Metadata is the rule's metadata.crypto block, its parameterCondition
	// included, with $name placeholders the conditions fill.
	Metadata map[string]string `json:"metadata"`
	// PURL is the package URL the rule's metadata names.
	PURL string `json:"purl,omitempty"`
	// CaptureNames name the unnamed groups of a condition regex by position.
	CaptureNames []string `json:"capture_names,omitempty"`
	// CaptureBinders are the rule's metavariable-regex patterns with named
	// groups, start-anchored.
	CaptureBinders []string `json:"capture_binders,omitempty"`

	conditions []paramcondition.Condition
	binders    []*regexp.Regexp
}

// Conditions are the rule's parsed parameterCondition.
func (r *Rule) Conditions() []paramcondition.Condition { return r.conditions }

// Binders are the rule's compiled capture binders.
func (r *Rule) Binders() []*regexp.Regexp { return r.binders }

// Catalog indexes the conditioned rules of one ecosystem by the symbols they
// call.
type Catalog struct {
	rules []*Rule
}

// NewCatalog parses each rule's condition and binders. A rule whose
// parameterCondition does not parse, or names none, is an error: a catalog
// holds conditioned rules only.
func NewCatalog(rules []Rule) (*Catalog, error) {
	c := &Catalog{rules: make([]*Rule, 0, len(rules))}
	for i := range rules {
		rule := rules[i]
		if rule.ID == "" || len(rule.Symbols) == 0 {
			return nil, fmt.Errorf("conditioned rule %d: id and symbols are required", i)
		}
		conditions, err := paramcondition.ParseAll(rule.Metadata["parameterCondition"])
		if err != nil || len(conditions) == 0 {
			return nil, fmt.Errorf("conditioned rule %s: parameterCondition %q: %w", rule.ID, rule.Metadata["parameterCondition"], err)
		}
		rule.conditions = conditions
		for _, source := range rule.CaptureBinders {
			re, err := regexp.Compile(source)
			if err != nil {
				return nil, fmt.Errorf("conditioned rule %s: capture binder %q: %w", rule.ID, source, err)
			}
			rule.binders = append(rule.binders, re)
		}
		c.rules = append(c.rules, &rule)
	}
	return c, nil
}

// Len is the number of rules in the catalog.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}

// RulesFor returns the rules that name callee, the fully qualified name of a
// called function, one per rule id, by id. A symbol names a callee when they
// are equal or one ends with "." and the other, as a scan matches a rule's
// symbol to a Java call.
func (c *Catalog) RulesFor(callee string) []*Rule {
	callee = strings.TrimSpace(callee)
	if c == nil || callee == "" {
		return nil
	}
	var out []*Rule
	for _, rule := range c.rules {
		if slices.ContainsFunc(out, func(r *Rule) bool { return r.ID == rule.ID }) {
			continue
		}
		if slices.ContainsFunc(rule.Symbols, func(symbol string) bool { return symbolNames(symbol, callee) }) {
			out = append(out, rule)
		}
	}
	slices.SortStableFunc(out, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func symbolNames(symbol, callee string) bool {
	return symbol == callee || strings.HasSuffix(symbol, "."+callee) || strings.HasSuffix(callee, "."+symbol)
}

// Specialization is the asset a rule yields for one argument list.
type Specialization struct {
	Rule *Rule
	// Metadata is the rule's template filled for the value.
	Metadata map[string]string
	// Conditions are the rule's conditions resolved to the value.
	Conditions []paramcondition.Condition
	// ConditionedValue joins Conditions ("param[0]==SCRYPT").
	ConditionedValue string
}

// Specialize returns the asset r yields for args, or false when its
// conditions do not hold.
func (r *Rule) Specialize(args []Argument) (Specialization, bool) {
	match, ok := MatchConditions(r.conditions, args, r.CaptureNames)
	if !ok {
		return Specialization{}, false
	}
	return Specialization{
		Rule:             r,
		Metadata:         match.Metadata(r.Metadata, r.binders),
		Conditions:       match.Conditions,
		ConditionedValue: match.ConditionedValue(),
	}, true
}

// FindingID is a finding's id: the first 8 hex digits of the SHA-256 of its
// path, start line and first rule id, and of its conditioned value when it
// has one, so two values of one rule at one call do not share an id.
func FindingID(path string, startLine int, ruleID, conditionedValue string) string {
	input := path + ":" + strconv.Itoa(startLine) + ":" + ruleID
	if conditionedValue != "" {
		input += ":" + conditionedValue
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:8]
}

// OccurrenceKey is the occurrence key of the asset an anchor yields for a
// value no scan of the anchor's component sees, because only another
// component passes it: the anchor's own key and the value, hashed. It is as
// stable as the anchor's key and distinct per value. Empty when the anchor has
// no key.
func OccurrenceKey(anchorKey, conditionedValue string) string {
	if anchorKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(anchorKey + "\n" + conditionedValue))
	return "v1:" + hex.EncodeToString(sum[:])[:16]
}
