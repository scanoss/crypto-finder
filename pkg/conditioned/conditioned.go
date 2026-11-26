// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package conditioned specializes a generic crypto finding by the value its
// selector argument resolves to: a rule whose metadata.crypto carries a
// parameterCondition (`param[0]==SHA256withECDSA`, `param[0]~=^PBKDF2`)
// applies to a call only when the argument satisfies it, and then names the
// algorithm the argument selects.
//
// Crypto semantics stay rule-owned: this package evaluates the predicates and
// fills the rule's metadata template from what they captured. Where the
// argument values come from is the caller's business: a scan reads them from
// its live call graph, the API and the offline mode from the stitched graph
// fragments of a pinned dependency closure (Expand).
//
// The package is dependency-light like pkg/graphfrag: it imports no scanner
// package, so the API can link it.
package conditioned

import (
	"maps"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/reach/paramcondition"
)

// Argument is one argument of a call, as the call graph resolved it.
type Argument struct {
	// Value is the statically resolved value as written ("\"SHA-256\"",
	// 'sha256', RSA_OAEP), or "" when it did not resolve.
	Value string
	// Type is the argument's static type, read by `:type` conditions.
	Type string
	// Name is the variable the argument passes, read by keyword selectors.
	Name string
	// Keyword is the name a Python keyword argument is passed under
	// (`algorithm="HS256"`), "" for a positional argument.
	Keyword string
}

// Match is what a set of conditions bound on one argument list.
type Match struct {
	captures captures
	// Actuals are the normalized argument values the conditions read, in
	// condition order.
	Actuals []string
	// Conditions are the conditions rewritten as exact predicates on the
	// values they matched (`param[0]==SHA256withECDSA`).
	Conditions []paramcondition.Condition
}

// captures holds what a condition regex bound, by how the name was
// established, so the metadata placeholders resolve with a fixed precedence:
// a group the condition names itself, then the rule's own named groups applied
// to the resolved value, then a name inferred from the position of an unnamed
// condition group.
type captures struct {
	numbered   map[string]string
	named      map[string]string
	positional map[string]string
}

func newCaptures() captures {
	return captures{numbered: map[string]string{}, named: map[string]string{}, positional: map[string]string{}}
}

// placeholders merges the captures into the $name -> value map used to fill
// rule metadata. bound is the rule's own named groups applied to the value.
func (c captures) placeholders(bound map[string]string) map[string]string {
	out := make(map[string]string, len(c.numbered)+len(c.named)+len(c.positional)+len(bound))
	for _, layer := range []map[string]string{c.numbered, c.positional, bound, c.named} {
		maps.Copy(out, layer)
	}
	return out
}

// MatchConditions reports whether every condition holds on args, and what
// they bound. A condition whose argument is missing or did not resolve does not
// hold. captureNames name the unnamed groups of a condition regex by position.
func MatchConditions(conditions []paramcondition.Condition, args []Argument, captureNames []string) (Match, bool) {
	result := Match{captures: newCaptures()}
	for _, condition := range conditions {
		index := ArgumentIndex(condition, args)
		if index < 0 || index >= len(args) {
			return Match{}, false
		}
		actual := args[index].Value
		if condition.Match == paramcondition.MatchType {
			actual = args[index].Type
		}
		actual = NormalizeValue(actual)
		if actual == "" {
			return Match{}, false
		}
		if !matchCondition(condition, actual, result.captures, captureNames) {
			return Match{}, false
		}
		result.Actuals = append(result.Actuals, actual)
		result.Conditions = append(result.Conditions, exactResolvedCondition(condition, actual))
	}
	return result, true
}

// ConditionHolds reports whether condition accepts actual, a normalized value.
func ConditionHolds(condition paramcondition.Condition, actual string) bool {
	return matchCondition(condition, actual, newCaptures(), nil)
}

// ArgumentIndex is the position in args of the argument condition selects, or
// -1 when it selects none. An index selects the positional argument at that
// position; `param[i|name]` selects it, else the keyword argument passed as
// name (Python: `jwt.encode(p, k, algorithm="HS256")`). A keyword argument
// is never selected by its place in the call: it binds the parameter its name
// gives, wherever it is written.
func ArgumentIndex(condition paramcondition.Condition, args []Argument) int {
	if condition.Selector.Index != nil { //nolint:nestif // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
		index := *condition.Selector.Index
		inRange := index < len(args)
		if inRange && args[index].Keyword == "" {
			return index
		}
		if condition.Selector.Name != nil {
			if keyword := keywordArgumentIndex(args, *condition.Selector.Name); keyword >= 0 {
				return keyword
			}
		}
		if inRange {
			return -1
		}
		return index
	}
	if condition.Selector.Name == nil {
		return -1
	}
	if keyword := keywordArgumentIndex(args, *condition.Selector.Name); keyword >= 0 {
		return keyword
	}
	for i := range args {
		if args[i].Name == *condition.Selector.Name {
			return i
		}
	}
	return -1
}

// keywordArgumentIndex is the position in args of the keyword argument passed
// as name, or -1.
func keywordArgumentIndex(args []Argument, name string) int {
	for i := range args {
		if args[i].Keyword == name {
			return i
		}
	}
	return -1
}

func matchCondition(condition paramcondition.Condition, actual string, captures captures, captureNames []string) bool {
	if condition.Operator == paramcondition.OpExact {
		return actual == NormalizeValue(condition.Value)
	}
	if condition.Operator != paramcondition.OpRegex {
		return false
	}
	re, err := regexp.Compile(condition.Value)
	if err != nil {
		return false
	}
	match := re.FindStringSubmatch(actual)
	if match == nil {
		return false
	}
	for i := 1; i < len(match); i++ {
		if match[i] == "" {
			continue
		}
		captures.numbered[strconv.Itoa(i)] = match[i]
		if name := re.SubexpNames()[i]; name != "" {
			captures.named[name] = match[i]
		} else if i-1 < len(captureNames) {
			captures.positional[captureNames[i-1]] = match[i]
		}
	}
	return true
}

func exactResolvedCondition(condition paramcondition.Condition, actual string) paramcondition.Condition {
	resolved := condition
	resolved.Operator = paramcondition.OpExact
	resolved.Value = actual
	selector := ""
	if condition.Selector.Index != nil {
		selector = strconv.Itoa(*condition.Selector.Index)
	} else if condition.Selector.Name != nil {
		selector = *condition.Selector.Name
	}
	typeSuffix := ""
	if condition.Match == paramcondition.MatchType {
		typeSuffix = ":type"
	}
	resolved.Raw = "param[" + selector + "]" + typeSuffix + "==" + actual
	return resolved
}

// Metadata fills a rule's metadata template with what m bound: each $name
// placeholder takes its captured value, binders (the rule's start-anchored
// metavariable-regex patterns with named groups) bind more names from the
// values, and a field that still holds a placeholder is dropped. The result
// carries the resolved condition in parameterCondition, and the operation as
// cryptoFunction when the template names none. template is not modified.
func (m Match) Metadata(template map[string]string, binders []*regexp.Regexp) map[string]string {
	metadata := maps.Clone(template)
	if metadata == nil {
		metadata = make(map[string]string, 2)
	}
	fill := placeholderFiller(m.captures.placeholders(bindRuleCaptures(binders, m.Actuals)))
	for key, value := range metadata {
		value = fill(value)
		if strings.Contains(value, "$") {
			delete(metadata, key)
			continue
		}
		metadata[key] = value
	}
	if metadata["cryptoFunction"] == "" && metadata["operation"] != "" {
		metadata["cryptoFunction"] = metadata["operation"]
	}
	metadata["parameterCondition"] = m.ConditionedValue()
	return metadata
}

// ConditionedValue is the resolved condition an asset specialized by m
// carries: its exact predicates joined by ",".
func (m Match) ConditionedValue() string {
	raws := make([]string, len(m.Conditions))
	for i := range m.Conditions {
		raws[i] = m.Conditions[i].Raw
	}
	return strings.Join(raws, ",")
}

// bindRuleCaptures applies the rule's named-group patterns to each resolved
// value, bare or inside the quotes the rule's source pattern is written against.
// A binder is start-anchored, as semgrep's metavariable-regex is, so a rule that
// does not end its regex with $ binds on a prefix of the value.
func bindRuleCaptures(binders []*regexp.Regexp, actuals []string) map[string]string {
	bound := make(map[string]string)
	for _, actual := range actuals {
		for _, re := range binders {
			bindWholeValue(re, actual, bound)
		}
	}
	return bound
}

// bindWholeValue adds the named groups of re, a start-anchored binder, to
// bound, for the first spelling of actual that it matches. A name already bound
// keeps its value.
func bindWholeValue(re *regexp.Regexp, actual string, bound map[string]string) {
	for _, candidate := range []string{actual, `"` + actual + `"`, "'" + actual + "'"} {
		match := re.FindStringSubmatch(candidate)
		if len(match) == 0 {
			continue
		}
		for i, name := range re.SubexpNames() {
			if name == "" || match[i] == "" {
				continue
			}
			if _, taken := bound[name]; !taken {
				bound[name] = match[i]
			}
		}
		return
	}
}

// placeholderFiller returns a function that replaces each $name of captures
// with its value in one pass, so a value that itself contains "$name" is never
// substituted again. Longer names come first, so $mode never eats the front of
// $model.
func placeholderFiller(captures map[string]string) func(string) string {
	if len(captures) == 0 {
		return func(value string) string { return value }
	}
	names := make([]string, 0, len(captures))
	for name := range captures {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j]) || len(names[i]) == len(names[j]) && names[i] < names[j]
	})
	re := regexp.MustCompile(`\$(?:` + strings.Join(names, "|") + `)`)
	return func(value string) string {
		return re.ReplaceAllStringFunc(value, func(match string) string { return captures[match[1:]] })
	}
}

// NormalizeValue strips the quotes around a string literal: double quotes
// (Java, Go, C), single quotes (Python, JavaScript, Ruby) and a backtick
// template without interpolation. A template with ${...} is not a constant and
// stays as written.
func NormalizeValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != value[len(value)-1] {
		return value
	}
	switch value[0] {
	case '"', '\'':
		return value[1 : len(value)-1]
	case '`':
		if !strings.Contains(value, "${") {
			return value[1 : len(value)-1]
		}
	}
	return value
}
