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

package engine

import (
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
)

// maxCatalogNames bounds both the names a metavariable constraint may expand
// to and the keys one pattern may produce. A constraint wider than this is
// treated as unbounded rather than enumerated.
const maxCatalogNames = 64

var plainIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// metavariableNames maps a metavariable to the finite set of names the rule
// allows it to bind. A metavariable absent from the map is unconstrained.
type metavariableNames map[string][]string

// ruleCryptoEntrypoints returns the callee keys a conditioned rule's matching
// patterns name. A taint rule is keyed by its sinks only; any other rule by its
// top-level pattern, patterns and pattern-either, read at any nesting.
func ruleCryptoEntrypoints(rule *ruleCryptoYAML) []string {
	keys := &catalogKeys{seen: make(map[string]struct{})}
	if len(rule.PatternSinks) > 0 {
		keys.disjunction(rule.PatternSinks, nil)
		return keys.ordered
	}
	keys.pattern(rule.Pattern, nil)
	keys.conjunction(rule.Patterns, nil)
	keys.disjunction(rule.PatternEither, nil)
	return keys.ordered
}

type catalogKeys struct {
	ordered []string
	seen    map[string]struct{}
}

func (k *catalogKeys) operand(op *rulePatternYAML, names metavariableNames) {
	k.pattern(op.Pattern, names)
	k.disjunction(op.PatternEither, names)
	k.conjunction(op.Patterns, names)
}

func (k *catalogKeys) disjunction(ops []rulePatternYAML, names metavariableNames) {
	for i := range ops {
		k.operand(&ops[i], names)
	}
}

// conjunction reads a patterns block. Its metavariable constraints apply to
// every operand in the block, including nested ones, on top of the
// constraints the enclosing blocks already impose.
func (k *catalogKeys) conjunction(ops []rulePatternYAML, names metavariableNames) {
	names = names.constrainedBy(ops)
	for i := range ops {
		k.operand(&ops[i], names)
	}
}

func (k *catalogKeys) pattern(pattern string, names metavariableNames) {
	for _, key := range patternCalleeKeys(pattern, names) {
		if _, ok := k.seen[key]; ok {
			continue
		}
		k.seen[key] = struct{}{}
		k.ordered = append(k.ordered, key)
	}
}

func (names metavariableNames) constrainedBy(ops []rulePatternYAML) metavariableNames {
	var out metavariableNames
	for i := range ops {
		metavariable, allowed, ok := ops[i].metavariableNameConstraint()
		if !ok {
			continue
		}
		if out == nil {
			out = make(metavariableNames, len(names)+1)
			maps.Copy(out, names)
		}
		if prior, constrained := out[metavariable]; constrained {
			allowed = slices.DeleteFunc(allowed, func(name string) bool { return !slices.Contains(prior, name) })
		}
		out[metavariable] = allowed
	}
	if out == nil {
		return names
	}
	return out
}

// metavariableNameConstraint reports the finite set of plain names a
// metavariable-regex or metavariable-pattern operator restricts its
// metavariable to. Any other operator, or a constraint that admits something
// other than a bounded list of identifiers, reports false.
func (op *rulePatternYAML) metavariableNameConstraint() (string, []string, bool) {
	switch {
	case op.MetavariableRegex != nil:
		names, ok := finiteRegexNames(op.MetavariableRegex.Regex)
		return strings.TrimSpace(op.MetavariableRegex.Metavariable), names, ok
	case op.MetavariablePattern != nil:
		names, ok := identifierPatternNames(op.MetavariablePattern)
		return strings.TrimSpace(op.MetavariablePattern.Metavariable), names, ok
	}
	return "", nil, false
}

func identifierPatternNames(op *ruleMetavariablePatternYAML) ([]string, bool) {
	var alternatives []string
	if op.Pattern != "" {
		alternatives = []string{op.Pattern}
	} else {
		for _, alternative := range op.PatternEither {
			if alternative.PatternEither != nil || alternative.Patterns != nil {
				return nil, false
			}
			alternatives = append(alternatives, alternative.Pattern)
		}
	}
	if len(alternatives) == 0 || len(alternatives) > maxCatalogNames {
		return nil, false
	}
	names := make([]string, 0, len(alternatives))
	for _, alternative := range alternatives {
		name := strings.TrimSpace(alternative)
		if !plainIdentifier.MatchString(name) {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// finiteRegexNames enumerates the identifiers a metavariable-regex accepts
// when that set is finite and small. Semgrep anchors metavariable-regex at the
// start of the value, so a leading ^ is optional, but a branch without a
// trailing $ accepts any suffix and makes the set unbounded.
func finiteRegexNames(expr string) ([]string, bool) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, false
	}
	matches, ok := enumerateRegex(re.Simplify())
	if !ok || len(matches) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		name, anchored := strings.CutSuffix(strings.TrimPrefix(match, regexBeginText), regexEndText)
		if !anchored || !plainIdentifier.MatchString(name) {
			return nil, false
		}
		names = unionStrings(names, []string{name})
	}
	return names, true
}

// regexBeginText and regexEndText stand for ^ and $ in an enumerated match,
// so finiteRegexNames can tell an anchored branch from an open one.
const (
	regexBeginText = "\x01"
	regexEndText   = "\x00"
)

// enumerateRegex lists every string re matches, or reports false when the
// language is infinite, case-folded or larger than maxCatalogNames.
func enumerateRegex(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch:
		return []string{""}, true
	case syntax.OpBeginText:
		return []string{regexBeginText}, true
	case syntax.OpEndText:
		return []string{regexEndText}, true
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil, false
		}
		return []string{string(re.Rune)}, true
	case syntax.OpCharClass:
		return enumerateCharClass(re.Rune)
	case syntax.OpCapture:
		return enumerateRegex(re.Sub[0])
	case syntax.OpQuest:
		return enumerateRepeat(re.Sub[0], 0, 1)
	case syntax.OpRepeat:
		return enumerateRepeat(re.Sub[0], re.Min, re.Max)
	case syntax.OpAlternate:
		return enumerateAlternate(re.Sub)
	case syntax.OpConcat:
		return enumerateConcat(re.Sub)
	case syntax.OpNoMatch, syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpStar, syntax.OpPlus:
		return nil, false
	}
	return nil, false
}

func enumerateCharClass(ranges []rune) ([]string, bool) {
	var out []string
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			if len(out) == maxCatalogNames {
				return nil, false
			}
			out = append(out, string(r))
		}
	}
	return out, true
}

func enumerateAlternate(subs []*syntax.Regexp) ([]string, bool) {
	var out []string
	for _, sub := range subs {
		names, ok := enumerateRegex(sub)
		if !ok {
			return nil, false
		}
		if out = unionStrings(out, names); len(out) > maxCatalogNames {
			return nil, false
		}
	}
	return out, true
}

func enumerateConcat(subs []*syntax.Regexp) ([]string, bool) {
	out := []string{""}
	for _, sub := range subs {
		names, ok := enumerateRegex(sub)
		if !ok {
			return nil, false
		}
		if out, ok = productStrings(out, "", names); !ok {
			return nil, false
		}
	}
	return out, true
}

// enumerateRepeat lists sub repeated between minimum and maximum times; a
// negative maximum is unbounded.
func enumerateRepeat(sub *syntax.Regexp, minimum, maximum int) ([]string, bool) {
	if maximum < 0 {
		return nil, false
	}
	once, ok := enumerateRegex(sub)
	if !ok {
		return nil, false
	}
	var out []string
	power := []string{""}
	for n := 0; n <= maximum; n++ {
		if n >= minimum {
			if out = unionStrings(out, power); len(out) > maxCatalogNames {
				return nil, false
			}
		}
		if n == maximum {
			break
		}
		if power, ok = productStrings(power, "", once); !ok {
			return nil, false
		}
	}
	return out, true
}

func unionStrings(dst, src []string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

func productStrings(prefixes []string, separator string, suffixes []string) ([]string, bool) {
	if len(prefixes)*len(suffixes) > maxCatalogNames {
		return nil, false
	}
	out := make([]string, 0, len(prefixes)*len(suffixes))
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			out = unionStrings(out, []string{prefix + separator + suffix})
		}
	}
	return out, true
}

// patternCalleeKeys returns the catalog keys for a pattern whose outermost
// expression is a call: the callee path, with each metavariable segment
// replaced by every name its constraints allow. A constructor call keys as
// the type plus ".<init>". A callee that is not a plain path (a call result,
// an unconstrained metavariable, a literal) yields no key, since nothing in
// the pattern names the function that call reaches.
func patternCalleeKeys(pattern string, names metavariableNames) []string {
	callee, constructor, ok := parseCallPattern(pattern)
	if !ok {
		return nil
	}
	keys := []string{""}
	for _, segment := range callee {
		options := []string{segment.name}
		if strings.HasPrefix(segment.name, "$") {
			options = names[segment.name]
			if len(options) == 0 {
				return nil
			}
		}
		if keys, ok = productStrings(keys, segment.separator, options); !ok {
			return nil
		}
	}
	if constructor {
		for i := range keys {
			keys[i] += ".<init>"
		}
	}
	return keys
}

type calleeSegment struct {
	separator string
	name      string
}

// parseCallPattern reads a pattern of the form `[new] primary(.name|::name)*(args)`
// and returns the callee path before the final argument list. The primary is
// an identifier, a metavariable or a typed metavariable `(Type $X)`, whose
// type path stands in for the receiver. A call anywhere before the final
// argument list, as in `require("m").fn(x)` or `a.b(x).c(y)`, rejects the
// pattern: the outermost callee is then a method on a call result.
func parseCallPattern(pattern string) ([]calleeSegment, bool, bool) {
	p := &calleeParser{src: strings.TrimSuffix(strings.TrimSpace(pattern), ";")}
	constructor := p.keyword("new")
	callee, typed, ok := p.primary()
	if !ok || (typed && constructor) {
		return nil, false, false
	}
	for {
		p.skipSpace()
		switch {
		case p.consume("::"):
			name, ok := p.name()
			if !ok {
				return nil, false, false
			}
			callee = append(callee, calleeSegment{separator: "::", name: name})
		case p.consume("."):
			name, ok := p.name()
			if !ok {
				return nil, false, false
			}
			callee = append(callee, calleeSegment{separator: ".", name: name})
			typed = false
		case p.peek() == '(':
			if !p.skipBalanced() {
				return nil, false, false
			}
			p.skipSpace()
			if p.pos != len(p.src) || typed || isControlKeywordCallee(callee) {
				return nil, false, false
			}
			return callee, constructor, true
		default:
			return nil, false, false
		}
	}
}

// controlKeywords are words that read as a call in a pattern, `if (f(x))` or
// `new(T)`, without naming a function.
var controlKeywords = map[string]bool{
	"if": true, "elif": true, "while": true, "for": true, "switch": true, "match": true,
	"return": true, "new": true, "catch": true, "sizeof": true, "typeof": true,
}

// isControlKeywordCallee reports a single-segment callee that is a control
// keyword, which names no function and must not become a catalog key.
func isControlKeywordCallee(callee []calleeSegment) bool {
	return len(callee) == 1 && controlKeywords[callee[0].name]
}

type calleeParser struct {
	src string
	pos int
}

func (p *calleeParser) skipSpace() {
	for p.pos < len(p.src) && strings.ContainsRune(" \t\r\n", rune(p.src[p.pos])) {
		p.pos++
	}
}

func (p *calleeParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *calleeParser) consume(token string) bool {
	if strings.HasPrefix(p.src[p.pos:], token) {
		p.pos += len(token)
		return true
	}
	return false
}

func (p *calleeParser) keyword(word string) bool {
	rest := p.src[p.pos:]
	if strings.HasPrefix(rest, word) && len(rest) > len(word) && strings.ContainsRune(" \t\r\n", rune(rest[len(word)])) {
		p.pos += len(word)
		p.skipSpace()
		return true
	}
	return false
}

// name reads an identifier or a metavariable.
func (p *calleeParser) name() (string, bool) {
	p.skipSpace()
	start := p.pos
	if p.peek() == '$' {
		p.pos++
	}
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			break
		}
		p.pos++
	}
	name := p.src[start:p.pos]
	if !plainIdentifier.MatchString(strings.TrimPrefix(name, "$")) {
		return "", false
	}
	return name, true
}

func (p *calleeParser) primary() ([]calleeSegment, bool, bool) {
	if p.peek() != '(' {
		name, ok := p.name()
		return []calleeSegment{{name: name}}, false, ok
	}
	start := p.pos
	if !p.skipBalanced() {
		return nil, false, false
	}
	fields := strings.Fields(p.src[start+1 : p.pos-1])
	if len(fields) != 2 || !strings.HasPrefix(fields[1], "$") || !plainIdentifier.MatchString(fields[1][1:]) {
		return nil, false, false
	}
	var typePath []calleeSegment
	for i, part := range strings.Split(fields[0], ".") {
		if !plainIdentifier.MatchString(part) {
			return nil, false, false
		}
		separator := "."
		if i == 0 {
			separator = ""
		}
		typePath = append(typePath, calleeSegment{separator: separator, name: part})
	}
	return typePath, true, true
}

// skipBalanced advances past the bracketed group that starts at the current
// position, skipping string literals, and reports false when it never closes.
func (p *calleeParser) skipBalanced() bool {
	depth := 0
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		p.pos++
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return true
			}
		case '"', '\'', '`':
			for p.pos < len(p.src) && p.src[p.pos] != c {
				if p.src[p.pos] == '\\' {
					p.pos++
				}
				p.pos++
			}
			p.pos++
		}
	}
	return false
}
