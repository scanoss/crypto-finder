// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// nodeMemberModifiers are the words that may precede a member's own name.
var nodeMemberModifiers = []string{"get", "set", "async", "static"}

var (
	nodeIdentifierKey = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	// nodeDecimalInteger is a plain base-10 integer literal. A leading zero is
	// a legacy octal in sloppy mode, and separators, exponents and fractions are
	// other spellings the reader does not interpret, so none of them match.
	nodeDecimalInteger = regexp.MustCompile(`^(?:0|[1-9]\d*)$`)
)

// NodeObjectLiteralProperty reads the literal value of one property from the
// source text of a JavaScript or TypeScript object-literal argument, such as
// `{ modulusLength: 2048, publicExponent: 0x10001 }`.
//
// It answers only when the property's value is certain from the text alone. The
// value is returned in the spelling the scan layer compares against: a decimal
// integer as written, a string literal as a double-quoted literal. It reports
// false when
//   - the text is not exactly one object literal;
//   - the object holds a spread element or a computed key, either of which can
//     supply or override any property;
//   - the object holds a comment, which the scanner below does not skip;
//   - the property is absent, written as a shorthand or a method, or given
//     twice;
//   - the value is anything but an integer or string literal: an identifier, a
//     call, an expression, a template with a substitution.
//
// The caller decides what a returned value means. An integer where a string was
// expected, or the reverse, is the caller's to reject.
func NodeObjectLiteralProperty(expression, name string) (string, bool) {
	entries, ok := splitNodeObjectLiteral(expression)
	if !ok {
		return "", false
	}
	var value string
	found := false
	for _, entry := range entries {
		key, rest, hasValue, ok := nodeObjectEntryKey(entry)
		if !ok {
			return "", false
		}
		if key != name {
			continue
		}
		if found || !hasValue {
			return "", false
		}
		found = true
		value = rest
	}
	if !found {
		return "", false
	}
	return nodeLiteralValue(value)
}

// splitNodeObjectLiteral returns the top-level entries of an object literal, or
// false when the text is not one or holds a comment.
func splitNodeObjectLiteral(expression string) ([]string, bool) {
	body, ok := nodeObjectBody(expression)
	if !ok {
		return nil, false
	}
	var (
		entries []string
		depth   int
		start   int
	)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch c {
		case '\'', '"', '`':
			end := closingQuote(body[i:])
			if end < 0 {
				return nil, false
			}
			i += end
		case '/':
			if startsNodeComment(body[i:]) {
				return nil, false
			}
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				entries = append(entries, body[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	entries = append(entries, body[start:])
	if last := len(entries) - 1; strings.TrimSpace(entries[last]) == "" {
		entries = entries[:last]
	}
	return entries, true
}

// nodeObjectBody returns the text between the braces of an expression that is
// exactly one object literal.
func nodeObjectBody(expression string) (string, bool) {
	text := strings.TrimSpace(expression)
	if len(text) < 2 || text[0] != '{' || text[len(text)-1] != '}' {
		return "", false
	}
	return text[1 : len(text)-1], true
}

// startsNodeComment reports whether text begins a line or block comment.
func startsNodeComment(text string) bool {
	return strings.HasPrefix(text, "//") || strings.HasPrefix(text, "/*")
}

// nodeObjectEntryKey splits one object-literal entry into its key and the text
// after the colon. hasValue is false for a shorthand or a method, whose key is
// still returned so a caller asking for that name can refuse it. ok is false
// for an entry whose key cannot be named: a spread, a computed key, or an
// empty entry.
func nodeObjectEntryKey(entry string) (key, value string, hasValue, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.HasPrefix(entry, "...") || entry[0] == '[' {
		return "", "", false, false
	}
	if entry[0] == '\'' || entry[0] == '"' {
		return nodeQuotedEntryKey(entry)
	}
	end := identifierPrefixLength(entry)
	if end == 0 {
		// Punctuation such as a generator's `*` can name any property.
		return "", "", false, false
	}
	name := entry[:end]
	rest := strings.TrimSpace(entry[end:])
	if !nodeIdentifierKey.MatchString(name) {
		// A numeric key names no identifier property.
		return name, "", false, true
	}
	if strings.HasPrefix(rest, ":") {
		return name, strings.TrimSpace(rest[1:]), true, true
	}
	if slices.Contains(nodeMemberModifiers, name) {
		// `get modulusLength() {}` defines modulusLength through an accessor.
		if next := identifierPrefixLength(rest); next > 0 {
			return rest[:next], "", false, true
		}
	}
	return name, "", false, true
}

func identifierPrefixLength(text string) int {
	end := 0
	for end < len(text) && isNodeIdentifierByte(text[end]) {
		end++
	}
	return end
}

// nodeQuotedEntryKey reads an entry whose key is a quoted string. A key written
// with an escape is refused: the escape can spell a name the text does not
// show, so a duplicate of the property asked for could go unseen.
func nodeQuotedEntryKey(entry string) (key, value string, hasValue, ok bool) {
	end := closingQuote(entry)
	if end < 0 || strings.Contains(entry[:end+1], `\`) {
		return "", "", false, false
	}
	literal, ok := canonicalNodeStringLiteral(entry[:end+1])
	if !ok {
		return "", "", false, false
	}
	unquoted, err := strconv.Unquote(literal)
	if err != nil {
		return "", "", false, false
	}
	rest := strings.TrimSpace(entry[end+1:])
	if !strings.HasPrefix(rest, ":") {
		return unquoted, "", false, true
	}
	return unquoted, strings.TrimSpace(rest[1:]), true, true
}

func isNodeIdentifierByte(c byte) bool {
	return c == '_' || c == '$' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// closingQuote returns the index of the quote that closes the string literal
// beginning at text[0], or -1.
func closingQuote(text string) int {
	quote := text[0]
	for i := 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case quote:
			return i
		}
	}
	return -1
}

// nodeLiteralValue accepts a decimal integer or a string literal.
func nodeLiteralValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if nodeDecimalInteger.MatchString(value) {
		return value, true
	}
	return canonicalNodeStringLiteral(value)
}
