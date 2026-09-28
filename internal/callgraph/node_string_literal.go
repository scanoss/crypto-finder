// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strconv"
	"strings"
	"unicode/utf16"
)

// canonicalNodeStringLiteral rewrites a JavaScript or TypeScript string
// literal ('...', "..." or a template without substitutions) as the double-quoted
// literal of the same value, the spelling every other parser records and the
// scan layer compares selector conditions against. It reports false for
// anything that is not exactly one literal, including a template with a
// ${...} substitution, whose value is not known until run time.
func canonicalNodeStringLiteral(text string) (string, bool) {
	if len(text) < 2 {
		return "", false
	}
	quote := text[0]
	if (quote != '"' && quote != '\'' && quote != '`') || text[len(text)-1] != quote {
		return "", false
	}
	value, ok := decodeNodeStringBody(text[1:len(text)-1], quote)
	if !ok {
		return "", false
	}
	return strconv.Quote(value), true
}

func decodeNodeStringBody(body string, quote byte) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == quote:
			return "", false
		case quote == '`' && c == '$' && i+1 < len(body) && body[i+1] == '{':
			return "", false
		case c != '\\':
			out.WriteByte(c)
			continue
		}
		if i+1 >= len(body) {
			return "", false
		}
		i++
		consumed, ok := decodeNodeEscape(&out, body[i:])
		if !ok {
			return "", false
		}
		i += consumed - 1
	}
	return out.String(), true
}

var nodeSingleCharEscapes = map[byte]string{
	'n': "\n", 'r': "\r", 't': "\t", 'b': "\b", 'f': "\f", 'v': "\v",
}

// decodeNodeEscape decodes the escape sequence that follows a backslash and
// returns how many bytes of rest it consumed.
func decodeNodeEscape(out *strings.Builder, rest string) (int, bool) {
	c := rest[0]
	if s, ok := nodeSingleCharEscapes[c]; ok {
		out.WriteString(s)
		return 1, true
	}
	if n := nodeLineContinuationLength(rest); n > 0 {
		return n, true
	}
	switch {
	case c == '0' && (len(rest) == 1 || rest[1] < '0' || rest[1] > '9'):
		out.WriteByte(0)
		return 1, true
	case c >= '0' && c <= '9':
		return 0, false // legacy octal escapes are rejected in strict code and templates
	case c == 'x':
		return decodeNodeHexEscape(out, rest)
	case c == 'u':
		return decodeNodeUnicodeEscape(out, rest)
	}
	out.WriteByte(c)
	return 1, true
}

// nodeLineContinuationLength reports the length of the line terminator a
// backslash escapes at the start of rest, which contributes nothing to the
// value, or 0 when rest does not start with one.
func nodeLineContinuationLength(rest string) int {
	for _, terminator := range []string{"\r\n", "\n", "\r", "\u2028", "\u2029"} {
		if strings.HasPrefix(rest, terminator) {
			return len(terminator)
		}
	}
	return 0
}

func decodeNodeHexEscape(out *strings.Builder, rest string) (int, bool) {
	if len(rest) < 3 {
		return 0, false
	}
	r, err := strconv.ParseUint(rest[1:3], 16, 8)
	if err != nil {
		return 0, false
	}
	out.WriteRune(rune(r))
	return 3, true
}

func decodeNodeUnicodeEscape(out *strings.Builder, rest string) (int, bool) {
	r, consumed, ok := parseNodeCodeUnit(rest)
	if !ok {
		return 0, false
	}
	if utf16.IsSurrogate(r) {
		after := rest[consumed:]
		if !strings.HasPrefix(after, `\u`) {
			return 0, false
		}
		low, lowConsumed, ok := parseNodeCodeUnit(after[1:])
		if !ok {
			return 0, false
		}
		r = utf16.DecodeRune(r, low)
		if r == '\uFFFD' {
			return 0, false
		}
		consumed += 1 + lowConsumed
	}
	out.WriteRune(r)
	return consumed, true
}

// parseNodeCodeUnit parses u0041 or u{1F600} at the start of rest.
func parseNodeCodeUnit(rest string) (rune, int, bool) {
	if strings.HasPrefix(rest, "u{") {
		end := strings.IndexByte(rest, '}')
		if end < 3 {
			return 0, 0, false
		}
		r, err := strconv.ParseUint(rest[2:end], 16, 32)
		if err != nil || r > 0x10FFFF {
			return 0, 0, false
		}
		return rune(r), end + 1, true
	}
	if len(rest) < 5 {
		return 0, 0, false
	}
	r, err := strconv.ParseUint(rest[1:5], 16, 16)
	if err != nil {
		return 0, 0, false
	}
	return rune(r), 5, true
}
