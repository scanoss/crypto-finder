package callgraph

import "strings"

func splitTopLevelCommaList(s string) []string {
	var parts []string
	var current strings.Builder
	state := commaSplitState{}

	flush := func() {
		part := strings.TrimSpace(current.String())
		current.Reset()
		if part != "" {
			parts = append(parts, part)
		}
	}

	for _, r := range s {
		if state.escapeNext {
			current.WriteRune(r)
			state.escapeNext = false
			continue
		}

		if state.inQuotedString() && r == '\\' {
			current.WriteRune(r)
			state.escapeNext = true
			continue
		}

		state.toggleQuotes(r)
		if state.inQuotedString() {
			current.WriteRune(r)
			continue
		}

		if state.handleDelimiter(r) {
			current.WriteRune(r)
			continue
		}
		if r == ',' && state.atTopLevel() {
			flush()
			continue
		}

		current.WriteRune(r)
	}

	flush()
	return parts
}

type commaSplitState struct {
	parenDepth   int
	bracketDepth int
	braceDepth   int
	angleDepth   int
	inSingle     bool
	inDouble     bool
	inBacktick   bool
	escapeNext   bool
}

func (s *commaSplitState) inQuotedString() bool {
	return s.inSingle || s.inDouble || s.inBacktick
}

func (s *commaSplitState) toggleQuotes(r rune) {
	switch r {
	case '\'':
		if !s.inDouble && !s.inBacktick {
			s.inSingle = !s.inSingle
		}
	case '"':
		if !s.inSingle && !s.inBacktick {
			s.inDouble = !s.inDouble
		}
	case '`':
		if !s.inSingle && !s.inDouble {
			s.inBacktick = !s.inBacktick
		}
	}
}

func (s *commaSplitState) handleDelimiter(r rune) bool {
	switch r {
	case '(':
		s.parenDepth++
	case ')':
		s.parenDepth = max(s.parenDepth-1, 0)
	case '[':
		s.bracketDepth++
	case ']':
		s.bracketDepth = max(s.bracketDepth-1, 0)
	case '{':
		s.braceDepth++
	case '}':
		s.braceDepth = max(s.braceDepth-1, 0)
	case '<':
		s.angleDepth++
	case '>':
		s.angleDepth = max(s.angleDepth-1, 0)
	default:
		return false
	}
	return true
}

func (s *commaSplitState) atTopLevel() bool {
	return s.parenDepth == 0 && s.bracketDepth == 0 && s.braceDepth == 0 && s.angleDepth == 0
}

func trimOuterParens(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && rune(s[0]) == '(' && rune(s[len(s)-1]) == ')' {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func parseArgumentsFromDelimitedContent(content string) []string {
	inner := trimOuterParens(content)
	if inner == "" {
		return nil
	}
	return splitTopLevelCommaList(inner)
}

// stripJavaExpressionComments removes `//` line comments and `/* */` block
// comments from a Java expression while preserving comment-like sequences that
// appear inside string or char literals (e.g. "http://example"). It is used
// before splitting/tracing multi-line argument lists, where inline comments
// (e.g. `new RSAKeyGenerationParameters(BigInteger.valueOf(65537), // exponent`)
// would otherwise be glued onto the following argument's expression text.
func stripJavaExpressionComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		switch {
		case runes[i] == '"' || runes[i] == '\'':
			i = writeJavaLiteral(&b, runes, i)
		case isCommentStart(runes, i, '/'):
			i = skipLineComment(runes, i) // line comment: drop to end-of-line (newline kept by caller)
		case isCommentStart(runes, i, '*'):
			i = skipBlockComment(runes, i)
		default:
			b.WriteRune(runes[i])
		}
	}
	return b.String()
}

// isCommentStart reports whether runes[i:] opens a comment of the given second
// character ('/' for line comments, '*' for block comments).
func isCommentStart(runes []rune, i int, second rune) bool {
	return runes[i] == '/' && i+1 < len(runes) && runes[i+1] == second
}

// writeJavaLiteral copies a string or char literal beginning at the opening
// quote runes[i] into b (honoring backslash escapes) and returns the index of
// its closing quote (or the final rune if the literal is unterminated).
func writeJavaLiteral(b *strings.Builder, runes []rune, i int) int {
	quote := runes[i]
	b.WriteRune(runes[i])
	for i++; i < len(runes); i++ {
		b.WriteRune(runes[i])
		if runes[i] == '\\' && i+1 < len(runes) {
			i++
			b.WriteRune(runes[i])
			continue
		}
		if runes[i] == quote {
			break
		}
	}
	return i
}

// skipLineComment returns the index of the last rune of a `//` comment — the
// rune just before the newline — leaving the newline for the caller to emit.
func skipLineComment(runes []rune, i int) int {
	for i+1 < len(runes) && runes[i+1] != '\n' {
		i++
	}
	return i
}

// skipBlockComment returns the index of the closing `/` of a `/* */` comment
// (or the final rune if unterminated).
func skipBlockComment(runes []rune, i int) int {
	for i += 2; i+1 < len(runes); i++ {
		if runes[i] == '*' && runes[i+1] == '/' {
			return i + 1
		}
	}
	return len(runes) - 1
}
