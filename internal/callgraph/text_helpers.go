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
