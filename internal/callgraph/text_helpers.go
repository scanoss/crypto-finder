package callgraph

import "strings"

func splitTopLevelCommaList(s string) []string {
	var parts []string
	var current strings.Builder

	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	angleDepth := 0

	inSingle := false
	inDouble := false
	inBacktick := false
	escapeNext := false

	flush := func() {
		part := strings.TrimSpace(current.String())
		current.Reset()
		if part != "" {
			parts = append(parts, part)
		}
	}

	for _, r := range s {
		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if (inSingle || inDouble || inBacktick) && r == '\\' {
			current.WriteRune(r)
			escapeNext = true
			continue
		}

		switch r {
		case '\'':
			if !inDouble && !inBacktick {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inBacktick {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inBacktick = !inBacktick
			}
		}

		if inSingle || inDouble || inBacktick {
			current.WriteRune(r)
			continue
		}

		switch r {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '<':
			angleDepth++
		case '>':
			if angleDepth > 0 {
				angleDepth--
			}
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 {
				flush()
				continue
			}
		}

		current.WriteRune(r)
	}

	flush()
	return parts
}

func trimOuterDelimiters(s string, open, close rune) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && rune(s[0]) == open && rune(s[len(s)-1]) == close {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func parseArgumentsFromDelimitedContent(content string) []string {
	inner := trimOuterDelimiters(content, '(', ')')
	if inner == "" {
		return nil
	}
	return splitTopLevelCommaList(inner)
}
