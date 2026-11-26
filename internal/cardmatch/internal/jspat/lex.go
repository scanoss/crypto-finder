package jspat

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind uint8

const (
	tEOF   tokKind = iota
	tIdent         // identifier or keyword (a metavariable too: `$X` is an identifier by the lexer)
	tNum
	tStr   // string literal, or a template literal without interpolation
	tTmpl  // template literal with interpolation
	tRegex // regular expression literal
	tPunct
)

type token struct {
	kind tokKind
	s    string // source text
	v    string // tStr: decoded value
	nl   bool   // a line break precedes the token
}

const (
	tokEllipsis  = "..."
	tokDeepOpen  = "<..."
	tokDeepClose = "...>"
	kwAwait      = "await"
	kwFunction   = "function"
	reasonExpr   = "expr"
)

var errLex = errors.New("lex")

// puncts lists the multi-character punctuators, longest first.
var puncts = []string{
	">>>=", tokEllipsis, "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=",
	"&=", "|=", "^=", "**", "<<", ">>",
}

var regexPrecedingWords = map[string]bool{
	"return": true, "typeof": true, "case": true, "delete": true, "void": true,
	"in": true, "of": true, "new": true, kwAwait: true, "yield": true, "throw": true,
}

func isIdentStart(r rune) bool { return r == '$' || r == '_' || unicode.IsLetter(r) }

func isIdentPart(r rune) bool { return isIdentStart(r) || unicode.IsDigit(r) }

// lex splits src into tokens. In pattern mode `<...` and `...>` are single tokens and an
// unterminated string is an error; in concrete mode lexing never fails.
func lex(src string, pattern bool) ([]token, error) { //nolint:funlen,gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	var toks []token
	nl := false
	emit := func(t token) {
		t.nl = nl
		nl = false
		toks = append(toks, t)
	}
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			nl = true
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			i++
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
				continue
			}
			if strings.Contains(src[i:i+2+end], "\n") {
				nl = true
			}
			i += end + 4
			continue
		}

		switch {
		case c == '"' || c == '\'':
			end, ok := scanQuoted(src, i)
			if !ok {
				if pattern {
					return nil, errLex
				}
				emit(token{kind: tTmpl, s: src[i:]})
				return toks, nil
			}
			emit(token{kind: tStr, s: src[i:end], v: decode(src[i+1 : end-1])})
			i = end
		case c == '`':
			end, interp, ok := scanTemplate(src, i)
			if !ok {
				if pattern {
					return nil, errLex
				}
				emit(token{kind: tTmpl, s: src[i:]})
				return toks, nil
			}
			if interp {
				emit(token{kind: tTmpl, s: src[i:end]})
			} else {
				emit(token{kind: tStr, s: src[i:end], v: decode(src[i+1 : end-1])})
			}
			i = end
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9':
			end := scanNumber(src, i)
			emit(token{kind: tNum, s: src[i:end]})
			i = end
		default:
			r, size := utf8.DecodeRuneInString(src[i:])
			switch {
			case isIdentStart(r):
				j := i + size
				for j < len(src) {
					r2, s2 := utf8.DecodeRuneInString(src[j:])
					if !isIdentPart(r2) {
						break
					}
					j += s2
				}
				emit(token{kind: tIdent, s: src[i:j]})
				i = j
			case c == '/' && regexAllowed(toks):
				if end, ok := scanRegex(src, i); ok {
					emit(token{kind: tRegex, s: src[i:end]})
					i = end
					continue
				}
				emit(token{kind: tPunct, s: "/"})
				i++
			default:
				p := punctAt(src[i:], pattern)
				if p == "" {
					p = src[i : i+size]
				}
				emit(token{kind: tPunct, s: p})
				i += len(p)
			}
		}
	}
	return toks, nil
}

func punctAt(s string, pattern bool) string {
	if pattern {
		if strings.HasPrefix(s, tokDeepOpen) {
			return tokDeepOpen
		}
		if strings.HasPrefix(s, tokDeepClose) {
			return tokDeepClose
		}
	}
	for _, p := range puncts {
		if strings.HasPrefix(s, p) {
			if p == "?." && len(s) > 2 && s[2] >= '0' && s[2] <= '9' {
				continue
			}
			return p
		}
	}
	return ""
}

func regexAllowed(toks []token) bool {
	if len(toks) == 0 {
		return true
	}
	p := toks[len(toks)-1]
	switch p.kind { //nolint:exhaustive // the remaining kinds share the default behavior
	case tPunct:
		return p.s != ")" && p.s != "]" && p.s != "}"
	case tIdent:
		return regexPrecedingWords[p.s]
	default:
		return false
	}
}

func scanRegex(src string, i int) (int, bool) {
	j := i + 1
	inClass := false
	for j < len(src) {
		switch src[j] {
		case '\n':
			return 0, false
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				j++
				for j < len(src) && (src[j] >= 'a' && src[j] <= 'z') {
					j++
				}
				return j, true
			}
		}
		j++
	}
	return 0, false
}

func scanNumber(src string, i int) int { //nolint:gocyclo // one case per grammar construct; splitting it hides the grammar
	j := i
	for j < len(src) {
		c := src[j]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			j++
		case c == '.' && j+1 < len(src) && src[j+1] >= '0' && src[j+1] <= '9':
			j++
		case (c == '+' || c == '-') && j > i && (src[j-1] == 'e' || src[j-1] == 'E') && !isHex(src[i:j]):
			j++
		default:
			return j
		}
	}
	return j
}

func isHex(s string) bool { return len(s) > 1 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') }

// scanQuoted returns the index just past the closing quote of the string opened at src[i].
func scanQuoted(src string, i int) (int, bool) {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case q:
			return j + 1, true
		case '\n':
			return 0, false
		}
	}
	return 0, false
}

// scanTemplate returns the index just past the closing backtick, and whether `${` occurs.
func scanTemplate(src string, i int) (end int, interp, ok bool) {
	depth := 0
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '$':
			if j+1 < len(src) && src[j+1] == '{' {
				depth++
				interp = true
				j++
			}
		case '}':
			if depth > 0 {
				depth--
			}
		case '`':
			if depth == 0 {
				return j + 1, interp, true
			}
		}
	}
	return 0, false, false
}

// decode resolves the escape sequences of a string literal body.
func decode(s string) string { //nolint:gocognit,gocyclo // one case per grammar construct; splitting it hides the grammar
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '0':
			b.WriteByte(0)
		case '\n':
		case 'x':
			if i+3 <= len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteRune(rune(v))
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		case 'u':
			if i+1 < len(s) && s[i+1] == '{' { //nolint:nestif // one case per grammar construct; splitting it hides the grammar
				if end := strings.IndexByte(s[i:], '}'); end > 0 {
					if v, err := strconv.ParseUint(s[i+2:i+end], 16, 32); err == nil && v <= unicode.MaxRune {
						b.WriteRune(rune(v)) //nolint:gosec // v <= unicode.MaxRune, checked above
						i += end
						continue
					}
				}
			} else if i+5 <= len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil && v <= unicode.MaxRune {
					b.WriteRune(rune(v)) //nolint:gosec // v <= unicode.MaxRune, checked above
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// canon is the canonical double-quoted text of a string value.
func canon(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tokText(t token) string {
	if t.kind == tStr {
		return canon(t.v)
	}
	return t.s
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// joinToks renders tokens as whitespace-normalised text.
func joinToks(ts []token) string {
	var b strings.Builder
	var a byte
	for _, t := range ts {
		s := tokText(t)
		if s == "" {
			continue
		}
		if f := s[0]; a != 0 && (isWordByte(a) && isWordByte(f) || (a == '+' || a == '-') && a == f || a == ',') {
			b.WriteByte(' ')
		}
		b.WriteString(s)
		a = s[len(s)-1]
	}
	return b.String()
}
