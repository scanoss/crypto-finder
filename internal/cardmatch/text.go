package cardmatch

// Expression text helpers (match2.py "expression text" section). The fragment gives expression text
// in three places: a call's `raw` (receiver expression + method name), an argument's
// `argument_expression`, and the initializer of a local variable. These read a call out of such text.
// Python indexes strings by code point, so the scanners work on runes.

import (
	"strings"
	"unicode"

	"github.com/dlclark/regexp2"
)

// pyWord is Python's `\w` for one character: [A-Za-z0-9_] plus Unicode letters and numbers.
func pyWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// identMatch is IDENT.match(s) with IDENT = ^[A-Za-z_]\w*$ (`$` also matches before a final newline).
func identMatch(s string) bool {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
		} else if !pyWord(r) {
			return false
		}
	}
	return true
}

// wordDotsMatch is re.match(r"^[\w.]+$", s).
func wordDotsMatch(s string) bool {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && !pyWord(r) {
			return false
		}
	}
	return true
}

// qualifiedMatch is QUALIFIED.match(s) with QUALIFIED = ^[a-z]\w*(?:\.\w+)+$.
func qualifiedMatch(s string) bool {
	s = strings.TrimSuffix(s, "\n")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for i, p := range parts {
		if p == "" && i > 0 {
			return false
		}
		for _, r := range p {
			if !pyWord(r) {
				return false
			}
		}
	}
	return true
}

func topLevelSplit(s string, sep rune) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	var quote, prev rune
	for _, ch := range s {
		switch {
		case quote != 0:
			cur.WriteRune(ch)
			if ch == quote && prev != '\\' {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
			cur.WriteRune(ch)
		case ch == '(' || ch == '[' || ch == '{':
			depth++
			cur.WriteRune(ch)
		case ch == ')' || ch == ']' || ch == '}':
			depth--
			cur.WriteRune(ch)
		case ch == sep && depth == 0:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
		prev = ch
	}
	return append(out, cur.String())
}

// unwrap drops parentheses that enclose the whole expression: '(new T())' -> 'new T()'.
func unwrap(text string) string {
	for strings.HasPrefix(text, "(") && strings.HasSuffix(text, ")") {
		rs := []rune(text)
		depth, i := 0, 0
		for i = 0; i < len(rs); i++ {
			if rs[i] == '(' {
				depth++
			}
			if rs[i] == ')' {
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if i == len(rs) { // the Python loop ran to the end without a break: i is the last index
			i = len(rs) - 1
		}
		if i != len(rs)-1 {
			break
		}
		text = pyStrip(string(rs[1 : len(rs)-1]))
	}
	return text
}

var castRx = regexp2.MustCompile(`\A(?:^\(\s*([A-Za-z_][\w.]*(?:<[^()]*>)?(?:\[\])?)\s*\)\s*(?=[A-Za-z_(]))`, regexp2.None)

// stripCast: '(T) expr' -> (T, 'expr'); also unwraps one pair of redundant parentheses.
// A nil text is passed as "" (Python: `text or ""`).
func stripCast(text string) (string, string) {
	text = unwrap(pyStrip(text))
	if !strings.HasPrefix(text, "(") {
		return "", text
	}
	m, err := castRx.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return "", text
	}
	rs := []rune(text)
	return m.GroupByNumber(1).String(), unwrap(pyStrip(string(rs[m.Index+m.Length:])))
}

// ParsedCall is the outermost call of an expression. Prefix is what the fragment stores as `raw`.
type ParsedCall struct {
	Prefix   string
	Receiver string // "" = None
	Method   string
	Type     string // "" = None (set for `new T(...)`)
	Args     []string
}

var newRx = `^new\s+([\w.]+)\s*(?:<[^()]*>)?$`

func parseCall(text string) *ParsedCall { //nolint:gocognit,gocyclo // mirrors the reference matcher's control flow branch for branch; the equivalence suites pin it, so a split is a separate change
	_, text = stripCast(text)
	if !strings.HasSuffix(text, ")") {
		return nil
	}
	rs := []rune(text)
	depth, openI := 0, -1
	var quote rune
scan:
	for i := len(rs) - 1; i >= 0; i-- {
		ch := rs[i]
		switch {
		case quote != 0:
			if ch == quote && (i == 0 || rs[i-1] != '\\') {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == ')':
			depth++
		case ch == '(':
			depth--
			if depth == 0 {
				openI = i
				break scan
			}
		}
	}
	if openI <= 0 {
		return nil
	}
	prefix, inner := pyStrip(string(rs[:openI])), string(rs[openI+1:len(rs)-1])
	var args []string
	if pyStrip(inner) != "" {
		for _, a := range topLevelSplit(inner, ',') {
			args = append(args, pyStrip(a))
		}
	}
	if strings.HasPrefix(prefix, "new") {
		if vals, ok, hit := reMatchNumbered(newRx, prefix); hit && ok[1] {
			return &ParsedCall{Prefix: prefix, Method: strInit, Type: vals[1], Args: args}
		}
	}
	parts := topLevelSplit(prefix, '.')
	method := pyStrip(parts[len(parts)-1])
	if !identMatch(method) {
		return nil
	}
	return &ParsedCall{Prefix: prefix, Receiver: pyStrip(strings.Join(parts[:len(parts)-1], ".")), Method: method, Args: args}
}
