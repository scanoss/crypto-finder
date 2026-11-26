package cardmatch

// Python `re` semantics on top of regexp2 (a .NET-style backtracking engine).
//
// The patterns in the index and the cards are written for Python's `re` (lookahead, named groups,
// inline flags). Go's RE2 rejects lookaround, so they go through regexp2 in its default (.NET) mode,
// which agrees with Python on what these patterns use: `^`/`$` ($ also before a final newline),
// `.` not matching a newline, Unicode `\d`/`\w`/`\s`, `(?i)`, `(?s)`, lookahead.
// Differences handled here:
//   - Python's `(?P<name>...)` is spelled `(?<name>...)` in .NET (regexp2 accepts `(?P<` only in
//     its RE2 mode, which changes other semantics), so it is rewritten.
//   - re.match anchors at the start only: the pattern is wrapped as `\A(?:...)`.
//     re.fullmatch is not used by the matchers. re.search is an unanchored find.
//   - groupdict(): the explicitly named groups, plus every group by its number ("1", "2", ...)
//     as OpenGrep binds `$1`, `$2` from a metavariable-regex; a group that did not participate
//     is None (callers drop None values, as the Python code does).
//   - Group numbers: .NET numbers unnamed groups before named ones, Python and OpenGrep left to
//     right over all groups; pyGroupOrder maps one to the other.

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
)

type pyRegex struct {
	match  *regexp2.Regexp // \A(?:pattern)
	search *regexp2.Regexp // pattern
	named  []string        // explicitly named groups
	order  []string        // regexp2 group name of Python group i+1, left to right
}

var (
	rxCache   = map[string]*pyRegex{}
	rxCacheMu sync.Mutex
	pNamed    = regexp.MustCompile(`\(\?P<([A-Za-z_][A-Za-z0-9_]*)>`)
)

// pyToNet rewrites the Python-only spellings the data uses into regexp2's.
func pyToNet(rx string) string {
	if strings.Contains(rx, "(?P<") {
		rx = pNamed.ReplaceAllString(rx, "(?<$1>")
	}
	return rx
}

// compileRx returns the compiled form of a Python pattern, compiled once.
func compileRx(rx string) *pyRegex {
	rxCacheMu.Lock()
	defer rxCacheMu.Unlock()
	if r, ok := rxCache[rx]; ok {
		return r
	}
	net := pyToNet(rx)
	r := &pyRegex{
		match:  regexp2.MustCompile(`\A(?:`+net+`)`, regexp2.None),
		search: regexp2.MustCompile(net, regexp2.None),
	}
	for _, n := range r.search.GetGroupNames() {
		if !isAllDigits(n) {
			r.named = append(r.named, n)
		}
	}
	r.order = pyGroupOrder(net)
	rxCache[rx] = r
	return r
}

// pyGroupOrder lists the capturing groups of a regexp2 pattern left to right,
// each as regexp2 names it: its name, or for an unnamed group its .NET number
// (unnamed groups are numbered first, in order).
func pyGroupOrder(rx string) []string {
	var order []string
	unnamed, inClass := 0, false
	for i := 0; i < len(rx); i++ {
		switch c := rx[i]; {
		case c == '\\':
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
			if i+1 < len(rx) && rx[i+1] == ']' { // a leading ] is a literal
				i++
			}
		case c == '(' && (i+1 >= len(rx) || rx[i+1] != '?'):
			unnamed++
			order = append(order, strconv.Itoa(unnamed))
		case c == '(' && strings.HasPrefix(rx[i:], "(?<") && !strings.HasPrefix(rx[i:], "(?<=") && !strings.HasPrefix(rx[i:], "(?<!"):
			end := strings.IndexByte(rx[i:], '>')
			if end > 3 {
				order = append(order, rx[i+3:i+end])
			}
		}
	}
	return order
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Groups is a groupdict with the None values left out (what every caller keeps).
type Groups map[string]string

func (r *pyRegex) groups(m *regexp2.Match) Groups {
	g := Groups{}
	for _, n := range r.named {
		grp := m.GroupByName(n)
		if grp != nil && len(grp.Captures) > 0 {
			g[n] = grp.String()
		}
	}
	for i, n := range r.order {
		grp := m.GroupByName(n)
		if grp != nil && len(grp.Captures) > 0 {
			g[strconv.Itoa(i+1)] = grp.String()
		}
	}
	return g
}

// reMatch is Python re.match(rx, text): nil when no match, else the groupdict without None values.
func reMatch(rx, text string) Groups {
	r := compileRx(rx)
	m, err := r.match.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return nil
	}
	return r.groups(m)
}

// reMatchOK is re.match used only as a boolean.
func reMatchOK(rx, text string) bool {
	ok, err := compileRx(rx).match.MatchString(text)
	if err != nil {
		panic(err)
	}
	return ok
}

// reSearch is Python re.search(rx, text).
func reSearch(rx, text string) Groups {
	r := compileRx(rx)
	m, err := r.search.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return nil
	}
	return r.groups(m)
}

// reSearchGroup1 is re.search(rx, text).group(1), ok=false when no match.
func reSearchGroup1(rx, text string) (string, bool) {
	r := compileRx(rx)
	m, err := r.search.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return "", false
	}
	return m.GroupByNumber(1).String(), true
}

// reMatchGroups is re.match returning numbered groups (1..n), "" plus false for a group that did not take part.
func reMatchNumbered(rx, text string) ([]string, []bool, bool) {
	r := compileRx(rx)
	m, err := r.match.FindStringMatch(text)
	if err != nil {
		panic(err)
	}
	if m == nil {
		return nil, nil, false
	}
	gs := m.Groups()
	vals, ok := make([]string, len(gs)), make([]bool, len(gs))
	for i, g := range gs {
		if len(g.Captures) > 0 {
			vals[i], ok[i] = g.String(), true
		}
	}
	return vals, ok, true
}

// reSubFunc is Python re.sub(rx, fn, s) for a pattern with no zero-width match (the `$NAME` patterns).
func reSubFunc(rx, s string, fn func(full string, groups []string) string) string {
	r := compileRx(rx).search
	var b strings.Builder
	runes := []rune(s)
	last := 0
	m, err := r.FindRunesMatch(runes)
	for ; m != nil && err == nil; m, err = r.FindNextMatch(m) {
		b.WriteString(string(runes[last:m.Index]))
		gs := m.Groups()
		vals := make([]string, len(gs))
		for i, g := range gs {
			vals[i] = g.String()
		}
		b.WriteString(fn(m.String(), vals))
		last = m.Index + m.Length
	}
	if err != nil {
		panic(err)
	}
	b.WriteString(string(runes[last:]))
	return b.String()
}

// --- Python str helpers ---------------------------------------------------------------------------

// pyIsSpace is str.isspace for one character (what `\s` and str.strip() use in Python 3).
func pyIsSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// norm is re.sub(r"\s+", "", s or "").
func norm(s string) string {
	clean := true
	for _, r := range s {
		if pyIsSpace(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !pyIsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pyStrip is str.strip().
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

func pyRStrip(s string) string {
	return strings.TrimRightFunc(s, pyIsSpace)
}

// trimQuotes is str.strip('"').
func trimQuotes(s string) string {
	return strings.Trim(s, `"`)
}
