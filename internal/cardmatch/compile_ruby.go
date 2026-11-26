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

package cardmatch

import (
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

// The Ruby rule compiler. Ruby writes a qualified name with `::` rather than
// `.`, and a rule may put a metavariable inside that path
// (`OpenSSL::Digest::$ALGO.new(...)`), which is the shape most of the ruleset's
// Ruby rules have: a constant path selects the algorithm and a
// metavariable-regex names it. Everything else -- arity, metavariables in
// arguments, the named groups that fill metadata -- is the shared compiler's,
// so only the receiver syntax is read here.
var (
	// rubyIdent is a Ruby constant or method name segment.
	rubyIdent = `[A-Za-z_][\w]*[?!]?`
	// rubyPathSegment is one segment of a constant path: a constant, or a
	// metavariable standing for one.
	rubyPathSegment = `(?:` + rubyIdent + `|\$[A-Z_0-9]+)`
	// rubyQName is a constant path: segments joined by `::`, optionally rooted
	// (`::OpenSSL`). The last `::` separates the path from nothing: a method
	// is reached with `.`, which is what rxRubyTypeRecv reads.
	rubyQName = `(?:::)?` + rubyPathSegment + `(?:::` + rubyPathSegment + `)*`

	// rxRubyTypeRecv: a call on a constant path, `OpenSSL::Digest::$ALGO.new(`.
	rxRubyTypeRecv = rxStart(`^(` + rubyQName + `)\s*\.\s*(\$?` + rubyIdent + `)\s*\(`)
	// rxRubyAnyRecv: a call on a metavariable receiver, `$ALGO.digest(`.
	rxRubyAnyRecv = rxStart(`^(\$[A-Z_0-9]+)\s*\.\s*(\$?` + rubyIdent + `)\s*\(`)
	// rxRubyNoRecv: a bare call, `Digest($NAME)`.
	rxRubyNoRecv = rxStart(`^(\$?` + rubyIdent + `)\s*\(`)
	// rxRubyNoArgs: a call written with no argument list at all, `$ALGO.new`.
	// Ruby allows it, and the ruleset uses it; it is a call of arity 0.
	rxRubyNoArgs = rxStart(`^(` + rubyQName + `)\s*\.\s*(\$?` + rubyIdent + `)\s*$`)
)

// parseRubyCall parses a Ruby call pattern into the entry shape the shared
// compiler builds for every language.
func parseRubyCall(p string) (*OMap, error) {
	p = strings.TrimSpace(p)
	if strings.Contains(p, "\n") || strings.Contains(p, "{") {
		return nil, skip("statement, block or declaration pattern")
	}
	// A call with no argument list is arity 0 and has no parentheses to walk.
	if m := find(rxRubyNoArgs, p); m != nil {
		call := omap("receiver", strType, strType, rubyUnrooted(group(m, 1)), "method", group(m, 2))
		if path := rubyUnrooted(group(m, 1)); strings.HasPrefix(path, "$") {
			call.Set("type_metavar", path)
		} else {
			rubyBindPathMetavar(call, path)
		}
		// `Digest::MD5.new` written with no argument list is the call by
		// name, whatever it is passed: OpenGrep reads the pattern that way
		// and matches `new`, `new()`, `new("x")` and `new("x", 2)` alike.
		call.Set("min_arity", int64(0))
		call.Set("max_arity", nil)
		call.Set("args", []any{})
		call.Set("method_regex", nil)
		if method := getString(call, "method"); strings.HasPrefix(method, "$") {
			call.Set("method_metavar", method)
			call.Set("method", nil)
		}
		return call, nil
	}
	var call *OMap
	var m *regexp2.Match
	switch {
	case func() bool { m = find(rxRubyTypeRecv, p); return m != nil }():
		call = omap("receiver", strType, strType, rubyUnrooted(group(m, 1)), "method", group(m, 2))
		rubyBindPathMetavar(call, rubyUnrooted(group(m, 1)))
	case func() bool { m = find(rxRubyAnyRecv, p); return m != nil }():
		// `$ALGO.digest(...)`: the whole receiver is a metavariable, which a
		// metavariable-regex then pins to a constant path (`^Digest::MD5$`).
		// Binding it as the type metavariable is what lets that regex reach
		// the entry, the same slot a path metavariable uses.
		call = omap("receiver", strType, strType, rubyUnrooted(group(m, 1)), "method", group(m, 2))
		call.Set("type_metavar", rubyUnrooted(group(m, 1)))
	case func() bool { m = find(rxRubyNoRecv, p); return m != nil }():
		call = omap("receiver", strNone, strType, nil, "method", group(m, 1))
	default:
		return nil, skip("unrecognised pattern shape") //nolint:misspell // verbatim compile-report text
	}
	return finishRubyCall(call, p, m)
}

// finishRubyCall reads the call's argument list and records its arity, the
// same way the shared compiler does. It is a Ruby copy rather than a shared
// helper: parseCallPattern mirrors the reference matcher branch for branch and
// its equivalence suites pin it, so Ruby diverging here must not move it.
func finishRubyCall(call *OMap, p string, m *regexp2.Match) (*OMap, error) {
	rs := []rune(p)
	openI := m.Index + m.Length - 1
	closeI, err := matchingParen(rs, openI)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(rs[closeI+1:])) != "" {
		return nil, skip("chained call pattern")
	}
	if strings.Contains(string(rs[:openI]), "(") {
		return nil, skip("chained call pattern")
	}
	var args []any
	seenEllipsis := false
	fixed := 0
	position := 0
	for _, text := range splitArgs(string(rs[openI+1 : closeI])) {
		kw, value := rubyPatternKeyword(text)
		a, err := parseArg(value)
		if err != nil {
			return nil, err
		}
		// A Ruby call site counts a keyword argument in its arity, so the
		// pattern must too, the way the Python compiler does.
		if getString(a, "kind") != strEllipsis {
			fixed++
		}
		if kw != "" {
			// A keyword argument has no position: the rule writes
			// `..., digest_algorithm: $D, ...`, and the ellipses on both
			// sides say the caller may put it anywhere.
			a.Set("kw", kw)
			a.Set("index", pyKeywordIndex(kw))
			args = append(args, a)
			continue
		}
		if getString(a, "kind") == strEllipsis {
			seenEllipsis = true
		} else if seenEllipsis {
			return nil, skip("argument after an ellipsis (index not fixed)")
		}
		a.Set("index", int64(position))
		position++
		args = append(args, a)
	}
	if args == nil {
		args = []any{}
	}
	call.Set("min_arity", int64(fixed))
	if seenEllipsis {
		call.Set("max_arity", nil)
	} else {
		call.Set("max_arity", int64(fixed))
	}
	call.Set("args", args)
	call.Set("method_regex", nil)
	if method := getString(call, "method"); strings.HasPrefix(method, "$") {
		call.Set("method_metavar", method)
		call.Set("method", nil)
	}
	return call, nil
}

// rubyBindPathMetavar records the metavariable a constant path puts in its
// last segment (`OpenSSL::Digest::$ALGO`), which is the ruleset's dominant
// Ruby shape: the path selects the algorithm and a metavariable-regex names
// it. Binding it as the call's type metavariable is what lets that regex
// reach the entry as a type_regex, the same slot a Python or Go receiver
// metavariable uses.
//
// Only the last segment binds. A metavariable earlier in the path would stand
// for a namespace, which no rule of the corpus constrains and which the
// written-text comparison could not check.
func rubyBindPathMetavar(call *OMap, path string) {
	i := strings.LastIndex(path, "::")
	last := path
	if i >= 0 {
		last = path[i+2:]
	}
	if !strings.HasPrefix(last, "$") {
		return
	}
	call.Set("type_metavar", last)
}

// rubyPatternKeyword splits `digest_algorithm: $DIGEST` into the keyword and
// the value pattern. A constant path (`OpenSSL::SSL::X`) is not a keyword,
// and neither is a bare symbol (`:sym`).
func rubyPatternKeyword(text string) (keyword, value string) {
	m := rxRubyPatternKeyword.FindStringSubmatch(strings.TrimSpace(text))
	if len(m) < 3 || strings.HasPrefix(m[2], ":") {
		return "", text
	}
	if value = strings.TrimSpace(m[2]); value == "" {
		return "", text
	}
	return m[1], value
}

// rxRubyPatternKeyword is `name:` at the head of an argument pattern.
var rxRubyPatternKeyword = regexp.MustCompile(`(?s)^([A-Za-z_][A-Za-z0-9_]*):(.*)$`)

// rubyUnrooted drops a constant path's leading `::`. `::OpenSSL::Digest` and
// `OpenSSL::Digest` name one class -- the first says so from the root -- and
// the call graph writes neither with it, so a rooted rule would compile and
// match nothing at all.
func rubyUnrooted(path string) string {
	return strings.TrimPrefix(path, rubyScopeSeparator)
}

// rubyLooseReceiver opens the receiver of an entry whose path is a lone
// metavariable that nothing constrains. `$ALGO.digest(..)` with a
// metavariable-regex on `$ALGO` asks for the class that regex names, and the
// entry keeps the type slot that carries it; written without one, the same
// pattern is semgrep's "any object", and asking for a class literally named
// `$ALGO` would match nothing.
func rubyLooseReceiver(entry *OMap) {
	typ, isString := entry.GetOr(strType).(string)
	if !isString || !strings.HasPrefix(typ, "$") {
		return
	}
	metavar, ok := entry.GetOr("type_metavar").(string)
	if !ok || metavar != typ {
		return
	}
	if rx, ok := entry.GetOr("type_regex").(string); ok && rx != "" {
		return // the regex names the class, which is what the type slot is for
	}
	entry.Set("receiver", strAny)
	entry.Set(strType, nil)
	entry.Set("type_metavar", nil)
}
