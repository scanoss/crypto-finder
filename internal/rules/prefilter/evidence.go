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

package prefilter

import (
	"regexp"
	"strings"
)

// Evidence is what one unit's sources can supply: the analyzers that have
// files, the identifiers they spell and, per family, the module spellings
// their imports could bind.
type Evidence struct {
	analyzers map[string]bool
	tokens    map[string]bool
	imports   map[Family][]string
	seen      map[Family]map[string]bool
	// opaque marks a family with an import the prefilter cannot read, such
	// as a C include through a macro: any import of that family may hold.
	opaque map[Family]bool
	files  int
}

// NewEvidence returns empty evidence.
func NewEvidence() *Evidence {
	return &Evidence{
		analyzers: make(map[string]bool),
		tokens:    make(map[string]bool),
		imports:   make(map[Family][]string),
		seen:      make(map[Family]map[string]bool),
		opaque:    make(map[Family]bool),
	}
}

// Files is the number of files added.
func (ev *Evidence) Files() int { return ev.files }

// HasAnalyzer reports whether some file was added for analyzer.
func (ev *Evidence) HasAnalyzer(analyzer string) bool { return ev.analyzers[analyzer] }

// AddFile records one source file that the scanner analyzes with the given
// analyzers.
func (ev *Evidence) AddFile(analyzers []string, content []byte) {
	ev.files++
	families := make(map[Family]bool, len(analyzers))
	for _, analyzer := range analyzers {
		ev.analyzers[analyzer] = true
		if family := FamilyOf(analyzer); family != "" {
			families[family] = true
		}
	}
	// A byte order mark would hide a first-line import from the line-anchored
	// import patterns.
	text := strings.TrimPrefix(string(content), "\uFEFF")
	addTokens(ev.tokens, text)
	for family := range families {
		ev.addImports(family, text)
	}
}

func (ev *Evidence) add(family Family, module string) {
	if module == "" {
		return
	}
	seen := ev.seen[family]
	if seen == nil {
		seen = make(map[string]bool)
		ev.seen[family] = seen
	}
	if !seen[module] {
		seen[module] = true
		ev.imports[family] = append(ev.imports[family], module)
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// addTokens records every identifier-shaped word of text, in code, strings
// and comments alike, so the set over-approximates what patterns can match.
func addTokens(tokens map[string]bool, text string) {
	for i := 0; i < len(text); {
		if !isIdentStart(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && isIdentPart(text[i]) {
			i++
		}
		if start > 0 && isIdentPart(text[start-1]) {
			continue // the tail of a number such as 0x1F
		}
		word := text[start:i]
		if !tokens[word] {
			tokens[word] = true
		}
	}
}

var (
	javaImportLine   = regexp.MustCompile(`(?m)^\s*(?:import\s+(?:static\s+)?|package\s+)([\w.$*\s]+?)\s*;`)
	pythonImportLine = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([^\n#;]+)`)
	pythonFromLine   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]*(\([^)]*\)|[^\n#;]*)`)
	rustUseDecl      = regexp.MustCompile(`(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use[ \t]+([^;]+);`)
	rustCrate        = regexp.MustCompile(`\bextern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)`)
	cIncludeLine     = regexp.MustCompile(`(?m)^[ \t\f\v]*#[ \t\f\v]*include[ \t]*([^\n]*)`)
	whitespaceRun    = regexp.MustCompile(`\s+`)
)

// inlineImport finds, per family, an import keyword that follows another
// statement, a block brace, an attribute or a comment on the same line, as
// in `import a; import b;`, `try: import jwt` or `#[cfg(x)] use a::B;`.
// Breaking the line there lets the line-anchored patterns read the import;
// a keyword that is not an import only adds candidates, which keeps rules.
var inlineImport = map[Family]*regexp.Regexp{
	FamilyJava:   regexp.MustCompile(`([;{}]|\*/)([ \t]*(?:import|package)\b)`),
	FamilyPython: regexp.MustCompile(`([;:])([ \t]*(?:import|from)\b)`),
	FamilyRust:   regexp.MustCompile(`([;{}\]]|\*/)([ \t]*(?:use|pub)\b)`),
	FamilyC:      regexp.MustCompile(`(\*/)([ \t]*#)`),
	// A Go import after a statement or a comment on the same line
	// (`package main; import "x"`, `/* keep */ import "x"`).
	FamilyGo: regexp.MustCompile(`(;|\*/)([ \t]*import\b)`),
	// JS specifiers are read from every string literal, wherever they stand.
	FamilyJS: nil,
}

func (ev *Evidence) addImports(family Family, text string) {
	if re := inlineImport[family]; re != nil {
		text = re.ReplaceAllString(text, "$1\n$2")
	}
	switch family {
	case FamilyGo:
		ev.addGoImports(text)
	case FamilyJava:
		for _, m := range javaImportLine.FindAllStringSubmatch(text, -1) {
			ev.add(FamilyJava, whitespaceRun.ReplaceAllString(m[1], ""))
		}
	case FamilyPython:
		ev.addPythonImports(text)
	case FamilyJS:
		// A module specifier may reach require/import through a constant,
		// so every string literal of the file is a candidate.
		for _, literal := range jsStringLiterals(text) {
			ev.add(FamilyJS, literal)
		}
	case FamilyRust:
		ev.addRustImports(text)
	case FamilyC:
		ev.addCIncludes(text)
	default:
	}
}

// jsStringLiterals reads the string literals of a JavaScript or TypeScript
// source without parsing it: a candidate literal starts at every quote and
// ends at the next unescaped quote of the same kind (a newline ends a
// single- or double-quoted one). A quote inside a comment or a regex
// literal (`/["']/g`, "it's") then yields a wrong candidate besides, never
// instead of, the real literals after it, so the result is a superset of
// the file's literals and can only keep more rules.
func jsStringLiterals(text string) []string {
	var out []string
	for i := 0; i < len(text); i++ {
		quote := text[i]
		if quote != '"' && quote != '\'' && quote != '`' {
			continue
		}
		j := i + 1
		for j < len(text) && text[j] != quote {
			if text[j] == '\\' {
				j++
			} else if text[j] == '\n' && quote != '`' {
				break
			}
			j++
		}
		if j < len(text) && text[j] == quote {
			out = append(out, text[i+1:j])
		}
	}
	return out
}

// addGoImports reads import declarations, single and grouped. Lines outside
// any declaration that merely start with "import" only add candidates.
func (ev *Evidence) addGoImports(text string) {
	text = stripGoComments(text)
	inBlock := false
	// pending marks an "import" keyword alone on its line: the "(" of its
	// block may follow on the next line.
	pending := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if inBlock {
			if strings.HasPrefix(trimmed, ")") {
				inBlock = false
				continue
			}
			ev.addGoStrings(trimmed)
			continue
		}
		if pending && trimmed != "" {
			pending = false
			trimmed = "import " + trimmed
		}
		if !strings.HasPrefix(trimmed, "import") {
			continue
		}
		// A comment between "import" and "(" or in the "(" line is not
		// part of the declaration.
		rest := strings.TrimSpace(stripGoLineComment(strings.TrimPrefix(trimmed, "import")))
		if rest == "" {
			pending = true
			continue
		}
		if strings.HasPrefix(rest, "(") {
			body := rest[1:]
			if end := strings.Index(body, ")"); end >= 0 {
				ev.addGoStrings(body[:end])
				continue
			}
			inBlock = true
			ev.addGoStrings(body)
			continue
		}
		ev.addGoStrings(rest)
	}
}

var goBlockComment = regexp.MustCompile(`/\*.*?\*/`)

// stripGoLineComment drops a "//" or one-line "/* */" comment from line.
func stripGoLineComment(line string) string {
	line = goBlockComment.ReplaceAllString(line, "")
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// stripGoComments blanks every comment of a Go source, keeping newlines, so
// a ")" or an "import" inside a comment that spans lines never reads as
// code. A comment marker inside a string literal is blanked too, which only
// drops candidates that were never import paths.
func stripGoComments(text string) string {
	b := []byte(text)
	for i := 0; i < len(b); i++ {
		if b[i] != '/' || i+1 >= len(b) {
			continue
		}
		var end int
		switch b[i+1] {
		case '/':
			end = i + 2
			for end < len(b) && b[end] != '\n' {
				end++
			}
		case '*':
			end = i + 2
			for end+1 < len(b) && (b[end] != '*' || b[end+1] != '/') {
				end++
			}
			end = min(end+2, len(b))
		default:
			continue
		}
		for k := i; k < end; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
		i = end - 1
	}
	return string(b)
}

func (ev *Evidence) addGoStrings(text string) {
	for _, literal := range goImportString.FindAllString(text, -1) {
		ev.add(FamilyGo, literal[1:len(literal)-1])
	}
}

func (ev *Evidence) addPythonImports(text string) {
	for _, m := range pythonImportLine.FindAllStringSubmatch(text, -1) {
		for _, part := range strings.Split(m[1], ",") {
			fields := strings.Fields(part)
			if len(fields) > 0 {
				ev.add(FamilyPython, strings.TrimRight(fields[0], "\\"))
			}
		}
	}
	for _, m := range pythonFromLine.FindAllStringSubmatch(text, -1) {
		module := m[1]
		if strings.HasPrefix(module, ".") {
			continue
		}
		ev.add(FamilyPython, module)
		names := strings.Trim(m[2], "() \t\\")
		for _, part := range strings.Split(names, ",") {
			fields := strings.Fields(part)
			if len(fields) > 0 && fields[0] != "*" {
				ev.add(FamilyPython, module+"."+fields[0])
			}
		}
	}
}

func (ev *Evidence) addRustImports(text string) {
	for _, m := range rustUseDecl.FindAllStringSubmatch(text, -1) {
		raw := strings.TrimSpace(m[1])
		ev.add(FamilyRust, raw)
		ev.add(FamilyRust, whitespaceRun.ReplaceAllString(raw, " "))
		ev.add(FamilyRust, whitespaceRun.ReplaceAllString(raw, ""))
		for _, path := range expandUseTree(whitespaceRun.ReplaceAllString(raw, " ")) {
			path = strings.TrimPrefix(path, "::")
			segments := strings.Split(path, "::")
			for i := 1; i <= len(segments); i++ {
				prefix := strings.Join(segments[:i], "::")
				ev.add(FamilyRust, prefix)
				ev.add(FamilyRust, "::"+prefix)
			}
		}
	}
	for _, m := range rustCrate.FindAllStringSubmatch(text, -1) {
		ev.add(FamilyRust, m[1])
	}
}

// expandUseTree lists the paths of a Rust use tree, `a::{b, c::{d}}` giving
// a::b and a::c::d, with aliases dropped and `self` leaves naming their
// parent.
func expandUseTree(tree string) []string {
	tree = strings.TrimSpace(tree)
	open := strings.IndexByte(tree, '{')
	if open < 0 {
		path := strings.TrimSpace(rustAlias.ReplaceAllString(tree, ""))
		path = strings.TrimSuffix(strings.TrimSuffix(path, "::self"), "::*")
		if path == "" || path == "self" || path == "*" {
			return nil
		}
		return []string{path}
	}
	prefix := strings.TrimSpace(tree[:open])
	body := tree[open+1:]
	if end := strings.LastIndexByte(body, '}'); end >= 0 {
		body = body[:end]
	}
	var paths []string
	if base := strings.TrimSuffix(prefix, "::"); base != "" {
		paths = append(paths, base)
	}
	for _, item := range splitTopLevel(body) {
		for _, sub := range expandUseTree(item) {
			if prefix == "" {
				paths = append(paths, sub)
			} else {
				paths = append(paths, prefix+sub)
			}
		}
	}
	return paths
}

func splitTopLevel(body string) []string {
	var items []string
	depth, start := 0, 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				items = append(items, body[start:i])
				start = i + 1
			}
		}
	}
	return append(items, body[start:])
}

func (ev *Evidence) addCIncludes(text string) {
	for _, m := range cIncludeLine.FindAllStringSubmatch(text, -1) {
		spec := strings.TrimSpace(m[1])
		if spec == "" {
			continue
		}
		var path string
		switch spec[0] {
		case '<':
			path, _, _ = strings.Cut(spec[1:], ">")
		case '"':
			path, _, _ = strings.Cut(spec[1:], "\"")
		default:
			// An include through a macro names a header the prefilter
			// cannot know.
			ev.opaque[FamilyC] = true
			continue
		}
		ev.add(FamilyC, path)
		ev.add(FamilyC, "<"+path+">")
		ev.add(FamilyC, "\""+path+"\"")
	}
}

// qualifiedNames derives token facts from the qualified names a Java, Python
// or Rust pattern spells outside string literals: all segments of a name
// appear in a file it matches, written in full or through an import. Roots
// the language provides implicitly (java.lang, builtins, std/core/alloc)
// and path keywords are not required.
func qualifiedNames(text string, family Family) Expr {
	// A name of two or more segments is required whole: even when a static
	// import or alias shortens it at the call site, the import spells every
	// segment.
	const minSegments = 2
	var sep string
	switch family {
	case FamilyJava, FamilyPython:
		sep = "."
	case FamilyRust:
		sep = "::"
	case FamilyGo, FamilyJS, FamilyC:
		return True
	default:
		return True
	}
	code := stripStrings(text, family)
	var tokens []string
	seen := make(map[string]bool)
	for _, chain := range chains(code, sep) {
		chain = trimImplicitRoot(chain, family)
		if len(chain) < 1 {
			continue
		}
		if len(chain) < minSegments {
			continue
		}
		for _, segment := range chain {
			if !seen[segment] {
				seen[segment] = true
				tokens = append(tokens, segment)
			}
		}
	}
	if len(tokens) == 0 {
		return True
	}
	return tokenAtom(tokens)
}

func trimImplicitRoot(chain []string, family Family) []string {
	switch family {
	case FamilyJava:
		if len(chain) >= 2 && chain[0] == "java" && chain[1] == "lang" {
			return nil
		}
	case FamilyPython:
		if chain[0] == "builtins" {
			return nil
		}
	case FamilyRust:
		for len(chain) > 0 {
			switch chain[0] {
			case "std", "core", "alloc", "crate", "self", "super", "Self":
				chain = chain[1:]
				continue
			}
			break
		}
		if len(chain) < 2 {
			return nil
		}
	case FamilyGo, FamilyJS, FamilyC:
	default:
	}
	return chain
}

// chains returns the maximal identifier chains joined by sep in code. A
// chain rooted after a metavariable, a member access or another identifier
// is not a qualified name and is skipped.
func chains(code, sep string) [][]string {
	var out [][]string
	for i := 0; i < len(code); {
		if !isIdentStart(code[i]) {
			i++
			continue
		}
		rooted := startsName(code, i)
		var chain []string
		chain, i = readChain(code, i, sep)
		if rooted {
			out = append(out, chain)
		}
	}
	return out
}

// startsName reports whether the identifier at start begins a name rather
// than continuing one: it follows no identifier character, metavariable,
// separator, preprocessor or annotation sign.
func startsName(code string, start int) bool {
	if start == 0 {
		return true
	}
	switch prev := code[start-1]; {
	case isIdentPart(prev):
		return false
	case prev == '$', prev == '.', prev == ':', prev == '#', prev == '@':
		return false
	default:
		return true
	}
}

// readChain reads identifiers joined by sep from start and returns them with
// the index after the chain.
func readChain(code string, start int, sep string) ([]string, int) {
	var chain []string
	i := start
	for {
		j := i
		for j < len(code) && isIdentPart(code[j]) {
			j++
		}
		chain = append(chain, code[i:j])
		i = j
		if !strings.HasPrefix(code[i:], sep) || i+len(sep) >= len(code) || !isIdentStart(code[i+len(sep)]) {
			return chain, i
		}
		i += len(sep)
	}
}

// stripStrings blanks string literals so their contents never read as
// names. Rust single quotes start lifetimes, so only double quotes count.
func stripStrings(text string, family Family) string {
	b := []byte(text)
	quotes := "\"'"
	if family == FamilyRust {
		quotes = "\""
	}
	for i := 0; i < len(b); i++ {
		if !strings.ContainsRune(quotes, rune(b[i])) {
			continue
		}
		quote := b[i]
		j := i + 1
		for j < len(b) && b[j] != quote && b[j] != '\n' {
			if b[j] == '\\' {
				j++
			}
			j++
		}
		for k := i; k < len(b) && k <= j; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
		i = j
	}
	return string(b)
}
