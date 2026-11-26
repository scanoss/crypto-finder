// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"regexp"
	"strings"
)

// The Go shapes of the rule compiler. A Go rule names its callee through an
// import: `age.Encrypt(...)` inside `import "filippo.io/age"`, or
// `$PKG.New(...)` inside `import $PKG "golang.org/x/crypto/sha3"`. The
// compiler writes the import path as the callee's type, which the matcher
// compares exactly with the package or type a Go call resolves to.

const (
	goReceiverMetavarKey = "go_receiver_metavar"
	// keyFocusReceiver marks a Go sink whose focus-metavariable is its receiver.
	keyFocusReceiver = "focus_receiver"
	// keyGoAliasOf marks a Go sink whose receiver `import $P "p"` binds.
	keyGoAliasOf = "go_alias_of"
	// keyGoFileImports marks a Go store sink matched only in a file that
	// imports this path.
	keyGoFileImports = "go_file_imports"
)

var (
	rxGoImportBinding = regexp.MustCompile(`(?:(\$?[A-Za-z_]\w*)\s+)?"([^"]+)"`)
	rxGoCallMetavar   = regexp.MustCompile(`^\s*(\$[A-Z_0-9]+)\s*\.`)
	rxGoTypedRecv     = regexp.MustCompile(`^\s*\(\s*(\$[A-Z_0-9]+)\s*:\s*\*?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\)`)
)

func goRule(r *OMap) bool {
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		if s, ok := l.(string); ok && strings.EqualFold(s, "go") {
			return true
		}
	}
	return false
}

// parseGoCall is parseCallPattern, reading Go's typed receiver
// `($X : *pkg.T).m(...)` as `(pkg.T $X).m(...)` and noting a metavariable
// receiver (`$PKG.New(...)`) so an import clause can bind it to a package.
func parseGoCall(text string) (*OMap, error) {
	if call, ok, err := parseGoValuePattern(text); ok {
		return call, err
	}
	typedMetavar := ""
	if m := rxGoTypedRecv.FindStringSubmatchIndex(text); m != nil {
		typedMetavar = text[m[2]:m[3]]
		text = "(" + text[m[4]:m[5]] + " " + typedMetavar + ")" + text[m[1]:]
	}
	call, err := parseCallPattern(text)
	if err != nil {
		return nil, err
	}
	if m := rxGoCallMetavar.FindStringSubmatch(text); m != nil && getString(call, "receiver") == strAny {
		call.Set(goReceiverMetavarKey, m[1])
	}
	if typedMetavar != "" && getString(call, "receiver") == strTypedMetavar {
		call.Set(goReceiverMetavarKey, typedMetavar)
	}
	return call, nil
}

// goImportBindings reads a Go import clause (`import "p"`,
// `import ( ... "p" ... )`, `import a "p"`, `import $A "p"`, each with or
// without a following `...`) into the names it binds and their paths; ok is
// false for any other text.
func goImportBindings(text string) (map[string]string, bool) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "import") {
		return nil, false
	}
	body := strings.TrimSpace(strings.TrimSuffix(text, "..."))
	body = strings.TrimSpace(strings.TrimPrefix(body, "import"))
	if strings.HasPrefix(body, "(") {
		if !strings.HasSuffix(body, ")") {
			return nil, false
		}
		body = body[1 : len(body)-1]
	}
	out := map[string]string{}
	for _, m := range rxGoImportBinding.FindAllStringSubmatch(body, -1) {
		name := m[1]
		if name == "" {
			name = goImplicitImportName(m[2])
		}
		out[name] = m[2]
	}
	return out, len(out) > 0
}

// compileGoInside compiles pattern-inside clauses naming Go imports: a sink
// whose receiver an import binds gets the import path as its type. Any other
// pattern-inside is not compiled.
func compileGoInside(val any, sinks []*OMap) error {
	bindings, err := goInsideBindings(val)
	if err != nil {
		return err
	}
	for _, s := range sinks {
		goQualifyProducers(s, bindings)
		if err := qualifyGoSink(s, bindings); err != nil {
			return err
		}
	}
	return nil
}

// goQualifyProducers writes the producers of a sink's origins
// (compile_go_producer.go) that a branch compiled before its import clause
// (`ssh.ParsePublicKey`) with the path the clause binds to their package
// name. A producer of another package keeps its name.
func goQualifyProducers(s *OMap, bindings map[string]map[string]bool) {
	for _, g := range listOf(s.GetOr("insides")) {
		for _, o := range listOf(g) {
			om, ok := o.(*OMap)
			if !ok {
				continue
			}
			for _, f := range listOf(om.GetOr("from")) {
				fm, ok := f.(*OMap)
				callee := getString(fm, "call")
				dot := strings.IndexByte(callee, '.')
				if !ok || dot <= 0 || strings.Contains(callee[:dot], "/") || len(bindings[callee[:dot]]) != 1 {
					continue
				}
				for p := range bindings[callee[:dot]] {
					fm.Set("call", p+callee[dot:])
				}
			}
		}
	}
}

// goInsideBindings reads each pattern-inside import clause into the paths
// each bound name may stand for.
func goInsideBindings(val any) (map[string]map[string]bool, error) {
	vals, ok := val.([]any)
	if !ok {
		vals = []any{val}
	}
	bindings := map[string]map[string]bool{}
	covering := 0
	for _, v := range vals {
		text, err := asString(v, "pattern-inside")
		if err != nil {
			return nil, err
		}
		b, ok := goImportBindings(text)
		if !ok {
			return nil, skip("pattern-inside that is not an import")
		}
		if !strings.HasSuffix(strings.TrimSpace(text), "...") {
			// Without a following `...` the clause covers the import
			// declaration only: OpenGrep matches no call inside it.
			continue
		}
		covering++
		for name, path := range b {
			if bindings[name] == nil {
				bindings[name] = map[string]bool{}
			}
			bindings[name][path] = true
		}
	}
	if covering == 0 {
		return nil, skip("pattern-inside import without a following ..., which covers no call")
	}
	return bindings, nil
}

// qualifyGoSink gives a sink the import path its receiver's name binds.
func qualifyGoSink(s *OMap, bindings map[string]map[string]bool) error {
	untyped := getString(s, "receiver") == strAny
	name, member := goSinkQualifier(s, untyped)
	paths := bindings[name]
	if len(paths) == 0 && !untyped {
		// A package whose name is not its path's last element (`package
		// jose` at .../go-jose/v4): the clause's only package is the one the
		// rule's qualifier names.
		paths = goOnlyPath(bindings)
	}
	if untyped && len(paths) == 0 && goStoreInImportingFile(s, bindings) {
		return nil
	}
	switch len(paths) {
	case 0:
		if untyped && goReceiverProduced(s, name) {
			// `$X := pkg.New(..) ... $X.m(..)`: the producer, which the
			// match checks, says what the receiver is; the import clause
			// adds nothing to it.
			return nil
		}
		if untyped {
			// `$X.m(...)` in a file importing p: the import is all that
			// keeps the method precise, and no card can check it.
			return skip("pattern-inside import on a call with an untyped receiver")
		}
		appendTo(s, "dropped_clauses", "pattern-inside import not about the callee")
		return nil
	case 1:
	default:
		return skip("import alternatives binding one name to several packages")
	}
	for path := range paths {
		if untyped {
			s.Set("receiver", strType)
			if strings.HasPrefix(name, "$") {
				// `import $P "p"` binds only an aliased import of p.
				s.Set(keyGoAliasOf, path)
			}
		}
		s.Set(strType, path+member)
	}
	return nil
}

// goReceiverProduced: a producer origin (compile_go_producer.go) sits on
// the sink's receiver metavariable.
func goReceiverProduced(s *OMap, mv string) bool {
	for _, g := range listOf(s.GetOr("insides")) {
		for _, o := range listOf(g) {
			if om, ok := o.(*OMap); ok && getString(om, strMetavar) == mv && len(listOf(om.GetOr("from"))) > 0 {
				return true
			}
		}
	}
	return false
}

// goSinkQualifier is the name a sink's receiver is written with, which an
// import may bind, and the type member after it: `kms` and `.Client` of a
// typed receiver `kms.Client`, `lib` of `lib.Open`, the metavariable of an
// untyped receiver `$X.m(..)`.
func goSinkQualifier(s *OMap, untyped bool) (string, string) {
	if untyped {
		return getString(s, goReceiverMetavarKey), ""
	}
	name := getString(s, strType)
	if getString(s, "receiver") == strTypedMetavar || goValueMethod(getString(s, "method")) {
		// A typed receiver, and a composite literal, new(T) or store, name a
		// type of the package: `kms.Client`, `tls.Config{...}`.
		if i := strings.IndexByte(name, '.'); i > 0 {
			return name[:i], name[i:]
		}
	}
	return name, ""
}

// goValueMethod: the pseudo-method of a Go value pattern (go_values.go).
func goValueMethod(m string) bool {
	return m == goValueComposite || m == goValueNew || strings.HasPrefix(m, goValueStorePfx)
}

// goStoreInImportingFile marks a store sink with an untyped receiver
// (`$C.F = v`) inside an import clause of one package p: OpenGrep matches any
// such store in a file importing p, and the fragment's import specs (1.32)
// tell the file. false for any other sink.
func goStoreInImportingFile(s *OMap, bindings map[string]map[string]bool) bool {
	if !strings.HasPrefix(getString(s, "method"), goValueStorePfx) {
		return false
	}
	only := goOnlyPath(bindings)
	if len(only) != 1 {
		return false
	}
	for path := range only {
		s.Set(keyGoFileImports, path)
	}
	return true
}

// goImplicitImportName is the name an unaliased Go import binds by the module
// path rules (the last element, skipping a /vN or gopkg.in .vN suffix).
func goImplicitImportName(path string) string {
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	if parts[0] == "gopkg.in" {
		if i := strings.LastIndex(name, ".v"); i > 0 {
			name = name[:i]
		}
		return name
	}
	if len(name) > 1 && name[0] == 'v' && len(parts) > 1 && strings.Trim(name[1:], "0123456789") == "" && name[1] != '0' && name != "v1" {
		return parts[len(parts)-2]
	}
	return name
}

// dropGoCompileKeys removes the compiler's working keys from a Go sink.
func dropGoCompileKeys(s *OMap) {
	s.del(goReceiverMetavarKey)
}

// goOnlyPath is the import path of clauses that bind a single package, or nil.
func goOnlyPath(bindings map[string]map[string]bool) map[string]bool {
	var only string
	for _, paths := range bindings {
		for path := range paths {
			if only != "" && path != only {
				return nil
			}
			only = path
		}
	}
	if only == "" {
		return nil
	}
	return map[string]bool{only: true}
}

// goReceiverSpan is the length of the receiver expression of a Go method call
// written as call (its text from the start column to the end column): the
// text before the `.Method(` that opens the final argument list. ok is false
// when call does not end in that argument list.
func goReceiverSpan(call, method string) (int, bool) {
	call = strings.TrimRight(call, " \t")
	if method == "" || !strings.HasSuffix(call, ")") {
		return 0, false
	}
	depth, open := 0, -1
	for i := len(call) - 1; i >= 0 && open < 0; i-- {
		switch call[i] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			depth--
			if depth == 0 {
				open = i
			}
		}
	}
	if open < 0 {
		return 0, false
	}
	head := strings.TrimRight(call[:open], " \t")
	if !strings.HasSuffix(head, method) {
		return 0, false
	}
	head = strings.TrimRight(strings.TrimSuffix(head, method), " \t")
	if !strings.HasSuffix(head, ".") {
		return 0, false
	}
	recv := strings.TrimRight(strings.TrimSuffix(head, "."), " \t")
	return len(recv), recv != ""
}

// goAliasScopedNotDropped records a dropped pattern-not scoped by an import alias.
const goAliasScopedNotDropped = "pattern-not scoped by an import alias: calls resolve by their import path"

// goAliasNot is a pattern-not sub-rule scoped by an import alias: OpenGrep's way to tell apart
// two imported packages that share a name, since a pattern written `lib.F` also matches a call
// through an alias of either. It starts with import clauses binding one metavariable alias
// (`import $B "example.com/other/lib"`), then either removes every call and value reached
// through the alias (`$B.$M(...)`, `$B.$M`: dispatch), or every one not reached through it
// (`$X.$M(...)` with `pattern-not: $B.$M(...)`).
type goAliasNot struct {
	paths    []string
	dispatch bool
}

var rxGoMetavarSelector = regexp.MustCompile(`^(\$[A-Z_0-9]+)\.\$[A-Z_0-9]+(?:\(\.{3}\))?$`)

// goAliasScopedNot reads a pattern-not's value as a goAliasNot, or nil. Every pattern after the
// import clauses selects a metavariable member of a metavariable, so the sub-rule removes calls
// by the package they reach, never by method or arguments.
func goAliasScopedNot(val any) *goAliasNot {
	sub, ok := val.(*OMap)
	if !ok || sub.Len() != 1 || pyStr(sub.Keys[0]) != "patterns" {
		return nil
	}
	items := as[[]any](sub.Vals[0])
	if len(items) < 2 {
		return nil
	}
	alias, paths := goImportAlias(items[0])
	if alias == "" {
		return nil
	}
	throughAlias, otherwise, negated, ok := goAliasUses(items[1:], alias)
	if !ok {
		return nil
	}
	switch {
	case throughAlias > 0 && otherwise == 0 && negated == 0:
		return &goAliasNot{paths: paths, dispatch: true}
	case throughAlias == 0 && otherwise > 0 && negated > 0:
		return &goAliasNot{paths: paths}
	}
	return nil
}

// goAliasUses counts the patterns of clauses that select a metavariable member of the alias,
// of another metavariable, and the pattern-nots of the alias; false when a pattern is anything
// else, or a pattern-not is not of the alias.
func goAliasUses(clauses []any, alias string) (throughAlias, otherwise, negated int, ok bool) {
	for _, item := range clauses {
		key, texts := goClausePatterns(item)
		if texts == nil {
			return 0, 0, 0, false
		}
		for _, text := range texts {
			sel := rxGoMetavarSelector.FindStringSubmatch(strings.TrimSpace(text))
			switch {
			case len(sel) < 2 || (key == keyPatternNot && sel[1] != alias):
				return 0, 0, 0, false
			case key == keyPatternNot:
				negated++
			case sel[1] == alias:
				throughAlias++
			default:
				otherwise++
			}
		}
	}
	return throughAlias, otherwise, negated, true
}

// goClausePatterns is the key and pattern texts of a pattern, pattern-not or pattern-either of
// patterns clause; nil texts for any other clause.
func goClausePatterns(item any) (string, []string) {
	m, ok := item.(*OMap)
	if !ok || m.Len() != 1 {
		return "", nil
	}
	key := pyStr(m.Keys[0])
	alts := []any{item}
	switch key {
	case jsLeaf, keyPatternNot:
	case jsEither:
		alts = as[[]any](m.Vals[0])
	default:
		return "", nil
	}
	var texts []string
	for _, alt := range alts {
		a, ok := alt.(*OMap)
		if !ok || a.Len() != 1 || (key == jsEither && pyStr(a.Keys[0]) != jsLeaf) {
			return "", nil
		}
		text, ok := a.Vals[0].(string)
		if !ok {
			return "", nil
		}
		texts = append(texts, text)
	}
	return key, texts
}

// impliedFor reports that the cards, which resolve each call to its import path, already apply
// the sub-rule to a sink of type typ: a dispatch through another package's alias, or a removal
// of what the sink's own package's alias does not reach. Only an import path resolves the call:
// a sink no import clause typed keeps its package name, which the cards match against any
// package of that name.
func (a *goAliasNot) impliedFor(typ string) bool {
	if !strings.Contains(typ, "/") {
		return false
	}
	for _, p := range a.paths {
		own := typ == p || strings.HasPrefix(typ, p+".")
		if own == a.dispatch {
			return false
		}
	}
	return true
}

// goImportAlias is the one metavariable a clause of import pattern-insides binds as the alias
// of every import it names, and those imports' paths; "" for any other clause.
func goImportAlias(clause any) (string, []string) {
	alias := ""
	var paths []string
	for _, text := range goInsideTexts(clause) {
		b, ok := goImportBindings(text)
		if !ok || len(b) != 1 {
			return "", nil
		}
		for name, path := range b {
			if !strings.HasPrefix(name, "$") || (alias != "" && name != alias) {
				return "", nil
			}
			alias = name
			paths = append(paths, path)
		}
	}
	return alias, paths
}

// goInsideTexts lists the patterns of a pattern-inside clause, or of a pattern-either of
// pattern-insides; nil for any other clause.
func goInsideTexts(clause any) []string {
	m, ok := clause.(*OMap)
	if !ok || m.Len() != 1 {
		return nil
	}
	alts := []any{clause}
	if pyStr(m.Keys[0]) == jsEither {
		alts = as[[]any](m.Vals[0])
	}
	var out []string
	for _, alt := range alts {
		a, ok := alt.(*OMap)
		if !ok || a.Len() != 1 || pyStr(a.Keys[0]) != jsInside {
			return nil
		}
		text, ok := a.Vals[0].(string)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}
