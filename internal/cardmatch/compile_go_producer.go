// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"regexp"
	"strings"
)

// Go producer flow (go-port audit T8). A conjunction may say where a
// metavariable of its sink comes from with a pattern-inside assignment:
//
//	patterns:
//	  - pattern-inside: |
//	      $BLOCK, $ERR := $PKG.NewCipher($KEY)
//	      ...
//	  - pattern: cipher.NewCBCEncrypter($BLOCK, ...)
//
// (also `$V = call`, `var $V = call`, or an either of them for one $V). The
// producer compiles into an origin on the sink's receiver or argument that
// $V binds: some assignment of the variable earlier in the sink's function
// is a call matching it, as OpenGrep's pattern-inside reads it (a later
// reassignment does not end it). The rule's import clauses qualify the
// producer's package, and the sink's when they name its package; the idiom
// that binds $PKG to a package whether or not
// the file aliases it (`import $PKG "p"`, or `import "p"` minus an aliased
// import with $PKG matching p's name) reads as that package.

var rxGoProducer = regexp.MustCompile(`^(?:var\s+)?(\$[A-Z_][A-Z0-9_]*)(?:\s*,\s*\$[A-Z_][A-Z0-9_]*)*\s*:?=\s*([^\n]+?)\s*\n\s*\.\.\.$`)

// goProducerConj holds what the pre-pass took out of a Go conjunction.
type goProducerConj struct {
	producers map[string][]string // by metavariable, the producer call texts
	order     []string
	bindings  map[string]map[string]bool
	used      map[string]bool // the bound names a producer or a sink took
}

// goProducerClauses takes the producers, and with them the import clauses
// that qualify them, out of a Go conjunction; nil when it has no producer.
func goProducerClauses(clauses []any) ([]any, *goProducerConj, error) {
	pc := &goProducerConj{producers: map[string][]string{}, bindings: map[string]map[string]bool{}, used: map[string]bool{}}
	var rest, imports []any
	for _, v := range clauses {
		c, ok := v.(*OMap)
		if !ok || c.Len() != 1 || !pc.take(c, &imports) {
			rest = append(rest, v)
		}
	}
	if len(pc.order) == 0 {
		return clauses, nil, nil
	}
	if len(imports) > 0 {
		b, err := goInsideBindings(imports)
		if err != nil {
			return nil, nil, err
		}
		for name, paths := range b {
			if pc.bindings[name] == nil {
				pc.bindings[name] = paths
			}
		}
	}
	return rest, pc, nil
}

// take reads a clause the pre-pass takes out: a producer (or an either of
// them), an import clause (or an either of them) into imports, or the
// import idiom. false for any other clause.
func (pc *goProducerConj) take(c *OMap, imports *[]any) bool {
	if c.Has(keyPatternInside) {
		text := c.GetOr(keyPatternInside)
		if goIsImport(text) {
			*imports = append(*imports, text)
			return true
		}
		return pc.addProducers([]any{text})
	}
	either, ok := c.Get(keyPatternEither)
	switch {
	case !ok:
		return false
	case !allPatternInside(either):
		return pc.importIdiom(either)
	case goAllImports(insideTexts(either)):
		*imports = append(*imports, insideTexts(either)...)
		return true
	}
	return pc.addProducers(insideTexts(either))
}

// addProducers records the texts when every one is a producer of one
// metavariable; false (nothing recorded) otherwise.
func (pc *goProducerConj) addProducers(texts []any) bool {
	mv := ""
	var calls []string
	for _, t := range texts {
		s, ok := t.(string)
		if !ok {
			return false
		}
		m := rxGoProducer.FindStringSubmatch(pyStrip(s))
		if len(m) < 3 || mv != "" && m[1] != mv {
			return false
		}
		mv = m[1]
		calls = append(calls, m[2])
	}
	if mv == "" {
		return false
	}
	if _, seen := pc.producers[mv]; !seen {
		pc.order = append(pc.order, mv)
	}
	pc.producers[mv] = append(pc.producers[mv], calls...)
	return true
}

// importIdiom reads the either that binds $PKG to package p whether or not
// the file aliases it: `import $PKG "p"`, or a conjunction of `import "p"`,
// a pattern-not-inside of an aliased import of p, producers already read,
// and a metavariable-pattern of $PKG matching p's name.
func (pc *goProducerConj) importIdiom(either any) bool {
	alts := listOf(either)
	if len(alts) != 2 || !keySet(alts[0], keyPatternInside) || !keySet(alts[1], keyPatterns) {
		return false
	}
	aliased, ok := goImportBindings(pyStr(asOr[*OMap](alts[0]).GetOr(keyPatternInside)))
	if !ok || len(aliased) != 1 {
		return false
	}
	var mv, path string
	for name, p := range aliased {
		mv, path = name, p
	}
	if !strings.HasPrefix(mv, "$") {
		return false
	}
	plain := false
	for _, c := range listOf(asOr[*OMap](alts[1]).GetOr(keyPatterns)) {
		names, ok := goIdiomClause(asOr[*OMap](c), mv, path)
		if !ok {
			return false
		}
		plain = plain || names
	}
	if !plain {
		return false
	}
	pc.bindings[mv] = map[string]bool{path: true}
	return true
}

// goIdiomClause reads a clause of the idiom's unaliased branch; imports is
// true for the `import "path"` clause.
func goIdiomClause(cm *OMap, mv, path string) (imports, ok bool) {
	switch {
	case cm == nil || cm.Len() != 1:
		return false, false
	case cm.Has(keyPatternInside):
		text := pyStr(cm.GetOr(keyPatternInside))
		if b, isImport := goImportBindings(text); isImport {
			for _, p := range b {
				imports = imports || p == path
			}
			return imports, true
		}
		return false, rxGoProducer.FindStringSubmatch(pyStrip(text)) != nil
	case cm.Has("pattern-not-inside"):
		_, isImport := goImportBindings(pyStr(cm.GetOr("pattern-not-inside")))
		return false, isImport
	case cm.Has("metavariable-pattern"):
		return false, getString(asOr[*OMap](cm.GetOr("metavariable-pattern")), "metavariable") == mv
	}
	return false, false
}

// attach gives each sink the origins of the producers: on the receiver or
// the argument their metavariable binds.
func (pc *goProducerConj) attach(sinks []*OMap) error {
	for _, mv := range pc.order {
		var froms []any
		for _, text := range pc.producers[mv] {
			from, err := pc.from(text)
			if err != nil {
				return err
			}
			froms = append(froms, from)
		}
		for _, s := range sinks {
			sl := metavarSlot(s, mv)
			if receiverMetavar(s) != mv && getString(s, goReceiverMetavarKey) != mv && (sl == nil || sl.method || sl.container) {
				return skip("producer metavariable the sink does not bind")
			}
			o := omap(strMetavar, mv, "types", []any{}, "from", froms, "not_from", []any{})
			s.Set("insides", append(listOf(s.GetOr("insides")), []any{o}))
		}
	}
	for _, s := range sinks {
		pc.qualifySink(s)
	}
	return pc.requireUnused(sinks)
}

// requireUnused keeps an import clause no producer or sink took as what it
// says: the sink's file imports that path (`import "crypto/aes"` around
// `$G, $E := cipher.NewGCM($B) ... $G.Seal(..)`). Clauses of several such
// paths skip the rule.
func (pc *goProducerConj) requireUnused(sinks []*OMap) error {
	paths := map[string]bool{}
	for name, ps := range pc.bindings {
		if !pc.used[name] {
			for p := range ps {
				paths[p] = true
			}
		}
	}
	switch len(paths) {
	case 0:
		return nil
	case 1:
	default:
		return skip("import clauses of several paths the producers do not use")
	}
	for p := range paths {
		for _, s := range sinks {
			if have := getString(s, keyGoFileImports); have != "" && have != p {
				return skip("import clauses of several paths the producers do not use")
			}
			s.Set(keyGoFileImports, p)
		}
	}
	return nil
}

// qualifySink gives a typed sink the path a taken import clause binds to
// its own package name (`mode.NewCBC` in `import "example.com/acme/mode"`).
// A sink of a package no clause names keeps its name: the clauses qualify
// the producers.
func (pc *goProducerConj) qualifySink(s *OMap) {
	if getString(s, "receiver") != strType && getString(s, "receiver") != strTypedMetavar {
		return
	}
	name, member := goSinkQualifier(s, false)
	if paths := pc.bindings[name]; len(paths) == 1 {
		pc.used[name] = true
		for p := range paths {
			s.Set(strType, p+member)
		}
	}
}

// from is the card call pattern of a producer call: its package qualified
// through the rule's imports.
func (pc *goProducerConj) from(text string) (*OMap, error) {
	call, err := parseGoCall(text)
	if err != nil {
		return nil, skip("producer that is not a call")
	}
	if constrainingArgs(call) {
		return nil, skip("producer call with constrained arguments")
	}
	method := getString(call, "method")
	var qual string
	switch {
	case method == "":
		return nil, skip("producer call with a metavariable method")
	case getString(call, "receiver") == strType:
		qual = getString(call, strType)
	case getString(call, goReceiverMetavarKey) != "":
		qual = getString(call, goReceiverMetavarKey)
	default:
		return nil, skip("producer call without a package")
	}
	if strings.HasPrefix(qual, "$") {
		paths := pc.bindings[qual]
		if len(paths) != 1 {
			return nil, skip("producer package metavariable no import binds")
		}
		pc.used[qual] = true
		for p := range paths {
			return omap("call", p+"."+method), nil
		}
	}
	// Only a clause that binds the producer's own name qualifies it: a
	// rule's single import is often the sink's package, not the producer's.
	switch paths := pc.bindings[qual]; len(paths) {
	case 0:
		return omap("call", qual+"."+method), nil
	case 1:
		pc.used[qual] = true
		for p := range paths {
			return omap("call", p+"."+method), nil
		}
	}
	return nil, skip("producer package bound to several imports")
}

// insideTexts are the pattern-inside texts of an either of them.
func insideTexts(either any) []any {
	l := listOf(either)
	out := make([]any, 0, len(l))
	for _, x := range l {
		out = append(out, asOr[*OMap](x).GetOr(keyPatternInside))
	}
	return out
}

// goIsImport: the text is a Go import clause.
func goIsImport(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, ok = goImportBindings(s)
	return ok
}

// goAllImports: every text is a Go import clause.
func goAllImports(texts []any) bool {
	for _, t := range texts {
		if !goIsImport(t) {
			return false
		}
	}
	return len(texts) > 0
}
