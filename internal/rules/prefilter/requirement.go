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

// Package prefilter decides, for one scanned unit (a project or a batch of
// dependencies), which Semgrep/OpenGrep rules cannot match any of its
// sources, so the scanner never loads them.
//
// The decision is conservative by construction. A rule's requirement is a
// boolean formula over facts that every match of the rule needs in the
// matched file:
//
//   - an import fact, derived only from patterns that are import statements
//     (Go `import "x"`, Java `import a.b.C;`, Python `import x`/`from x
//     import y`, JavaScript `require("x")`/`import ... from "x"`, Rust
//     `use x::y;`/`extern crate x;`, C/C++ `#include <x>`), with any
//     metavariable-regex constraint on a metavariable inside the import;
//   - a token fact, derived from qualified names in Java, Python and Rust
//     patterns (`org.bouncycastle.crypto.X`, `cryptography.hazmat.y`,
//     `aes_gcm::Aes256Gcm`): every segment of such a name appears in any
//     file the pattern matches, written in full or through its import.
//
// `patterns` is a conjunction of its positive members, `pattern-either` a
// disjunction, a taint rule needs one source and one sink. Negations,
// metavariable filters, regex patterns and anything not understood are true,
// which keeps the rule. Rule ids, messages and metadata other than an
// explicit `metadata.imports` list are never read: a rule id such as
// go.crypto.sha256 names a library the rule's patterns do not require.
//
// A unit's evidence is the union over all its files, so a fact needed in one
// file is satisfied when any file of the unit provides it.
package prefilter

import (
	"regexp"
	"strings"
)

// Family groups the analyzers whose import syntax the prefilter reads.
type Family string

// Families with import evidence. Analyzers outside them never drop a rule
// on import grounds.
const (
	FamilyGo     Family = "go"
	FamilyJava   Family = "java"
	FamilyPython Family = "python"
	FamilyJS     Family = "js"
	FamilyRust   Family = "rust"
	FamilyC      Family = "c"
)

// FamilyOf maps an OpenGrep analyzer id (lang.json id) to its family, or ""
// when the prefilter has no evidence for it.
func FamilyOf(analyzer string) Family {
	switch analyzer {
	case "go":
		return FamilyGo
	case "java":
		return FamilyJava
	case "python", "python2", "python3":
		return FamilyPython
	case "js", "ts":
		return FamilyJS
	case "rust":
		return FamilyRust
	case "c", "cpp":
		return FamilyC
	default:
		return ""
	}
}

// Expr is a rule requirement.
type Expr interface {
	eval(ev *Evidence) bool
	// known reports whether the expression can ever be false.
	known() bool
}

type trueExpr struct{}

func (trueExpr) eval(*Evidence) bool { return true }
func (trueExpr) known() bool         { return false }

// True is the requirement every unit meets.
var True Expr = trueExpr{}

type andExpr []Expr

func (a andExpr) eval(ev *Evidence) bool {
	for _, e := range a {
		if !e.eval(ev) {
			return false
		}
	}
	return true
}

func (a andExpr) known() bool {
	for _, e := range a {
		if e.known() {
			return true
		}
	}
	return false
}

type orExpr []Expr

func (o orExpr) eval(ev *Evidence) bool {
	for _, e := range o {
		if e.eval(ev) {
			return true
		}
	}
	return false
}

func (o orExpr) known() bool {
	for _, e := range o {
		if !e.known() {
			return false
		}
	}
	return len(o) > 0
}

func and(exprs []Expr) Expr {
	kept := exprs[:0:0]
	for _, e := range exprs {
		if e.known() {
			kept = append(kept, e)
		}
	}
	switch len(kept) {
	case 0:
		return True
	case 1:
		return kept[0]
	default:
		return andExpr(kept)
	}
}

func or(exprs []Expr) Expr {
	if len(exprs) == 0 {
		return True
	}
	for _, e := range exprs {
		if !e.known() {
			return True
		}
	}
	if len(exprs) == 1 {
		return exprs[0]
	}
	return orExpr(exprs)
}

// tokenAtom needs every token among the unit's identifiers.
type tokenAtom []string

func (t tokenAtom) eval(ev *Evidence) bool {
	for _, token := range t {
		if !ev.tokens[token] {
			return false
		}
	}
	return true
}

func (tokenAtom) known() bool { return true }

// importAtom needs an import of family the literal relates to, or one the
// template matches under its metavariable constraints.
type importAtom struct {
	family  Family
	literal string
	// template is set for an import naming metavariables; literal then holds
	// the literal text before the first metavariable.
	template    *regexp.Regexp
	constraints map[int][]*regexp.Regexp
}

func (a *importAtom) known() bool { return true }

func (a *importAtom) eval(ev *Evidence) bool {
	if ev.opaque[a.family] {
		return true
	}
	sep := separator(a.family)
	for _, candidate := range ev.imports[a.family] {
		if a.template == nil {
			if a.literal == "" || related(candidate, a.literal, sep) {
				return true
			}
			continue
		}
		if a.matchesTemplate(candidate) {
			return true
		}
		// A wildcard import names a whole package; it may supply any
		// member the template's literal prefix leaves open.
		if wildcard(candidate) && a.literal != "" && related(strings.TrimRight(candidate, ".*:{} "), strings.TrimRight(a.literal, ".:/ "), sep) {
			return true
		}
	}
	return false
}

func (a *importAtom) matchesTemplate(candidate string) bool {
	groups := a.template.FindStringSubmatch(candidate)
	if groups == nil {
		return false
	}
	for index, regexes := range a.constraints {
		for _, re := range regexes {
			if !re.MatchString(groups[index]) {
				return false
			}
		}
	}
	return true
}

func wildcard(candidate string) bool {
	return strings.HasSuffix(candidate, ".*") || strings.HasSuffix(candidate, "::*")
}

func separator(family Family) string {
	switch family {
	case FamilyJava, FamilyPython:
		return "."
	case FamilyRust:
		return "::"
	case FamilyGo, FamilyJS, FamilyC:
		return "/"
	default:
		return "/"
	}
}

// related reports whether a and b are equal or one extends the other at a
// separator, so either may name the other's module.
func related(a, b, sep string) bool {
	if a == b {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return a != "" && strings.HasPrefix(b, a) && strings.HasPrefix(b[len(a):], sep)
}
