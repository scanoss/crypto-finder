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

// constraints maps a metavariable name to the metavariable-regex patterns
// that every match binding it must satisfy. A regex Go cannot compile is
// left out, which only weakens the requirement.
type constraints map[string][]*regexp.Regexp

// alwaysOn is the metadata.imports entry of a rule that needs no import.
const alwaysOn = "*"

func (c constraints) with(items []any) constraints {
	var added constraints
	for _, item := range items {
		node, ok := item.(map[string]any)
		if !ok {
			continue
		}
		spec, ok := node["metavariable-regex"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := spec["metavariable"].(string) //nolint:errcheck // A missing name adds no constraint.
		expr, _ := spec["regex"].(string)        //nolint:errcheck // A missing regex adds no constraint.
		re, err := regexp.Compile(expr)
		if name == "" || expr == "" || err != nil {
			continue
		}
		if added == nil {
			added = make(constraints, len(c)+1)
			for k, v := range c {
				added[k] = v
			}
		}
		added[name] = append(added[name][:len(added[name]):len(added[name])], re)
	}
	if added == nil {
		return c
	}
	return added
}

// Requirement derives the requirement of one rule, decoded from JSON, whose
// languages are the given OpenGrep analyzer ids.
func Requirement(rule map[string]any, analyzers []string) Expr {
	family := commonFamily(analyzers)
	if metadata, ok := rule["metadata"].(map[string]any); ok {
		if explicit := explicitImports(metadata, family); explicit != nil {
			return explicit
		}
	}
	mode, _ := rule["mode"].(string) //nolint:errcheck // An absent mode is search.
	switch mode {
	case "", "search":
		return formula(rule, family, nil)
	case "taint":
		return and([]Expr{taintSide(rule["pattern-sources"], family), taintSide(rule["pattern-sinks"], family)})
	default:
		return True
	}
}

// explicitImports reads metadata.imports: the modules a rule author declares
// that every match imports, one of which the unit must import. The entry
// "*" declares a rule that matches without any import, which is kept for
// every unit of its language.
func explicitImports(metadata map[string]any, family Family) Expr {
	list, ok := metadata["imports"].([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	for _, item := range list {
		if module, ok := item.(string); ok && strings.TrimSpace(module) == alwaysOn {
			return True
		}
	}
	if family == "" {
		return nil
	}
	alternatives := make([]Expr, 0, len(list))
	for _, item := range list {
		module, ok := item.(string)
		if !ok || strings.TrimSpace(module) == "" {
			return nil
		}
		alternatives = append(alternatives, &importAtom{family: family, literal: strings.TrimSpace(module), declared: true})
	}
	return or(alternatives)
}

func commonFamily(analyzers []string) Family {
	var family Family
	for _, analyzer := range analyzers {
		f := FamilyOf(analyzer)
		if f == "" || (family != "" && f != family) {
			return ""
		}
		family = f
	}
	return family
}

func taintSide(value any, family Family) Expr {
	items, ok := value.([]any)
	if !ok {
		return True
	}
	alternatives := make([]Expr, 0, len(items))
	for _, item := range items {
		alternatives = append(alternatives, formula(item, family, nil))
	}
	return or(alternatives)
}

// formula reads one pattern formula node.
func formula(node any, family Family, inherited constraints) Expr {
	switch value := node.(type) {
	case string:
		return atom(value, family, inherited)
	case map[string]any:
		return formulaNode(value, family, inherited)
	default:
		return True
	}
}

func formulaNode(node map[string]any, family Family, inherited constraints) Expr {
	if pattern, ok := node["pattern"].(string); ok {
		return atom(pattern, family, inherited)
	}
	if inside, ok := node["pattern-inside"].(string); ok {
		return atom(inside, family, inherited)
	}
	if items, ok := node["patterns"].([]any); ok {
		scoped := inherited.with(items)
		conjuncts := make([]Expr, 0, len(items))
		for _, item := range items {
			if positive(item) {
				conjuncts = append(conjuncts, formula(item, family, scoped))
			}
		}
		return and(conjuncts)
	}
	if items, ok := node["pattern-either"].([]any); ok {
		alternatives := make([]Expr, 0, len(items))
		for _, item := range items {
			alternatives = append(alternatives, formula(item, family, inherited))
		}
		return or(alternatives)
	}
	return True
}

// positive reports whether a member of a patterns list must itself match.
func positive(item any) bool {
	node, ok := item.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"pattern", "pattern-inside", "patterns", "pattern-either"} {
		if _, ok := node[key]; ok {
			return true
		}
	}
	return false
}

// atom derives the facts one pattern needs.
func atom(pattern string, family Family, scope constraints) Expr {
	text := strings.TrimSpace(pattern)
	if text == "" {
		return True
	}
	if modules, ok := importModules(text, family); ok {
		conjuncts := make([]Expr, 0, len(modules))
		for _, module := range modules {
			conjuncts = append(conjuncts, importRequirement(module, family, scope))
		}
		return and(conjuncts)
	}
	return qualifiedNames(text, family)
}

var metavariable = regexp.MustCompile(`\$(?:\.{3})?[A-Z_][A-Z0-9_]*`)

// importRequirement turns one module spelling from an import pattern into an
// atom. Ellipsis and regex strings match any module, so they are true.
func importRequirement(module string, family Family, scope constraints) Expr {
	module = strings.TrimSpace(module)
	if module == "" || strings.Contains(module, "...") || strings.HasPrefix(module, "=~/") {
		return True
	}
	locations := metavariable.FindAllStringIndex(module, -1)
	if len(locations) == 0 {
		return &importAtom{family: family, literal: strings.TrimRight(module, ".*:")}
	}
	var expr strings.Builder
	expr.WriteString(`^`)
	byGroup := make(map[int][]*regexp.Regexp)
	last := 0
	for i, loc := range locations {
		expr.WriteString(regexp.QuoteMeta(module[last:loc[0]]))
		expr.WriteString(`(.+?)`)
		if regexes := scope[module[loc[0]:loc[1]]]; len(regexes) > 0 {
			byGroup[i+1] = regexes
		}
		last = loc[1]
	}
	expr.WriteString(regexp.QuoteMeta(module[last:]))
	expr.WriteString(`$`)
	template, err := regexp.Compile(expr.String())
	if err != nil {
		return True
	}
	return &importAtom{family: family, literal: module[:locations[0][0]], template: template, constraints: byGroup}
}

var (
	goImportString   = regexp.MustCompile("\"[^\"\\n]*\"|`[^`]*`")
	javaImport       = regexp.MustCompile(`^import\s+(?:static\s+)?([\w.$*]+)\s*;?`)
	pythonImport     = regexp.MustCompile(`^import\s+([\w.$]+)`)
	pythonFromImport = regexp.MustCompile(`^from\s+([\w.$]+)\s+import\b`)
	// jsSpecifier finds module specifiers: require/import calls, from
	// clauses, bare imports, and a metavariable callee taking one string, the
	// loader-wrapper form ($E("x")) rules use for interop helpers.
	jsSpecifier     = regexp.MustCompile(`(?:\brequire|\bimport|\$[A-Z_][A-Z0-9_]*)\s*\(\s*("[^"\n]*"|'[^'\n]*'|\$[A-Z_][A-Z0-9_]*)\s*\)|\bfrom\s+("[^"\n]*"|'[^'\n]*')|^import\s+("[^"\n]*"|'[^'\n]*')`)
	rustUse         = regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+?)\s*;`)
	rustExternCrate = regexp.MustCompile(`^extern\s+crate\s+([\w$]+)`)
	cInclude        = regexp.MustCompile(`^#\s*include\s*([<"])([^>"]*)[>"]`)
	rustAlias       = regexp.MustCompile(`\s+as\s+[\w$]+\s*$`)
)

// importModules returns the modules an import pattern names, and false when
// the pattern is no import statement of family.
func importModules(text string, family Family) ([]string, bool) {
	switch family {
	case FamilyGo:
		return goModules(text)
	case FamilyJava:
		if m := javaImport.FindStringSubmatch(text); m != nil {
			return []string{m[1]}, true
		}
	case FamilyPython:
		return pythonModules(text)
	case FamilyJS:
		return jsModules(text)
	case FamilyRust:
		if m := rustUse.FindStringSubmatch(text); m != nil {
			return []string{strings.TrimPrefix(rustAlias.ReplaceAllString(m[1], ""), "::")}, true
		}
		if m := rustExternCrate.FindStringSubmatch(text); m != nil {
			return []string{m[1]}, true
		}
	case FamilyC:
		if m := cInclude.FindStringSubmatch(text); m != nil {
			return []string{m[2]}, true
		}
	}
	return nil, false
}

// goModules reads the import paths of a single or grouped Go import.
func goModules(text string) ([]string, bool) {
	if !strings.HasPrefix(text, "import") {
		return nil, false
	}
	decl := text
	if open := strings.Index(text, "("); open >= 0 && strings.TrimSpace(text[len("import"):open]) == "" {
		if end := strings.Index(text[open:], ")"); end >= 0 {
			decl = text[:open+end]
		}
	} else if newline := strings.IndexByte(text, '\n'); newline >= 0 {
		decl = text[:newline]
	}
	var modules []string
	for _, literal := range goImportString.FindAllString(decl, -1) {
		modules = append(modules, literal[1:len(literal)-1])
	}
	return modules, true
}

// pythonModules reads `from X import ...` and `import X`; a relative import
// names no module the prefilter can check.
func pythonModules(text string) ([]string, bool) {
	if m := pythonFromImport.FindStringSubmatch(text); m != nil {
		if strings.HasPrefix(m[1], ".") {
			return nil, true
		}
		return []string{m[1]}, true
	}
	if m := pythonImport.FindStringSubmatch(text); m != nil {
		return []string{m[1]}, true
	}
	return nil, false
}

// jsModules reads the module specifiers of a require/import pattern. Every
// specifier the pattern spells must appear in a matching file.
func jsModules(text string) ([]string, bool) {
	// A statement starting with `{` is a block: OpenGrep reads
	// `{..., $F, ...} = require("x")` as the brace alone, which matches any
	// object literal, so the require constrains nothing.
	if strings.HasPrefix(text, "{") {
		return nil, false
	}
	firstLine := text
	if newline := strings.IndexByte(text, '\n'); newline >= 0 {
		firstLine = text[:newline]
	}
	matches := jsSpecifier.FindAllStringSubmatch(firstLine, -1)
	if len(matches) == 0 {
		return nil, false
	}
	modules := make([]string, 0, len(matches))
	for _, m := range matches {
		for _, group := range m[1:] {
			if group == "" {
				continue
			}
			if group[0] == '"' || group[0] == '\'' {
				group = group[1 : len(group)-1]
			}
			modules = append(modules, group)
			break
		}
	}
	return modules, true
}
