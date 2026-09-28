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

package callgraph

import (
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const javaNodeExtendsInterfaces = "extends_interfaces"

// extractJavaSupertypes returns the fully qualified direct supertypes a Java
// class, enum, record or interface declaration names in its extends and
// implements clauses, one entry per named type. An entry whose simple name an
// on-demand import leaves ambiguous lists its possible names separated by
// javaSupertypeAlternatives. Unlike extractJavaClassBases it takes only the named
// type of each clause entry, never its generic arguments, so
// `implements Future<T>` yields Future and not T.
func extractJavaSupertypes(node *sitter.Node, src []byte, analysis *FileAnalysis) []string {
	out := []string{}
	// Enums and records have an implicit superclass besides Object.
	switch node.Type() {
	case javaNodeEnumDeclaration:
		out = append(out, "java.lang.Enum")
	case javaNodeRecordDeclaration:
		out = append(out, "java.lang.Record")
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeSuperclass, javaNodeSuperInterfaces, javaNodeExtendsInterfaces:
			for _, typeText := range javaClauseTypeNames(child, src) {
				out = append(out, strings.Join(resolveJavaSupertype(typeText, analysis), javaSupertypeAlternatives))
			}
		}
	}
	return out
}

// javaClauseTypeNames collects the erased type names listed directly in an
// extends/implements clause, descending through the type_list wrapper but not
// into type arguments.
func javaClauseTypeNames(node *sitter.Node, src []byte) []string {
	var names []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case javaNodeTypeList:
			names = append(names, javaClauseTypeNames(child, src)...)
		case "annotated_type":
			// `implements @Ann Foo`: the annotation is not a supertype.
			names = append(names, javaClauseTypeNames(child, src)...)
		case javaNodeTypeIdentifier, javaNodeScopedTypeIdentifier, javaNodeGenericType:
			if name := strings.TrimSpace(stripGenericSuffix(child.Content(src))); name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// javaUnresolvableSupertype stands in, among a supertype entry's
// alternatives, for a type this file may declare where the resolver cannot
// see it (a local class). An entry carrying it is never certain.
const javaUnresolvableSupertype = "?"

// resolveJavaSupertype maps a type name written in an extends/implements clause
// to every fully qualified name it can plausibly denote. Java's scoping (which
// member, inherited or local type shadows an import) is not modeled, so all
// candidates are listed: each type of that name declared in this file, a
// single-type import, and otherwise the file's own package, any on-demand
// import and java.lang. The hierarchy treats an entry with more than one
// known candidate as uncertain: it may prove a subtype but never rule one out.
func resolveJavaSupertype(typeText string, analysis *FileAnalysis) []string {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return nil
	}
	pkg := javaAnalysisPackagePath(analysis)
	head, rest, qualified := strings.Cut(typeText, ".")
	if qualified && head != "" && !looksLikeJavaTypeName(head) {
		// Already fully qualified: org.example.Base.
		return []string{typeText}
	}
	candidates := javaFileSupertypeCandidates(typeText, head, analysis)
	if len(candidates) > 0 {
		return candidates
	}
	if qualified {
		// Outer.Inner where Outer is neither imported nor declared here: it
		// can only be a type of this package.
		return []string{joinJavaPackage(pkg, head+"."+rest)}
	}
	candidates = []string{joinJavaPackage(pkg, typeText)}
	if analysis != nil {
		for _, wildcard := range analysis.WildcardImports {
			if wildcard != "" {
				candidates = append(candidates, wildcard+"."+typeText)
			}
		}
	}
	return append(candidates, "java.lang."+typeText)
}

// declaredJavaTypeNames returns the file-local (possibly nested, dotted) names
// of the types declared in this file that typeText can refer to: a top-level
// type of that name and every nested type whose trailing segments equal it.
// Which one applies depends on the enclosing scope, which is not tracked, so
// more than one result means the name is ambiguous here.
func declaredJavaTypeNames(typeText string, analysis *FileAnalysis) []string {
	if analysis == nil || len(analysis.ClassBases) == 0 {
		return nil
	}
	var matches []string
	for declared := range analysis.ClassBases {
		if declared == typeText || strings.HasSuffix(declared, "."+typeText) {
			matches = append(matches, declared)
		}
	}
	sort.Strings(matches)
	return matches
}

func joinJavaPackage(pkg, typeName string) string {
	if pkg == "" {
		return typeName
	}
	return pkg + "." + typeName
}

// recordJavaSupertypes stores the resolved supertypes of the file-local type
// typeName under its fully qualified name. Every declared type is recorded,
// with an empty list when it names no supertype.
func recordJavaSupertypes(analysis *FileAnalysis, typeName string, supertypes []string) {
	if analysis == nil || typeName == "" {
		return
	}
	if analysis.Supertypes == nil {
		analysis.Supertypes = make(map[string][]string)
	}
	owner := joinJavaPackage(javaAnalysisPackagePath(analysis), typeName)
	// The key is stored even with no supertypes: its presence records that the
	// type extends only Object.
	existing := analysis.Supertypes[owner]
	if existing == nil {
		existing = []string{}
	}
	analysis.Supertypes[owner] = append(existing, supertypes...)
}

// javaParameterBaseType strips generic arguments, array brackets and a varargs
// ellipsis from a parameter's source type.
func javaParameterBaseType(raw string) string {
	base := strings.TrimSpace(stripGenericSuffix(strings.TrimSpace(raw)))
	base = strings.TrimSpace(strings.TrimSuffix(base, "..."))
	for strings.HasSuffix(base, "[]") {
		base = strings.TrimSpace(strings.TrimSuffix(base, "[]"))
	}
	return base
}

// qualifyJavaParameters fills FunctionParameter.QualifiedType for the
// parameters whose type the source did not spell fully qualified, with the
// names resolveJavaSupertype would give it (import, type declared in this
// file, this package, then any on-demand import and java.lang).
func qualifyJavaParameters(params []FunctionParameter, analysis *FileAnalysis) {
	for i := range params {
		if params[i].QualifiedType != "" {
			continue
		}
		params[i].QualifiedType = qualifyJavaType(params[i].Type, analysis)
	}
}

// qualifyJavaType resolves a source type the way qualifyJavaParameters does:
// as written when fully qualified, otherwise through the file's imports and
// declarations, listing alternatives where they leave it open. Empty for
// primitives, void and type variables.
func qualifyJavaType(raw string, analysis *FileAnalysis) string {
	base := javaParameterBaseType(raw)
	if base == "" || base == javaVoidType || isJavaPrimitive(base) || isJavaTypeVariable(base) {
		return ""
	}
	if strings.Contains(base, ".") && !looksLikeJavaTypeName(base) {
		return base
	}
	if analysis != nil && analysis.TypeNamesAtRisk[simpleTypeName(base)] {
		// The file declares a type or type parameter of this name somewhere;
		// without javac's scoping the reference is not certain.
		return ""
	}
	return strings.Join(resolveJavaSupertype(base, analysis), javaSupertypeAlternatives)
}

// javaFileSupertypeCandidates lists the candidates the file itself supplies for
// a supertype name: every type of that name it declares (or the unresolvable
// marker for one the resolver cannot see, such as a local class), plus a
// single-type import of it. Empty when the file supplies none.
func javaFileSupertypeCandidates(typeText, head string, analysis *FileAnalysis) []string {
	if analysis == nil {
		return nil
	}
	pkg := javaAnalysisPackagePath(analysis)
	var candidates []string
	for _, name := range declaredJavaTypeNames(typeText, analysis) {
		candidates = append(candidates, joinJavaPackage(pkg, name))
	}
	if analysis.TypeNamesAtRisk[simpleTypeName(typeText)] && len(candidates) == 0 {
		candidates = append(candidates, javaUnresolvableSupertype)
	}
	if imported, ok := analysis.Imports[head]; ok && imported != "" {
		candidates = append(candidates, imported+"."+typeText)
	}
	return candidates
}

// collectJavaTypeNamesAtRisk gathers the simple names of every type
// declaration (member, nested and local) and every type parameter in a
// compilation unit.
func collectJavaTypeNamesAtRisk(root *sitter.Node, src []byte) map[string]bool {
	names := make(map[string]bool)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case javaNodeClassDeclaration, javaNodeInterfaceDeclaration, javaNodeEnumDeclaration,
			javaNodeRecordDeclaration, javaNodeAnnotationTypeDecl:
			if name := n.ChildByFieldName(javaFieldName); name != nil {
				names[name.Content(src)] = true
			}
		case "type_parameter":
			for i := 0; i < int(n.NamedChildCount()); i++ {
				if c := n.NamedChild(i); c.Type() == javaNodeTypeIdentifier || c.Type() == javaNodeIdentifier {
					names[c.Content(src)] = true
					break
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return names
}
