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
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

const javaNodeExtendsInterfaces = "extends_interfaces"

// extractJavaSupertypes returns the fully qualified direct supertypes a Java
// class, enum, record or interface declaration names in its extends and
// implements clauses. Unlike extractJavaClassBases it takes only the named
// type of each clause entry, never its generic arguments, so
// `implements Future<T>` yields Future and not T.
func extractJavaSupertypes(node *sitter.Node, src []byte, analysis *FileAnalysis) []string {
	var out []string
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case javaNodeSuperclass, javaNodeSuperInterfaces, javaNodeExtendsInterfaces:
			for _, typeText := range javaClauseTypeNames(child, src) {
				out = append(out, resolveJavaSupertype(typeText, analysis)...)
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
		case javaNodeTypeIdentifier, javaNodeScopedTypeIdentifier, javaNodeGenericType:
			if name := strings.TrimSpace(stripGenericSuffix(child.Content(src))); name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// resolveJavaSupertype maps a type name written in an extends/implements clause
// to the fully qualified names it can denote, following Java's lookup order: a
// single-type import, then a type declared in this file, then the file's own
// package. When the file also has on-demand (wildcard) imports the name may
// come from one of them instead, so each such package, and java.lang, is
// returned as a further candidate. The result can therefore over-approximate
// by names that no type in the graph carries; a candidate that names no known
// type contributes nothing to a subtype check.
func resolveJavaSupertype(typeText string, analysis *FileAnalysis) []string {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return nil
	}
	pkg := javaAnalysisPackagePath(analysis)
	head, rest, qualified := strings.Cut(typeText, ".")
	if analysis != nil {
		if imported, ok := analysis.Imports[head]; ok && imported != "" {
			return []string{imported + "." + typeText}
		}
	}
	if qualified && head != "" && !looksLikeJavaTypeName(head) {
		// Already fully qualified: org.example.Base.
		return []string{typeText}
	}
	if declared := declaredJavaTypeName(typeText, analysis); declared != "" {
		return []string{joinJavaPackage(pkg, declared)}
	}
	if qualified {
		// Outer.Inner where Outer is neither imported nor declared here: it
		// can only be a type of this package.
		return []string{joinJavaPackage(pkg, head+"."+rest)}
	}
	candidates := []string{joinJavaPackage(pkg, typeText)}
	if analysis != nil {
		for _, wildcard := range analysis.WildcardImports {
			if wildcard != "" {
				candidates = append(candidates, wildcard+"."+typeText)
			}
		}
	}
	return append(candidates, "java.lang."+typeText)
}

// declaredJavaTypeName returns the file-local (possibly nested, dotted) name
// of the type declared in this file that typeText refers to, or "" when none
// does. An exact key wins; otherwise a nested type whose trailing segments
// equal typeText.
func declaredJavaTypeName(typeText string, analysis *FileAnalysis) string {
	if analysis == nil || len(analysis.ClassBases) == 0 {
		return ""
	}
	if _, ok := analysis.ClassBases[typeText]; ok {
		return typeText
	}
	match := ""
	for declared := range analysis.ClassBases {
		if !strings.HasSuffix(declared, "."+typeText) {
			continue
		}
		if match == "" || len(declared) < len(match) || (len(declared) == len(match) && declared < match) {
			match = declared
		}
	}
	return match
}

func joinJavaPackage(pkg, typeName string) string {
	if pkg == "" {
		return typeName
	}
	return pkg + "." + typeName
}

// recordJavaSupertypes stores the resolved supertypes of the file-local type
// typeName under its fully qualified name.
func recordJavaSupertypes(analysis *FileAnalysis, typeName string, supertypes []string) {
	if analysis == nil || typeName == "" || len(supertypes) == 0 {
		return
	}
	if analysis.Supertypes == nil {
		analysis.Supertypes = make(map[string][]string)
	}
	owner := joinJavaPackage(javaAnalysisPackagePath(analysis), typeName)
	analysis.Supertypes[owner] = append(analysis.Supertypes[owner], supertypes...)
}
