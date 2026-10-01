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

	"github.com/scanoss/crypto-finder/internal/callgraph/entrypoints"
)

// Java entry points from the framework catalog (entrypoints/java): methods
// whose annotation a container reads by reflection, and callbacks a container
// calls on a subtype of one of its types.

// javaAnnotationEntryKind returns the root kind of the first annotation on a
// method declaration that the catalog names. An annotation is resolved to its
// type the way javac does: a qualified name as written, else a single-type
// import, else an on-demand import, else the file's own package. So
// @GetMapping counts only when the file imports it from Spring, and an
// annotation of the same simple name from another package does not.
func javaAnnotationEntryKind(node *sitter.Node, src []byte, analysis *FileAnalysis) (RootKind, bool) {
	catalog := entryCatalog()
	for _, written := range javaWrittenAnnotations(node, src) {
		simple := written[strings.LastIndex(written, ".")+1:]
		if !catalog.Named(entryLanguageJava, entrypoints.ShapeDecorator, simple) {
			continue
		}
		for _, pkg := range javaAnnotationPackages(written, analysis) {
			if entry, ok := catalog.Match(entryLanguageJava, entrypoints.ShapeDecorator, pkg, "", simple); ok {
				return catalogEntryKind(&entry), true
			}
		}
	}
	return "", false
}

// javaAnnotationPackages lists the packages an annotation name can denote,
// in javac's lookup order.
func javaAnnotationPackages(written string, analysis *FileAnalysis) []string {
	if dot := strings.LastIndex(written, "."); dot >= 0 {
		return []string{written[:dot]}
	}
	if pkg, ok := analysis.Imports[written]; ok {
		return []string{pkg}
	}
	return append(append([]string(nil), analysis.WildcardImports...), analysis.PackagePath)
}

// javaSupertypeEntryKind reports whether decl is a callback a container
// calls on a subtype of one of its types, often written without @Override:
// a method the catalog names on a type that extends or implements, through
// application supertypes, a catalog type such as HttpServlet.
func (t *Tracer) javaSupertypeEntryKind(decl *FunctionDecl, owner string, isUserType func(string) bool) (RootKind, bool) {
	catalog := entryCatalog()
	name := BaseFunctionName(decl.ID.Name)
	if !catalog.Named(entryLanguageJava, entrypoints.ShapeSupertype, name) {
		return "", false
	}
	for _, external := range t.externalSupertypes(owner, isUserType, map[string]bool{}) {
		dot := strings.LastIndex(external, ".")
		if dot < 0 {
			continue
		}
		if entry, ok := catalog.Match(entryLanguageJava, entrypoints.ShapeSupertype, external[:dot], external[dot+1:], name); ok {
			return catalogEntryKind(&entry), true
		}
	}
	return "", false
}

// externalSupertypes lists the types outside the application that typeName
// extends or implements, directly or through application supertypes.
func (t *Tracer) externalSupertypes(typeName string, isUserType func(string) bool, seen map[string]bool) []string {
	if seen[typeName] {
		return nil
	}
	seen[typeName] = true
	supertypes := t.graph.SourceSupertypes[typeName]
	supertypes = append(supertypes[:len(supertypes):len(supertypes)], t.graph.TypeHierarchy[typeName]...)
	var out []string
	for _, entry := range supertypes {
		for _, candidate := range strings.Split(entry, javaSupertypeAlternatives) {
			switch {
			case candidate == "" || candidate == javaObjectType || candidate == javaUnresolvableSupertype:
			case !isUserType(candidate):
				out = append(out, candidate)
			default:
				out = append(out, t.externalSupertypes(candidate, isUserType, seen)...)
			}
		}
	}
	return out
}
