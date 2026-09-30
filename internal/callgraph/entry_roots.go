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

import "strings"

// RootKind says what the first frame of a call chain is: why the walk back
// from the crypto stopped there.
type RootKind string

const (
	// RootKindMain is a program entry point: a Java `static main(String[])`,
	// or a free function named main in the other ecosystems.
	RootKindMain RootKind = "main"
	// RootKindFrameworkEntry is a method a framework calls rather than the
	// application: a Java method that overrides a method of a type outside
	// the application (HttpHandler.handle, Runnable.run, HttpServlet.doPost),
	// or one carrying a request-mapping, scheduling or listener annotation.
	RootKindFrameworkEntry RootKind = "framework_entry"
	// RootKindNoCallers is an application function that no application code
	// calls and that is not recognized as an entry point. On a scan without
	// user code (a library scanned alone) it is a graph root: the library's
	// public surface.
	RootKindNoCallers RootKind = "no_callers"
	// RootKindDepthLimit is an application frame where the walk stopped
	// because of the depth limit, with callers it did not follow. The chain is
	// real but may not start at an entry point.
	RootKindDepthLimit RootKind = "depth_limit"
)

// rootKindRank orders root kinds for chain selection: a chain from a
// recognized entry point tells a reader more than one from a function nothing
// calls, which tells more than one the depth limit cut.
func rootKindRank(kind RootKind) int {
	switch kind {
	case RootKindMain, RootKindFrameworkEntry:
		return 0
	case RootKindNoCallers:
		return 1
	case RootKindDepthLimit:
		return 2
	default:
		return 3
	}
}

// entryRootKind reports whether decl is a recognized entry point, and which
// kind. isUserType tells whether a fully qualified type belongs to the
// application.
func (t *Tracer) entryRootKind(decl *FunctionDecl, isUserType func(string) bool) (RootKind, bool) {
	if decl == nil || isTestDeclaration(decl) {
		return "", false
	}
	if decl.EntryKind != "" {
		return decl.EntryKind, true
	}
	if isMainFunction(decl) {
		return RootKindMain, true
	}
	return t.javaCallbackEntryKind(decl, isUserType)
}

func isMainFunction(decl *FunctionDecl) bool {
	if BaseFunctionName(decl.ID.Name) != "main" {
		return false
	}
	if decl.ID.Type == "" {
		return true
	}
	// Java: public static void main(String[] args).
	return decl.Static && len(decl.Parameters) == 1
}

// javaCallbackEntryKind recognizes a Java method that code outside the
// application calls: an @Override of a method of an external type
// (HttpHandler.handle, Runnable.run), or a container callback the catalog
// names on a subtype of a container type, which is often written without
// @Override (HttpServlet.doPost).
func (t *Tracer) javaCallbackEntryKind(decl *FunctionDecl, isUserType func(string) bool) (RootKind, bool) {
	if decl.Static || decl.ID.Type == "" {
		return "", false
	}
	owner := decl.ID.Type
	if decl.ID.Package != "" {
		owner = decl.ID.Package + "." + decl.ID.Type
	}
	for _, annotation := range decl.Annotations {
		if annotation == "Override" {
			if t.hasExternalSupertype(owner, isUserType, map[string]bool{}) {
				return RootKindFrameworkEntry, true
			}
			break
		}
	}
	return t.javaSupertypeEntryKind(decl, owner, isUserType)
}

// hasExternalSupertype reports whether typeName extends or implements, directly
// or through application supertypes, a type outside the application. An
// @Override method of such a type is a callback the outside code invokes.
func (t *Tracer) hasExternalSupertype(typeName string, isUserType func(string) bool, seen map[string]bool) bool {
	if seen[typeName] {
		return false
	}
	seen[typeName] = true
	supertypes := t.graph.SourceSupertypes[typeName]
	supertypes = append(supertypes[:len(supertypes):len(supertypes)], t.graph.TypeHierarchy[typeName]...)
	for _, entry := range supertypes {
		for _, candidate := range strings.Split(entry, javaSupertypeAlternatives) {
			switch {
			case candidate == "" || candidate == javaObjectType || candidate == javaUnresolvableSupertype:
				continue
			case !isUserType(candidate):
				return true
			case t.hasExternalSupertype(candidate, isUserType, seen):
				return true
			}
		}
	}
	return false
}
