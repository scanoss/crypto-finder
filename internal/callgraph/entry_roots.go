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
)

// frameworkEntryAnnotations are the Java method annotations whose methods a
// framework invokes by reflection, so no call edge leads to them: web request
// mappings (Spring MVC, JAX-RS), scheduled jobs, and message or event
// listeners.
var frameworkEntryAnnotations = map[string]bool{
	"RequestMapping": true, "GetMapping": true, "PostMapping": true, "PutMapping": true,
	"DeleteMapping": true, "PatchMapping": true,
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true,
	"Scheduled": true, "EventListener": true,
	"KafkaListener": true, "RabbitListener": true, "JmsListener": true, "SqsListener": true,
}

// entryRootKind reports whether decl is a recognized entry point, and which
// kind. isUserType tells whether a fully qualified type belongs to the
// application.
func (t *Tracer) entryRootKind(decl *FunctionDecl, isUserType func(string) bool) (RootKind, bool) {
	if decl == nil {
		return "", false
	}
	if isMainFunction(decl) {
		return RootKindMain, true
	}
	if t.isFrameworkEntry(decl, isUserType) {
		return RootKindFrameworkEntry, true
	}
	return "", false
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

func (t *Tracer) isFrameworkEntry(decl *FunctionDecl, isUserType func(string) bool) bool {
	overrides := false
	for _, annotation := range decl.Annotations {
		if frameworkEntryAnnotations[annotation] {
			return true
		}
		if annotation == "Override" {
			overrides = true
		}
	}
	if !overrides || decl.Static || decl.ID.Type == "" {
		return false
	}
	owner := decl.ID.Type
	if decl.ID.Package != "" {
		owner = decl.ID.Package + "." + decl.ID.Type
	}
	return t.hasExternalSupertype(owner, isUserType, map[string]bool{})
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
