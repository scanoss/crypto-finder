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
	"unicode"
)

// EntryRef names a function that source code hands to a framework instead of
// calling it: the handler of app.get('/x', handler), the view of a Django
// path('x/', views.index), a Go http.HandleFunc("/", handle).
type EntryRef struct {
	// Function is the handler's identity as the registering file spells it.
	// A Go method matches with a pointer or a value receiver: the method
	// value s.handleLogin does not say which.
	Function FunctionID
	// AllExported matches every exported method of Function.Type, whose Name
	// is empty: a gRPC service implementation.
	AllExported bool
	// Module says Function.Package is a Python module path, as an import
	// or a manifest spells it (shop.web.views). The graph keys a Python
	// function by its defining module, so it matches that module exactly, or
	// under the root module a manifest-named project prefixes onto its own,
	// and under no other leading segments.
	Module bool
	// Kind is the root kind the handler gets.
	Kind RootKind
}

// resolveEntryRefs marks the declarations the collected EntryRefs name. A
// reference to a function the graph does not declare, such as a handler
// imported from a dependency, is dropped. A declaration keeps the kind a rule
// gave it first. pythonRoots are the root modules the build's project-local
// Python modules are keyed under.
func resolveEntryRefs(graph *CallGraph, pythonRoots []string) {
	refs := uniqueEntryRefs(graph.entryRefs)
	graph.entryRefs = nil
	if len(refs) == 0 {
		return
	}
	var byPackage map[string][]*FunctionDecl
	for _, ref := range refs {
		if decl := lookupEntryRef(graph, ref.Function); decl != nil && !ref.AllExported {
			markEntry(decl, ref.Kind)
			continue
		}
		if !ref.AllExported && !ref.Module {
			continue
		}
		if byPackage == nil {
			byPackage = make(map[string][]*FunctionDecl)
			for _, decl := range graph.Functions {
				byPackage[decl.ID.Package] = append(byPackage[decl.ID.Package], decl)
			}
		}
		if ref.Module {
			markPythonModuleFunction(byPackage, ref, pythonRoots)
			continue
		}
		for _, decl := range byPackage[ref.Function.Package] {
			if ref.matchesMethod(decl) {
				markEntry(decl, ref.Kind)
			}
		}
	}
}

// uniqueEntryRefs drops repeated references. Every file under a manifest
// names the manifest's console scripts, and each reference costs a lookup.
func uniqueEntryRefs(refs []EntryRef) []EntryRef {
	seen := make(map[EntryRef]struct{}, len(refs))
	out := refs[:0:0]
	for _, ref := range refs {
		if _, duplicate := seen[ref]; !duplicate {
			seen[ref] = struct{}{}
			out = append(out, ref)
		}
	}
	return out
}

// markPythonModuleFunction marks the function ref names in the Python module
// ref.Function.Package. The graph keys a Python function by its defining
// module, so the spelled module matches directly, or after the root module a
// manifest-named project prefixes onto its own modules (`probe.app.views` for
// `import app.views`). A module nested under other segments (`probe.x.app.views`)
// is a different module and stays unmarked.
func markPythonModuleFunction(byPackage map[string][]*FunctionDecl, ref EntryRef, roots []string) {
	module := ref.Function.Package
	if module == "" {
		return
	}
	candidates := make([]string, 0, 1+len(roots))
	candidates = append(candidates, module)
	for _, root := range roots {
		candidates = append(candidates, root+"."+module)
	}
	for _, pkg := range candidates {
		for _, decl := range byPackage[pkg] {
			if decl.ID.Type == "" && decl.ID.Name == ref.Function.Name {
				markEntry(decl, ref.Kind)
			}
		}
	}
}

// lookupEntryRef returns the declaration id names, with either receiver form
// for a method.
func lookupEntryRef(graph *CallGraph, id FunctionID) *FunctionDecl {
	if decl := graph.Functions[id.String()]; decl != nil || id.Type == "" {
		return decl
	}
	if strings.HasPrefix(id.Type, "*") {
		id.Type = strings.TrimPrefix(id.Type, "*")
	} else {
		id.Type = "*" + id.Type
	}
	return graph.Functions[id.String()]
}

func (ref EntryRef) matchesMethod(decl *FunctionDecl) bool {
	if decl.ID.Type == "" {
		return false
	}
	return strings.TrimPrefix(decl.ID.Type, "*") == strings.TrimPrefix(ref.Function.Type, "*") &&
		isExportedName(decl.ID.Name)
}

func markEntry(decl *FunctionDecl, kind RootKind) {
	if decl != nil && decl.EntryKind == "" {
		decl.EntryKind = kind
	}
}

func isExportedName(name string) bool {
	for _, r := range name {
		return unicode.IsUpper(r)
	}
	return false
}
