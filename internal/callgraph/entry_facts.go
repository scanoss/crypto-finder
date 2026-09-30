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
// path('x/', views.index).
type EntryRef struct {
	// Function is the handler's identity as the registering file spells it.
	Function FunctionID
	// Module says Function.Package is a Python module path, as an import
	// spells it (shop.web.views). The graph keys a Python function by its
	// defining module, so it also matches that module under the root module
	// a manifest-named project prefixes onto its own.
	Module bool
	// Kind is the root kind the handler gets.
	Kind RootKind
}

// resolveEntryRefs marks the declarations the collected EntryRefs name. A
// reference to a function the graph does not declare, such as a handler
// imported from a dependency, is dropped. A declaration keeps the kind a rule
// gave it first.
func resolveEntryRefs(graph *CallGraph) {
	refs := graph.entryRefs
	graph.entryRefs = nil
	if len(refs) == 0 {
		return
	}
	var byPackage map[string][]*FunctionDecl
	for _, ref := range refs {
		if decl := graph.Functions[ref.Function.String()]; decl != nil {
			markEntry(decl, ref.Kind)
			continue
		}
		if !ref.Module {
			continue
		}
		if byPackage == nil {
			byPackage = make(map[string][]*FunctionDecl)
			for _, decl := range graph.Functions {
				byPackage[decl.ID.Package] = append(byPackage[decl.ID.Package], decl)
			}
		}
		markPythonModuleFunction(byPackage, ref)
	}
}

// markPythonModuleFunction marks the function ref names in the Python module
// ref.Function.Package. The graph keys a Python function by its defining
// module, so the spelled module matches directly, or after the root module a
// manifest-named project prefixes onto its own modules (`probe.app.views` for
// `import app.views`).
func markPythonModuleFunction(byPackage map[string][]*FunctionDecl, ref EntryRef) {
	module := ref.Function.Package
	if module == "" {
		return
	}
	for pkg, decls := range byPackage {
		if pkg != module && !strings.HasSuffix(pkg, "."+module) {
			continue
		}
		for _, decl := range decls {
			if decl.ID.Type == "" && decl.ID.Name == ref.Function.Name {
				markEntry(decl, ref.Kind)
			}
		}
	}
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
