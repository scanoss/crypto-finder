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

import "unicode"

// EntryRef names a function that source code hands to a framework instead of
// calling it: the handler of app.get('/x', handler).
type EntryRef struct {
	// Function is the handler's identity as the registering file spells it.
	Function FunctionID
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
	for _, ref := range refs {
		markEntry(graph.Functions[ref.Function.String()], ref.Kind)
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
