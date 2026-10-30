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

import "testing"

// TestEntryPoint_NamesTheCatalogEntry: a declaration a catalog entry makes an
// entry point carries that entry's ID; one that language semantics make an
// entry point (main) carries none.
func TestEntryPoint_NamesTheCatalogEntry(t *testing.T) {
	t.Parallel()
	fns := parseJavaInline(t, `package com.example;

import org.springframework.web.bind.annotation.GetMapping;

class Controller {
    @GetMapping("/sign")
    String sign() { return ""; }

    public static void main(String[] args) {}
}
`)
	tracer := NewTracer(&CallGraph{Functions: map[string]*FunctionDecl{}}, ".")
	for _, tc := range []struct {
		name string
		want EntryMark
	}{
		{"sign", EntryMark{Kind: RootKindFrameworkEntry, Rule: "java/spring:decorator:RequestMapping"}},
		{"main", EntryMark{Kind: RootKindMain}},
	} {
		decl := findFunctionByName(fns, tc.name)
		if decl == nil {
			t.Fatalf("no function %s", tc.name)
		}
		if got, ok := tracer.EntryPoint(decl, nil); !ok || got != tc.want {
			t.Errorf("EntryPoint(%s) = %+v, %v; want %+v", tc.name, got, ok, tc.want)
		}
	}
}
