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

package cardmatch

import (
	"math/rand"
	"slices"
	"testing"
)

// TestRustShadowedIndex: the indexed shadowed answers what its definition
// does, a let of one of names that starts at or after the end of span and
// ends at or before at, on lets that nest (a let inside a block of another
// let's initializer) and repeat names.
func TestRustShadowedIndex(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	names := []string{"a", "b", "c"}
	decls := make([]*Site, 0, 60)
	for range 60 {
		line := 1 + r.Intn(40)
		endLine := line + r.Intn(3)
		col, endCol := 1+r.Intn(20), 1+r.Intn(30)
		if endLine == line && endCol <= col {
			endCol = col + 1
		}
		decls = append(decls, &Site{Caller: "f", Line: line, Col: col, EndLine: endLine, EndCol: endCol, AssignedVar: names[r.Intn(len(names))]})
	}
	m := &rustMatcher{fr: &Frag{DeclsByCaller: map[string][]*Site{"f": decls}}}
	linear := func(names []string, span rustSpan, at rustPos) bool {
		for _, d := range decls {
			ds := rustSpanOf(d.Line, d.Col, d.EndCol, d.EndLine)
			if slices.Contains(names, d.AssignedVar) && !ds.from.before(span.to) && !at.before(ds.to) {
				return true
			}
		}
		return false
	}
	pos := func() rustPos { return rustPos{1 + r.Intn(45), 1 + r.Intn(30)} }
	for range 5000 {
		span := rustSpan{pos(), pos()}
		at := pos()
		ns := names[:r.Intn(len(names)+1)]
		if got, want := m.shadowed("f", ns, span, at), linear(ns, span, at); got != want {
			t.Fatalf("shadowed(%v, %v, %v) = %v, want %v", ns, span, at, got, want)
		}
	}
}

// TestRustVarsLatest: an environment reads the latest binding of a name, and
// lists each name once with it.
func TestRustVarsLatest(t *testing.T) {
	env, _ := rustEnv{}.bind("$A", "x")
	env, _ = env.bind("$B", "y")
	env = env.set("$A", "z")
	if _, ok := env.bind("$A", "x"); ok {
		t.Errorf("bind $A to x over z succeeded")
	}
	got := map[string]string{}
	env.vars.each(func(k, v string) {
		if _, dup := got[k]; dup {
			t.Errorf("%s listed twice", k)
		}
		got[k] = v
	})
	if got["$A"] != "z" || got["$B"] != "y" || len(got) != 2 {
		t.Errorf("each = %v, want $A=z $B=y", got)
	}
}
