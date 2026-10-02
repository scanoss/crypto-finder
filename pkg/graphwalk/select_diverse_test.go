// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphwalk

import (
	"slices"
	"strings"
	"testing"
)

// libraryGraph returns a target "sink" called by the given middle nodes, each
// called by the single entry point "app".
func libraryGraph(middle ...string) (Reachable[string], Condensed[string]) {
	callers := map[string][]string{"sink": middle}
	for _, m := range middle {
		callers[m] = []string{"app"}
	}
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return n == "app" },
	}
	reach := Reach("sink", opts)
	return reach, Condense(reach, opts.Less)
}

func libraryOf(route []string) string {
	var path []string
	for _, n := range route {
		lib := "app"
		if strings.HasPrefix(n, "x") {
			lib = "x"
		} else if strings.HasPrefix(n, "y") {
			lib = "y"
		} else if n == "sink" {
			lib = "sink"
		}
		if len(path) == 0 || path[len(path)-1] != lib {
			path = append(path, lib)
		}
	}
	return strings.Join(path, ">")
}

// The plain fill spends the budget on variants through library x because its
// callers sort first; the class-aware selection keeps the route through y.
func TestSelectDiverseKeepsAnotherLibraryPath(t *testing.T) {
	t.Parallel()
	reach, condensed := libraryGraph("x1", "x2", "x3", "y1")
	less := func(a, b string) bool { return a < b }

	plain := Select(reach, condensed, 2, less)
	for _, route := range plain {
		if slices.Contains(route, "y1") {
			t.Fatalf("plain Select = %v, want it to spend the budget on x variants", plain)
		}
	}
	if nilClass := SelectDiverse(reach, condensed, 2, less, nil, 100); !slices.EqualFunc(nilClass, plain, slices.Equal) {
		t.Fatalf("SelectDiverse with nil class = %v, want Select's %v", nilClass, plain)
	}

	diverse := SelectDiverse(reach, condensed, 2, less, libraryOf, 100)
	if len(diverse) != 2 {
		t.Fatalf("SelectDiverse = %v, want 2 routes", diverse)
	}
	if libraryOf(diverse[0]) == libraryOf(diverse[1]) {
		t.Fatalf("SelectDiverse = %v, want two different library paths", diverse)
	}
	if !slices.ContainsFunc(diverse, func(r []string) bool { return slices.Contains(r, "y1") }) {
		t.Fatalf("SelectDiverse = %v, want the route through y1", diverse)
	}
}

// With the scan cut short the route through y is never examined; the plain
// fill still spends the budget.
func TestSelectDiverseScanIsBounded(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{}
	top := layeredFanIn(callers, "sink", "n", 4, 9) // 4^9 routes per terminal
	terminals := map[string]bool{}
	for _, n := range top {
		terminals[n] = true
	}
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return terminals[n] },
	}
	reach := Reach("sink", opts)
	condensed := Condense(reach, opts.Less)

	const limit = 50
	calls := 0
	same := func([]string) string { calls++; return "one class" }
	got := SelectDiverse(reach, condensed, 8, opts.Less, same, limit)

	if len(got) != 8 {
		t.Fatalf("got %d routes, want the budget of 8 filled", len(got))
	}
	// The terminal routes are classified once each; the scan adds at most limit.
	if calls <= len(top) {
		t.Fatalf("class called %d times, want the scan to examine routes beyond the %d terminals", calls, len(top))
	}
	if max := len(top) + limit; calls > max {
		t.Fatalf("class called %d times, want at most %d", calls, max)
	}
	if DiverseScanLimit(4) < 1024 || DiverseScanLimit(32) != 4096 {
		t.Fatalf("DiverseScanLimit = %d, %d, want floor 1024 and 128 per chain", DiverseScanLimit(4), DiverseScanLimit(32))
	}
}
