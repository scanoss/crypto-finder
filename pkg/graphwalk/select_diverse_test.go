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

func libraryOf(n string) string {
	switch {
	case strings.HasPrefix(n, "x"):
		return "x"
	case strings.HasPrefix(n, "y"):
		return "y"
	case n == "sink":
		return "sink"
	}
	return "app"
}

func classOf(route []string) string { return routeClass(route, libraryOf) }

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
	if nilGroup := SelectDiverse(reach, condensed, 2, less, nil); !slices.EqualFunc(nilGroup, plain, slices.Equal) {
		t.Fatalf("SelectDiverse with nil group = %v, want Select's %v", nilGroup, plain)
	}

	diverse := SelectDiverse(reach, condensed, 2, less, libraryOf)
	if len(diverse) != 2 {
		t.Fatalf("SelectDiverse = %v, want 2 routes", diverse)
	}
	if classOf(diverse[0]) == classOf(diverse[1]) {
		t.Fatalf("SelectDiverse = %v, want two different library paths", diverse)
	}
	if !slices.ContainsFunc(diverse, func(r []string) bool { return slices.Contains(r, "y1") }) {
		t.Fatalf("SelectDiverse = %v, want the route through y1", diverse)
	}
}

// The real failure of a depth-first scan: every route it meets first goes
// through library x, a 4^6-route fan-in, while library y is reached by one
// longer route the depth-first order reaches last. The route through y is built
// directly from the graph, and finding it does not enumerate the fan-in.
func TestSelectDiverseReachesALibraryBehindAFanIn(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{}
	top := layeredFanIn(callers, "xsink", "x", 4, 6)
	// Longer than any route through x, so the one-route-per-terminal step
	// picks x as well.
	callers["sink"] = []string{"xsink", "y1"}
	ys := []string{"y1", "y2", "y3", "y4", "y5", "y6", "y7", "y8"}
	for i := 0; i+1 < len(ys); i++ {
		callers[ys[i]] = []string{ys[i+1]}
	}
	callers["y8"] = []string{"app"}
	for _, n := range top {
		callers[n] = []string{"app"}
	}
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return n == "app" },
	}
	reach := Reach("sink", opts)
	condensed := Condense(reach, opts.Less)

	plain := Select(reach, condensed, 4, opts.Less)
	for _, route := range plain {
		if slices.Contains(route, "y1") {
			t.Fatalf("plain Select = %v, want the depth-first fill to stay in library x", plain)
		}
	}

	calls := 0
	group := func(n string) string { calls++; return libraryOf(n) }
	got := SelectDiverse(reach, condensed, 4, opts.Less, group)
	if len(got) != 4 {
		t.Fatalf("got %d routes, want the budget of 4 filled", len(got))
	}
	var throughY []string
	for _, route := range got {
		if slices.Contains(route, "y1") {
			throughY = route
		}
	}
	if want := append(append([]string{"sink"}, ys...), "app"); !slices.Equal(throughY, want) {
		t.Fatalf("route through y = %v, want %v", throughY, want)
	}
	// Grouping touches each reached node a bounded number of times, never once
	// per route: the fan-in holds 4^6 routes.
	if limit := 8 * len(reach.Depth); calls > limit {
		t.Fatalf("group called %d times for %d nodes, want at most %d", calls, len(reach.Depth), limit)
	}
	if again := SelectDiverse(reach, condensed, 4, opts.Less, libraryOf); !slices.EqualFunc(again, got, slices.Equal) {
		t.Fatalf("second selection = %v, want the same %v", again, got)
	}
}
