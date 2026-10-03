// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphwalk

import (
	"slices"
	"strings"
	"testing"
)

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

func TestRouteClassCollapsesConsecutiveGroups(t *testing.T) {
	t.Parallel()
	a := RouteClass([]string{"sink", "x1", "x2", "y1", "app"}, libraryOf)
	b := RouteClass([]string{"sink", "x3", "y2", "y3", "app"}, libraryOf)
	if a != b {
		t.Fatalf("RouteClass = %q and %q, want one class for sink>x>y>app", a, b)
	}
	if c := RouteClass([]string{"sink", "y1", "x1", "app"}, libraryOf); c == a {
		t.Fatalf("RouteClass = %q for sink>y>x>app, want it to differ from sink>x>y>app", c)
	}
}

// Every route a depth-first scan meets first goes through library x, a
// 4^6-route fan-in, while library y is reached by one longer route that the
// depth-first order reaches last. GroupRoutes builds the route through y
// directly from the graph, and finding it does not enumerate the fan-in.
func TestGroupRoutesReachesALibraryBehindAFanIn(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{}
	top := layeredFanIn(callers, "xsink", "x", 4, 6)
	// Longer than any route through x, so a per-terminal shortest route and
	// the depth-first fill both stay in x.
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

	for _, route := range Select(reach, condensed, 4, opts.Less) {
		if slices.Contains(route, "y1") {
			t.Fatalf("plain Select reached y: %v; the test needs it to stay in x", route)
		}
	}

	calls := 0
	group := func(n string) string { calls++; return libraryOf(n) }
	got := GroupRoutes(reach, opts.Less, group)

	classes := map[string][]string{}
	for _, route := range got {
		classes[RouteClass(route, libraryOf)] = route
	}
	wantY := append(append([]string{"sink"}, ys...), "app")
	if route := classes[RouteClass(wantY, libraryOf)]; !slices.Equal(route, wantY) {
		t.Fatalf("GroupRoutes = %v, want the route through y %v", got, wantY)
	}
	if len(got) > 4 {
		t.Fatalf("GroupRoutes = %d routes, want at most one per group (sink, x, y, app)", len(got))
	}
	// Grouping touches each reached node once, never once per route: the
	// fan-in holds 4^6 routes.
	if calls > len(reach.Depth) {
		t.Fatalf("group called %d times for %d nodes, want at most one call per node", calls, len(reach.Depth))
	}
	if again := GroupRoutes(reach, opts.Less, libraryOf); !slices.EqualFunc(again, got, slices.Equal) {
		t.Fatalf("second call = %v, want the same %v", again, got)
	}
}

// A route through a group's nearest node that would have to revisit a node
// is never returned: every route GroupRoutes builds is a simple path from the
// target to a terminal.
func TestGroupRoutesReturnsSimpleRoutesToATerminal(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{
		"sink": {"x1", "y1"},
		"x1":   {"y1", "app"},
		"y1":   {"app", "x1"},
	}
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return n == "app" },
	}
	reach := Reach("sink", opts)
	for _, route := range GroupRoutes(reach, opts.Less, libraryOf) {
		if route[0] != "sink" || !reach.Terminal[route[len(route)-1]] {
			t.Fatalf("route %v does not run from the target to a terminal", route)
		}
		seen := map[string]bool{}
		for _, n := range route {
			if seen[n] {
				t.Fatalf("route %v revisits %s", route, n)
			}
			seen[n] = true
		}
	}
}
