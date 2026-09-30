// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphwalk

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// layeredFanIn returns callers for width^depth routes from target up to the
// top layer, prefixing every node with name so two regions can share a graph.
func layeredFanIn(callers map[string][]string, target, name string, width, depth int) []string {
	prev := []string{target}
	var layer []string
	for d := 1; d <= depth; d++ {
		layer = make([]string, 0, width)
		for w := 0; w < width; w++ {
			layer = append(layer, fmt.Sprintf("%s-%02d-%d", name, d, w))
		}
		for _, callee := range prev {
			callers[callee] = append(callers[callee], layer...)
		}
		prev = layer
	}
	return layer
}

// TestRoutesSkipsDeadEndComponents: a budgeted walk must not spend its time in
// callers that never reach a terminal. The target has 16^8 (4.3 billion)
// dead-end routes, sorted first, and one live route through a boundary. Without
// pruning the walk enumerates every dead route before it finds the live one.
func TestRoutesSkipsDeadEndComponents(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{}
	layeredFanIn(callers, "sink", "a-dead", 16, 8)
	callers["sink"] = append(callers["sink"], "z-app")
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return n == "z-app" },
	}

	reach := Reach("sink", opts)
	condensed := Condense(reach, opts.Less)

	done := make(chan [][]string, 1)
	go func() { done <- Routes(reach, condensed, 4) }()
	var routes [][]string
	select {
	case routes = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Routes still running after 5s, want dead-end components skipped")
	}

	if len(routes) != 1 || len(routes[0]) != 2 || routes[0][1] != "z-app" {
		t.Fatalf("routes = %v, want the single live route sink <- z-app", routes)
	}
}

// TestCountSaturates: a 2^70 fan-in must report the ceiling, not a wrapped
// count that reads as a handful of routes or none.
func TestCountSaturates(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{}
	top := layeredFanIn(callers, "sink", "n", 2, 70)
	terminal := map[string]bool{}
	for _, n := range top {
		terminal[n] = true
	}
	opts := Options[string]{
		Callers:    func(n string) []string { return callers[n] },
		Less:       func(a, b string) bool { return a < b },
		IsBoundary: func(n string) bool { return terminal[n] },
	}

	reach := Reach("sink", opts)
	if got := Count(reach, Condense(reach, opts.Less)); got != math.MaxInt {
		t.Fatalf("Count = %d, want math.MaxInt for 2^70 routes", got)
	}
}
