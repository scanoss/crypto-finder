// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphwalk

import (
	"sort"
	"strings"
	"testing"
)

// routeFixture is a diamond over a cycle: alpha and beta both call mid, and beta
// and gamma call each other. Both shapes are the ones that make a path-collecting
// walk lose branches, so they are the ones a single-route walk has to survive.
//
//	sink  <- mid <- alpha            (alpha has no callers: a graph root)
//	              <- beta  <-> gamma
func routeFixture() Options[string] {
	callers := map[string][]string{
		"sink":  {"mid"},
		"mid":   {"alpha", "beta"},
		"beta":  {"gamma"},
		"gamma": {"beta"},
	}
	return Options[string]{
		Callers:        func(n string) []string { return callers[n] },
		Less:           func(a, b string) bool { return a < b },
		RootIsTerminal: true,
	}
}

// assertRouteInvariants is the whole correctness argument, checked over every
// node a walk admitted: a route has Depth+1 frames, every consecutive pair is a
// real call edge, and it ends at the target.
func assertRouteInvariants(t *testing.T, r Reachable[string], opts Options[string]) {
	t.Helper()

	nodes := make([]string, 0, len(r.Depth))
	for n := range r.Depth {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	for _, n := range nodes {
		route := r.Route(n)
		if route == nil {
			t.Errorf("Route(%q) = nil, want a route: the node was reached at depth %d", n, r.Depth[n])
			continue
		}
		if got, want := len(route), r.Depth[n]+1; got != want {
			t.Errorf("Route(%q) has %d frames, want Depth+1 = %d: %v", n, got, want, route)
		}
		if route[0] != n {
			t.Errorf("Route(%q) starts at %q", n, route[0])
		}
		if last := route[len(route)-1]; last != r.Target {
			t.Errorf("Route(%q) ends at %q, want the target %q: %v", n, last, r.Target, route)
		}
		for i := 0; i+1 < len(route); i++ {
			caller, callee := route[i], route[i+1]
			var found bool
			for _, c := range opts.Callers(callee) {
				if c == caller {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Route(%q) step %d: %q does not call %q — not a real edge: %v",
					n, i, caller, callee, route)
			}
		}
	}
}

func TestReachRoute(t *testing.T) {
	t.Parallel()

	opts := routeFixture()
	r := Reach("sink", opts)

	assertRouteInvariants(t, r, opts)

	for _, tc := range []struct {
		node string
		want string
	}{
		{"sink", "sink"},
		{"mid", "mid,sink"},
		{"alpha", "alpha,mid,sink"},
		{"beta", "beta,mid,sink"},
		// gamma reaches the target only through the cycle partner.
		{"gamma", "gamma,beta,mid,sink"},
	} {
		if got := strings.Join(r.Route(tc.node), ","); got != tc.want {
			t.Errorf("Route(%q) = %q, want %q", tc.node, got, tc.want)
		}
	}
}

// TestReachRouteUnreached: a node the walk never admitted has no route. Returning
// a partial one would assert a reachability the walk did not establish.
func TestReachRouteUnreached(t *testing.T) {
	t.Parallel()

	r := Reach("sink", routeFixture())
	if route := r.Route("absent"); route != nil {
		t.Errorf("Route(absent) = %v, want nil", route)
	}
}

// TestReachRouteRespectsMaxDepth pins that a route cannot exceed the frame bound
// the walk was given, which is what keeps a stored route bounded.
func TestReachRouteRespectsMaxDepth(t *testing.T) {
	t.Parallel()

	opts := routeFixture()
	opts.MaxDepth = 3
	r := Reach("sink", opts)

	assertRouteInvariants(t, r, opts)

	if _, admitted := r.Depth["gamma"]; admitted {
		t.Errorf("gamma admitted at MaxDepth 3: its route needs 4 frames")
	}
	for n := range r.Depth {
		if got := len(r.Route(n)); got > opts.MaxDepth {
			t.Errorf("Route(%q) has %d frames, over MaxDepth %d", n, got, opts.MaxDepth)
		}
	}
}

// TestReachRouteBoundaryStops: a boundary node terminates a chain and is not
// expanded, so nothing behind it is reachable and nothing behind it gets a route.
func TestReachRouteBoundaryStops(t *testing.T) {
	t.Parallel()

	opts := routeFixture()
	opts.IsBoundary = func(n string) bool { return n == "mid" }
	r := Reach("sink", opts)

	assertRouteInvariants(t, r, opts)

	if !r.Terminal["mid"] {
		t.Error("mid is a boundary and must be a terminal")
	}
	for _, behind := range []string{"alpha", "beta", "gamma"} {
		if route := r.Route(behind); route != nil {
			t.Errorf("Route(%q) = %v, want nil: it sits behind a boundary", behind, route)
		}
	}
}

// TestReachRouteAdditive pins that adding Step left the answer alone: the fields
// consumers already read must not depend on it.
func TestReachRouteAdditive(t *testing.T) {
	t.Parallel()

	r := Reach("sink", routeFixture())

	wantDepth := map[string]int{"sink": 0, "mid": 1, "alpha": 2, "beta": 2, "gamma": 3}
	if len(r.Depth) != len(wantDepth) {
		t.Fatalf("Depth = %v, want %v", r.Depth, wantDepth)
	}
	for n, d := range wantDepth {
		if r.Depth[n] != d {
			t.Errorf("Depth[%q] = %d, want %d", n, r.Depth[n], d)
		}
	}
	if !r.Terminal["alpha"] {
		t.Error("alpha has no callers and must be a terminal")
	}
	if _, ok := r.Step[r.Target]; ok {
		t.Error("the target must carry no Step entry")
	}
}
