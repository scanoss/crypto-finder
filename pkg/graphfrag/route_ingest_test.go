// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"strings"
	"testing"
)

// routeFragmentJSON is one entry point reaching one finding three calls away,
// with the route named as indexes into functions[].
const routeFragmentJSON = `{
	"schema_version": "graph-fragment-1.13",
	"scan_metadata": {"root_module": "org.example.client", "graph_algo_version": "graph-algo-2"},
	"functions": [
		{"key": "org.example.client.(Api).entry#0", "canonical_signature": "org.example.client.Api.entry(): void"},
		{"key": "org.example.client.(Api).mid#0",   "canonical_signature": "org.example.client.Api.mid(): void"},
		{"key": "org.example.client.(Ssl).init#0",  "canonical_signature": "org.example.client.Ssl.init(): void"}
	],
	"crypto_entry_points": [{
		"function_key": "org.example.client.(Api).entry#0",
		"canonical_signature": "org.example.client.Api.entry(): void",
		"reachable_findings": [
			{"finding_id": "aaaa1111", "chain_depth": 3, "route": [0, 1, 2], "finding_graph_ref": "aaaa1111"}
		]
	}]
}`

func ingestRouteFragment(t *testing.T, body string) Fragment {
	t.Helper()
	var export GraphFragmentExport
	if err := json.Unmarshal([]byte(body), &export); err != nil {
		t.Fatalf("unmarshal fragment: %v", err)
	}
	return export.ToFragment(ComponentKey{Purl: "pkg:maven/org.example/client", Version: "1.0.0"})
}

func onlyReachableFinding(t *testing.T, frag Fragment) ReachableFinding {
	t.Helper()
	if len(frag.CryptoEntryPoints) != 1 {
		t.Fatalf("entry points = %d, want 1", len(frag.CryptoEntryPoints))
	}
	rf := frag.CryptoEntryPoints[0].ReachableFindings
	if len(rf) != 1 {
		t.Fatalf("reachable findings = %d, want 1", len(rf))
	}
	return rf[0]
}

// TestIngestRouteResolvesIndexes: the wire form is indexes, the model is function
// keys, and the route's length is the depth the same record reports.
func TestIngestRouteResolvesIndexes(t *testing.T) {
	t.Parallel()

	rf := onlyReachableFinding(t, ingestRouteFragment(t, routeFragmentJSON))

	want := []string{
		"org.example.client.(Api).entry#0",
		"org.example.client.(Api).mid#0",
		"org.example.client.(Ssl).init#0",
	}
	if got := strings.Join(rf.Route, " -> "); got != strings.Join(want, " -> ") {
		t.Errorf("Route = %q, want %q", got, strings.Join(want, " -> "))
	}
	if len(rf.Route) != rf.ChainDepth {
		t.Errorf("route has %d frames, want ChainDepth = %d", len(rf.Route), rf.ChainDepth)
	}
	if rf.Route[0] != frag0Key {
		t.Errorf("route starts at %q, want the entry point %q", rf.Route[0], frag0Key)
	}
}

const frag0Key = "org.example.client.(Api).entry#0"

// TestIngestRouteAbsent: a fragment written before the field existed keeps
// working and simply reports no route, which is the pre-1.13 answer.
func TestIngestRouteAbsent(t *testing.T) {
	t.Parallel()

	body := strings.Replace(routeFragmentJSON, `, "route": [0, 1, 2]`, "", 1)
	rf := onlyReachableFinding(t, ingestRouteFragment(t, body))

	if rf.Route != nil {
		t.Errorf("Route = %v, want nil", rf.Route)
	}
	if rf.ChainDepth != 3 {
		t.Errorf("ChainDepth = %d, want 3: the depth is unaffected", rf.ChainDepth)
	}
}

// TestIngestRouteUnresolvableIndexDropsWholeRoute: a frame that cannot be
// resolved must not leave a hole. A route with a gap claims a call that is not
// in the graph, so the whole route goes and the depth stands alone.
func TestIngestRouteUnresolvableIndexDropsWholeRoute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		route string
	}{
		{"index past the end", `"route": [0, 1, 99]`},
		{"negative index", `"route": [0, -1, 2]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(routeFragmentJSON, `"route": [0, 1, 2]`, tc.route, 1)
			rf := onlyReachableFinding(t, ingestRouteFragment(t, body))
			if rf.Route != nil {
				t.Errorf("Route = %v, want nil: one frame was unresolvable", rf.Route)
			}
			if rf.ChainDepth != 3 {
				t.Errorf("ChainDepth = %d, want 3", rf.ChainDepth)
			}
		})
	}
}
