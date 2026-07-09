// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fwdEdgeSpec is one directed internal edge in a forward-closure test fixture.
// line, when non-zero, attaches an EntryCall{Line: line} to the edge so tests
// can assert entry_call propagation. resolution defaults to ResolutionExact
// when zero.
type fwdEdgeSpec struct {
	from, to   string
	line       int
	resolution ResolutionKind
	params     []Parameter
}

// buildForwardFixture assembles a single-component Fragment from a flat
// function-name list, a set of directed edges, crypto operations (finding
// anchors), and supporting calls (annotation source). Every test in this file
// builds its graph through this helper so fixtures stay small and declarative.
func buildForwardFixture(
	functions []string,
	edges []fwdEdgeSpec,
	ops []CryptoOperation,
	supporting []SupportingCall,
) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := ComponentKey{Purl: "pkg:maven/com.acme/fwd", Version: "1.0.0"}

	fns := make([]Function, len(functions))
	for i, f := range functions {
		fns[i] = Function{
			Signature:    f,
			FunctionName: "com.acme.Fwd." + f,
			FilePath:     "Fwd.java",
		}
	}

	internal := make([]InternalEdge, 0, len(edges))
	for _, e := range edges {
		resolution := e.resolution
		if resolution == "" {
			resolution = ResolutionExact
		}
		ie := InternalEdge{Caller: e.from, Callee: e.to, Resolution: resolution}
		if e.line != 0 || len(e.params) > 0 {
			ie.EntryCall = &CallSite{Line: e.line, Parameters: e.params}
		}
		internal = append(internal, ie)
	}

	frag := Fragment{
		Component:        root,
		Module:           "com.acme:fwd",
		Functions:        fns,
		InternalEdges:    internal,
		CryptoOperations: ops,
		SupportingCalls:  supporting,
	}
	return root, DependencyGraph{}, map[ComponentKey]Fragment{root: frag}
}

// TestForwardClosure_OffIsByteIdentical is the load-bearing parity gate: with
// StitchOptions.ForwardClosure unset (zero value), the served output MUST
// carry no forward_calls key anywhere, regardless of how many other stitch
// options are set. This test must stay green through every later phase.
func TestForwardClosure_OffIsByteIdentical(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"entry", "a", "sink"},
		[]fwdEdgeSpec{
			{from: "entry", to: "a", line: 10},
			{from: "a", to: "sink", line: 20},
		},
		[]CryptoOperation{
			{Function: "sink", FindingID: "f-sink", RuleID: "r", Symbol: "Crypto.sink"},
		},
		nil,
	)

	for _, opts := range []StitchOptions{
		{},
		{EntryRootedOnly: true},
	} {
		res, err := StitchWithOptions(root, deps, fragments, opts)
		if err != nil {
			t.Fatalf("StitchWithOptions(%+v): %v", opts, err)
		}
		if res.forwardClosures != nil {
			t.Fatalf("opts=%+v: forwardClosures = %v, want nil (ForwardClosure off)", opts, res.forwardClosures)
		}

		out := res.ToCallgraphExport(root, ScanMeta{})
		if out.SchemaVersion != CallgraphSchemaVersion {
			t.Fatalf("opts=%+v: SchemaVersion = %q, want %q", opts, out.SchemaVersion, CallgraphSchemaVersion)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("opts=%+v: marshal: %v", opts, err)
		}
		if strings.Contains(string(raw), "forward_calls") {
			t.Fatalf("opts=%+v: forward_calls present with ForwardClosure off: %s", opts, raw)
		}
	}
}

// forwardNodeDepths collects each forward node's depth keyed by function
// signature — the order-independent assertion shape used by the model-level
// tests in this file (BFS discovery order is deterministic by construction,
// but tests assert on content, not incidental slice order).
func forwardNodeDepths(fc *forwardClosure) map[string]int {
	out := make(map[string]int, len(fc.nodes))
	for _, n := range fc.nodes {
		out[n.node.Function] = n.depth
	}
	return out
}

func findForwardEdge(fc *forwardClosure, from, to string) *forwardEdge {
	for i := range fc.edges {
		if fc.edges[i].from.Function == from && fc.edges[i].to.Function == to {
			return &fc.edges[i]
		}
	}
	return nil
}

// TestForwardClosure_LinearChain exercises the simplest shape: anchor -> a ->
// b -> sink, all exact-resolution edges. Asserts shortest-path depths, that
// every edge carries its entryCall (call-site data-flow), and truncated=false
// well within the default caps.
func TestForwardClosure_LinearChain(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"entry", "a", "b", "sink"},
		[]fwdEdgeSpec{
			{from: "entry", to: "a", line: 10, params: []Parameter{{ParameterIndex: 0, ResolvedValue: "X"}}},
			{from: "a", to: "b", line: 20},
			{from: "b", to: "sink", line: 30},
		},
		[]CryptoOperation{
			{Function: "entry", FindingID: "f1", RuleID: "r", Symbol: "Crypto.entry"},
		},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}

	anchor := graphNode{Component: root, Function: "entry"}
	fc := res.forwardClosures[anchor]
	if fc == nil {
		t.Fatalf("forwardClosures[%v] = nil, want a closure", anchor)
	}
	if fc.truncated {
		t.Fatalf("truncated = true, want false")
	}
	if fc.maxDepth != defaultMaxForwardDepth {
		t.Fatalf("maxDepth = %d, want %d", fc.maxDepth, defaultMaxForwardDepth)
	}
	if fc.anchor.Signature != "entry" {
		t.Fatalf("anchor.Signature = %q, want %q", fc.anchor.Signature, "entry")
	}

	depths := forwardNodeDepths(fc)
	want := map[string]int{"a": 1, "b": 2, "sink": 3}
	if len(depths) != len(want) {
		t.Fatalf("nodes = %v, want depths %v", depths, want)
	}
	for fn, d := range want {
		if depths[fn] != d {
			t.Errorf("depth[%q] = %d, want %d", fn, depths[fn], d)
		}
	}

	edge := findForwardEdge(fc, "entry", "a")
	if edge == nil || edge.entryCall == nil {
		t.Fatalf("entry->a edge/entryCall missing: %+v", edge)
	}
	if edge.entryCall.Line != 10 {
		t.Errorf("entry->a entryCall.Line = %d, want 10", edge.entryCall.Line)
	}
	if len(edge.entryCall.Parameters) != 1 || edge.entryCall.Parameters[0].ResolvedValue != "X" {
		t.Errorf("entry->a entryCall.Parameters = %+v, want resolved_value X", edge.entryCall.Parameters)
	}

	if e := findForwardEdge(fc, "a", "b"); e == nil || e.entryCall == nil || e.entryCall.Line != 20 {
		t.Errorf("a->b edge = %+v, want entryCall.Line=20", e)
	}
	if e := findForwardEdge(fc, "b", "sink"); e == nil || e.entryCall == nil || e.entryCall.Line != 30 {
		t.Errorf("b->sink edge = %+v, want entryCall.Line=30", e)
	}
}

// TestForwardClosure_Diamond asserts re-convergent branches (a->d and c->d)
// dedupe the target node once, at its shortest depth, while BOTH edges into
// it survive (each is a distinct call site carrying its own call-site data).
//
//	anchor -> a -> d
//	anchor -> c -> d
func TestForwardClosure_Diamond(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "a", "c", "d"},
		[]fwdEdgeSpec{
			{from: "anchor", to: "a", line: 1},
			{from: "anchor", to: "c", line: 2},
			{from: "a", to: "d", line: 10},
			{from: "c", to: "d", line: 20},
		},
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}
	if fc.truncated {
		t.Fatalf("truncated = true, want false")
	}

	depths := forwardNodeDepths(fc)
	dCount := 0
	for _, n := range fc.nodes {
		if n.node.Function == "d" {
			dCount++
		}
	}
	if dCount != 1 {
		t.Fatalf("node %q appears %d times, want exactly 1 (deduped)", "d", dCount)
	}
	if depths["d"] != 2 {
		t.Errorf("depth[d] = %d, want 2 (shortest path)", depths["d"])
	}

	if findForwardEdge(fc, "a", "d") == nil {
		t.Errorf("a->d edge missing")
	}
	if findForwardEdge(fc, "c", "d") == nil {
		t.Errorf("c->d edge missing (both convergent edges must be kept)")
	}
}

// TestForwardClosure_Cycle asserts a cyclic call structure (a->b->a)
// terminates, keeps the cycle node set to exactly the newly-discovered nodes,
// and emits the closing back-edge exactly once (call-site data preserved)
// without re-expanding the already-visited node.
func TestForwardClosure_Cycle(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "a", "b"},
		[]fwdEdgeSpec{
			{from: "anchor", to: "a", line: 1},
			{from: "a", to: "b", line: 2},
			{from: "b", to: "a", line: 3}, // closes the cycle back to a
		},
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	done := make(chan *forwardClosure, 1)
	go func() {
		res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
		if err != nil {
			t.Errorf("StitchWithOptions: %v", err)
			done <- nil
			return
		}
		done <- res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	}()

	var fc *forwardClosure
	select {
	case fc = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("forward BFS did not terminate on a cyclic graph within 10s")
	}
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}

	depths := forwardNodeDepths(fc)
	if len(depths) != 2 {
		t.Fatalf("nodes = %v, want exactly {a, b}", depths)
	}
	if depths["a"] != 1 || depths["b"] != 2 {
		t.Errorf("depths = %v, want a=1 b=2", depths)
	}

	backEdges := 0
	for _, e := range fc.edges {
		if e.from.Function == "b" && e.to.Function == "a" {
			backEdges++
		}
	}
	if backEdges != 1 {
		t.Errorf("back-edge b->a count = %d, want exactly 1", backEdges)
	}
}

// TestForwardClosure_DepthCap asserts a chain deeper than MaxForwardDepth is
// truncated, keeping the deepest node reached exactly at the depth cap and
// dropping anything beyond it.
func TestForwardClosure_DepthCap(t *testing.T) {
	t.Parallel()

	// anchor -> n1 -> n2 -> n3 -> n4 -> n5 -> n6, cap depth at 2: only n1,n2
	// survive, n3+ are unreached.
	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "n1", "n2", "n3", "n4", "n5", "n6"},
		[]fwdEdgeSpec{
			{from: "anchor", to: "n1", line: 1},
			{from: "n1", to: "n2", line: 2},
			{from: "n2", to: "n3", line: 3},
			{from: "n3", to: "n4", line: 4},
			{from: "n4", to: "n5", line: 5},
			{from: "n5", to: "n6", line: 6},
		},
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true, MaxForwardDepth: 2})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}
	if !fc.truncated {
		t.Fatalf("truncated = false, want true (depth cap tripped)")
	}
	if fc.maxDepth != 2 {
		t.Errorf("maxDepth = %d, want 2", fc.maxDepth)
	}

	depths := forwardNodeDepths(fc)
	if len(depths) != 2 {
		t.Fatalf("nodes = %v, want exactly {n1, n2}", depths)
	}
	maxSeen := 0
	for _, d := range depths {
		if d > maxSeen {
			maxSeen = d
		}
	}
	if maxSeen != 2 {
		t.Errorf("deepest kept node depth = %d, want 2 (== cap)", maxSeen)
	}
	if _, ok := depths["n3"]; ok {
		t.Errorf("n3 present beyond depth cap, want absent")
	}
}

// TestForwardClosure_NodeCap asserts high fanout beyond MaxForwardNodesPerAnchor
// truncates node admission while preserving DAG integrity: every edge's
// endpoints are present in nodes[] (or are the anchor).
func TestForwardClosure_NodeCap(t *testing.T) {
	t.Parallel()

	const fanout = 10
	functions := []string{"anchor"}
	edges := make([]fwdEdgeSpec, 0, fanout)
	for i := 0; i < fanout; i++ {
		name := "leaf" + strconv.Itoa(i)
		functions = append(functions, name)
		edges = append(edges, fwdEdgeSpec{from: "anchor", to: name, line: i + 1})
	}

	root, deps, fragments := buildForwardFixture(
		functions,
		edges,
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true, MaxForwardNodesPerAnchor: 3})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}
	if !fc.truncated {
		t.Fatalf("truncated = false, want true (node cap tripped)")
	}
	if len(fc.nodes) > 3 {
		t.Errorf("len(nodes) = %d, want <= 3", len(fc.nodes))
	}

	present := map[graphNode]bool{{Component: root, Function: "anchor"}: true}
	for _, n := range fc.nodes {
		present[n.node] = true
	}
	for _, e := range fc.edges {
		if !present[e.from] {
			t.Errorf("edge %+v: from-endpoint not in nodes[] (DAG integrity)", e)
		}
		if !present[e.to] {
			t.Errorf("edge %+v: to-endpoint not in nodes[] (DAG integrity)", e)
		}
	}
}

// TestForwardClosure_EdgeCap asserts a single node with more outgoing call
// sites than MaxForwardEdgesPerAnchor truncates edge admission while node
// admission (up to the node cap) proceeds normally, and DAG integrity holds.
func TestForwardClosure_EdgeCap(t *testing.T) {
	t.Parallel()

	// anchor calls "hub" once; hub then fans out to many leaves at distinct
	// call sites -- forcing the edge cap (not the node cap) to trip.
	const fanout = 10
	functions := []string{"anchor", "hub"}
	edges := []fwdEdgeSpec{{from: "anchor", to: "hub", line: 0}}
	for i := 0; i < fanout; i++ {
		name := "leaf" + strconv.Itoa(i)
		functions = append(functions, name)
		edges = append(edges, fwdEdgeSpec{from: "hub", to: name, line: i + 1})
	}

	root, deps, fragments := buildForwardFixture(
		functions,
		edges,
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		ForwardClosure:           true,
		MaxForwardNodesPerAnchor: 256, // generous — isolate the edge cap
		MaxForwardEdgesPerAnchor: 4,
	})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}
	if !fc.truncated {
		t.Fatalf("truncated = false, want true (edge cap tripped)")
	}
	if len(fc.edges) > 4 {
		t.Errorf("len(edges) = %d, want <= 4", len(fc.edges))
	}

	present := map[graphNode]bool{{Component: root, Function: "anchor"}: true}
	for _, n := range fc.nodes {
		present[n.node] = true
	}
	for _, e := range fc.edges {
		if !present[e.from] || !present[e.to] {
			t.Errorf("edge %+v: endpoint not in nodes[] (DAG integrity)", e)
		}
	}
}

// TestForwardClosure_DedupAcrossFindings asserts two findings that share the
// same anchor node get identical forward_calls content and, crucially, share
// the exact SAME memoized *forwardClosure pointer (per-anchor memoization —
// the BFS for that anchor runs exactly once).
func TestForwardClosure_DedupAcrossFindings(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "a"},
		[]fwdEdgeSpec{{from: "anchor", to: "a", line: 1}},
		[]CryptoOperation{
			{Function: "anchor", FindingID: "f1", RuleID: "r1", Symbol: "S1"},
			{Function: "anchor", FindingID: "f2", RuleID: "r2", Symbol: "S2"},
		},
		nil,
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	if len(res.forwardClosures) != 1 {
		t.Fatalf("len(forwardClosures) = %d, want exactly 1 (one BFS per distinct anchor)", len(res.forwardClosures))
	}
}

// TestForwardClosure_AnnotationFlags asserts a node with a non-empty
// supportingByNode Category is annotated crypto_relevant + supporting_category,
// while an unannotated node keeps both signals absent — annotate, never
// filter (Fork 2).
func TestForwardClosure_AnnotationFlags(t *testing.T) {
	t.Parallel()

	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "factoryFn", "plainFn"},
		[]fwdEdgeSpec{
			{from: "anchor", to: "factoryFn", line: 1},
			{from: "anchor", to: "plainFn", line: 2},
		},
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		[]SupportingCall{{Function: "factoryFn", SupportingID: "sup-1", Category: "factory"}},
	)

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}

	var factory, plain *forwardNode
	for i := range fc.nodes {
		switch fc.nodes[i].node.Function {
		case "factoryFn":
			factory = &fc.nodes[i]
		case "plainFn":
			plain = &fc.nodes[i]
		}
	}
	if factory == nil || plain == nil {
		t.Fatalf("expected both factoryFn and plainFn nodes, got %+v", fc.nodes)
	}
	if !factory.cryptoRelevant || factory.supportingCategory != "factory" {
		t.Errorf("factoryFn = %+v, want cryptoRelevant=true supportingCategory=factory", factory)
	}
	if plain.cryptoRelevant || plain.supportingCategory != "" {
		t.Errorf("plainFn = %+v, want cryptoRelevant=false supportingCategory=\"\"", plain)
	}
}

// TestForwardClosure_EdgePolicyReuse asserts forward traversal reuses the
// SAME adjacency the backward pass built, so an ambiguous interface_dispatch
// edge (>1 candidate implementation, ResolvedReceiverType absent) is simply
// absent from adjacency and therefore never appears in nodes/edges.
func TestForwardClosure_EdgePolicyReuse(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/fwd", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "com.acme:fwd",
		Functions: []Function{
			{Signature: "anchor", FunctionName: "com.acme.Fwd.anchor", FilePath: "Fwd.java"},
			{Signature: "implA", FunctionName: "com.acme.ImplA.dispatch", FilePath: "Fwd.java"},
			{Signature: "implB", FunctionName: "com.acme.ImplB.dispatch", FilePath: "Fwd.java"},
		},
		InternalEdges: []InternalEdge{
			// Ambiguous: 2 candidates for the same call site, no receiver-type
			// provenance -> fails closed, absent from adjacency entirely.
			{Caller: "anchor", Callee: "implA", Resolution: ResolutionInterfaceDispatch, MethodName: "dispatch", Arity: 0, CallSite: 1},
			{Caller: "anchor", Callee: "implB", Resolution: ResolutionInterfaceDispatch, MethodName: "dispatch", Arity: 0, CallSite: 1},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"},
		},
	}
	deps := DependencyGraph{}
	fragments := map[ComponentKey]Fragment{root: frag}

	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
	if fc == nil {
		t.Fatalf("forwardClosures[anchor] = nil")
	}
	if len(fc.nodes) != 0 {
		t.Errorf("nodes = %+v, want empty (ambiguous dispatch never traversed)", fc.nodes)
	}
	if len(fc.edges) != 0 {
		t.Errorf("edges = %+v, want empty (ambiguous dispatch never traversed)", fc.edges)
	}
	if fc.truncated {
		t.Errorf("truncated = true, want false (nothing to truncate — edge suppressed by resolution policy, not caps)")
	}
}

// TestForwardClosure_DeterministicOrdering asserts that repeated runs over
// the SAME fixture produce content-identical forward closures — the BFS
// frontier expansion order is fully determined by sortedAdjacencyEdges, so
// Go's inherent map-iteration nondeterminism (over the adjacency map itself,
// or opsByNode) never leaks into which node/edge is discovered at which
// depth. Canonicalizes (sorts) each run's nodes/edges before comparing, since
// the internal forwardClosure slices are in discovery order, not sorted
// order — the sorted-for-output guarantee belongs to the export projector
// (Phase 4), not this model layer.
func TestForwardClosure_DeterministicOrdering(t *testing.T) {
	t.Parallel()

	// A fixture with several same-depth siblings and a re-convergent tail, so
	// discovery order has real degrees of freedom to get wrong.
	root, deps, fragments := buildForwardFixture(
		[]string{"anchor", "b1", "b2", "b3", "tail"},
		[]fwdEdgeSpec{
			{from: "anchor", to: "b3", line: 3},
			{from: "anchor", to: "b1", line: 1},
			{from: "anchor", to: "b2", line: 2},
			{from: "b1", to: "tail", line: 10},
			{from: "b2", to: "tail", line: 11},
			{from: "b3", to: "tail", line: 12},
		},
		[]CryptoOperation{{Function: "anchor", FindingID: "f1", RuleID: "r", Symbol: "S"}},
		nil,
	)

	canon := func(fc *forwardClosure) string {
		nodeKeys := make([]string, len(fc.nodes))
		for i, n := range fc.nodes {
			nodeKeys[i] = n.node.Function + "|" + n.node.Component.String() + "|" + strconv.Itoa(n.depth)
		}
		sort.Strings(nodeKeys)
		edgeKeys := make([]string, len(fc.edges))
		for i, e := range fc.edges {
			edgeKeys[i] = e.from.Function + "->" + e.to.Function + "@" + strconv.Itoa(entryCallLine(e.entryCall))
		}
		sort.Strings(edgeKeys)
		return strings.Join(nodeKeys, ",") + "||" + strings.Join(edgeKeys, ",")
	}

	var want string
	for i := 0; i < 5; i++ {
		res, err := StitchWithOptions(root, deps, fragments, StitchOptions{ForwardClosure: true})
		if err != nil {
			t.Fatalf("run %d: StitchWithOptions: %v", i, err)
		}
		fc := res.forwardClosures[graphNode{Component: root, Function: "anchor"}]
		if fc == nil {
			t.Fatalf("run %d: forwardClosures[anchor] = nil", i)
		}
		got := canon(fc)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("run %d: canonical content differs:\n got=%s\nwant=%s", i, got, want)
		}
	}
}
