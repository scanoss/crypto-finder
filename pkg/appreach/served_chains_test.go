// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	core "github.com/scanoss/reach/appreach"
)

// servedChainsCallgraph is a stitched callgraph as Run holds it after
// hydration: finding-tls has five chains, the first with a frame the catalog
// could not name, finding-md5 one chain and no indexes.
func servedChainsCallgraph() CallgraphExport {
	named := func(sig string) ExportChainNode { return ExportChainNode{FunctionKey: sig, CanonicalSignature: sig} }
	catalog := make([]ExportInternedFunction, 1, 5)
	catalog[0] = ExportInternedFunction{FunctionKey: "blank"}
	chains := make([][]ExportChainNode, 1, 5)
	chains[0] = []ExportChainNode{{FunctionKey: "blank"}}
	indexes := make([][]int, 1, 5)
	indexes[0] = []int{0}
	for _, entry := range []string{"a.A.run(): void", "b.B.run(): void", "c.C.run(): void", "d.D.run(): void"} {
		catalog = append(catalog, ExportInternedFunction{FunctionKey: entry, FunctionName: entry, CanonicalSignature: entry})
		chains = append(chains, []ExportChainNode{named(entry), named("example.Socket.connect(): void")})
		indexes = append(indexes, []int{len(catalog) - 1, len(catalog) - 1})
	}
	return CallgraphExport{
		SchemaVersion: CallgraphInternedSchemaVersion,
		Functions:     catalog,
		FindingGraphs: []ExportFindingGraph{
			{FindingID: "finding-tls", CallChains: chains, CallChainIndexes: indexes, Reachability: "reachable"},
			{FindingID: "finding-md5", CallChains: [][]ExportChainNode{{named("example.Other.run(): void")}}, Reachability: "reachable"},
		},
	}
}

func renderServed(t *testing.T, cg CallgraphExport, maxChains int) (string, error) {
	t.Helper()
	raw, err := json.Marshal(cg)
	if err != nil {
		t.Fatal(err)
	}
	block, _, err := ComponentBlock(ComponentInput{
		Purl: "pkg:maven/x/y", Findings: []byte(filterFindings), Callgraph: raw,
		IncludeCallChains: true, MaxChainsPerAsset: maxChains,
	})
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), nil
}

// Trimming to the served chains renders exactly what the whole callgraph
// renders, for any chain budget.
func TestKeepServedChainsRendersTheSameBlock(t *testing.T) {
	t.Parallel()
	for _, maxChains := range []int{0, 1, 2, 4, 5, 200} {
		whole, err := renderServed(t, servedChainsCallgraph(), maxChains)
		if err != nil {
			t.Fatal(err)
		}
		cg := servedChainsCallgraph()
		core.KeepServedChains(cg.FindingGraphs, resolveMaxChains(maxChains))
		trimmed, err := renderServed(t, cg, maxChains)
		if err != nil {
			t.Fatal(err)
		}
		if trimmed != whole {
			t.Fatalf("max %d: trimmed block\n%s\nwant\n%s", maxChains, trimmed, whole)
		}
		if n, want := len(cg.FindingGraphs[0].CallChains), min(resolveMaxChains(maxChains), 4); n != want {
			t.Fatalf("max %d: kept %d chains, want %d", maxChains, n, want)
		}
		if !strings.Contains(trimmed, "a.A.run") {
			t.Fatalf("max %d: the first named chain is not served: %s", maxChains, trimmed)
		}
	}
}

// The kept chains keep their own indexes.
func TestKeepServedChainsKeepsIndexesInStep(t *testing.T) {
	t.Parallel()
	cg := servedChainsCallgraph()
	core.KeepServedChains(cg.FindingGraphs, 2)
	if got, want := cg.FindingGraphs[0].CallChainIndexes, [][]int{{1, 1}, {2, 2}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes = %v, want %v", got, want)
	}
}

// A nameless frame without indexes is corruption the renderer refuses; the
// trim leaves it for the renderer to see.
func TestKeepServedChainsLeavesUnindexedNamelessFrames(t *testing.T) {
	t.Parallel()
	cg := servedChainsCallgraph()
	cg.FindingGraphs[0].CallChainIndexes = nil
	core.KeepServedChains(cg.FindingGraphs, 1)
	if len(cg.FindingGraphs[0].CallChains) != 5 {
		t.Fatalf("kept %d chains, want all 5", len(cg.FindingGraphs[0].CallChains))
	}
	if _, err := renderServed(t, cg, 1); err == nil {
		t.Fatal("render accepted a nameless frame without indexes")
	}
}
