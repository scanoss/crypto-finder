// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/graphfrag/equiv"
)

// equivalence_corpus_test.go replays a REAL scanned corpus through the stitcher
// and diffs it against the live export of the same component.
//
// The existing equivalence tests build their graph from a source string, which
// keeps them fast but also small: they cannot reproduce what a dense library
// does to the traversal — hundreds of public entry functions converging on one
// chokepoint, retry cycles, dispatch fan-out. This one takes the two artifacts a
// real scan already produces and compares them:
//
//	crypto-finder scan --export-callgraph      live.json
//	crypto-finder scan --export-graph-fragment fragment.json
//
// then stitches the fragment in-process and diffs the result against the live
// export. No scanner run is needed at test time, so any corpus that has been
// scanned once can be replayed here.
//
// What it asserts is referential integrity, not chain-set equality — see the
// comment at the assertion for why the latter cannot hold while the stitcher
// fails closed on ambiguous dispatch. The chain and entry-point counts are
// logged so a divergence is visible as numbers.
//
// Gated because it needs those artifacts:
//
//	CRYPTO_FINDER_EQUIV_LIVE=live.json \
//	CRYPTO_FINDER_EQUIV_FRAGMENT=fragment.json \
//	CRYPTO_FINDER_EQUIV_PURL=pkg:maven/redis.clients/jedis \
//	CRYPTO_FINDER_EQUIV_VERSION=5.1.0 \
//	  go test -run TestEquivalence_Corpus_StitchReferentialIntegrity ./internal/scan/
func TestEquivalence_Corpus_StitchReferentialIntegrity(t *testing.T) {
	livePath := os.Getenv("CRYPTO_FINDER_EQUIV_LIVE")
	fragPath := os.Getenv("CRYPTO_FINDER_EQUIV_FRAGMENT")
	if livePath == "" || fragPath == "" {
		t.Skip("set CRYPTO_FINDER_EQUIV_LIVE and CRYPTO_FINDER_EQUIV_FRAGMENT to replay a scanned corpus")
	}

	purl := os.Getenv("CRYPTO_FINDER_EQUIV_PURL")
	if purl == "" {
		purl = "pkg:maven/com.app/app"
	}
	key := graphfrag.ComponentKey{Purl: purl, Version: os.Getenv("CRYPTO_FINDER_EQUIV_VERSION")}

	liveRaw, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("read live export: %v", err)
	}
	fragRaw, err := os.ReadFile(fragPath)
	if err != nil {
		t.Fatalf("read fragment: %v", err)
	}

	frag, err := graphfrag.DecodeFragment(key, fragRaw)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	t.Logf("fragment: %d functions, %d internal edges, %d crypto operations",
		len(frag.Functions), len(frag.InternalEdges), len(frag.CryptoOperations))

	res, err := graphfrag.StitchWithOptions(
		key,
		graphfrag.DependencyGraph{},
		map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag},
		// The serving path is the one under the parity contract.
		graphfrag.StitchOptions{EntryRootedOnly: true},
	)
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: frag.Module, Ecosystem: "java"})

	live := decodeEquivRaw(t, liveRaw)
	report := equiv.Compare(live, decodeEquiv(t, stitched), res.Suppressed, equiv.Options{})

	t.Logf("suppressed edges at stitch time: %d", len(res.Suppressed))
	t.Logf("live:     %d finding graphs, %d entry points, %d chains",
		len(live.FindingGraphs), len(live.CryptoEntryPoints), countEquivChains(live))
	t.Logf("stitched: %d finding graphs, %d entry points, %d chains",
		len(stitched.FindingGraphs), len(stitched.CryptoEntryPoints), countEquivChains(decodeEquiv(t, stitched)))

	// Chain-set equality is NOT asserted here, and that is the point of running
	// this against a real corpus rather than a fixture: the stitcher fails closed
	// on ambiguous dispatch, so it walks a strictly smaller edge set than the
	// live in-memory graph — 5,740 edges smaller on the jedis sample. Two
	// different graphs cannot yield the same chains no matter how either side
	// traverses them, so asserting it would be asserting something false. The
	// counts are reported instead.
	t.Logf("chain-set difference: %d only in live, %d only in stitched, %d node field mismatches",
		len(report.MissingInB), len(report.ExtraInB), len(report.NodeFieldMismatches))

	// Referential integrity, however, must hold on any corpus: an entry point
	// that names a finding or a supporting call the export does not contain is a
	// dangling reference the served API would hand a consumer.
	if len(report.EntryPointDivergences) != 0 {
		t.Errorf("crypto_entry_points reference something absent from the export: %v", report.EntryPointDivergences)
	}
	if len(report.SupportingCallIDDivergences) != 0 {
		t.Errorf("supporting_call_ids foreign key broken: %v", report.SupportingCallIDDivergences)
	}
}

// countEquivChains totals the call chains across a decoded export.
func countEquivChains(e equiv.CallgraphExportJSON) int {
	n := 0
	for i := range e.FindingGraphs {
		n += len(e.FindingGraphs[i].CallChains)
	}
	return n
}

// decodeEquivRaw decodes an already-marshaled export into the comparison shape.
func decodeEquivRaw(t *testing.T, raw []byte) equiv.CallgraphExportJSON {
	t.Helper()
	var out equiv.CallgraphExportJSON
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal live export into equiv shape: %v", err)
	}
	return out
}
