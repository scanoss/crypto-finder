// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package equiv

import "testing"

func TestCompare_CryptoEntryPointConsistency(t *testing.T) {
	t.Parallel()

	chain := []ExportChainNodeJSON{
		{FunctionName: "com.acme.App.entry", CanonicalSignature: "com.acme.App.entry(): void"},
		{FunctionName: "com.acme.Crypto.encrypt", CanonicalSignature: "com.acme.Crypto.encrypt(): void"},
	}
	a := CallgraphExportJSON{
		SchemaVersion: "6.0",
		FindingGraphs: []ExportFindingGraphJSON{{
			FindingID:  "finding-1",
			CallChains: [][]ExportChainNodeJSON{chain},
		}},
	}
	b := CallgraphExportJSON{
		SchemaVersion: "6.0",
		FindingGraphs: []ExportFindingGraphJSON{{
			FindingID:  "finding-1",
			CallChains: [][]ExportChainNodeJSON{chain},
		}},
		CryptoEntryPoints: []ExportCryptoEntryPointJSON{{
			FunctionKey:         "com.acme.App.entry(): void",
			FunctionName:        "com.acme.App.entry",
			CanonicalSignature:  "com.acme.App.entry(): void",
			ReachableFindings:   []ExportReachableFindingJSON{{FindingID: "finding-1", ChainDepth: 2}},
			ReachableSupporting: []ExportReachableSupportingCallJSON{{SupportingID: "support-1", ChainDepth: 1}},
		}},
		SupportingCalls: []ExportSupportingCallJSON{{
			SupportingID: "support-1",
			FunctionKey:  "com.acme.App.entry(): void",
		}},
	}

	report := Compare(a, b, nil, Options{})
	if len(report.EntryPointDivergences) != 0 {
		t.Fatalf("EntryPointDivergences = %#v, want none", report.EntryPointDivergences)
	}

	b.CryptoEntryPoints[0].ReachableFindings[0].FindingID = "phantom"
	report = Compare(a, b, nil, Options{})
	if len(report.EntryPointDivergences) == 0 {
		t.Fatal("expected divergence for crypto_entry_points reference to phantom finding")
	}
}

func TestCompare_CryptoEntryPointFunctionNameOnlyMatchesCanonicalChainNode(t *testing.T) {
	t.Parallel()

	chain := []ExportChainNodeJSON{{
		FunctionName:       "com.acme.App.entry",
		CanonicalSignature: "com.acme.App.entry(): void",
	}}
	graph := ExportFindingGraphJSON{
		FindingID:  "finding-1",
		CallChains: [][]ExportChainNodeJSON{chain},
	}
	a := CallgraphExportJSON{
		SchemaVersion: "6.0",
		FindingGraphs: []ExportFindingGraphJSON{graph},
	}
	b := CallgraphExportJSON{
		SchemaVersion: "6.0",
		FindingGraphs: []ExportFindingGraphJSON{graph},
		CryptoEntryPoints: []ExportCryptoEntryPointJSON{{
			FunctionName:      "com.acme.App.entry",
			ReachableFindings: []ExportReachableFindingJSON{{FindingID: "finding-1", ChainDepth: 1}},
		}},
	}

	report := Compare(a, b, nil, Options{})
	if len(report.EntryPointDivergences) != 0 {
		t.Fatalf("EntryPointDivergences = %#v, want none", report.EntryPointDivergences)
	}
}
