// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestStitchDropsOperationOnlyEntryPoints asserts that a role:operation
// crypto_entry_point carried on a stored fragment is not appended to the served
// crypto_entry_points when no reachable finding exists for that function.
func TestStitchDropsOperationOnlyEntryPoints(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/lib", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "com.acme:lib",
		Functions: []Function{
			{Signature: "com.acme.(Engine).processBlock#4", FunctionName: "com.acme.Engine.processBlock"},
		},
		CryptoEntryPoints: []CryptoEntryPoint{{
			FunctionKey:  "com.acme.(Engine).processBlock#4",
			FunctionName: "com.acme.Engine.processBlock",
			MethodRole:   "operation",
			RoleProvenance: &RoleProvenance{
				Kind:           "contract-operation",
				ContractMethod: "com.acme.Engine.processBlock",
				Inherited:      &InheritedRole{AlgorithmFamily: "AES", Primitive: "block-cipher"},
			},
		}},
	}
	fragments := map[ComponentKey]Fragment{root: frag}

	result, err := StitchWithOptions(root, DependencyGraph{root: nil}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	export := result.ToCallgraphExport(root, ScanMeta{})

	if ep := findExportEntryPointByFunctionKey(export.CryptoEntryPoints, "com.acme.(Engine).processBlock#4"); ep != nil {
		t.Fatalf("operation-only entry point was appended: %+v", ep)
	}
}

// TestStitchEnrichesExistingEntryPointWithRoles asserts that when a
// reachability-projected entry point and a fragment operation-entry share a
// function_key, the served entry is ENRICHED with role fields rather than
// duplicated.
func TestStitchEnrichesExistingEntryPointWithRoles(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/lib", Version: "1.0.0"}
	// A reachable finding whose terminal is the same function that also carries
	// an operation role, so the rebuilt entry point already exists by key.
	frag := Fragment{
		Component: root,
		Module:    "com.acme:lib",
		Functions: []Function{
			{Signature: "com.acme.(Digest).doFinal#2", FunctionName: "com.acme.Digest.doFinal"},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "com.acme.(Digest).doFinal#2", FindingID: "f-digest", RuleID: "r", Symbol: "Digest.doFinal", FilePath: "Digest.java", StartLine: 10},
		},
		CryptoEntryPoints: []CryptoEntryPoint{
			{
				FunctionKey:    "com.acme.(Digest).doFinal#2",
				FunctionName:   "com.acme.Digest.doFinal",
				MethodRole:     "operation",
				RoleProvenance: &RoleProvenance{Kind: "contract-operation"},
			},
		},
	}
	fragments := map[ComponentKey]Fragment{root: frag}

	result, err := StitchWithOptions(root, DependencyGraph{root: nil}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	export := result.ToCallgraphExport(root, ScanMeta{})

	matches := 0
	for i := range export.CryptoEntryPoints {
		if export.CryptoEntryPoints[i].FunctionKey == "com.acme.(Digest).doFinal#2" {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("expected exactly one entry point for the shared key (enrich, not duplicate); got %d", matches)
	}
	ep := findExportEntryPointByFunctionKey(export.CryptoEntryPoints, "com.acme.(Digest).doFinal#2")
	if ep.MethodRole != "operation" {
		t.Errorf("existing entry point not enriched with method_role: %+v", ep)
	}
}
