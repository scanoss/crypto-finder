// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestStitchCarriesOperationEntryPointsToServed asserts that a role:operation
// crypto_entry_point carried on a stored fragment (WU2) survives the stitch →
// ToCallgraphExport round trip and appears in the SERVED crypto_entry_points,
// even though it has no reachable finding (the served path otherwise rebuilds
// crypto_entry_points purely from finding chains and would drop it).
func TestStitchCarriesOperationEntryPointsToServed(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/lib", Version: "1.0.0"}
	frag := Fragment{
		Component: root,
		Module:    "com.acme:lib",
		Functions: []Function{
			{Signature: "com.acme.(Engine).processBlock#4", FunctionName: "com.acme.Engine.processBlock"},
		},
		CryptoEntryPoints: []CryptoEntryPoint{
			{
				FunctionKey:  "com.acme.(Engine).processBlock#4",
				FunctionName: "com.acme.Engine.processBlock",
				MethodRole:   "operation",
				RoleProvenance: &RoleProvenance{
					Kind:           "contract-operation",
					ContractMethod: "com.acme.Engine.processBlock",
					Inherited:      &InheritedRole{AlgorithmFamily: "AES", Primitive: "block-cipher"},
				},
				ParameterRoles: []ParameterRole{
					{Index: 0, Role: "metadata-contributing", Contributes: &Contribution{Property: "keySize", Derivation: "argument_bit_length"}},
				},
			},
		},
	}
	fragments := map[ComponentKey]Fragment{root: frag}

	result, err := StitchWithOptions(root, DependencyGraph{root: nil}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("StitchWithOptions: %v", err)
	}
	export := result.ToCallgraphExport(root, ScanMeta{})

	ep := findExportEntryPointByFunctionKey(export.CryptoEntryPoints, "com.acme.(Engine).processBlock#4")
	if ep == nil {
		t.Fatalf("role:operation entry point missing from served crypto_entry_points: %+v", export.CryptoEntryPoints)
	}
	if ep.MethodRole != "operation" {
		t.Errorf("method_role = %q, want operation", ep.MethodRole)
	}
	// Class/Method must be derived (matching the live exporter), not left blank
	// on an appended catalog entry.
	if ep.Class != "com.acme.Engine" || ep.Method != "processBlock" {
		t.Errorf("class/method = %q/%q, want com.acme.Engine/processBlock", ep.Class, ep.Method)
	}
	if ep.RoleProvenance == nil || ep.RoleProvenance.Inherited == nil || ep.RoleProvenance.Inherited.AlgorithmFamily != "AES" {
		t.Errorf("role_provenance not carried through: %+v", ep.RoleProvenance)
	}
	if len(ep.ParameterRoles) != 1 || ep.ParameterRoles[0].Contributes == nil ||
		ep.ParameterRoles[0].Contributes.Derivation != "argument_bit_length" {
		t.Errorf("parameter_roles not carried through: %+v", ep.ParameterRoles)
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
