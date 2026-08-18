// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

func TestResolvedKeyLength_SurvivesFragmentDecodeAndStitch(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/key-app", Version: "1.0.0"}
	bits := 256
	wire := GraphFragmentExport{
		SchemaVersion: SchemaVersion,
		Functions: []GraphFragmentFunction{{
			Key:      "com.acme.KeyFlow.configure(): void",
			FilePath: "KeyFlow.java",
		}},
		CryptoAnnotations: []GraphFragmentCryptoOp{{
			FunctionKey: "com.acme.KeyFlow.configure(): void",
			FindingID:   "keygen-init",
			RuleID:      "java.jca.keygenerator.init",
			CryptoCall: &GraphFragmentCryptoCall{
				FunctionName: "javax.crypto.KeyGenerator.init",
				Line:         5,
				ResolvedKeyLength: &ResolvedKeyLength{
					Bits:       &bits,
					Provenance: "constant",
					SourceCall: SourceCallRef{FunctionName: "javax.crypto.KeyGenerator.init", Line: 5, ParameterIndex: 0},
				},
			},
		}},
	}

	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	decoded, err := DecodeFragment(root, encoded)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	stitched, err := Stitch(root, DependencyGraph{}, map[ComponentKey]Fragment{root: decoded})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	out := stitched.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"})
	if len(out.FindingGraphs) != 1 || len(out.FindingGraphs[0].CallChains) != 1 {
		t.Fatalf("FindingGraphs = %#v, want one stitched finding chain", out.FindingGraphs)
	}
	got := out.FindingGraphs[0].CallChains[0][0].CryptoCall.ResolvedKeyLength
	if got == nil || got.Bits == nil || *got.Bits != 256 || got.Provenance != "constant" ||
		got.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" ||
		got.SourceCall.Line != 5 || got.SourceCall.ParameterIndex != 0 {
		t.Fatalf("ResolvedKeyLength = %#v, want literal KeyGenerator.init(256) reference", got)
	}
}
