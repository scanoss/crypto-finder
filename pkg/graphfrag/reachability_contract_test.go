// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

func TestDecodeFragment13_CarriesEntryPointsSupportingCallsAndAliases(t *testing.T) {
	t.Parallel()

	const fragment13JSON = `{
	  "schema_version": "graph-fragment-1.3",
	  "scan_metadata": {
	    "ecosystem": "java",
	    "root_module": "com.acme:crypto-lib"
	  },
	  "functions": [
	    {
	      "key": "com.acme.(Factory).<init>#0",
	      "function_name": "com.acme.Factory.<init>",
	      "canonical_signature": "com.acme.Factory.<init>(): Factory",
	      "display_symbol": "com.acme.Factory.Factory",
	      "aliases": ["com.acme.Factory.Factory"],
	      "file_path": "Factory.java",
	      "start_line": 3
	    }
	  ],
	  "supporting_calls": [
	    {
	      "supporting_id": "support-1",
	      "function_key": "com.acme.(Factory).<init>#0",
	      "category": "config",
	      "matched_operation": {
	        "kind": "call",
	        "symbol": "com.password4j.HashBuilder.<init>",
	        "line": 4
	      }
	    }
	  ],
	  "crypto_entry_points": [
	    {
	      "function_key": "com.acme.(Factory).<init>#0",
	      "function_name": "com.acme.Factory.<init>",
	      "canonical_signature": "com.acme.Factory.<init>(): Factory",
	      "display_symbol": "com.acme.Factory.Factory",
	      "aliases": ["com.acme.Factory.Factory"],
	      "reachable_findings": [
	        { "finding_id": "finding-1", "chain_depth": 2, "finding_graph_ref": "finding-1" }
	      ],
	      "reachable_supporting_calls": [
	        { "supporting_id": "support-1", "chain_depth": 1 }
	      ]
	    }
	  ]
	}`

	fragment, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/com.acme/crypto-lib", Version: "1.0.0"}, []byte(fragment13JSON))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if len(fragment.Functions) != 1 {
		t.Fatalf("Functions len = %d, want 1", len(fragment.Functions))
	}
	fn := fragment.Functions[0]
	if fn.DisplaySymbol != "com.acme.Factory.Factory" {
		t.Fatalf("Function.DisplaySymbol = %q, want constructor alias", fn.DisplaySymbol)
	}
	if len(fn.Aliases) != 1 || fn.Aliases[0] != "com.acme.Factory.Factory" {
		t.Fatalf("Function.Aliases = %#v, want constructor alias", fn.Aliases)
	}

	if len(fragment.SupportingCalls) != 1 {
		t.Fatalf("SupportingCalls len = %d, want 1", len(fragment.SupportingCalls))
	}
	if fragment.SupportingCalls[0].Category != "config" {
		t.Fatalf("SupportingCalls[0].Category = %q, want config", fragment.SupportingCalls[0].Category)
	}

	if len(fragment.CryptoEntryPoints) != 1 {
		t.Fatalf("CryptoEntryPoints len = %d, want 1", len(fragment.CryptoEntryPoints))
	}
	entry := fragment.CryptoEntryPoints[0]
	if entry.DisplaySymbol != "com.acme.Factory.Factory" {
		t.Fatalf("CryptoEntryPoint.DisplaySymbol = %q, want constructor alias", entry.DisplaySymbol)
	}
	if len(entry.ReachableFindings) != 1 || entry.ReachableFindings[0].FindingID != "finding-1" {
		t.Fatalf("ReachableFindings = %#v, want finding-1", entry.ReachableFindings)
	}
	if len(entry.ReachableSupportingCalls) != 1 || entry.ReachableSupportingCalls[0].SupportingID != "support-1" {
		t.Fatalf("ReachableSupportingCalls = %#v, want support-1", entry.ReachableSupportingCalls)
	}
}

func TestToCallgraphExport_UsesCryptoEntryPointsNotEntryPointIndex(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	res := &Result{
		Chains: []FindingChain{{
			FindingID: "finding-1",
			RuleID:    "java.crypto",
			Symbol:    "javax.crypto.Cipher.getInstance",
			Frames: []CallFrame{
				{
					Component: root,
					Signature: "com.acme.(App).entry#0",
					Function: Function{
						Signature:          "com.acme.(App).entry#0",
						FunctionName:       "com.acme.App.entry",
						CanonicalSignature: "com.acme.App.entry(): void",
						FilePath:           "App.java",
						StartLine:          3,
					},
					Module: "com.acme:app",
				},
			},
			CryptoOp: &CryptoOperation{
				Function:  "com.acme.(App).entry#0",
				FindingID: "finding-1",
				RuleID:    "java.crypto",
				FilePath:  "App.java",
				StartLine: 4,
				MatchedOperation: &MatchedOp{
					Kind:   "call",
					Symbol: "javax.crypto.Cipher.getInstance",
				},
			},
		}},
		SupportingCalls: []SupportingCall{{
			SupportingID: "support-1",
			Function:     "com.acme.(App).entry#0",
			Category:     "config",
			MatchedOperation: &MatchedOp{
				Kind:   "call",
				Symbol: "com.password4j.HashBuilder.withPepper",
			},
		}},
	}

	out := res.ToCallgraphExport(root, ScanMeta{SchemaVersion: "6.0", RootModule: "com.acme:app", Ecosystem: "java"})

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if _, ok := decoded["entry_point_index"]; ok {
		t.Fatal("entry_point_index must not be emitted by schema 6.0 graphfrag projection")
	}
	if _, ok := decoded["crypto_entry_points"]; !ok {
		t.Fatal("crypto_entry_points missing from schema 6.0 graphfrag projection")
	}
	if len(out.CryptoEntryPoints) != 1 {
		t.Fatalf("CryptoEntryPoints len = %d, want 1", len(out.CryptoEntryPoints))
	}
	if len(out.CryptoEntryPoints[0].ReachableSupportingCalls) != 1 {
		t.Fatalf("ReachableSupportingCalls = %#v, want support-1", out.CryptoEntryPoints[0].ReachableSupportingCalls)
	}
	if len(out.SupportingCalls) != 1 || out.SupportingCalls[0].SupportingID != "support-1" {
		t.Fatalf("SupportingCalls = %#v, want support-1", out.SupportingCalls)
	}
}

func TestConstructorDisplayFromSymbol(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		symbol string
		want   string
	}{
		{"constructor", "org.bouncycastle.crypto.params.AEADParameters.<init>", "org.bouncycastle.crypto.params.AEADParameters.AEADParameters"},
		{"platform constructor", "java.security.SecureRandom.<init>", "java.security.SecureRandom.SecureRandom"},
		{"inner class", "com.acme.Outer.Inner.<init>", "com.acme.Outer.Inner.Inner"},
		{"not a constructor", "org.bouncycastle.crypto.engines.AESEngine.processBytes", ""},
		{"plain method", "javax.crypto.Cipher.getInstance", ""},
		{"empty", "", ""},
		{"fluent chain prefix", "Jwts.builder().setId(id).<init>", ""},
		{"arity marker prefix", "com.acme.Factory.<init>#0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ConstructorDisplayFromSymbol(tc.symbol); got != tc.want {
				t.Fatalf("ConstructorDisplayFromSymbol(%q) = %q, want %q", tc.symbol, got, tc.want)
			}
		})
	}
}

func TestToCallgraphExport_MatchedOperationCarriesConstructorDisplaySymbol(t *testing.T) {
	t.Parallel()

	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	res := &Result{
		Chains: []FindingChain{{
			FindingID: "finding-1",
			RuleID:    "java.crypto",
			Symbol:    "org.bouncycastle.crypto.modes.GCMBlockCipher.<init>",
			Frames: []CallFrame{{
				Component: root,
				Signature: "com.acme.(App).entry#0",
				Function: Function{
					Signature:          "com.acme.(App).entry#0",
					FunctionName:       "com.acme.App.entry",
					CanonicalSignature: "com.acme.App.entry(): void",
					FilePath:           "App.java",
					StartLine:          3,
				},
				Module: "com.acme:app",
			}},
			CryptoOp: &CryptoOperation{
				Function:  "com.acme.(App).entry#0",
				FindingID: "finding-1",
				RuleID:    "java.crypto",
				FilePath:  "App.java",
				StartLine: 4,
				MatchedOperation: &MatchedOp{
					Kind:   "call",
					Symbol: "org.bouncycastle.crypto.modes.GCMBlockCipher.<init>",
				},
			},
		}},
	}

	out := res.ToCallgraphExport(root, ScanMeta{RootModule: "com.acme:app", Ecosystem: "java"})
	if len(out.FindingGraphs) != 1 || out.FindingGraphs[0].MatchedOperation == nil {
		t.Fatalf("FindingGraphs = %#v, want one with a matched operation", out.FindingGraphs)
	}
	const want = "org.bouncycastle.crypto.modes.GCMBlockCipher.GCMBlockCipher"
	if got := out.FindingGraphs[0].MatchedOperation.DisplaySymbol; got != want {
		t.Fatalf("matched_operation.display_symbol = %q, want %q", got, want)
	}
}

func TestExportSourceNode_CallTargetDisplaySymbolForConstructor(t *testing.T) {
	t.Parallel()

	ctor := exportSourceNode(SourceNode{
		Type:       "CALL_RESULT",
		Value:      "new AEADParameters(keyParam, 128, iv)",
		CallTarget: "org.bouncycastle.crypto.params.AEADParameters.<init>",
	})
	const want = "org.bouncycastle.crypto.params.AEADParameters.AEADParameters"
	if ctor.CallTargetDisplaySymbol != want {
		t.Fatalf("CALL_RESULT call_target_display_symbol = %q, want %q", ctor.CallTargetDisplaySymbol, want)
	}

	plain := exportSourceNode(SourceNode{
		Type:       "CALL_RESULT",
		CallTarget: "org.bouncycastle.crypto.modes.GCMBlockCipher.processBytes",
	})
	if plain.CallTargetDisplaySymbol != "" {
		t.Fatalf("non-constructor call_target_display_symbol = %q, want empty", plain.CallTargetDisplaySymbol)
	}
}
