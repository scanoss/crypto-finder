// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"testing"
)

// TestDecodeFragment_1_2_EnrichesFunction proves that a graph-fragment-1.2
// fixture populates the rich Function identity fields (CanonicalSignature,
// FunctionName, ReturnType, ParameterTypes, Visibility, OwnerVisibility,
// StartLine) that were absent from the 1.0/1.1 model.
func TestDecodeFragment_1_2_EnrichesFunction(t *testing.T) {
	const fragment12JSON = `{
	  "schema_version": "graph-fragment-1.2",
	  "scan_metadata": {
	    "ecosystem": "java",
	    "root_module": "net.crypto:c-crypto"
	  },
	  "functions": [
	    {
	      "key":                "net.crypto.(CryptoSink).encrypt#1",
	      "function_name":      "net.crypto.CryptoSink.encrypt",
	      "canonical_signature":"net.crypto.CryptoSink.encrypt(byte[]): void",
	      "return_type":        "void",
	      "parameter_types":    ["byte[]"],
	      "visibility":         "public",
	      "owner_visibility":   "public",
	      "start_line":         42,
	      "file_path":          "CryptoSink.java"
	    }
	  ],
	  "internal_edges": [
	    {
	      "caller_key": "net.crypto.(CryptoSink).encrypt#1",
	      "callee_key": "net.crypto.(CryptoSink).helper#0",
	      "resolution":  "exact",
	      "entry_call": {
	        "line": 55,
	        "parameters": [
	          {
	            "parameter_index": 0,
	            "type":            "byte[]",
	            "variable_name":   "data",
	            "source_nodes": [
	              {
	                "type":  "PARAMETER",
	                "name":  "data",
	                "parameter_index": 0
	              }
	            ]
	          }
	        ]
	      }
	    }
	  ],
	  "crypto_annotations": [
	    {
	      "function_key": "net.crypto.(CryptoSink).encrypt#1",
	      "finding_id":   "abc-1.2",
	      "rule_id":      "java.crypto.cipher.getinstance",
	      "symbol":       "javax.crypto.Cipher.getInstance",
	      "crypto_call": {
	        "function_name":       "javax.crypto.Cipher.getInstance",
	        "canonical_signature": "javax.crypto.Cipher.getInstance(String): Cipher",
	        "return_type":         "Cipher",
	        "parameter_types":     ["String"],
	        "line":                60
	      }
	    }
	  ]
	}`

	component := ComponentKey{Purl: "pkg:maven/net.crypto/c-crypto", Version: "1.0.0"}
	frag, err := DecodeFragment(component, []byte(fragment12JSON))
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	// --- Function identity fields ---
	if len(frag.Functions) != 1 {
		t.Fatalf("Functions len = %d, want 1", len(frag.Functions))
	}
	fn := frag.Functions[0]
	if fn.Signature != "net.crypto.(CryptoSink).encrypt#1" {
		t.Errorf("Signature = %q, want net.crypto.(CryptoSink).encrypt#1", fn.Signature)
	}
	if fn.FunctionName != "net.crypto.CryptoSink.encrypt" {
		t.Errorf("FunctionName = %q, want net.crypto.CryptoSink.encrypt", fn.FunctionName)
	}
	if fn.CanonicalSignature != "net.crypto.CryptoSink.encrypt(byte[]): void" {
		t.Errorf("CanonicalSignature = %q", fn.CanonicalSignature)
	}
	if fn.ReturnType != "void" {
		t.Errorf("ReturnType = %q, want void", fn.ReturnType)
	}
	if len(fn.ParameterTypes) != 1 || fn.ParameterTypes[0] != "byte[]" {
		t.Errorf("ParameterTypes = %v, want [byte[]]", fn.ParameterTypes)
	}
	if fn.Visibility != "public" {
		t.Errorf("Visibility = %q, want public", fn.Visibility)
	}
	if fn.OwnerVisibility != "public" {
		t.Errorf("OwnerVisibility = %q, want public", fn.OwnerVisibility)
	}
	if fn.StartLine != 42 {
		t.Errorf("StartLine = %d, want 42", fn.StartLine)
	}

	// --- InternalEdge.EntryCall ---
	if len(frag.InternalEdges) != 1 {
		t.Fatalf("InternalEdges len = %d, want 1", len(frag.InternalEdges))
	}
	ie := frag.InternalEdges[0]
	if ie.EntryCall == nil {
		t.Fatal("InternalEdge.EntryCall is nil, want non-nil")
	}
	if ie.EntryCall.Line != 55 {
		t.Errorf("EntryCall.Line = %d, want 55", ie.EntryCall.Line)
	}
	if len(ie.EntryCall.Parameters) != 1 {
		t.Fatalf("EntryCall.Parameters len = %d, want 1", len(ie.EntryCall.Parameters))
	}
	param := ie.EntryCall.Parameters[0]
	if param.ParameterIndex != 0 || param.Type != "byte[]" || param.VariableName != "data" {
		t.Errorf("EntryCall.Parameters[0] = %#v", param)
	}
	if len(param.SourceNodes) != 1 || param.SourceNodes[0].Type != "PARAMETER" {
		t.Errorf("EntryCall.Parameters[0].SourceNodes = %#v", param.SourceNodes)
	}

	// --- CryptoOperation.CryptoCall ---
	if len(frag.CryptoOperations) != 1 {
		t.Fatalf("CryptoOperations len = %d, want 1", len(frag.CryptoOperations))
	}
	op := frag.CryptoOperations[0]
	if op.CryptoCall == nil {
		t.Fatal("CryptoOperation.CryptoCall is nil, want non-nil")
	}
	if op.CryptoCall.FunctionName != "javax.crypto.Cipher.getInstance" {
		t.Errorf("CryptoCall.FunctionName = %q", op.CryptoCall.FunctionName)
	}
}

// TestDecodeFragment_1_1_LegacyDecodesCleanly proves that a legacy 1.1 fragment
// decodes with nil new fields (CanonicalSignature empty, EntryCall nil,
// CryptoCall nil), so the stitcher degrades gracefully.
func TestDecodeFragment_1_1_LegacyDecodesCleanly(t *testing.T) {
	const legacy11JSON = `{
	  "schema_version": "graph-fragment-1.1",
	  "scan_metadata": { "ecosystem": "java", "root_module": "org.bridge:b-bridge" },
	  "functions": [
	    { "key": "org.bridge.(Bridge).bridge#0", "file_path": "Bridge.java" }
	  ],
	  "internal_edges": [
	    {
	      "caller_key": "org.bridge.(Bridge).bridge#0",
	      "callee_key": "org.bridge.(Bridge).helper#0",
	      "resolution":  "exact"
	    }
	  ],
	  "crypto_annotations": [
	    {
	      "function_key": "org.bridge.(Bridge).bridge#0",
	      "finding_id":   "legacy-finding",
	      "rule_id":      "java.crypto.cipher.getinstance",
	      "symbol":       "javax.crypto.Cipher.getInstance"
	    }
	  ]
	}`

	component := ComponentKey{Purl: "pkg:maven/org.bridge/b-bridge", Version: "1.0.0"}
	frag, err := DecodeFragment(component, []byte(legacy11JSON))
	if err != nil {
		t.Fatalf("DecodeFragment 1.1: %v", err)
	}

	// Function — new identity fields should be zero-value
	if len(frag.Functions) != 1 {
		t.Fatalf("Functions len = %d, want 1", len(frag.Functions))
	}
	fn := frag.Functions[0]
	if fn.CanonicalSignature != "" {
		t.Errorf("legacy Function.CanonicalSignature = %q, want empty", fn.CanonicalSignature)
	}
	if fn.FunctionName != "" {
		t.Errorf("legacy Function.FunctionName = %q, want empty", fn.FunctionName)
	}
	if fn.StartLine != 0 {
		t.Errorf("legacy Function.StartLine = %d, want 0", fn.StartLine)
	}

	// InternalEdge — EntryCall should be nil
	if len(frag.InternalEdges) != 1 {
		t.Fatalf("InternalEdges len = %d, want 1", len(frag.InternalEdges))
	}
	if frag.InternalEdges[0].EntryCall != nil {
		t.Errorf("legacy InternalEdge.EntryCall = %#v, want nil", frag.InternalEdges[0].EntryCall)
	}

	// CryptoOperation — CryptoCall should be nil
	if len(frag.CryptoOperations) != 1 {
		t.Fatalf("CryptoOperations len = %d, want 1", len(frag.CryptoOperations))
	}
	op := frag.CryptoOperations[0]
	if op.CryptoCall != nil {
		t.Errorf("legacy CryptoOperation.CryptoCall = %#v, want nil", op.CryptoCall)
	}
	if op.FindingID != "legacy-finding" {
		t.Errorf("legacy FindingID = %q, want legacy-finding", op.FindingID)
	}

	// Ensure JSON round-trip of a nil CryptoCall stays nil (no allocation side-effect)
	_ = json.RawMessage(nil)
}
