// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package graphfrag

import (
	"encoding/json"
	"testing"
)

// TestGraphFragmentEdge_EntryCall_JSONRoundTrip verifies that a GraphFragmentEdge
// carrying an EntryCall with nested recursive source_nodes round-trips through
// JSON encoding/decoding without loss.
func TestGraphFragmentEdge_EntryCall_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	paramIdx := 0
	edge := GraphFragmentEdge{
		CallerKey:  "com.app.(Service).init#0",
		CalleeKey:  "javax.crypto.(Cipher).getInstance#1",
		Line:       5,
		Resolution: "exact",
		EntryCall: &GraphFragmentCallSite{
			Line: 5,
			Parameters: []GraphFragmentParameter{
				{
					ParameterIndex:     0,
					Type:               "String",
					VariableName:       "algo",
					ArgumentExpression: "algo",
					ResolvedValue:      "",
					SourceNodes: []GraphFragmentSourceNode{
						{
							Type:           "PARAMETER",
							Name:           "algo",
							ParameterIndex: &paramIdx,
							SourceNodes: []GraphFragmentSourceNode{
								{
									Type:       "CALL_RESULT",
									Name:       "getAlgo",
									CallTarget: "com.app.(Util).getAlgo#0",
								},
							},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded GraphFragmentEdge
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.CallerKey != edge.CallerKey {
		t.Errorf("CallerKey = %q, want %q", decoded.CallerKey, edge.CallerKey)
	}
	if decoded.EntryCall == nil {
		t.Fatal("EntryCall is nil after round-trip")
	}
	if decoded.EntryCall.Line != edge.EntryCall.Line {
		t.Errorf("EntryCall.Line = %d, want %d", decoded.EntryCall.Line, edge.EntryCall.Line)
	}
	if len(decoded.EntryCall.Parameters) != 1 {
		t.Fatalf("EntryCall.Parameters len = %d, want 1", len(decoded.EntryCall.Parameters))
	}
	p := decoded.EntryCall.Parameters[0]
	if p.Type != "String" {
		t.Errorf("Parameter.Type = %q, want %q", p.Type, "String")
	}
	if len(p.SourceNodes) != 1 {
		t.Fatalf("SourceNodes len = %d, want 1", len(p.SourceNodes))
	}
	sn := p.SourceNodes[0]
	if sn.Type != "PARAMETER" {
		t.Errorf("SourceNode.Type = %q, want PARAMETER", sn.Type)
	}
	if sn.ParameterIndex == nil || *sn.ParameterIndex != 0 {
		t.Errorf("SourceNode.ParameterIndex = %v, want &0", sn.ParameterIndex)
	}
	if len(sn.SourceNodes) != 1 {
		t.Fatalf("nested SourceNodes len = %d, want 1", len(sn.SourceNodes))
	}
	nested := sn.SourceNodes[0]
	if nested.Type != "CALL_RESULT" {
		t.Errorf("nested.Type = %q, want CALL_RESULT", nested.Type)
	}
	if nested.CallTarget != "com.app.(Util).getAlgo#0" {
		t.Errorf("nested.CallTarget = %q, want com.app.(Util).getAlgo#0", nested.CallTarget)
	}
}

// TestGraphFragmentCryptoOp_JSONRoundTrip verifies that GraphFragmentCryptoOp
// carrying crypto_call, oid, metadata (raw JSON passthrough) and source
// round-trips through JSON encoding/decoding without loss.
func TestGraphFragmentCryptoOp_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	rawMeta := json.RawMessage(`{"algorithmFamily":"AES","assetType":"algorithm"}`)

	op := GraphFragmentCryptoOp{
		FindingID:  "beaecdb7",
		RuleID:     "java.crypto.cipher.getinstance",
		Symbol:     "javax.crypto.Cipher.getInstance",
		Expression: `Cipher.getInstance("AES")`,
		FilePath:   "Service.java",
		StartLine:  6,
		EndLine:    6,
		OID:        "2.16.840.1.101.3.4.1.2",
		Metadata:   rawMeta,
		Source:     "direct",
		CryptoCall: &GraphFragmentCryptoCall{
			FunctionName:       "javax.crypto.Cipher.getInstance",
			CanonicalSignature: "javax.crypto.Cipher.getInstance(String):Cipher",
			ReturnType:         "Cipher",
			ParameterTypes:     []string{"String"},
			Line:               6,
			Parameters: []GraphFragmentParameter{
				{
					ParameterIndex:     0,
					Type:               "String",
					ArgumentExpression: `"AES"`,
					ResolvedValue:      `"AES"`,
				},
			},
		},
	}

	data, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded GraphFragmentCryptoOp
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.FindingID != op.FindingID {
		t.Errorf("FindingID = %q, want %q", decoded.FindingID, op.FindingID)
	}
	if decoded.OID != op.OID {
		t.Errorf("OID = %q, want %q", decoded.OID, op.OID)
	}
	if decoded.Source != op.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, op.Source)
	}
	if string(decoded.Metadata) != string(op.Metadata) {
		t.Errorf("Metadata = %s, want %s", decoded.Metadata, op.Metadata)
	}
	if decoded.CryptoCall == nil {
		t.Fatal("CryptoCall is nil after round-trip")
	}
	if decoded.CryptoCall.FunctionName != op.CryptoCall.FunctionName {
		t.Errorf("CryptoCall.FunctionName = %q, want %q", decoded.CryptoCall.FunctionName, op.CryptoCall.FunctionName)
	}
	if decoded.CryptoCall.CanonicalSignature != op.CryptoCall.CanonicalSignature {
		t.Errorf("CryptoCall.CanonicalSignature = %q, want %q", decoded.CryptoCall.CanonicalSignature, op.CryptoCall.CanonicalSignature)
	}
	if len(decoded.CryptoCall.ParameterTypes) != 1 || decoded.CryptoCall.ParameterTypes[0] != "String" {
		t.Errorf("CryptoCall.ParameterTypes = %v, want [String]", decoded.CryptoCall.ParameterTypes)
	}
	if len(decoded.CryptoCall.Parameters) != 1 {
		t.Fatalf("CryptoCall.Parameters len = %d, want 1", len(decoded.CryptoCall.Parameters))
	}
	if decoded.CryptoCall.Parameters[0].ResolvedValue != `"AES"` {
		t.Errorf("CryptoCall.Parameters[0].ResolvedValue = %q, want \"AES\"", decoded.CryptoCall.Parameters[0].ResolvedValue)
	}
}

// TestSchemaVersion_Is_1_8 verifies the schema version constant has been bumped.
// 1.8 removes operation-only crypto entry point synthesis from fragment exports.
func TestSchemaVersion_Is_1_8(t *testing.T) {
	t.Parallel()
	if SchemaVersion != "graph-fragment-1.8" {
		t.Errorf("SchemaVersion = %q, want graph-fragment-1.8", SchemaVersion)
	}
}
