// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestEncodeFragment_RoundTripsStructuralIdentity verifies EncodeFragment ->
// DecodeFragment preserves the structural payload the annotate import depends on:
// function line ranges, edge keys, the graph-fragment-1.4 object identity
// (receiver_var/assigned_var/chain_id), Raw, and entry_call args.
func TestEncodeFragment_RoundTripsStructuralIdentity(t *testing.T) {
	t.Parallel()

	in := Fragment{
		Module: "com.app",
		Functions: []Function{{
			Signature: "com.app.(Svc).run#0", FunctionName: "com.app.Svc.run",
			FilePath: "Svc.java", StartLine: 4, EndLine: 11,
		}},
		ExternalCalls: []ExternalCall{{
			Caller: "com.app.(Svc).run#0", TargetSignature: "org.bc.(Gen).init#1",
			Raw: "gen.init", CallSite: 6, Resolution: ResolutionExact,
			MethodName: "init", Arity: 1, ReceiverVar: "gen", ChainID: "167",
			StartCol: 9, EndCol: 17,
			EntryCall: &CallSite{Line: 6, Parameters: []Parameter{{
				ParameterIndex: 0, ArgumentExpression: "new Params()",
				SourceNodes: []SourceNode{{Type: "CALL_RESULT", CallTarget: "org.bc.Params.<init>"}},
			}}},
		}},
		InternalEdges: []InternalEdge{{
			Caller: "com.app.(Svc).run#0", Callee: "com.app.(Svc).helper#0",
			CallSite: 5, Resolution: ResolutionExact, AssignedVar: "h",
			StartCol: 5, EndCol: 13,
		}},
	}

	data, err := EncodeFragment(in)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	got, err := DecodeFragment(ComponentKey{}, data)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if len(got.Functions) != 1 || got.Functions[0].StartLine != 4 || got.Functions[0].EndLine != 11 {
		t.Fatalf("function line range lost: %+v", got.Functions)
	}
	if len(got.ExternalCalls) != 1 {
		t.Fatalf("external calls len = %d, want 1", len(got.ExternalCalls))
	}
	ec := got.ExternalCalls[0]
	if ec.ReceiverVar != "gen" || ec.ChainID != "167" || ec.Raw != "gen.init" || ec.CallSite != 6 {
		t.Errorf("external edge identity lost: recv=%q chain=%q raw=%q line=%d", ec.ReceiverVar, ec.ChainID, ec.Raw, ec.CallSite)
	}
	if ec.StartCol != 9 || ec.EndCol != 17 {
		t.Errorf("external edge columns lost: startCol=%d endCol=%d, want 9/17", ec.StartCol, ec.EndCol)
	}
	if ec.EntryCall == nil || len(ec.EntryCall.Parameters) != 1 ||
		ec.EntryCall.Parameters[0].ArgumentExpression != "new Params()" ||
		len(ec.EntryCall.Parameters[0].SourceNodes) != 1 {
		t.Errorf("entry_call args lost: %+v", ec.EntryCall)
	}
	if len(got.InternalEdges) != 1 || got.InternalEdges[0].AssignedVar != "h" {
		t.Errorf("internal edge AssignedVar lost: %+v", got.InternalEdges)
	}
	if got.InternalEdges[0].StartCol != 5 || got.InternalEdges[0].EndCol != 13 {
		t.Errorf("internal edge columns lost: startCol=%d endCol=%d, want 5/13", got.InternalEdges[0].StartCol, got.InternalEdges[0].EndCol)
	}
}
