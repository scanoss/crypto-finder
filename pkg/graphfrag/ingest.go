// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"encoding/json"
	"fmt"
)

// ToFragment projects an exported graph fragment onto the stitch model for the
// given component. The component key is supplied by the caller because the
// export carries source-level identity (module, function keys) but not the
// (purl, version) it was requested for.
//
// All graph-fragment-1.2 fields (CanonicalSignature, EntryCall, CryptoCall,
// asset metadata) are mapped when present. Legacy 1.0/1.1 fragments decode with
// nil/zero for the new fields — safe structural-only degradation.
func (e GraphFragmentExport) ToFragment(component ComponentKey) Fragment {
	frag := Fragment{Component: component, Module: e.ScanMetadata.RootModule}

	for i := range e.Functions {
		fn := &e.Functions[i]
		frag.Functions = append(frag.Functions, Function{
			Signature:          fn.Key,
			FunctionName:       fn.FunctionName,
			CanonicalSignature: fn.CanonicalSignature,
			ReturnType:         fn.ReturnType,
			ParameterTypes:     fn.ParameterTypes,
			Visibility:         fn.Visibility,
			OwnerVisibility:    fn.OwnerVisibility,
			StartLine:          fn.StartLine,
			FilePath:           fn.FilePath,
		})
	}
	for i := range e.InternalEdges {
		ie := &e.InternalEdges[i]
		edge := InternalEdge{
			Caller:       ie.CallerKey,
			Callee:       ie.CalleeKey,
			Resolution:   normalizeResolutionKind(ie.Resolution),
			DeclaredType: ie.DeclaredType,
			MethodName:   ie.MethodName,
			Arity:        ie.Arity,
			CallSite:     ie.Line,
			EntryCall:    toCallSite(ie.EntryCall),
		}
		frag.InternalEdges = append(frag.InternalEdges, edge)
	}
	for i := range e.ExternalCalls {
		ec := &e.ExternalCalls[i]
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalCall{
			Caller:          ec.CallerKey,
			TargetSignature: ec.TargetKey,
			Resolution:      normalizeResolutionKind(ec.Resolution),
			DeclaredType:    ec.DeclaredType,
			MethodName:      ec.MethodName,
			Arity:           ec.Arity,
			CallSite:        ec.Line,
			EntryCall:       toCallSite(ec.EntryCall),
		})
	}
	for i := range e.CryptoAnnotations {
		op := &e.CryptoAnnotations[i]
		frag.CryptoOperations = append(frag.CryptoOperations, CryptoOperation{
			Function:         op.FunctionKey,
			FindingID:        op.FindingID,
			RuleID:           op.RuleID,
			Symbol:           op.Symbol,
			FilePath:         op.FilePath,
			StartLine:        op.StartLine,
			EndLine:          op.EndLine,
			Match:            op.Expression,
			CryptoCall:       toCryptoCall(op.CryptoCall),
			OID:              op.OID,
			Metadata:         op.Metadata,
			Source:           op.Source,
			MatchedOperation: toMatchedOp(op.MatchedOperation),
		})
	}
	return frag
}

// toCallSite converts a GraphFragmentCallSite pointer to a CallSite pointer.
// Returns nil if src is nil (1.0/1.1 fragments that have no entry_call).
func toCallSite(src *GraphFragmentCallSite) *CallSite {
	if src == nil {
		return nil
	}
	cs := &CallSite{Line: src.Line}
	for i := range src.Parameters {
		cs.Parameters = append(cs.Parameters, toParameter(src.Parameters[i]))
	}
	return cs
}

// toParameter converts a GraphFragmentParameter to a Parameter.
func toParameter(src GraphFragmentParameter) Parameter {
	p := Parameter{
		ParameterIndex:     src.ParameterIndex,
		Type:               src.Type,
		VariableName:       src.VariableName,
		ArgumentExpression: src.ArgumentExpression,
		ResolvedValue:      src.ResolvedValue,
	}
	for i := range src.SourceNodes {
		p.SourceNodes = append(p.SourceNodes, toSourceNode(src.SourceNodes[i]))
	}
	return p
}

// toSourceNode recursively converts a GraphFragmentSourceNode to a SourceNode.
func toSourceNode(src GraphFragmentSourceNode) SourceNode {
	sn := SourceNode{
		Type:           src.Type,
		Name:           src.Name,
		DeclaredType:   src.DeclaredType,
		Value:          src.Value,
		ParameterIndex: src.ParameterIndex,
		CallTarget:     src.CallTarget,
	}
	if src.Location != nil {
		sn.Location = &SourceLocation{
			FilePath: src.Location.FilePath,
			Line:     src.Location.Line,
		}
	}
	for i := range src.SourceNodes {
		sn.SourceNodes = append(sn.SourceNodes, toSourceNode(src.SourceNodes[i]))
	}
	return sn
}

// toCryptoCall converts a GraphFragmentCryptoCall pointer to a CryptoCall pointer.
// Returns nil if src is nil (1.0/1.1 fragments).
func toCryptoCall(src *GraphFragmentCryptoCall) *CryptoCall {
	if src == nil {
		return nil
	}
	cc := &CryptoCall{
		FunctionName:       src.FunctionName,
		CanonicalSignature: src.CanonicalSignature,
		ReturnType:         src.ReturnType,
		ParameterTypes:     src.ParameterTypes,
		Line:               src.Line,
	}
	for i := range src.Parameters {
		cc.Parameters = append(cc.Parameters, toParameter(src.Parameters[i]))
	}
	return cc
}

// toMatchedOp converts a GraphFragmentMatchedOp pointer to a MatchedOp pointer.
// Returns nil if src is nil (1.0/1.1 fragments).
func toMatchedOp(src *GraphFragmentMatchedOp) *MatchedOp {
	if src == nil {
		return nil
	}
	return &MatchedOp{
		Kind:       src.Kind,
		Symbol:     src.Symbol,
		Expression: src.Expression,
		Line:       src.Line,
	}
}

func normalizeResolutionKind(value string) ResolutionKind {
	switch kind := ResolutionKind(value); kind {
	case ResolutionExact, ResolutionInterfaceDispatch, ResolutionNameOnly, ResolutionUnknown:
		return kind
	default:
		return ResolutionUnknown
	}
}

// DecodeFragment parses one graph-fragment export (JSON) into a Fragment for the
// given component. Legacy fragments exported before the resolution fields
// existed decode to ResolutionUnknown, which the stitcher fails closed on —
// safe under-reporting, never a false positive.
func DecodeFragment(component ComponentKey, data []byte) (Fragment, error) {
	var e GraphFragmentExport
	if err := json.Unmarshal(data, &e); err != nil {
		return Fragment{}, fmt.Errorf("graphfrag: decode fragment for %s: %w", component, err)
	}
	return e.ToFragment(component), nil
}
