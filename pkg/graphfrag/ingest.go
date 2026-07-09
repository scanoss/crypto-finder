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
func (e *GraphFragmentExport) ToFragment(component ComponentKey) Fragment {
	frag := Fragment{
		Component:        component,
		Module:           e.ScanMetadata.RootModule,
		GraphAlgoVersion: e.ScanMetadata.GraphAlgoVersion,
	}

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
			EndLine:            fn.EndLine,
			FilePath:           fn.FilePath,
			DisplaySymbol:      fn.DisplaySymbol,
			Aliases:            append([]string(nil), fn.Aliases...),
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
			ReceiverVar:  ie.ReceiverVar,
			AssignedVar:  ie.AssignedVar,
			ChainID:      ie.ChainID,
			StartCol:     ie.StartCol,
			EndCol:       ie.EndCol,
			EntryCall:    toCallSite(ie.EntryCall),

			ResolvedReceiverType: ie.ResolvedReceiverType,
		}
		frag.InternalEdges = append(frag.InternalEdges, edge)
	}
	for i := range e.ExternalCalls {
		ec := &e.ExternalCalls[i]
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalCall{
			Caller:          ec.CallerKey,
			TargetSignature: ec.TargetKey,
			Raw:             ec.Raw,
			Resolution:      normalizeResolutionKind(ec.Resolution),
			DeclaredType:    ec.DeclaredType,
			MethodName:      ec.MethodName,
			Arity:           ec.Arity,
			CallSite:        ec.Line,
			ReceiverVar:     ec.ReceiverVar,
			AssignedVar:     ec.AssignedVar,
			ChainID:         ec.ChainID,
			StartCol:        ec.StartCol,
			EndCol:          ec.EndCol,
			EntryCall:       toCallSite(ec.EntryCall),

			ResolvedReceiverType: ec.ResolvedReceiverType,
		})
	}
	for i := range e.CryptoAnnotations {
		op := &e.CryptoAnnotations[i]
		frag.CryptoOperations = append(frag.CryptoOperations, CryptoOperation{
			Function:          op.FunctionKey,
			FindingID:         op.FindingID,
			RuleID:            op.RuleID,
			Symbol:            op.Symbol,
			FilePath:          op.FilePath,
			StartLine:         op.StartLine,
			EndLine:           op.EndLine,
			Match:             op.Expression,
			CryptoCall:        toCryptoCall(op.CryptoCall),
			OID:               op.OID,
			Metadata:          op.Metadata,
			Source:            op.Source,
			MatchedOperation:  toMatchedOp(op.MatchedOperation),
			SupportingCallIDs: append([]string(nil), op.SupportingCallIDs...),
		})
	}
	for i := range e.SupportingCalls {
		s := &e.SupportingCalls[i]
		frag.SupportingCalls = append(frag.SupportingCalls, SupportingCall{
			Function:           s.FunctionKey,
			SupportingID:       s.SupportingID,
			Category:           s.Category,
			FilePath:           s.FilePath,
			StartLine:          s.StartLine,
			EndLine:            s.EndLine,
			FunctionName:       s.FunctionName,
			CanonicalSignature: s.CanonicalSignature,
			DisplaySymbol:      s.DisplaySymbol,
			Aliases:            append([]string(nil), s.Aliases...),
			SupportingCall:     toCryptoCall(s.SupportingCall),
			Metadata:           s.Metadata,
			MatchedOperation:   toMatchedOp(s.MatchedOperation),
		})
	}
	frag.CryptoEntryPoints = appendCryptoEntryPoints(frag.CryptoEntryPoints, e.CryptoEntryPoints)
	return frag
}

func appendCryptoEntryPoints(dst []CryptoEntryPoint, src []GraphFragmentCryptoEntryPoint) []CryptoEntryPoint {
	for i := range src {
		ep := &src[i]
		dst = append(dst, CryptoEntryPoint{
			FunctionKey:              ep.FunctionKey,
			FunctionName:             ep.FunctionName,
			CanonicalSignature:       ep.CanonicalSignature,
			DisplaySymbol:            ep.DisplaySymbol,
			Aliases:                  append([]string(nil), ep.Aliases...),
			ReturnType:               ep.ReturnType,
			ParameterTypes:           append([]string(nil), ep.ParameterTypes...),
			Visibility:               ep.Visibility,
			OwnerVisibility:          ep.OwnerVisibility,
			ReachableFindings:        toReachableFindings(ep.ReachableFindings),
			ReachableSupportingCalls: toReachableSupportingCalls(ep.ReachableSupportingCalls),
			MethodRole:               ep.MethodRole,
			RoleProvenance:           toRoleProvenance(ep.RoleProvenance),
			ParameterRoles:           toParameterRoles(ep.ParameterRoles),
		})
	}
	return dst
}

// toRoleProvenance converts a GraphFragmentRoleProvenance pointer to a
// RoleProvenance pointer. Returns nil if src is nil (issue-103: absent on
// fragments with no KB role match, and on all fragments exported before
// schema graph-fragment-1.7 / callgraph 6.4).
func toRoleProvenance(src *GraphFragmentRoleProvenance) *RoleProvenance {
	if src == nil {
		return nil
	}
	rp := &RoleProvenance{
		Kind:               src.Kind,
		ContractMethod:     src.ContractMethod,
		InheritedFrom:      src.InheritedFrom,
		InheritedAmbiguous: src.InheritedAmbiguous,
	}
	if src.Inherited != nil {
		rp.Inherited = &InheritedRole{
			AlgorithmFamily: src.Inherited.AlgorithmFamily,
			Primitive:       src.Inherited.Primitive,
		}
	}
	return rp
}

// toParameterRoles converts a []GraphFragmentParameterRole to a []ParameterRole.
func toParameterRoles(src []GraphFragmentParameterRole) []ParameterRole {
	if len(src) == 0 {
		return nil
	}
	out := make([]ParameterRole, len(src))
	for i := range src {
		out[i] = ParameterRole{
			Index: src[i].Index,
			Name:  src[i].Name,
			Role:  src[i].Role,
		}
		if src[i].Contributes != nil {
			out[i].Contributes = &Contribution{
				Property:   src[i].Contributes.Property,
				Derivation: src[i].Contributes.Derivation,
			}
		}
	}
	return out
}

func toReachableFindings(src []GraphFragmentReachableFinding) []ReachableFinding {
	if len(src) == 0 {
		return nil
	}
	out := make([]ReachableFinding, len(src))
	for i := range src {
		out[i] = ReachableFinding{
			FindingID:       src[i].FindingID,
			ChainDepth:      src[i].ChainDepth,
			FindingGraphRef: src[i].FindingGraphRef,
		}
	}
	return out
}

func toReachableSupportingCalls(src []GraphFragmentReachableSupportingCall) []ReachableSupportingCall {
	if len(src) == 0 {
		return nil
	}
	out := make([]ReachableSupportingCall, len(src))
	for i := range src {
		out[i] = ReachableSupportingCall{
			SupportingID:      src[i].SupportingID,
			ChainDepth:        src[i].ChainDepth,
			SupportingCallRef: src[i].SupportingCallRef,
		}
	}
	return out
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
		DisplaySymbol:      src.DisplaySymbol,
		Aliases:            append([]string(nil), src.Aliases...),
		Line:               src.Line,
		ParameterRoles:     toParameterRoles(src.ParameterRoles),
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
