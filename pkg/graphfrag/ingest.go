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
func (e GraphFragmentExport) ToFragment(component ComponentKey) Fragment {
	frag := Fragment{Component: component, Module: e.ScanMetadata.RootModule}

	for _, fn := range e.Functions {
		frag.Functions = append(frag.Functions, Function{Signature: fn.Key, FilePath: fn.FilePath})
	}
	for _, ie := range e.InternalEdges {
		frag.InternalEdges = append(frag.InternalEdges, InternalEdge{
			Caller:       ie.CallerKey,
			Callee:       ie.CalleeKey,
			Resolution:   ResolutionKind(ie.Resolution),
			DeclaredType: ie.DeclaredType,
			MethodName:   ie.MethodName,
			Arity:        ie.Arity,
			CallSite:     ie.Line,
		})
	}
	for _, ec := range e.ExternalCalls {
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalCall{
			Caller:          ec.CallerKey,
			TargetSignature: ec.TargetKey,
			Resolution:      ResolutionKind(ec.Resolution),
			DeclaredType:    ec.DeclaredType,
			MethodName:      ec.MethodName,
			Arity:           ec.Arity,
			CallSite:        ec.Line,
		})
	}
	for _, op := range e.CryptoAnnotations {
		frag.CryptoOperations = append(frag.CryptoOperations, CryptoOperation{
			Function:  op.FunctionKey,
			FindingID: op.FindingID,
			RuleID:    op.RuleID,
			Symbol:    op.Symbol,
		})
	}
	return frag
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
