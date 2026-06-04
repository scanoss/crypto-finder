// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// EncodeFragment renders a Fragment back to graph-fragment-1.4 wire JSON — the
// inverse of DecodeFragment for the STRUCTURAL payload (scan_metadata, functions,
// internal_edges, external_calls, including each edge's call-site object identity
// receiver_var/assigned_var/chain_id and entry_call args).
//
// It exists for consumers that cached only the rules-independent structural graph
// (e.g. the mining service's component_code_graphs) and need to materialize it as
// a graph-fragment file to feed `crypto-finder annotate --import-fragment`. The
// crypto sections (crypto_annotations, supporting_calls, crypto_entry_points) are
// intentionally NOT re-encoded: they are rules-versioned and the annotate path
// re-derives them from the structural edges, so a structural-only fragment is
// exactly what the import needs.
func EncodeFragment(frag Fragment) ([]byte, error) {
	out := GraphFragmentExport{
		SchemaVersion: SchemaVersion,
		ScanMetadata: GraphFragmentScanMetadata{
			RootModule:       frag.Module,
			GraphAlgoVersion: frag.GraphAlgoVersion,
		},
	}

	for i := range frag.Functions {
		fn := &frag.Functions[i]
		out.Functions = append(out.Functions, GraphFragmentFunction{
			Key:                fn.Signature,
			FunctionName:       fn.FunctionName,
			CanonicalSignature: fn.CanonicalSignature,
			FilePath:           fn.FilePath,
			StartLine:          fn.StartLine,
			EndLine:            fn.EndLine,
			ReturnType:         fn.ReturnType,
			ParameterTypes:     append([]string(nil), fn.ParameterTypes...),
			Visibility:         fn.Visibility,
			OwnerVisibility:    fn.OwnerVisibility,
			DisplaySymbol:      fn.DisplaySymbol,
			Aliases:            append([]string(nil), fn.Aliases...),
		})
	}
	for i := range frag.InternalEdges {
		e := &frag.InternalEdges[i]
		out.InternalEdges = append(out.InternalEdges, GraphFragmentEdge{
			CallerKey:    e.Caller,
			CalleeKey:    e.Callee,
			Line:         e.CallSite,
			Resolution:   string(e.Resolution),
			DeclaredType: e.DeclaredType,
			MethodName:   e.MethodName,
			Arity:        e.Arity,
			ReceiverVar:  e.ReceiverVar,
			AssignedVar:  e.AssignedVar,
			ChainID:      e.ChainID,
			EntryCall:    fromCallSite(e.EntryCall),
		})
	}
	for i := range frag.ExternalCalls {
		e := &frag.ExternalCalls[i]
		out.ExternalCalls = append(out.ExternalCalls, GraphFragmentExternal{
			CallerKey:    e.Caller,
			TargetKey:    e.TargetSignature,
			Raw:          e.Raw,
			Line:         e.CallSite,
			Resolution:   string(e.Resolution),
			DeclaredType: e.DeclaredType,
			MethodName:   e.MethodName,
			Arity:        e.Arity,
			ReceiverVar:  e.ReceiverVar,
			AssignedVar:  e.AssignedVar,
			ChainID:      e.ChainID,
			EntryCall:    fromCallSite(e.EntryCall),
		})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&out); err != nil {
		return nil, fmt.Errorf("graphfrag: encode fragment: %w", err)
	}
	return buf.Bytes(), nil
}

// fromCallSite is the inverse of toCallSite (model -> wire).
func fromCallSite(src *CallSite) *GraphFragmentCallSite {
	if src == nil {
		return nil
	}
	cs := &GraphFragmentCallSite{Line: src.Line}
	for i := range src.Parameters {
		cs.Parameters = append(cs.Parameters, fromParameter(src.Parameters[i]))
	}
	return cs
}

func fromParameter(p Parameter) GraphFragmentParameter {
	out := GraphFragmentParameter{
		ParameterIndex:     p.ParameterIndex,
		Type:               p.Type,
		VariableName:       p.VariableName,
		ArgumentExpression: p.ArgumentExpression,
		ResolvedValue:      p.ResolvedValue,
	}
	for i := range p.SourceNodes {
		out.SourceNodes = append(out.SourceNodes, fromSourceNode(p.SourceNodes[i]))
	}
	return out
}

func fromSourceNode(n SourceNode) GraphFragmentSourceNode {
	out := GraphFragmentSourceNode{
		Type:           n.Type,
		Name:           n.Name,
		DeclaredType:   n.DeclaredType,
		Value:          n.Value,
		ParameterIndex: n.ParameterIndex,
		CallTarget:     n.CallTarget,
	}
	if n.Location != nil {
		out.Location = &GraphFragmentSourceLoc{FilePath: n.Location.FilePath, Line: n.Location.Line}
	}
	for i := range n.SourceNodes {
		out.SourceNodes = append(out.SourceNodes, fromSourceNode(n.SourceNodes[i]))
	}
	return out
}
