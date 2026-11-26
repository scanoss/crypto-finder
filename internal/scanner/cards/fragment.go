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

package cards

import (
	"github.com/scanoss/reach/cardmatch"
	"github.com/scanoss/reach/graphfrag"
)

// toMatcherFragment hands the matcher the in-memory fragment in the shape
// it reads from an exported one: functions, external calls, and internal
// edges in the compact form with their strings interned. The matcher never
// sees crypto annotations.
func toMatcherFragment(fragment *graphfrag.GraphFragmentExport) *cardmatch.FragmentJSON {
	out := &cardmatch.FragmentJSON{
		Functions:     make([]cardmatch.FunctionJSON, len(fragment.Functions)),
		ExternalCalls: make([]cardmatch.ExternalJSON, len(fragment.ExternalCalls)),
		InternalEdges: make([]cardmatch.CompactEdge, len(fragment.InternalEdges)),
		SourceLines:   fragment.SourceLines,
		ConstantRefs:  fragment.ConstantRefs,
		SchemaVersion: fragment.SchemaVersion,
		Declarations:  fragment.Declarations,
		Casts:         fragment.Casts,
		// Python, Rust, Node and C (Items and BinaryExprs: Rust only;
		// Strings: C and C++ only).
		Imports:         fragment.Imports,
		Items:           fragment.Items,
		BinaryExprs:     fragment.BinaryExprs,
		Strings:         fragment.Strings,
		AttributeStores: fragment.AttributeStores,
		LocalBindings:   fragment.LocalBindings,
		// Go only.
		GoValues: fragment.GoValues,
		GoBlocks: fragment.GoBlocks,
		// Node only.
		ObjectLiterals: fragment.ObjectLiterals,
		PropertyReads:  fragment.PropertyReads,
	}
	out.ScanMetadata.EntryKinds = fragment.ScanMetadata.EntryKinds
	out.ScanMetadata.Ecosystem = fragment.ScanMetadata.Ecosystem
	if out.ScanMetadata.Ecosystem == ecosystemCPP {
		// C++ only: a construction site is read by its anchor's kind.
		out.Anchors = fragment.CallAnchors
	}

	functionIndex := make(map[string]int, len(fragment.Functions))
	for i := range fragment.Functions {
		fn := &fragment.Functions[i]
		functionIndex[fn.Key] = i
		out.Functions[i] = cardmatch.FunctionJSON{
			Key: fn.Key, Package: fn.Package, FilePath: fn.FilePath,
			StartLine: fn.StartLine, EndLine: fn.EndLine, EntryKind: fn.EntryKind,
			ParameterNames: fn.ParameterNames, Name: fn.Name, ReturnType: fn.ReturnType,
			ReturnSources:     toMatcherRawSources(fn.ReturnSources),
			WrittenParameters: fn.WrittenParameters,
		}
	}

	for i := range fragment.ExternalCalls {
		call := &fragment.ExternalCalls[i]
		out.ExternalCalls[i] = cardmatch.ExternalJSON{
			CallerKey: call.CallerKey, TargetKey: call.TargetKey, Raw: call.Raw,
			Line: optional(call.Line), Resolution: call.Resolution, MethodName: call.MethodName, Arity: call.Arity,
			ReceiverVar: call.ReceiverVar, AssignedVar: call.AssignedVar, ChainID: call.ChainID,
			StartCol: optional(call.StartCol), EndCol: optional(call.EndCol), EndLine: call.EndLine,
			EntryCall:        toMatcherCallSite(call.EntryCall),
			CandidateModules: call.CandidateModules,
			DeclaredType:     call.DeclaredType,
		}
	}

	// Index 0 is the empty string, as in an exported fragment.
	strings := map[string]int{"": 0}
	out.InternalEdgeStrings = []string{""}
	intern := func(value string) int {
		index, seen := strings[value]
		if !seen {
			index = len(out.InternalEdgeStrings)
			strings[value] = index
			out.InternalEdgeStrings = append(out.InternalEdgeStrings, value)
		}
		return index
	}
	for i := range fragment.InternalEdges {
		edge := &fragment.InternalEdges[i]
		out.InternalEdges[i] = cardmatch.CompactEdge{
			N: [13]int{
				functionIndex[edge.CallerKey], functionIndex[edge.CalleeKey], edge.Line,
				intern(edge.Resolution), intern(edge.DeclaredType), intern(edge.MethodName), edge.Arity,
				intern(edge.ReceiverVar), intern(edge.AssignedVar), intern(edge.ChainID),
				edge.StartCol, edge.EndCol, intern(edge.ResolvedReceiverType),
			},
			EndLine: edge.EndLine,
			Entry:   toMatcherCallSite(edge.EntryCall),
		}
	}
	return out
}

// optional is a JSON omitempty integer as the matcher decodes it: absent
// when zero.
func optional(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

func toMatcherCallSite(call *graphfrag.GraphFragmentCallSite) *cardmatch.CallSiteJSON {
	if call == nil {
		return nil
	}
	out := &cardmatch.CallSiteJSON{Parameters: make([]cardmatch.Param, len(call.Parameters))}
	for i := range call.Parameters {
		param := &call.Parameters[i]
		out.Parameters[i] = cardmatch.Param{
			ParameterIndex: param.ParameterIndex, Keyword: param.Keyword, Type: param.Type, VariableName: param.VariableName,
			ArgumentExpression: param.ArgumentExpression, ResolvedValue: param.ResolvedValue,
			SourceNodes: toMatcherSourceNodes(param.SourceNodes),
		}
	}
	return out
}

func toMatcherSourceNodes(nodes []graphfrag.GraphFragmentSourceNode) []cardmatch.SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]cardmatch.SourceNode, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		out[i] = cardmatch.SourceNode{
			Type: node.Type, Name: node.Name, DeclaredType: node.DeclaredType, Value: node.Value,
			ParameterIndex: node.ParameterIndex, SourceNodes: toMatcherSourceNodes(node.SourceNodes),
			MayValues: node.MayValues, MayValuesExhaustive: node.MayValuesExhaustive,
		}
		if node.Location != nil {
			out[i].Location = &cardmatch.SourceLocation{Line: node.Location.Line}
		}
	}
	return out
}

// toMatcherRawSources converts a function's return sources: their type,
// value, location and nested nodes, all the Go object flow reads.
func toMatcherRawSources(nodes []graphfrag.GraphFragmentRawSource) []cardmatch.SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]cardmatch.SourceNode, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		out[i] = cardmatch.SourceNode{
			Type: node.Type, Name: node.Name, DeclaredType: node.DeclaredType, Value: node.Value,
			SourceNodes: toMatcherRawSources(node.SourceNodes), MayValues: node.MayValues,
		}
		if node.Location != nil {
			out[i].Location = &cardmatch.SourceLocation{Line: node.Location.Line}
		}
	}
	return out
}
