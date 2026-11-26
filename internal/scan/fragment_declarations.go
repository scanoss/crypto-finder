// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"cmp"
	"slices"

	"github.com/scanoss/reach/graphfrag"
)

// buildGraphFragmentDeclarations lists the declarations and the casts of
// every exported function (graph-fragment-1.18), each in function index
// order, then line and column.
func buildGraphFragmentDeclarations(ctx *exportBuildContext, functionIndex map[string]int) ([]graphfrag.GraphFragmentDeclaration, []graphfrag.GraphFragmentCast) {
	if ctx == nil || ctx.graph == nil {
		return nil, nil
	}
	var declarations []graphfrag.GraphFragmentDeclaration
	var casts []graphfrag.GraphFragmentCast
	for _, key := range sortedKeys(ctx.graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		fn := ctx.graph.Functions[key]
		for _, d := range fn.Declarations {
			declarations = append(declarations, graphfrag.GraphFragmentDeclaration{
				Function: index, Line: d.Line, StartCol: d.StartCol, EndCol: d.EndCol, EndLine: d.EndLine,
				Type: d.Type, Name: d.Name, Init: d.Init,
			})
		}
		for _, c := range fn.Casts {
			casts = append(casts, graphfrag.GraphFragmentCast{
				Function: index, Line: c.Line, StartCol: c.StartCol, EndCol: c.EndCol, EndLine: c.EndLine,
				Type: c.Type, InnerLine: c.InnerLine, InnerCol: c.InnerCol,
			})
		}
	}
	slices.SortStableFunc(declarations, func(a, b graphfrag.GraphFragmentDeclaration) int {
		return cmp.Or(cmp.Compare(a.Function, b.Function), cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	slices.SortStableFunc(casts, func(a, b graphfrag.GraphFragmentCast) int {
		return cmp.Or(cmp.Compare(a.Function, b.Function), cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return declarations, casts
}

// buildGraphFragmentCallAnchors lists every call of every exported function
// (graph-fragment-1.20) with its syntax-tree position, and, in a Java or
// Python fragment, the call itself (1.21): its target, text, arguments and their
// provenance. They are in function index order, each function's calls in
// the order the parser recorded them.
func buildGraphFragmentCallAnchors(ctx *exportBuildContext, functionIndex map[string]int) []graphfrag.GraphFragmentCallAnchor {
	if ctx == nil || ctx.graph == nil {
		return nil
	}
	var anchors []graphfrag.GraphFragmentCallAnchor
	for _, key := range sortedKeys(ctx.graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		for i := range ctx.graph.Functions[key].Calls {
			call := &ctx.graph.Functions[key].Calls[i]
			anchor := graphfrag.GraphFragmentCallAnchor{
				Function: index, Line: call.Line, StartCol: call.StartCol, EndCol: call.EndCol,
				Kind: call.ASTKind, Path: call.NamedASTPath, ChainID: call.ChainID,
			}
			if fragmentCarriesCalls(ctx) {
				anchor.Callee, anchor.Raw, anchor.Arguments = call.Callee.String(), call.Raw, call.Arguments
				anchor.ArgumentSources = fragmentArgumentSources(ctx, call.ArgumentSources)
			}
			anchors = append(anchors, anchor)
		}
	}
	slices.SortStableFunc(anchors, func(a, b graphfrag.GraphFragmentCallAnchor) int { return cmp.Compare(a.Function, b.Function) })
	return anchors
}
