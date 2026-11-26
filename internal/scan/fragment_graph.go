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

package scan

import (
	"path/filepath"
	"sort"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// fragmentFunctionDecl is the graph's declaration of a fragment function.
func fragmentFunctionDecl(fn *graphfrag.GraphFragmentFunction, id callgraph.FunctionID, projectRoot string) *callgraph.FunctionDecl {
	decl := &callgraph.FunctionDecl{
		ID:              id,
		FilePath:        filepath.Join(projectRoot, filepath.FromSlash(fn.FilePath)),
		StartLine:       fn.StartLine,
		EndLine:         fn.EndLine,
		StartCol:        fn.StartCol,
		EndCol:          fn.EndCol,
		ReturnType:      fn.ReturnType,
		Visibility:      fn.Visibility,
		OwnerVisibility: fn.OwnerVisibility,
		OwnerType:       id.Type,
		EntryKind:       callgraph.RootKind(fn.EntryKind),
		Abstract:        fn.Abstract,
		ReturnSources:   callgraphRawSources(projectRoot, fn.ReturnSources),
	}
	// A function whose parameters are all untyped (Python) lists their
	// names alone.
	for i := range max(len(fn.ParameterTypes), len(fn.ParameterNames)) {
		var parameter callgraph.FunctionParameter
		if i < len(fn.ParameterTypes) {
			parameter.Type = fn.ParameterTypes[i]
		}
		if i < len(fn.ParameterNames) {
			parameter.Name = fn.ParameterNames[i]
		}
		decl.Parameters = append(decl.Parameters, parameter)
	}
	return decl
}

// FragmentScanResult rebuilds, from a stored graph fragment, the call graph
// the scan's post-detection passes and its crypto export read, rooted at
// projectRoot, with report attached. A fragment is a projection of the
// graph, so what it does not carry is missing here: function columns, and
// what the parser records only for its own passes. A fragment older than
// 1.21 also lacks parameter names (a parameter is named after the arguments
// the function's own calls trace to it), the parser's calls (each call is
// rebuilt from its edges, with the target of its most exact one and the
// argument provenance the export already resolved across calls), return
// provenance and external signatures, and one older than 1.20 the
// syntax-tree identity of a call.
func FragmentScanResult(doc *graphfrag.GraphFragmentExport, projectRoot string, report *entities.InterimReport) *engine.DepScanResult { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	graph := &callgraph.CallGraph{
		Functions:                make(map[string]*callgraph.FunctionDecl, len(doc.Functions)),
		Callers:                  make(map[string][]string),
		SourceSupertypes:         doc.Supertypes,
		ServiceProviders:         doc.ServiceProviders,
		ExternalMethodSignatures: callgraphExternalSignatures(doc.ExternalSignatures),
		RebindLines:              fragmentRebindLines(doc),
		PythonPublicPaths:        doc.PublicPaths,
		PublicTypePaths:          doc.PublicTypePaths,
	}
	for i := range doc.Functions {
		fn := &doc.Functions[i]
		id, err := callgraph.ParseFunctionID(fn.Key)
		if err != nil {
			continue
		}
		decl := fragmentFunctionDecl(fn, id, projectRoot)
		graph.Functions[fn.Key] = decl
	}
	// The fragment lists an edge per call target: a call that dispatches to
	// several implementations is several edges at one site. The graph holds
	// the call once, with the target the parser gave it, and the caller index
	// holds every target.
	sites := make(map[fragmentSiteKey]*fragmentSite)
	var order []fragmentSiteKey
	addEdge := func(callerKey, calleeKey, resolution string, call callgraph.FunctionCall, method string, entry *graphfrag.GraphFragmentCallSite, declaredType string) {
		if graph.Functions[callerKey] == nil {
			return
		}
		graph.Callers[calleeKey] = append(graph.Callers[calleeKey], callerKey)
		// Each edge is one resolution of the graph's, as the export wrote it.
		graph.RecordEdgeResolution(callerKey, calleeKey, callgraph.EdgeResolution{
			Kind: callgraph.EdgeKind(resolution), DeclaredType: declaredType, MethodName: method, Arity: len(call.Arguments),
			CallSite: call.Line, StartCol: call.StartCol, EndCol: call.EndCol, ResolvedReceiverType: call.ResolvedReceiverType,
		})
		key := fragmentSiteKey{caller: callerKey, line: call.Line, startCol: call.StartCol, endCol: call.EndCol, method: method, arity: len(call.Arguments)}
		site := sites[key]
		if site == nil {
			site = &fragmentSite{call: call, entry: entry}
			sites[key] = site
			order = append(order, key)
		}
		// Python's extra edge of a call (an instantiation's __init__, a
		// declaration an import names) records no variables; the call's own
		// edge does.
		fillEmpty(&site.call.ReceiverVar, call.ReceiverVar)
		fillEmpty(&site.call.AssignedVar, call.AssignedVar)
		if site.call.EndLine == 0 {
			site.call.EndLine = call.EndLine
		}
		if site.target == "" || fragmentResolutionRank(resolution) > fragmentResolutionRank(site.resolution) {
			site.target, site.resolution = calleeKey, resolution
			if call.Raw != "" {
				site.call.Raw = call.Raw
			}
			// The most exact edge is the call's own and records the call's
			// variables; a dispatch edge listed before it can hold another
			// call of the same method's (an override the caller also calls
			// directly, `sk.write()` beside `const Base& pk = sk;
			// pk.write()`), which would join this call to that object's
			// lifecycle.
			overrideNonEmpty(&site.call.ReceiverVar, call.ReceiverVar)
			overrideNonEmpty(&site.call.AssignedVar, call.AssignedVar)
			overrideNonEmpty(&site.call.ResolvedReceiverType, call.ResolvedReceiverType)
			if entry != nil {
				site.entry = entry
			}
		}
	}
	for i := range doc.InternalEdges {
		edge := &doc.InternalEdges[i]
		addEdge(edge.CallerKey, edge.CalleeKey, edge.Resolution, callgraph.FunctionCall{
			Line: edge.Line, StartCol: edge.StartCol, EndCol: edge.EndCol, EndLine: edge.EndLine,
			ReceiverVar: edge.ReceiverVar, AssignedVar: edge.AssignedVar, ChainID: edge.ChainID,
			ResolvedReceiverType: edge.ResolvedReceiverType, Arguments: make([]string, edge.Arity),
		}, edge.MethodName, edge.EntryCall, edge.DeclaredType)
	}
	for i := range doc.ExternalCalls {
		call := &doc.ExternalCalls[i]
		addEdge(call.CallerKey, call.TargetKey, call.Resolution, callgraph.FunctionCall{
			Raw: call.Raw, Line: call.Line, StartCol: call.StartCol, EndCol: call.EndCol, EndLine: call.EndLine,
			ReceiverVar: call.ReceiverVar, AssignedVar: call.AssignedVar, ChainID: call.ChainID,
			ResolvedReceiverType: call.ResolvedReceiverType, Arguments: make([]string, call.Arity),
		}, call.MethodName, call.EntryCall, call.DeclaredType)
	}
	if hasAnchoredCalls(doc) {
		placeAnchoredCalls(doc, graph, projectRoot, sites)
		switch doc.ScanMetadata.Ecosystem {
		case ecosystemC:
			restoreCCallLinkage(graph)
		case ecosystemCPP:
			restoreCPPCallLinkage(graph)
		}
	} else {
		placeEdgeCalls(doc, graph, projectRoot, sites, order)
	}
	for i := range doc.Functions {
		// A fragment older than 1.21 lists the parameters by type only.
		if decl := graph.Functions[doc.Functions[i].Key]; decl != nil && doc.Functions[i].ParameterNames == nil {
			nameFragmentParameters(decl)
		}
	}
	for callee := range graph.Callers {
		callers := graph.Callers[callee]
		sort.Strings(callers)
		graph.Callers[callee] = compactStrings(callers)
	}
	return &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		RootModule:  doc.ScanMetadata.RootModule,
		Ecosystem:   doc.ScanMetadata.Ecosystem,
		ProjectRoot: projectRoot,
	}
}

// hasAnchoredCalls reports a fragment whose call anchors carry the calls
// (1.21).
func hasAnchoredCalls(doc *graphfrag.GraphFragmentExport) bool {
	for i := range doc.CallAnchors {
		if doc.CallAnchors[i].Callee != "" {
			return true
		}
	}
	return false
}

// placeAnchoredCalls gives each function the calls its anchors record, in
// the parser's order. What the parser records on a call and its anchor does
// not (the receiver and assigned variables, the resolved receiver type, the
// end line) comes from the call's edges.
func placeAnchoredCalls(doc *graphfrag.GraphFragmentExport, graph *callgraph.CallGraph, root string, sites map[fragmentSiteKey]*fragmentSite) {
	bySpan := make(map[fragmentAnchorKey][]*fragmentSite, len(sites))
	for key, site := range sites {
		span := fragmentAnchorKey{key.caller, key.line, key.startCol, key.endCol}
		bySpan[span] = append(bySpan[span], site)
	}
	for i := range doc.CallAnchors {
		anchor := &doc.CallAnchors[i]
		if anchor.Function < 0 || anchor.Function >= len(doc.Functions) {
			continue
		}
		decl := graph.Functions[doc.Functions[anchor.Function].Key]
		callee, err := callgraph.ParseFunctionID(anchor.Callee)
		if decl == nil || err != nil {
			continue
		}
		call := callgraph.FunctionCall{
			Callee: callee, Raw: anchor.Raw, FilePath: decl.FilePath,
			Line: anchor.Line, StartCol: anchor.StartCol, EndCol: anchor.EndCol,
			ASTKind: anchor.Kind, NamedASTPath: anchor.Path, ChainID: anchor.ChainID,
			Arguments: anchor.Arguments, ArgumentSources: callgraphArgumentSources(root, anchor.ArgumentSources),
		}
		span := fragmentAnchorKey{decl.ID.String(), anchor.Line, anchor.StartCol, anchor.EndCol}
		if site := anchoredCallSite(bySpan[span], callgraph.BaseFunctionName(callee.Name), len(call.Arguments)); site != nil {
			call.ReceiverVar, call.AssignedVar = site.call.ReceiverVar, site.call.AssignedVar
			call.ResolvedReceiverType, call.EndLine = site.call.ResolvedReceiverType, site.call.EndLine
		}
		decl.Calls = append(decl.Calls, call)
	}
}

// anchoredCallSite picks, of the edge sites at a call's span, the one of the
// call: the one of its method and argument count, else the only one of its
// method (a Python edge that resolves exactly records no argument count),
// else the only one.
func anchoredCallSite(sites []*fragmentSite, method string, arity int) *fragmentSite {
	var exact, named *fragmentSite
	exacts, nameds := 0, 0
	for _, site := range sites {
		target, err := callgraph.ParseFunctionID(site.target)
		if err != nil || callgraph.BaseFunctionName(target.Name) != method {
			continue
		}
		nameds++
		named = site
		if len(site.call.Arguments) == arity {
			exacts++
			exact = site
		}
	}
	switch {
	case exacts == 1:
		return exact
	case exacts == 0 && nameds == 1:
		return named
	case len(sites) == 1:
		return sites[0]
	}
	return nil
}

// placeEdgeCalls gives each function a call per call site its edges name, in
// the parser's order where an anchor records it (1.20) and by position
// otherwise.
func placeEdgeCalls(doc *graphfrag.GraphFragmentExport, graph *callgraph.CallGraph, projectRoot string, sites map[fragmentSiteKey]*fragmentSite, order []fragmentSiteKey) {
	anchors := fragmentCallAnchors(doc)
	type placedCall struct {
		order int
		call  callgraph.FunctionCall
	}
	placed := make(map[string][]placedCall)
	for _, key := range order {
		site := sites[key]
		callee, err := callgraph.ParseFunctionID(site.target)
		if err != nil {
			continue
		}
		call := site.call
		call.Callee = callee
		call.FilePath = graph.Functions[key.caller].FilePath
		call.Arguments, call.ArgumentSources = fragmentCallArguments(projectRoot, site.entry, call.Arguments)
		position := len(doc.CallAnchors)
		if anchor, ok := anchors[fragmentAnchorKey{key.caller, key.line, key.startCol, key.endCol}]; ok {
			call.ASTKind, call.NamedASTPath, call.ChainID = anchor.Kind, anchor.Path, anchor.ChainID
			position = anchor.order
		}
		placed[key.caller] = append(placed[key.caller], placedCall{position, call})
	}
	for callerKey, calls := range placed {
		sort.SliceStable(calls, func(i, j int) bool {
			a, b := &calls[i], &calls[j]
			switch {
			case a.order != b.order:
				return a.order < b.order
			case a.call.Line != b.call.Line:
				return a.call.Line < b.call.Line
			default:
				return a.call.StartCol < b.call.StartCol
			}
		})
		decl := graph.Functions[callerKey]
		for i := range calls {
			decl.Calls = append(decl.Calls, calls[i].call)
		}
	}
}

// overrideNonEmpty sets *field to value when value is not empty.
func overrideNonEmpty(field *string, value string) {
	if value != "" {
		*field = value
	}
}

// fillEmpty sets *field to value when it is empty.
func fillEmpty(field *string, value string) {
	if *field == "" {
		*field = value
	}
}

func compactStrings(values []string) []string {
	out := values[:0]
	for i, value := range values {
		if i == 0 || value != values[i-1] {
			out = append(out, value)
		}
	}
	return out
}

// fragmentCallArguments restores a call's argument expressions and their
// provenance from its call-site record. arguments holds one empty slot per
// argument the call passes. As the parser records them, a call with
// arguments has one provenance slot per argument, empty when nothing was
// traced, and a call without has none.
func fragmentCallArguments(root string, entry *graphfrag.GraphFragmentCallSite, arguments []string) ([]string, [][]callgraph.SourceNode) { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if entry != nil {
		for i := range entry.Parameters {
			param := &entry.Parameters[i]
			for len(arguments) <= param.ParameterIndex && param.ArgumentExpression != "" {
				arguments = append(arguments, "")
			}
			if param.ParameterIndex >= 0 && param.ParameterIndex < len(arguments) {
				arguments[param.ParameterIndex] = param.ArgumentExpression
				if param.Keyword != "" {
					// The parser's text of a Python keyword argument.
					arguments[param.ParameterIndex] = param.Keyword + "=" + param.ArgumentExpression
				}
			}
		}
	}
	if len(arguments) == 0 {
		return arguments, nil
	}
	sources := make([][]callgraph.SourceNode, len(arguments))
	if entry != nil {
		for i := range entry.Parameters {
			param := &entry.Parameters[i]
			if param.ParameterIndex >= 0 && param.ParameterIndex < len(sources) {
				sources[param.ParameterIndex] = fragmentSourceNodes(root, param.SourceNodes)
			}
		}
	}
	return arguments, sources
}

func fragmentSourceNodes(root string, nodes []graphfrag.GraphFragmentSourceNode) []callgraph.SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]callgraph.SourceNode, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		out[i] = callgraph.SourceNode{
			Type: node.Type, Name: node.Name, DeclaredType: node.DeclaredType, Value: node.Value,
			MayValues: node.MayValues, MayValuesExhaustive: node.MayValuesExhaustive,
		}
		// The export resolves a parameter through the function's callers and
		// nests their arguments' provenance under it; the graph holds the
		// parameter alone and the passes resolve it again.
		if node.Type != sourceNodeTypeParameter {
			out[i].SourceNodes = fragmentSourceNodes(root, node.SourceNodes)
		}
		if node.ParameterIndex != nil {
			out[i].ParameterIndex = *node.ParameterIndex
		}
		if node.CallTarget != "" {
			if target, err := callgraph.ParseFunctionID(node.CallTarget); err == nil {
				out[i].CallTarget = &target
			}
		}
		if node.Location != nil {
			out[i].Location = &callgraph.SourceLocation{Line: node.Location.Line}
			if node.Location.FilePath != "" {
				out[i].Location.FilePath = filepath.Join(root, filepath.FromSlash(node.Location.FilePath))
			}
		}
	}
	return out
}

// nameFragmentParameters names decl's parameters, which a fragment lists by
// type only, after the parameters its own calls pass: an argument traced to
// a parameter of decl names it. A parameter no call passes, or that two
// calls name differently, stays unnamed.
func nameFragmentParameters(decl *callgraph.FunctionDecl) {
	names := make(map[int]string)
	conflict := make(map[int]bool)
	for i := range decl.Calls {
		for _, sources := range decl.Calls[i].ArgumentSources {
			for j := range sources {
				node := &sources[j]
				if node.Type != sourceNodeTypeParameter || node.ParameterIndex < 0 || node.ParameterIndex >= len(decl.Parameters) {
					continue
				}
				if name, seen := names[node.ParameterIndex]; seen && name != node.Name {
					conflict[node.ParameterIndex] = true
				}
				names[node.ParameterIndex] = node.Name
			}
		}
	}
	for index, name := range names {
		if !conflict[index] {
			decl.Parameters[index].Name = name
		}
	}
}

// fragmentAnchorKey is the function and span a call anchor is recorded at.
type fragmentAnchorKey struct {
	function               string
	line, startCol, endCol int
}

// fragmentAnchor is a call anchor and its place among the fragment's
// anchors, which is the parser's order within a function.
type fragmentAnchor struct {
	graphfrag.GraphFragmentCallAnchor
	order int
}

// fragmentCallAnchors indexes the fragment's call anchors (1.20) by function
// and span. Of two anchors at one span the first is kept.
func fragmentCallAnchors(doc *graphfrag.GraphFragmentExport) map[fragmentAnchorKey]fragmentAnchor {
	anchors := make(map[fragmentAnchorKey]fragmentAnchor, len(doc.CallAnchors))
	for i, anchor := range doc.CallAnchors {
		if anchor.Function < 0 || anchor.Function >= len(doc.Functions) {
			continue
		}
		key := fragmentAnchorKey{doc.Functions[anchor.Function].Key, anchor.Line, anchor.StartCol, anchor.EndCol}
		if _, seen := anchors[key]; !seen {
			anchors[key] = fragmentAnchor{anchor, i}
		}
	}
	return anchors
}

// fragmentSiteKey identifies one call in a fragment: its caller and span,
// and the method name and argument count every edge of the call shares.
type fragmentSiteKey struct {
	caller                 string
	line, startCol, endCol int
	method                 string
	arity                  int
}

// fragmentSite is one call and the edge whose target stands for it.
type fragmentSite struct {
	call       callgraph.FunctionCall
	entry      *graphfrag.GraphFragmentCallSite
	target     string
	resolution string
}

// fragmentResolutionRank orders the edges of one call: the exact target is
// the call's own; a dispatch or name-only edge is one of its expansions.
func fragmentResolutionRank(resolution string) int {
	switch callgraph.EdgeKind(resolution) {
	case callgraph.EdgeKindExact:
		return 2
	case callgraph.EdgeKindNameOnly:
		return 0
	case callgraph.EdgeKindInterfaceDispatch, callgraph.EdgeKindPythonSubclassDispatch:
		return 1
	default:
		return 1
	}
}
