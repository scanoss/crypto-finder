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
	"maps"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
)

// dependencySidePackage is the package of the stand-in functions
// UnreachableCallers traces back from. No source declares it, so it is never
// user code.
const dependencySidePackage = "<dependency>"

// UnreachableCallers returns the functions of fragment that call out of the
// project and that the project's reachability reads unreachable, keyed as the
// call graph keys them (FunctionID.String(), which a fragment function's Key
// and an external call's CallerKey repeat). project is the result fragment was
// built from, named as the scan's result is (engine.ApplicationClosure.Project).
//
// The question asked of each caller is the one the call graph export asks of
// a finding: is the function the caller calls reachable from the project's
// entry points. The dependency function is not in the project's graph, so a
// stand-in the caller alone calls takes its place, and the same trace back
// over the same user packages, read by liveReachability, answers. The caller
// is therefore a frame of the route and never its target: an uncalled
// function of a project with no entry point is a root, a function passed as
// a value stays one, and a caller the depth limit cut or that only a
// name-only edge reaches reads unknown, which is not unreachable.
//
// It returns nil when the project has no user code to trace to.
func UnreachableCallers(project *engine.DepScanResult, fragment *graphfrag.GraphFragmentExport) map[string]bool {
	if project == nil || project.CallGraph == nil || fragment == nil {
		return nil
	}
	userPackages := projectUserPackages(project)
	if userPackages == nil {
		return nil
	}
	graph := *project.CallGraph
	graph.Functions = maps.Clone(project.CallGraph.Functions)
	graph.Callers = maps.Clone(project.CallGraph.Callers)
	callerOf := make(map[string]string, len(fragment.ExternalCalls))
	var standIns []*callgraph.FunctionDecl
	for i := range fragment.ExternalCalls {
		caller := fragment.ExternalCalls[i].CallerKey
		if _, declared := graph.Functions[caller]; !declared {
			continue
		}
		standIn := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Package: dependencySidePackage, Name: caller}}
		key := standIn.ID.String()
		if _, seen := callerOf[key]; seen {
			continue
		}
		callerOf[key] = caller
		graph.Functions[key] = standIn
		graph.Callers[key] = []string{caller}
		standIns = append(standIns, standIn)
	}

	traced := *project
	traced.CallGraph = &graph
	ctx := newExportPathContext(&traced)
	ctx.userPackages = userPackages
	ctx.packageSeparator = exportPackageSeparator(project.Ecosystem)
	ctx.maxDepth = callGraphExportMaxDepth
	// One chain proves a function reachable; the verdict reads no more.
	ctx.maxChainsBudget = 1
	prewarmTracebacks(ctx, standIns)

	var unreachable map[string]bool
	for _, standIn := range standIns {
		key := standIn.ID.String()
		routed := len(structuralTracebackChains(ctx, standIn)) > 0
		verdict := liveReachability(standIn, userPackages, routed, ctx.callChainDepthLimited[key], ctx.callChainUnresolvedDispatch[key])
		if verdict != graphfrag.ReachabilityUnreachable {
			continue
		}
		if unreachable == nil {
			unreachable = make(map[string]bool)
		}
		unreachable[callerOf[key]] = true
	}
	return unreachable
}

// receiverProducerSite places a call in its function, as both the call graph
// and a fragment's external call record it.
type receiverProducerSite struct {
	caller                 string
	line, startCol, endCol int
}

// AddReceiverProducers names, on each call site of fragment whose receiver is
// the result of a function outside the project, that function
// (graphfrag.GraphFragmentExternal.ReceiverProducer), as project's call graph
// records it: the one call that binds the receiver, a local bound exactly
// once. The API holds that function's graph and reads there the class of the
// object it builds, so the call reaches that class's method and not every
// implementation of the type the project sees.
//
// Only the request carries it. A fragment written by a scan does not, so no
// stored graph changes; and only a Java request does, as only a Java graph
// records what a function builds. It returns how many call sites it named a
// producer on.
func AddReceiverProducers(project *engine.DepScanResult, fragment *graphfrag.GraphFragmentExport) int {
	if project == nil || project.CallGraph == nil || fragment == nil || project.Ecosystem != ecosystemJava {
		return 0
	}
	producers := make(map[receiverProducerSite]string)
	for key, fn := range project.CallGraph.Functions {
		if fn == nil {
			continue
		}
		for i := range fn.Calls {
			if call := &fn.Calls[i]; call.ReceiverProducer != "" {
				producers[receiverProducerSite{key, call.Line, call.StartCol, call.EndCol}] = call.ReceiverProducer
			}
		}
	}
	named := 0
	for i := range fragment.ExternalCalls {
		call := &fragment.ExternalCalls[i]
		if call.ReceiverVar == "" || call.ResolvedReceiverType != "" {
			continue
		}
		call.ReceiverProducer = producers[receiverProducerSite{call.CallerKey, call.Line, call.StartCol, call.EndCol}]
		if call.ReceiverProducer != "" {
			named++
		}
	}
	return named
}
