// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"sort"
	"strings"

	"github.com/scanoss/static-engine/callgraph"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// fragEdge is a caller's outgoing call site projected from a graph-fragment-1.4
// edge (internal or external), normalized to the fields the supporting-call
// derivation needs. It is the cache-side analog of a callgraph.FunctionCall.
type fragEdge struct {
	callerKey string
	calleeKey string
	raw       string
	line      int
	startCol  int
	endCol    int
	identity  objectIdentity
	entryCall *graphfrag.CallSite
	// exact is true when the producer resolved the call to calleeKey exactly,
	// so calleeKey is the function the source call names. A dispatch or
	// name-only edge leads to one candidate implementation of it instead.
	exact bool
}

// view projects the edge onto the shared candidateView so the annotate path runs
// the same position/chain terminal selection as the live exporter.
func (e fragEdge) view() candidateView {
	return candidateView{
		StartCol:    e.startCol,
		EndCol:      e.endCol,
		ChainID:     e.identity.ChainID,
		AssignedVar: e.identity.AssignedVar,
		RawLen:      len(e.raw),
		Constructor: strings.HasPrefix(strings.TrimSpace(e.raw), "new ") || isConstructorFunctionKey(e.calleeKey),
	}
}

func isConstructorFunctionKey(key string) bool {
	id, err := callgraph.ParseFunctionID(key)
	return err == nil && callgraph.BaseFunctionName(id.Name) == constructorMethodName
}

// functionName derives the dotted callee name from the edge's callee key, the
// same value fullFunctionName produces in the live exporter.
func (e fragEdge) functionName() string {
	id, err := callgraph.ParseFunctionID(e.calleeKey)
	if err != nil {
		return ""
	}
	return fullFunctionName(id)
}

// fragmentEdgesByCaller indexes a fragment's edges (external + internal) by the
// caller function key, projecting each to a fragEdge. Each caller's edges are
// put back in source order, the order the parser recorded the calls in: a call
// starts before the calls nested in it and ends after them. The lifecycle
// selector reads a variable's calls only after the call that bound it, and the
// fragment lists edges by target, which would hide `h.update(..)` from the
// factory call `h = sha256()` whenever update sorts first.
func fragmentEdgesByCaller(fragment graphfrag.Fragment) map[string][]fragEdge {
	out := make(map[string][]fragEdge)
	for i := range fragment.ExternalCalls {
		e := &fragment.ExternalCalls[i]
		out[e.Caller] = append(out[e.Caller], fragEdge{
			callerKey: e.Caller,
			calleeKey: e.TargetSignature,
			raw:       e.Raw,
			line:      e.CallSite,
			startCol:  e.StartCol,
			endCol:    e.EndCol,
			identity:  objectIdentity{ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar, ChainID: e.ChainID},
			entryCall: e.EntryCall,
			exact:     e.Resolution == graphfrag.ResolutionExact,
		})
	}
	for i := range fragment.InternalEdges {
		e := &fragment.InternalEdges[i]
		out[e.Caller] = append(out[e.Caller], fragEdge{
			callerKey: e.Caller,
			calleeKey: e.Callee,
			line:      e.CallSite,
			startCol:  e.StartCol,
			endCol:    e.EndCol,
			identity:  objectIdentity{ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar, ChainID: e.ChainID},
			entryCall: e.EntryCall,
			exact:     e.Resolution == graphfrag.ResolutionExact,
		})
	}
	for _, edges := range out {
		sort.SliceStable(edges, func(i, j int) bool {
			a, b := edges[i], edges[j]
			if a.line != b.line {
				return a.line < b.line
			}
			if a.startCol != b.startCol {
				return a.startCol < b.startCol
			}
			return a.endCol > b.endCol
		})
	}
	return out
}

// annotateIndex is a cached fragment indexed for annotate: each function's
// edges in source order, and the callers and returned calls the
// returned-object walk reads. It is the fragment's returnedObjectGraph.
type annotateIndex struct {
	edgesByCaller map[string][]fragEdge
	functions     map[string]*graphfrag.Function
	callersOf     map[string][]string
}

func newAnnotateIndex(fragment graphfrag.Fragment) *annotateIndex {
	idx := &annotateIndex{
		edgesByCaller: fragmentEdgesByCaller(fragment),
		functions:     make(map[string]*graphfrag.Function, len(fragment.Functions)),
		callersOf:     make(map[string][]string),
	}
	for i := range fragment.Functions {
		idx.functions[fragment.Functions[i].Signature] = &fragment.Functions[i]
	}
	for _, callerKey := range sortedKeys(idx.edgesByCaller) {
		if idx.functions[callerKey] == nil {
			continue
		}
		seen := map[string]bool{}
		for i := range idx.edgesByCaller[callerKey] {
			e := &idx.edgesByCaller[callerKey][i]
			if e.exact && idx.functions[e.calleeKey] != nil && !seen[e.calleeKey] {
				seen[e.calleeKey] = true
				idx.callersOf[e.calleeKey] = append(idx.callersOf[e.calleeKey], callerKey)
			}
		}
	}
	return idx
}

func (idx *annotateIndex) callers(fnKey string) []string {
	return idx.callersOf[fnKey]
}

// calls names an edge's callee only when the edge is exact, the one case the
// live walk's call names the same function.
func (idx *annotateIndex) calls(fnKey string) []returnedObjectCall {
	edges := idx.edgesByCaller[fnKey]
	out := make([]returnedObjectCall, len(edges))
	for i := range edges {
		out[i].identity = edges[i].identity
		if edges[i].exact {
			out[i].callee = edges[i].calleeKey
		}
	}
	return out
}

// returnsCall reads the function's returns_calls. A fragment without it
// (graph-fragment-1.14 and older) returns nothing, so annotate follows no
// returned object, as before.
func (idx *annotateIndex) returnsCall(fnKey string, call int) bool {
	fn := idx.functions[fnKey]
	edges := idx.edgesByCaller[fnKey]
	if fn == nil || call < 0 || call >= len(edges) || !edges[call].exact {
		return false
	}
	return slices.Contains(fn.ReturnsCalls, edges[call].calleeKey)
}

// deriveAnnotateSupportingCalls re-derives the object-lifecycle supporting calls
// for the detected (terminal) findings using ONLY the cached fragment's enriched
// edges — no live call graph. It mirrors the live exporter: select lifecycle
// siblings with the shared isLifecycleSibling policy, then build each entry with
// the same id-based metadata helpers, so the output matches a full
// `scan --export-graph-fragment` for the same source + rules.
func deriveAnnotateSupportingCalls(report *oid.ResolvedReport, fragment graphfrag.Fragment) []graphfrag.GraphFragmentSupporting {
	if report == nil {
		return nil
	}
	idx := newAnnotateIndex(fragment)
	keyLengthsByID := make(map[string]*graphfrag.ResolvedKeyLength, len(fragment.SupportingCalls))
	for i := range fragment.SupportingCalls {
		supporting := &fragment.SupportingCalls[i]
		if supporting.SupportingCall == nil || supporting.SupportingCall.ResolvedKeyLength == nil {
			continue
		}
		keyLengthsByID[supporting.SupportingID] = supporting.SupportingCall.ResolvedKeyLength
	}

	var out []graphfrag.GraphFragmentSupporting
	seen := make(map[string]int)
	for i := range report.Findings {
		finding := &report.Findings[i]
		for a := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[a]
			calls := annotateSupportingForAsset(fragment, idx, *finding, asset)
			// The cached bits are structural and survive a rules refresh, but the
			// rule-vs-callgraph conflict marker is rule-derived: clone the cached
			// evidence per asset and recompute the marker against the fresh rule
			// metadata, so annotate never republishes a stale conflict.
			declared := ruleDeclaredKeyLength(asset)
			for j := range calls {
				keyLength, ok := keyLengthsByID[calls[j].SupportingID]
				if !ok || calls[j].SupportingCall == nil {
					continue
				}
				resolved := keyLength.Clone()
				applyRuleKeyLengthConflict(resolved, declared)
				calls[j].SupportingCall.ResolvedKeyLength = resolved
			}
			appendUniqueAnnotateSupporting(&out, seen, calls)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SupportingID < out[j].SupportingID })
	return out
}

// annotateSupportingForAsset derives a finding's supporting calls from the
// cached fragment: the lifecycle of its object in its own function, then, when
// the function returns that object, its lifecycle in the callers that keep it
// (returnedObjectSites, the walk a scan runs).
func annotateSupportingForAsset(
	fragment graphfrag.Fragment,
	idx *annotateIndex,
	finding entities.Finding,
	asset entities.CryptographicAsset,
) []graphfrag.GraphFragmentSupporting {
	fn, ok := annotateContainingFunction(fragment, finding.FilePath, asset.StartLine)
	if !ok {
		return nil
	}
	edges := idx.edgesByCaller[fn.Signature]
	terminalIdx := terminalEdgeIndex(edges, asset)
	if terminalIdx < 0 {
		return nil
	}
	out := annotateLifecycleSiblings(&fn, finding.FilePath, edges, terminalIdx)
	for _, site := range returnedObjectSites(idx, fn.Signature, terminalIdx) {
		caller := idx.functions[site.fnKey]
		out = append(out, buildAnnotateSupportingFromEdge(caller, caller.FilePath, idx.edgesByCaller[site.fnKey][site.call]))
	}
	return out
}

func annotateLifecycleSiblings(
	fn *graphfrag.Function,
	sourcePath string,
	edges []fragEdge,
	terminalIdx int,
) []graphfrag.GraphFragmentSupporting {
	identities := make([]objectIdentity, len(edges))
	for i := range edges {
		identities[i] = edges[i].identity
	}
	indices := lifecycleCallIndices(identities, terminalIdx)
	out := make([]graphfrag.GraphFragmentSupporting, 0, len(indices))
	for _, i := range indices {
		// The supporting call lives in the finding's file; use the detection
		// finding's normalized, relative path for file_path and the
		// path-derived supporting_id so both match the live exporter.
		out = append(out, buildAnnotateSupportingFromEdge(fn, sourcePath, edges[i]))
	}
	return out
}

// appendUniqueAnnotateSupporting keeps the first entry per supporting_id and
// folds each later claimant's rule-declared key-length conflict into it, so a
// supporting call shared by several findings never loses one of their conflicts.
func appendUniqueAnnotateSupporting(
	out *[]graphfrag.GraphFragmentSupporting,
	seen map[string]int,
	calls []graphfrag.GraphFragmentSupporting,
) {
	for i := range calls {
		id := calls[i].SupportingID
		if id == "" {
			continue
		}
		if kept, exists := seen[id]; exists {
			mergeRuleKeyLengthConflict(annotateSupportingKeyLength(&(*out)[kept]), annotateSupportingKeyLength(&calls[i]))
			continue
		}
		seen[id] = len(*out)
		*out = append(*out, calls[i])
	}
}

// annotateSupportingKeyLength returns the key-length evidence carried by a
// graph-fragment supporting-call entry, or nil when it carries none.
func annotateSupportingKeyLength(call *graphfrag.GraphFragmentSupporting) *graphfrag.ResolvedKeyLength {
	if call == nil || call.SupportingCall == nil {
		return nil
	}
	return call.SupportingCall.ResolvedKeyLength
}

// supportingIDsFromAnnotate returns the sorted, de-duplicated supporting_id
// values of one finding's derived supporting calls — the per-finding breadcrumb
// stored on crypto_annotation.supporting_call_ids. It mirrors supportingCallIDsOf
// (the live exporter's helper) for the fragment-shaped GraphFragmentSupporting, so
// the annotate path and the full export produce identical ids per finding.
func supportingIDsFromAnnotate(calls []graphfrag.GraphFragmentSupporting) []string {
	if len(calls) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(calls))
	ids := make([]string, 0, len(calls))
	for i := range calls {
		id := calls[i].SupportingID
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// edgeCandidateViews projects every edge onto the shared candidateView so the
// annotate path runs the identical position/chain terminal selection as the live
// exporter.
func edgeCandidateViews(edges []fragEdge) []candidateView {
	views := make([]candidateView, len(edges))
	for i := range edges {
		views[i] = edges[i].view()
	}
	return views
}

// terminalEdgeIndex selects the edge that is the terminal crypto call for asset,
// running the SAME position/chain selection policy (terminal_selection.go) as the
// live exporter (findCryptoCallNode) over the cached fragment's edges. Because
// graph-fragment 1.4 edges now carry call columns (start_col/end_col), the
// source-position anchor is identical on both paths — so a finding's terminal,
// and therefore its derived supporting calls, match a live
// `scan --export-graph-fragment` even on nested / multi-call / fluent-chain lines.
//
// Steps mirror findCryptoCallNode:
//  1. line-range candidates (edges on the finding's line);
//  2. column intersection and tightest containing span (shared columnFilterIndices);
//  3. chain-root, then longest-chain tie-break (shared);
//  4. fallback for legacy column-less fragments (schema < 1.4, every column 0) or
//     non-chain calls: see annotateNonChainEdgeIndex.
func terminalEdgeIndex(edges []fragEdge, asset entities.CryptographicAsset) int {
	lineIdx := make([]int, 0, len(edges))
	for i := range edges {
		if edges[i].line == asset.StartLine {
			lineIdx = append(lineIdx, i)
		}
	}
	if len(lineIdx) == 0 {
		return -1
	}

	views := edgeCandidateViews(edges)
	colIdx := columnFilterIndices(views, lineIdx, asset.StartCol, asset.EndCol)

	if i := chainRootIndexAmong(views, colIdx); i >= 0 {
		return i
	}
	if i := longestChainIndexAmong(views, colIdx); i >= 0 {
		return i
	}
	return annotateNonChainEdgeIndex(edges, views, colIdx, asset)
}

// annotateNonChainEdgeIndex is the column-less / non-chain fallback used when
// neither columns nor fluent-chain structure single out a terminal. The live path
// uses graph-aware scoring (resolved callee / args) here; the annotate path has no
// live graph, so it uses the one resolved-name signal it carries — the rule's
// crypto symbol (exact or glob, e.g. "...HashBuilder.with*") — and otherwise the
// deterministic lowest-StartCol candidate, matching the live path's final
// tie-break.
func annotateNonChainEdgeIndex(edges []fragEdge, views []candidateView, idxs []int, asset entities.CryptographicAsset) int {
	if len(idxs) == 0 {
		return -1
	}
	var symbol string
	if op := buildMatchedOperation(asset); op != nil {
		symbol = op.Symbol
	}
	if symbol != "" {
		for _, i := range idxs {
			if symbolMatchesFunction(symbol, edges[i].functionName()) {
				return i
			}
		}
	}
	return lowestStartColIndexAmong(views, idxs)
}

// symbolMatchesFunction reports whether a crypto-rule api symbol matches a
// resolved function name. A trailing "*" (e.g. "com.password4j.HashBuilder.with*")
// is treated as a prefix glob, mirroring how the detection rules express
// method-family apis; otherwise the match is exact.
func symbolMatchesFunction(symbol, functionName string) bool {
	if strings.HasSuffix(symbol, "*") {
		return strings.HasPrefix(functionName, strings.TrimSuffix(symbol, "*"))
	}
	return symbol == functionName
}

// buildAnnotateSupportingFromEdge renders one supporting-call entry from a
// fragment edge + its containing function, reproducing the live exporter's shape
// via the shared id-based metadata helpers and the edge's carried call-site args.
func buildAnnotateSupportingFromEdge(fn *graphfrag.Function, sourcePath string, e fragEdge) graphfrag.GraphFragmentSupporting {
	call := fragmentCryptoCallFromEdge(e)
	return graphfrag.GraphFragmentSupporting{
		SupportingID:       supportingIDFromParts(sourcePath, e.line, e.calleeKey),
		FunctionKey:        fn.Signature,
		FunctionName:       fn.FunctionName,
		CanonicalSignature: fn.CanonicalSignature,
		DisplaySymbol:      fn.DisplaySymbol,
		Aliases:            fn.Aliases,
		FilePath:           sourcePath,
		StartLine:          e.line,
		EndLine:            e.line,
		MatchedOperation: &graphfrag.GraphFragmentMatchedOp{
			Kind:       matchedOperationCall,
			Symbol:     call.FunctionName,
			Expression: e.raw,
			Line:       e.line,
		},
		SupportingCall: call,
	}
}

// fragmentCryptoCallFromEdge renders the called-function detail (identity +
// call-site args) from a fragment edge, reusing the live exporter's id-based
// metadata helpers + the edge's carried EntryCall. Shared by the supporting-call
// derivation and the terminal crypto_call re-derivation (annotate path), so a
// new rule's finding gets a crypto_call from the cached structural fragment
// without a live callgraph.
func fragmentCryptoCallFromEdge(e fragEdge) *graphfrag.GraphFragmentCryptoCall {
	funcName, returnType, displaySymbol, aliases := fragmentCallMetadata(e)

	call := &graphfrag.GraphFragmentCryptoCall{
		FunctionName:       funcName,
		CanonicalSignature: canonicalSignature(funcName, nil, returnType),
		ReturnType:         returnType,
		DisplaySymbol:      displaySymbol,
		Aliases:            aliases,
		Line:               e.line,
	}
	if e.entryCall != nil {
		for i := range e.entryCall.Parameters {
			call.Parameters = append(call.Parameters, fragmentParameterFromModel(e.entryCall.Parameters[i]))
		}
	}
	return call
}

func fragmentCallMetadata(e fragEdge) (string, string, string, []string) {
	calleeID, err := callgraph.ParseFunctionID(e.calleeKey)
	if err != nil {
		return e.calleeKey, "", e.calleeKey, nil
	}

	funcName := fullFunctionName(calleeID)
	if funcName == "" {
		funcName = e.calleeKey
	}
	returnType := normalizeExportReturnType(calleeID, "")
	displaySymbol, aliases := exportDisplaySymbolAndAliases(calleeID, funcName)
	return funcName, returnType, displaySymbol, aliases
}

// annotateTerminalCryptoCall re-derives the terminal crypto_call for a finding
// from the cached fragment's edges. Returns nil when the finding's containing
// function or terminal edge cannot be located.
func annotateTerminalCryptoCall(fragment graphfrag.Fragment, idx *annotateIndex, finding entities.Finding, asset entities.CryptographicAsset) *graphfrag.GraphFragmentCryptoCall {
	fn, ok := annotateContainingFunction(fragment, finding.FilePath, asset.StartLine)
	if !ok {
		return nil
	}
	edges := idx.edgesByCaller[fn.Signature]
	ti := terminalEdgeIndex(edges, asset)
	if ti < 0 {
		return nil
	}
	return fragmentCryptoCallFromEdge(edges[ti])
}
