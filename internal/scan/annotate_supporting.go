// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// fragEdge is a caller's outgoing call site projected from a graph-fragment-1.4
// edge (internal or external), normalized to the fields the supporting-call
// derivation needs. It is the cache-side analogue of a callgraph.FunctionCall.
type fragEdge struct {
	callerKey string
	calleeKey string
	raw       string
	line      int
	identity  objectIdentity
	entryCall *graphfrag.CallSite
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
// caller function key, projecting each to a fragEdge.
func fragmentEdgesByCaller(fragment graphfrag.Fragment) map[string][]fragEdge {
	out := make(map[string][]fragEdge)
	for i := range fragment.ExternalCalls {
		e := &fragment.ExternalCalls[i]
		out[e.Caller] = append(out[e.Caller], fragEdge{
			callerKey: e.Caller,
			calleeKey: e.TargetSignature,
			raw:       e.Raw,
			line:      e.CallSite,
			identity:  objectIdentity{ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar, ChainID: e.ChainID},
			entryCall: e.EntryCall,
		})
	}
	for i := range fragment.InternalEdges {
		e := &fragment.InternalEdges[i]
		out[e.Caller] = append(out[e.Caller], fragEdge{
			callerKey: e.Caller,
			calleeKey: e.Callee,
			line:      e.CallSite,
			identity:  objectIdentity{ReceiverVar: e.ReceiverVar, AssignedVar: e.AssignedVar, ChainID: e.ChainID},
			entryCall: e.EntryCall,
		})
	}
	return out
}

// deriveAnnotateSupportingCalls re-derives the object-lifecycle supporting calls
// for the detected (terminal) findings using ONLY the cached fragment's enriched
// edges — no live call graph. It mirrors the live exporter: select lifecycle
// siblings with the shared isLifecycleSibling policy, then build each entry with
// the same id-based metadata helpers, so the output matches a full
// `scan --export-graph-fragment` for the same source + rules.
func deriveAnnotateSupportingCalls(report *entities.InterimReport, fragment graphfrag.Fragment) []graphfrag.GraphFragmentSupporting {
	if report == nil {
		return nil
	}
	edgesByCaller := fragmentEdgesByCaller(fragment)

	var out []graphfrag.GraphFragmentSupporting
	seen := make(map[string]bool)
	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			if isSupportingCryptoAsset(asset) {
				continue
			}
			fn, ok := annotateContainingFunction(fragment, finding.FilePath, asset.StartLine)
			if !ok {
				continue
			}
			edges := edgesByCaller[fn.Signature]
			terminalIdx := terminalEdgeIndex(edges, asset)
			if terminalIdx < 0 {
				continue
			}
			terminalID := edges[terminalIdx].identity
			for j := range edges {
				if j == terminalIdx {
					continue
				}
				if !isLifecycleSibling(edges[j].identity, terminalID) {
					continue
				}
				// The supporting call lives in the finding's file; use the
				// detection finding's (normalized, relative) path for the
				// file_path and the path-derived supporting_id so both match the
				// live exporter (the fragment's function FilePath is absolute).
				sc := buildAnnotateSupportingFromEdge(fn, finding.FilePath, edges[j])
				if sc.SupportingID == "" || seen[sc.SupportingID] {
					continue
				}
				seen[sc.SupportingID] = true
				out = append(out, sc)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SupportingID < out[j].SupportingID })
	return out
}

// terminalEdgeIndex finds the edge that is the terminal crypto call for asset:
// an edge on the finding's line whose resolved function name matches the asset's
// crypto symbol. Falls back to any edge on the finding's line so the object
// identity (receiver/chain) can still seed the lifecycle grouping.
func terminalEdgeIndex(edges []fragEdge, asset entities.CryptographicAsset) int {
	var symbol string
	if op := buildMatchedOperation(asset); op != nil {
		symbol = op.Symbol
	}
	// Among edges on the finding's line, prefer the one whose resolved name
	// matches the asset's crypto symbol (exact or glob, e.g. "...HashBuilder.with*").
	// Otherwise fall back to the outermost fluent link — the link with the longest
	// Raw expression — which is the actual terminal of a chain. Picking the
	// outermost link matters: it carries the chain's result-binding (AssignedVar),
	// which seeds the lifecycle identity for separate-statement siblings.
	best := -1
	for i := range edges {
		if edges[i].line != asset.StartLine {
			continue
		}
		if symbol != "" && symbolMatchesFunction(symbol, edges[i].functionName()) {
			return i
		}
		if best == -1 || len(edges[i].raw) > len(edges[best].raw) {
			best = i
		}
	}
	return best
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
func buildAnnotateSupportingFromEdge(fn graphfrag.Function, sourcePath string, e fragEdge) graphfrag.GraphFragmentSupporting {
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
	calleeID, _ := callgraph.ParseFunctionID(e.calleeKey)
	funcName := fullFunctionName(calleeID)
	if funcName == "" {
		funcName = e.functionName()
	}
	returnType := normalizeExportReturnType(calleeID, "")
	displaySymbol, aliases := exportDisplaySymbolAndAliases(calleeID, funcName)

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

// annotateTerminalCryptoCall re-derives the terminal crypto_call for a finding
// from the cached fragment's edges. Returns nil when the finding's containing
// function or terminal edge cannot be located.
func annotateTerminalCryptoCall(fragment graphfrag.Fragment, edgesByCaller map[string][]fragEdge, finding entities.Finding, asset entities.CryptographicAsset) *graphfrag.GraphFragmentCryptoCall {
	fn, ok := annotateContainingFunction(fragment, finding.FilePath, asset.StartLine)
	if !ok {
		return nil
	}
	edges := edgesByCaller[fn.Signature]
	ti := terminalEdgeIndex(edges, asset)
	if ti < 0 {
		return nil
	}
	return fragmentCryptoCallFromEdge(edges[ti])
}
