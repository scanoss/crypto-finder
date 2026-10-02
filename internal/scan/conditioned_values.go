// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"sort"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// maxConditionedSelectorValues bounds the distinct values one parameter may
// contribute to specialization. Hitting it is logged and reported: the
// specialized findings and their anchor read analysis.call_chains as partial.
const maxConditionedSelectorValues = 256

// maxConditionedWalkDepth bounds how many callers deep the value enumeration
// follows a parameter. It is independent of the chain export, which has no
// depth cap: the walk is exponential in fan-in, so it needs its own bound.
const maxConditionedWalkDepth = 32

// conditionedValueEnumerator finds every distinct value that reaches a
// selector argument by following its PARAMETER provenance through all callers,
// independent of the sampled call chains. Each step reuses the chain step
// itself (buildEntryCall, then propagateParameterProvenance), so one value
// resolves the same way here as on an exported chain.
type conditionedValueEnumerator struct {
	ctx      *exportBuildContext
	maxDepth int
	maxValue int
	memo     map[string][]conditionedUpstreamCall
	onStack  map[string]bool
	// walkMemo holds every (function, parameter) result of the current
	// top-level walk, partial ones included. A cycle or the depth cap makes a
	// result partial from that entry, and memo keeps only complete ones, so
	// without this every function below a recursion was re-walked once per
	// path: exponential in the fan-in depth. Reusing a partial result within
	// one walk loses nothing at its root, because a value cut at an ancestor
	// still on the stack reaches the root through that ancestor's own walk.
	walkMemo map[string][]conditionedUpstreamCall
	// walks counts collectCallerArguments calls, for tests of the walk's cost.
	walks int
	// truncated records that the depth cap or the value bound cut an
	// enumeration, so a caller value may be missing. A cycle does not set it:
	// a value cut at an ancestor still on the stack reaches the root through
	// that ancestor's own walk. terminalVariants resets it per call.
	truncated bool
	// dynamic records that some route into the parameter being walked carries
	// no resolved value: a call site passes a dynamic expression, or nothing
	// calls the function at all. dynamicMemo remembers it per (function,
	// parameter), so a cached walk still reports it. terminalVariants resets
	// dynamic per parameter.
	dynamic     bool
	dynamicMemo map[string]bool
}

// conditionedUpstreamCall is the argument list of one call into a function,
// with provenance already propagated from that call's own callers.
type conditionedUpstreamCall struct {
	params   []callGraphParameter
	filePath string
	line     int
}

func newConditionedValueEnumerator(ctx *exportBuildContext) *conditionedValueEnumerator {
	return &conditionedValueEnumerator{
		ctx:         ctx,
		maxDepth:    maxConditionedWalkDepth,
		maxValue:    maxConditionedSelectorValues,
		memo:        make(map[string][]conditionedUpstreamCall),
		onStack:     make(map[string]bool),
		dynamicMemo: make(map[string]bool),
	}
}

// terminalVariants returns copies of the terminal call's parameters, one per
// distinct caller value of each unresolved parameter. truncated reports that
// the depth cap or the value bound cut an enumeration, so some caller value
// may be missing from the result. dynamic lists the parameter indices that
// some route reaches with no resolved value, which no variant stands for.
func (e *conditionedValueEnumerator) terminalVariants(owner callgraph.FunctionID, params []callGraphParameter) (variants [][]callGraphParameter, truncated bool, dynamic map[int]bool) {
	e.truncated = false
	dynamic = make(map[int]bool)
	for index := range params {
		if params[index].ResolvedValue != "" {
			continue
		}
		e.walkMemo = make(map[string][]conditionedUpstreamCall)
		e.dynamic = false
		resolved, _ := e.resolveVariants(owner, params, index, 0)
		variants = append(variants, resolved...)
		if e.dynamic {
			dynamic[index] = true
		}
	}
	return variants, e.truncated, dynamic
}

// resolveVariants returns copies of params, a call made inside owner, in which
// params[index] resolved through owner's callers: one copy per distinct value.
// complete is false when a cycle, the depth cap or the value bound cut the walk.
func (e *conditionedValueEnumerator) resolveVariants(
	owner callgraph.FunctionID,
	params []callGraphParameter,
	index, depth int,
) (variants [][]callGraphParameter, complete bool) {
	if params[index].ResolvedValue != "" {
		return [][]callGraphParameter{params}, true
	}
	complete = true
	seen := make(map[string]struct{})
	callerIndices := propagatedParameterIndices(params[index].SourceNodes)
	if len(callerIndices) == 0 {
		e.dynamic = true
	}
	for _, callerIndex := range callerIndices {
		upstream, upstreamComplete := e.callerArguments(owner, callerIndex, depth)
		if upstreamComplete && len(upstream) == 0 {
			e.dynamic = true
		}
		complete = complete && upstreamComplete
		for _, call := range upstream {
			variant := cloneCallGraphParameters(params)
			propagateParameterProvenance(variant, call.params, call.filePath, call.line)
			admitted, full := e.admit(seen, variant[index].ResolvedValue)
			if full {
				e.logValueBound(owner, index)
				return variants, false
			}
			if admitted {
				variants = append(variants, variant)
			}
		}
	}
	return variants, complete
}

// callerArguments returns the argument lists of every call into fn whose
// argument at index resolved, one per distinct value of that argument.
func (e *conditionedValueEnumerator) callerArguments(fn callgraph.FunctionID, index, depth int) ([]conditionedUpstreamCall, bool) {
	key := fn.String() + "\x00" + strconv.Itoa(index)
	if cached, ok := e.memo[key]; ok {
		e.dynamic = e.dynamic || e.dynamicMemo[key]
		return cached, true
	}
	if cached, ok := e.walkMemo[key]; ok {
		e.dynamic = e.dynamic || e.dynamicMemo[key]
		return cached, false
	}
	if e.onStack[key] {
		return nil, false
	}
	if depth >= e.maxDepth {
		e.truncated = true
		log.Warn().Str("function", fn.String()).Int("parameter_index", index).Int("max_depth", e.maxDepth).
			Msg("Selector value enumeration hit the depth cap; remaining caller values are not specialized")
		return nil, false
	}
	e.onStack[key] = true
	outerDynamic := e.dynamic
	e.dynamic = false
	calls, complete := e.collectCallerArguments(fn, index, depth)
	delete(e.onStack, key)
	if e.dynamic {
		e.dynamicMemo[key] = true
	}
	e.dynamic = e.dynamic || outerDynamic
	// A walk a cycle cut short is only partial from this entry; recompute it
	// from the next one instead of caching the partial set.
	if complete {
		e.memo[key] = calls
	} else if e.walkMemo != nil {
		e.walkMemo[key] = calls
	}
	return calls, complete
}

func (e *conditionedValueEnumerator) collectCallerArguments(fn callgraph.FunctionID, index, depth int) ([]conditionedUpstreamCall, bool) {
	e.walks++
	complete := true
	seen := make(map[string]struct{})
	var calls []conditionedUpstreamCall
	for _, callerKey := range e.ctx.reverseCallersOf(fn.String()) {
		callerFn := e.ctx.graph.Functions[callerKey]
		if callerFn == nil {
			continue
		}
		for _, call := range matchingInvocations(callerFn, fn.String()) {
			site, siteComplete := e.callSiteArguments(callerFn, call, fn, index, depth)
			complete = complete && siteComplete
			for _, upstream := range site {
				admitted, full := e.admit(seen, upstream.params[index].ResolvedValue)
				if full {
					e.logValueBound(fn, index)
					return calls, false
				}
				if admitted {
					calls = append(calls, upstream)
				}
			}
		}
	}
	return calls, complete
}

// callSiteArguments builds the argument list of one call into fn, exactly as an
// exported chain's entry_call, and resolves its argument at index upstream.
func (e *conditionedValueEnumerator) callSiteArguments(
	callerFn *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
	fn callgraph.FunctionID,
	index, depth int,
) ([]conditionedUpstreamCall, bool) {
	filePath := call.FilePath
	if filePath == "" {
		filePath = callerFn.FilePath
	}
	entry := buildEntryCall(e.ctx, e.ctx.graph, callerFn.ID, filePath, call.Line, call.StartCol, call.EndCol, fn)
	if index >= len(entry.Parameters) {
		return nil, true
	}
	variants, complete := e.resolveVariants(callerFn.ID, entry.Parameters, index, depth+1)
	calls := make([]conditionedUpstreamCall, len(variants))
	for i := range variants {
		calls[i] = conditionedUpstreamCall{params: variants[i], filePath: entry.FilePath, line: entry.Line}
	}
	return calls, complete
}

// admit records a new resolved value. full reports that the bound was reached
// before this new value could be added.
func (e *conditionedValueEnumerator) admit(seen map[string]struct{}, value string) (admitted, full bool) {
	if _, duplicate := seen[value]; value == "" || duplicate {
		return false, false
	}
	if len(seen) >= e.maxValue {
		return false, true
	}
	seen[value] = struct{}{}
	return true, false
}

func (e *conditionedValueEnumerator) logValueBound(fn callgraph.FunctionID, index int) {
	e.truncated = true
	log.Warn().Str("function", fn.String()).Int("parameter_index", index).Int("max_values", e.maxValue).
		Msg("Selector value enumeration hit its bound; remaining caller values are not specialized")
}

// propagatedParameterIndices lists the caller parameter indices that
// propagateSourceNodeChildren would fill for these nodes: top-level PARAMETER
// nodes and those nested under CALL_RESULT nodes.
func propagatedParameterIndices(nodes []exportSourceNode) []int {
	set := make(map[int]struct{})
	collectPropagatedParameterIndices(nodes, set)
	indices := make([]int, 0, len(set))
	for index := range set {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices
}

func collectPropagatedParameterIndices(nodes []exportSourceNode, set map[int]struct{}) {
	for i := range nodes {
		switch nodes[i].Type {
		case sourceNodeTypeCallResult:
			collectPropagatedParameterIndices(nodes[i].SourceNodes, set)
		case sourceNodeTypeParameter:
			if nodes[i].ParameterIndex != nil && *nodes[i].ParameterIndex >= 0 {
				set[*nodes[i].ParameterIndex] = struct{}{}
			}
		}
	}
}
