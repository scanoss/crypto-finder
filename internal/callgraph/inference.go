package callgraph

import (
	"log"
	"sort"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Origin constants for InferredReturn.Origin.
// These values appear verbatim in the exported call graph JSON and in telemetry
// logs. OriginJoinFailed is internal-only: the export layer omits the
// inferred_return field entirely when the origin is join-failed.
const (
	// OriginConstructor indicates the inferred type comes directly from a
	// constructor call expression (new ClassName(...)).
	OriginConstructor = "constructor"

	// OriginKBDirect indicates the inferred type comes from an unconditional
	// KB contract match (e.g. KeyGenerator.generateKey → SecretKey).
	OriginKBDirect = "kb-direct"

	// OriginKBConditional indicates the inferred type comes from an
	// argument-conditional KB contract match (e.g. Cipher.unwrap with SECRET_KEY).
	OriginKBConditional = "kb-conditional"

	// OriginPropagated indicates the inferred type was propagated from a callee
	// that already has an inference result.
	OriginPropagated = "propagated"

	// OriginJoinFailed is an internal-only origin used for telemetry and logging.
	// It is set when the lattice join of multiple return-branch candidates produces
	// no useful common ancestor (e.g. SecretKey ∪ String). The export layer treats
	// this identically to a nil InferredReturn and omits the field entirely.
	OriginJoinFailed = "join-failed"
)

// Confidence constants for InferredReturn.Confidence.
const (
	// ConfidenceHigh indicates a deterministic, single-path inference with no
	// ambiguity (direct constructor, direct KB hit, or unambiguous conditional).
	ConfidenceHigh = "high"

	// ConfidenceMedium indicates an inference with some ambiguity: joined
	// branches, single-plausible conditional match, or a propagated chain
	// whose root was high-confidence but traversed a join point.
	ConfidenceMedium = "medium"

	// ConfidenceLow indicates a low-confidence inference, e.g. a KB authoring
	// conflict where multiple unconditional contracts matched the same key.
	ConfidenceLow = "low"
)

// inferenceMaxIterations caps the fixpoint loop for cyclic SCCs.
// If the SCC has not converged after this many iterations, the best-known
// stable type is used; if none exists, InferredReturn is left nil.
const inferenceMaxIterations = 10

// SourceNode type constants used by the inference engine.
const (
	sourceNodeCallResult = "CALL_RESULT"
	sourceNodeVariable   = "VARIABLE"
	sourceNodeField      = "FIELD"
	sourceNodeParameter  = "PARAMETER"
	sourceNodeValue      = "VALUE"
	sourceNodeExpression = "EXPRESSION"
)

// ---------------------------------------------------------------------------
// inferenceTriggerTypes — declared types for which inference fires.
// Inference is SUPPRESSED when a function already declares a specific,
// useful return type (e.g. "javax.crypto.SecretKey"). It fires only when
// the declared type is vague, absent, or a raw generic.
// ---------------------------------------------------------------------------

//nolint:gochecknoglobals // package-level set is intentional for O(1) lookup
var inferenceTriggerTypes = map[string]struct{}{
	"":                  {},
	"Object":            {},
	"java.lang.Object":  {},
	"byte[]":            {},
	"Object[]":          {},
	"Key":               {},
	"java.security.Key": {},
	"T":                 {},
	"E":                 {},
	"V":                 {},
	"?":                 {},
	// Java primitives
	"int":     {},
	"long":    {},
	"short":   {},
	"byte":    {},
	"float":   {},
	"double":  {},
	"boolean": {},
	"char":    {},
	"void":    {},
}

// shouldInfer returns true when inference should fire for the given declared
// return type. Returns false when the type is already specific and useful.
func shouldInfer(declaredType string) bool {
	_, ok := inferenceTriggerTypes[declaredType]
	return ok || strings.HasSuffix(strings.TrimSpace(declaredType), "*")
}

// ---------------------------------------------------------------------------
// Tarjan SCC
// ---------------------------------------------------------------------------

// tarjanState holds the mutable state for Tarjan's algorithm.
type tarjanState struct {
	graph   *CallGraph
	index   map[string]int
	lowlink map[string]int
	onStack map[string]bool
	stack   []string
	counter int
	result  [][]string // SCCs in reverse-topological order (callees first)
}

// computeSCCs computes Strongly Connected Components of the call graph using
// Tarjan's algorithm. The result is in reverse-topological order (callees
// before callers), which is the correct processing order for the inference
// fixpoint: leaf functions are processed first, allowing callers to propagate
// from already-resolved callees.
func computeSCCs(graph *CallGraph) [][]string {
	ts := &tarjanState{
		graph:   graph,
		index:   make(map[string]int),
		lowlink: make(map[string]int),
		onStack: make(map[string]bool),
	}

	// Process nodes in deterministic order for reproducible output.
	keys := make([]string, 0, len(graph.Functions))
	for k := range graph.Functions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if _, visited := ts.index[k]; !visited {
			ts.strongConnect(k)
		}
	}
	return ts.result
}

func (ts *tarjanState) strongConnect(v string) {
	ts.index[v] = ts.counter
	ts.lowlink[v] = ts.counter
	ts.counter++
	ts.stack = append(ts.stack, v)
	ts.onStack[v] = true

	ts.visitSuccessors(v)

	// v is a root of an SCC.
	if ts.lowlink[v] == ts.index[v] {
		ts.popSCC(v)
	}
}

// visitSuccessors iterates over the call edges of v and updates lowlink values.
func (ts *tarjanState) visitSuccessors(v string) {
	decl, ok := ts.graph.Functions[v]
	if !ok {
		return
	}
	for i := range decl.Calls {
		w := decl.Calls[i].Callee.String()
		if _, exists := ts.graph.Functions[w]; !exists {
			continue
		}
		if _, visited := ts.index[w]; !visited {
			ts.strongConnect(w)
			if ts.lowlink[w] < ts.lowlink[v] {
				ts.lowlink[v] = ts.lowlink[w]
			}
		} else if ts.onStack[w] && ts.index[w] < ts.lowlink[v] {
			ts.lowlink[v] = ts.index[w]
		}
	}
}

// popSCC pops an SCC from the stack starting at v.
func (ts *tarjanState) popSCC(v string) {
	scc := make([]string, 0, len(ts.stack))
	for {
		w := ts.stack[len(ts.stack)-1]
		ts.stack = ts.stack[:len(ts.stack)-1]
		ts.onStack[w] = false
		scc = append(scc, w)
		if w == v {
			break
		}
	}
	ts.result = append(ts.result, scc)
}

// ---------------------------------------------------------------------------
// candidate — internal inference result for a single return-source analysis
// ---------------------------------------------------------------------------

// candidate represents a single typed return-source candidate produced during
// inference. Multiple candidates from multiple return branches are then
// reduced via latticeJoin.
type candidate struct {
	typ        string
	confidence string
	origin     string
}

// ---------------------------------------------------------------------------
// latticeJoin — compute LUB across multiple candidates
// ---------------------------------------------------------------------------

// hierarchy is a type alias for the merged KB+graph hierarchy map.
type hierarchy = map[string][]string

// mergeHierarchy produces a merged view of kb.Hierarchy ∪ graph.TypeHierarchy
// without mutating either source map.
func mergeHierarchy(kb *contracts.KnowledgeBase, graph *CallGraph) hierarchy {
	merged := make(map[string][]string, len(kb.Hierarchy)+len(graph.TypeHierarchy))
	for k, v := range kb.Hierarchy {
		merged[k] = v
	}
	for k, v := range graph.TypeHierarchy {
		// Merge parents without duplicating entries.
		existing := merged[k]
		for _, parent := range v {
			found := false
			for _, ep := range existing {
				if ep == parent {
					found = true
					break
				}
			}
			if !found {
				existing = append(existing, parent)
			}
		}
		merged[k] = existing
	}
	return merged
}

// ancestors returns all ancestor types for the given type in the hierarchy,
// including the type itself, up to but not including java.lang.Object (which is
// a trivial LUB and therefore not useful for inference).
func ancestors(typ string, hier hierarchy) []string {
	visited := make(map[string]struct{})
	var result []string
	var walk func(t string)
	walk = func(t string) {
		if _, seen := visited[t]; seen {
			return
		}
		visited[t] = struct{}{}
		result = append(result, t)
		for _, parent := range hier[t] {
			walk(parent)
		}
	}
	walk(typ)
	return result
}

// downgradeConfidence returns the next-lower confidence level.
func downgradeConfidence(c string) string {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	default:
		return ConfidenceLow
	}
}

// minConfidence returns the lower of two confidence levels.
func minConfidence(a, b string) string {
	order := map[string]int{ConfidenceHigh: 2, ConfidenceMedium: 1, ConfidenceLow: 0}
	if order[a] <= order[b] {
		return a
	}
	return b
}

// isTrivialLUB returns true when the type is a root/universal ancestor that
// adds no useful information (Object, java.lang.Object, empty, or any).
func isTrivialLUB(typ string) bool {
	switch typ {
	case "", "Object", "java.lang.Object", "Any", "any":
		return true
	}
	return false
}

// latticeJoin computes the Least Upper Bound of a slice of typed candidates
// using the provided merged type hierarchy.
//
// Rules (per design §4):
//   - 0 candidates → ok=false (caller should leave InferredReturn nil)
//   - 1 candidate → adopt directly
//   - >1 same type → adopt, confidence = min across candidates
//   - >1 different types, non-trivial LUB → adopt LUB, downgrade confidence once
//   - >1 different types, only trivial LUB (Object) → ok=false (join-failed)
func latticeJoin(cands []candidate, hier hierarchy) (candidate, bool) {
	if len(cands) == 0 {
		return candidate{}, false
	}
	if len(cands) == 1 {
		return cands[0], true
	}
	if allSameType(cands) {
		return joinSameType(cands), true
	}
	return joinDifferentTypes(cands, hier)
}

// allSameType returns true when every candidate has the same type.
func allSameType(cands []candidate) bool {
	for i := 1; i < len(cands); i++ {
		if cands[i].typ != cands[0].typ {
			return false
		}
	}
	return true
}

// joinSameType produces a merged candidate when all types are identical.
func joinSameType(cands []candidate) candidate {
	conf := cands[0].confidence
	for _, c := range cands[1:] {
		conf = minConfidence(conf, c.confidence)
	}
	return candidate{typ: cands[0].typ, confidence: conf, origin: cands[0].origin}
}

// joinDifferentTypes computes the LUB across candidates with different types.
func joinDifferentTypes(cands []candidate, hier hierarchy) (candidate, bool) {
	common := commonAncestors(cands, hier)
	lub := mostSpecificNonTrivial(common, hier)
	if lub == "" {
		return candidate{}, false
	}
	baseConf := minAllConfidence(cands)
	return candidate{typ: lub, confidence: downgradeConfidence(baseConf), origin: OriginPropagated}, true
}

// commonAncestors returns types present in ALL candidates' ancestor sets.
func commonAncestors(cands []candidate, hier hierarchy) []string {
	ancSets := make([][]string, len(cands))
	for i, c := range cands {
		ancSets[i] = ancestors(c.typ, hier)
	}
	var common []string
	for _, a := range ancSets[0] {
		if presentInAll(a, ancSets[1:]) {
			common = append(common, a)
		}
	}
	return common
}

// presentInAll returns true when typ appears in every set.
func presentInAll(typ string, sets [][]string) bool {
	for _, set := range sets {
		found := false
		for _, s := range set {
			if s == typ {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// mostSpecificNonTrivial picks the deepest non-trivial type from a common-ancestor list.
func mostSpecificNonTrivial(common []string, hier hierarchy) string {
	var lub string
	for _, c := range common {
		if isTrivialLUB(c) {
			continue
		}
		if lub == "" {
			lub = c
			continue
		}
		lub = moreSpecific(lub, c, hier)
	}
	return lub
}

// moreSpecific returns the more specific (deeper) of two types in the hierarchy.
// If neither is an ancestor of the other, the first argument is returned unchanged.
func moreSpecific(a, b string, hier hierarchy) string {
	// If b is in a's ancestors → a is more specific than b → keep a.
	for _, anc := range ancestors(a, hier) {
		if anc == b {
			return a
		}
	}
	// If a is in b's ancestors → b is more specific → use b.
	for _, anc := range ancestors(b, hier) {
		if anc == a {
			return b
		}
	}
	return a
}

// minAllConfidence returns the minimum confidence across all candidates.
func minAllConfidence(cands []candidate) string {
	conf := cands[0].confidence
	for _, c := range cands[1:] {
		conf = minConfidence(conf, c.confidence)
	}
	return conf
}

// ---------------------------------------------------------------------------
// InferReturnTypes — engine entry point
// ---------------------------------------------------------------------------

// inferenceDisabled is a package-level test seam. When set to true,
// InferReturnTypes returns immediately without running the pass. This is used
// exclusively by inference performance benchmarks to isolate the baseline
// (build-without-inference) cost. Do NOT set this in production code.
var inferenceDisabled bool //nolint:gochecknoglobals // test-seam for performance benchmarks only

// InferReturnTypes runs the return-type inference pass over the entire call
// graph. It:
//  1. Computes SCCs via Tarjan.
//  2. Processes SCCs in reverse-topological order (callees first).
//  3. For each SCC, iterates inferenceSCC up to inferenceMaxIterations times.
//  4. Emits a structured telemetry log line with per-origin counts.
//
// Error handling follows the "inference:" package prefix convention.
// The engine is language-agnostic: it operates only on CallGraph + KnowledgeBase.
func InferReturnTypes(graph *CallGraph, kb *contracts.KnowledgeBase) error {
	if inferenceDisabled {
		return nil
	}
	hier := mergeHierarchy(kb, graph)
	sccs := computeSCCs(graph)
	stats := inferenceStats{}

	for _, scc := range sccs {
		processSCC(scc, graph, kb, hier, &stats)
	}

	log.Printf("inference: stats origin_counts=%+v join_failed=%d suppressed=%d",
		stats.byCounts(), stats.joinFailed, stats.suppressed)

	return nil
}

// processSCC runs inference over a single SCC.
// Acyclic SCCs get a single pass; cyclic SCCs iterate to fixpoint.
func processSCC(
	scc []string,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
	hier hierarchy,
	stats *inferenceStats,
) {
	isCyclic := len(scc) > 1 || hasSelfEdge(graph, scc[0])
	if !isCyclic {
		for _, fid := range scc {
			if fn := graph.Functions[fid]; fn != nil {
				inferOnce(fn, graph, kb, hier, stats)
			}
		}
		return
	}
	// Fixpoint loop for cyclic SCCs.
	for range inferenceMaxIterations {
		changed := false
		for _, fid := range scc {
			if fn := graph.Functions[fid]; fn != nil {
				if inferOnce(fn, graph, kb, hier, stats) {
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}

// hasSelfEdge returns true if the function calls itself.
func hasSelfEdge(graph *CallGraph, fid string) bool {
	fn := graph.Functions[fid]
	if fn == nil {
		return false
	}
	for i := range fn.Calls {
		if fn.Calls[i].Callee.String() == fid {
			return true
		}
	}
	return false
}

// inferenceStats tracks inference statistics for telemetry.
type inferenceStats struct {
	byOrigin   map[string]int
	joinFailed int
	suppressed int
}

func (s *inferenceStats) byCounts() map[string]int {
	if s.byOrigin == nil {
		return map[string]int{}
	}
	return s.byOrigin
}

func (s *inferenceStats) record(origin string) {
	if s.byOrigin == nil {
		s.byOrigin = make(map[string]int)
	}
	s.byOrigin[origin]++
}

// inferOnce runs one pass of inference on a single function.
// Returns true if InferredReturn changed.
func inferOnce(
	fn *FunctionDecl,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
	hier hierarchy,
	stats *inferenceStats,
) bool {
	// Suppression: if declared type is specific, skip inference.
	if !shouldInfer(fn.ReturnType) {
		stats.suppressed++
		return false
	}

	if len(fn.ReturnSources) == 0 {
		return false
	}

	// Collect candidates from all return sources.
	var cands []candidate
	for _, src := range fn.ReturnSources {
		c, ok := candidateFromSource(src, graph, kb)
		if ok {
			cands = append(cands, c)
		}
	}

	if len(cands) == 0 {
		return false
	}

	// Apply lattice join.
	result, ok := latticeJoin(cands, hier)
	if !ok {
		// Join failed: leave nil (or keep nil).
		// Record join-failed in telemetry only once per function.
		if fn.InferredReturn == nil || fn.InferredReturn.Origin != OriginJoinFailed {
			stats.joinFailed++
		}
		return false
	}

	// Compare with current result to detect change.
	prev := fn.InferredReturn
	next := &InferredReturn{
		Type:       result.typ,
		Confidence: result.confidence,
		Origin:     result.origin,
	}

	if prev != nil && prev.Type == next.Type && prev.Confidence == next.Confidence && prev.Origin == next.Origin {
		return false
	}

	fn.InferredReturn = next
	stats.record(next.Origin)
	return true
}

// candidateFromSource derives a typed candidate from a single SourceNode.
// Returns (candidate, true) if a type can be determined, (zero, false) otherwise.
func candidateFromSource(
	src SourceNode,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
) (candidate, bool) {
	switch src.Type {
	case sourceNodeCallResult:
		return candidateFromCallResult(src, graph, kb)
	case sourceNodeVariable, sourceNodeField, sourceNodeParameter:
		// Recurse into sub-sources.
		for _, sub := range src.SourceNodes {
			if c, ok := candidateFromSource(sub, graph, kb); ok {
				return c, true
			}
		}
		return candidate{}, false
	case sourceNodeValue, sourceNodeExpression:
		// Literal or expression: only useful if DeclaredType is set.
		if src.DeclaredType != "" && !isTrivialLUB(src.DeclaredType) {
			return candidate{typ: src.DeclaredType, confidence: ConfidenceMedium, origin: OriginPropagated}, true
		}
		return candidate{}, false
	default:
		return candidate{}, false
	}
}

// candidateFromCallResult handles CALL_RESULT SourceNodes.
func candidateFromCallResult(
	src SourceNode,
	graph *CallGraph,
	kb *contracts.KnowledgeBase,
) (candidate, bool) {
	if src.CallTarget == nil {
		return candidate{}, false
	}

	ct := src.CallTarget

	// Constructor call: CallTarget.Name contains "<init>".
	if strings.Contains(ct.Name, constructorMethodName) {
		if src.DeclaredType != "" {
			return candidate{
				typ:        src.DeclaredType,
				confidence: ConfidenceHigh,
				origin:     OriginConstructor,
			}, true
		}
		// Fallback: use CallTarget.Type as the constructed class.
		if ct.Type != "" {
			return candidate{
				typ:        qualifiedType(ct.Package, ct.Type),
				confidence: ConfidenceHigh,
				origin:     OriginConstructor,
			}, true
		}
		return candidate{}, false
	}

	// splitMethodArity extracts the FQN (without arity) and the arity integer.
	// C alone retries a bare global symbol; other ecosystems preserve exact lookup.
	methodFQN, arity := splitMethodArity(ct)
	callee := callResultCallee(graph, ct, arity)
	ctrs := kb.ContractsFor(methodFQN, arity)
	if len(ctrs) == 0 && kb.Ecosystem == "c" {
		ctrs = kb.ContractsForCFunction(methodFQN, arity, ct.Linkage == LinkageExternal && callee == nil)
	}
	ctrs = cppExternalContracts(kb, ct, arity, callee, ctrs)

	if len(ctrs) > 0 {
		return candidateFromKBContracts(ctrs, src, kb)
	}

	// Propagation: callee has an inferred type already.
	if callee != nil && callee.InferredReturn != nil {
		ir := callee.InferredReturn
		if ir.Origin != OriginJoinFailed {
			return candidate{
				typ:        ir.Type,
				confidence: ir.Confidence,
				origin:     OriginPropagated,
			}, true
		}
	}

	return candidate{}, false
}

func callResultCallee(graph *CallGraph, target *FunctionID, arity int) *FunctionDecl {
	if callee := graph.Functions[target.String()]; callee != nil {
		return callee
	}
	if arity < 0 {
		return nil
	}
	undecorated := *target
	undecorated.Name = BaseFunctionName(undecorated.Name)
	return graph.Functions[undecorated.String()]
}

// candidateFromKBContracts resolves KB contracts for a CALL_RESULT source.
func candidateFromKBContracts(
	ctrs []contracts.Contract,
	src SourceNode,
	_ *contracts.KnowledgeBase,
) (candidate, bool) {
	// Separate unconditional and conditional contracts.
	var uncond *contracts.Contract
	var conds []contracts.Contract
	for i := range ctrs {
		if ctrs[i].When == nil {
			uncond = &ctrs[i]
		} else {
			conds = append(conds, ctrs[i])
		}
	}

	// Unconditional match: no conditions.
	if uncond != nil {
		return candidate{
			typ:        uncond.Return.Type,
			confidence: uncond.Return.Confidence,
			origin:     OriginKBDirect,
		}, true
	}

	// Conditional match: check arg values.
	if len(conds) == 0 {
		return candidate{}, false
	}

	// Try to resolve arg values from SourceNodes (positional).
	resolvedArgs := resolveArgValues(src.SourceNodes)

	// Determine whether any condition's arg index is resolved.
	anyResolved := false
	for _, c := range conds {
		if _, ok := resolvedArgs[c.When.ArgIndex]; ok {
			anyResolved = true
			break
		}
	}

	if anyResolved {
		return resolveExactConditionalMatch(conds, resolvedArgs)
	}

	// Args unresolved: all branches are plausible.
	if len(conds) == 1 {
		// Single plausible branch: medium confidence.
		return candidate{
			typ:        conds[0].Return.Type,
			confidence: ConfidenceMedium,
			origin:     OriginKBConditional,
		}, true
	}

	// Multiple plausible branches: cannot determine.
	return candidate{}, false
}

// resolveExactConditionalMatch finds exactly-matching conditional contracts when
// arg values are resolved. Returns a candidate only when exactly 1 branch matches.
func resolveExactConditionalMatch(conds []contracts.Contract, resolvedArgs map[int]string) (candidate, bool) {
	var exactMatched []contracts.Contract
	for _, c := range conds {
		argIdx := c.When.ArgIndex
		resolvedVal, resolved := resolvedArgs[argIdx]
		if !resolved {
			continue
		}
		for _, v := range c.When.ArgValueIn {
			if v == resolvedVal {
				exactMatched = append(exactMatched, c)
				break
			}
		}
	}
	if len(exactMatched) == 1 {
		return candidate{
			typ:        exactMatched[0].Return.Type,
			confidence: exactMatched[0].Return.Confidence,
			origin:     OriginKBConditional,
		}, true
	}
	return candidate{}, false
}

// resolveArgValues extracts literal values from SourceNodes keyed by ParameterIndex.
// Returns a map from arg index to resolved literal value string.
func resolveArgValues(nodes []SourceNode) map[int]string {
	result := make(map[int]string)
	for _, n := range nodes {
		if n.Type == sourceNodeValue && n.Value != "" {
			result[n.ParameterIndex] = n.Value
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// qualifiedType builds a fully-qualified type name from package + simple type.
func qualifiedType(pkg, typ string) string {
	if pkg == "" {
		return typ
	}
	return pkg + "." + typ
}

// splitMethodArity returns the FQN method name and numeric arity from a FunctionID.
// e.g. FunctionID{Package:"javax.crypto", Type:"KeyGenerator", Name:"generateKey#0"}
// returns ("javax.crypto.KeyGenerator.generateKey", 0).
func splitMethodArity(id *FunctionID) (string, int) {
	name := id.Name
	arity := -1
	if idx := strings.LastIndex(name, "#"); idx >= 0 {
		arityStr := name[idx+1:]
		n := 0
		valid := arityStr != ""
		for _, ch := range arityStr {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if valid {
			arity = n
			name = name[:idx]
		}
	}
	base := name
	if id.Type != "" {
		return id.Package + "." + id.Type + "." + base, arity
	}
	return id.Package + "." + base, arity
}

func cppContractMethod(id *FunctionID) string {
	if id == nil || id.Type == "" {
		return ""
	}
	return id.Type + "." + BaseFunctionName(id.Name)
}

func cppExternalContracts(kb *contracts.KnowledgeBase, id *FunctionID, arity int, callee *FunctionDecl, current []contracts.Contract) []contracts.Contract {
	if len(current) > 0 || kb.Ecosystem != ecosystemCPP || id.Type == "" || id.Linkage == LinkageInternal || callee != nil {
		return current
	}
	return kb.ContractsFor(cppContractMethod(id), arity)
}
