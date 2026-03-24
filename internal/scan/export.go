package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const (
	callGraphSchemaVersion = "2.0"
	forwardTraceDepthLimit = 8
	maxForwardPathCount    = 32
	maxForwardSinkCount    = 24
	maxForwardBranchFactor = 8
	maxForwardVisitedNodes = 3000
	maxForwardExpansions   = 20000
)

// --- v2 JSON schema types (simplified) ---

type exportBuildContext struct {
	graph               *callgraph.CallGraph
	functionsByAPIShort map[string][]string
	forwardByStart      map[string]forwardTraceCacheEntry
}

type forwardTraceCacheEntry struct {
	forwardPaths [][]callGraphPathNode
	sinks        []callGraphFunctionRef
	truncated    bool
}

type callGraphExportV2 struct {
	SchemaVersion string                   `json:"schema_version"`
	ScanMetadata  callGraphExportScanMeta  `json:"scan_metadata"`
	FindingGraphs []callGraphExportFinding `json:"finding_graphs"`
}

type callGraphExportScanMeta struct {
	Ecosystem     string `json:"ecosystem"`
	RootModule    string `json:"root_module"`
	ToolName      string `json:"tool_name,omitempty"`
	ToolVersion   string `json:"tool_version,omitempty"`
	ExportedAt    string `json:"exported_at"`
	FunctionCount int    `json:"function_count"`
	EdgeCount     int    `json:"edge_count"`
}

type callGraphExportFinding struct {
	FindingID          string                     `json:"finding_id"`
	ContainingFunction *callGraphFunctionLocation `json:"containing_function,omitempty"`
	CryptoCall         *callGraphCalledFunction   `json:"crypto_call,omitempty"`
	BackwardPaths      [][]callGraphPathNode       `json:"backward_paths,omitempty"`
	ForwardPaths       [][]callGraphPathNode       `json:"forward_paths,omitempty"`
	Sinks              []callGraphFunctionRef      `json:"sinks,omitempty"`
}

// callGraphFunctionRef identifies a function with structured fields.
type callGraphFunctionRef struct {
	FunctionName string `json:"function_name"`
	ClassName    string `json:"class_name,omitempty"`
	Namespace    string `json:"namespace"`
}

type callGraphFunctionLocation struct {
	callGraphFunctionRef
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type callGraphCalledFunction struct {
	callGraphFunctionRef
	Line       int                  `json:"line"`
	Parameters []callGraphParameter `json:"parameters,omitempty"`
}

type callGraphParameter struct {
	Type         string           `json:"type,omitempty"`
	VariableName string           `json:"variable_name,omitempty"`
	SourceNodes  []exportSourceNode `json:"source_nodes,omitempty"`
}

type exportSourceNode struct {
	Type           string             `json:"type"`
	Name           string             `json:"name,omitempty"`
	DeclaredType   string             `json:"declared_type,omitempty"`
	Value          string             `json:"value,omitempty"`
	ParameterIndex int                `json:"parameter_index,omitempty"`
	Location       *exportSourceLocation `json:"location,omitempty"`
	SourceNodes    []exportSourceNode `json:"source_nodes,omitempty"`
}

type exportSourceLocation struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type callGraphPathNode struct {
	callGraphFunctionRef
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
}

// --- Entry point ---

// ExportCallGraph writes a finding-centric call graph export (schema v2.0).
func ExportCallGraph(path, format string, result *engine.DepScanResult) error {
	if result == nil {
		return fmt.Errorf("cannot export call graph: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("cannot export call graph: result.CallGraph is nil")
	}
	if result.Report == nil {
		return fmt.Errorf("cannot export call graph: result.Report is nil")
	}
	if format != "json" {
		return fmt.Errorf("unsupported call graph format %q (supported: json)", format)
	}

	payload := buildCallGraphExportV2(result)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("failed to serialize call graph export: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}

	log.Info().
		Str("file", path).
		Str("format", format).
		Int("functions", payload.ScanMetadata.FunctionCount).
		Int("edges", payload.ScanMetadata.EdgeCount).
		Int("findings", len(payload.FindingGraphs)).
		Msg("Exported integration call graph")

	return nil
}

// --- Build pipeline ---

func buildCallGraphExportV2(result *engine.DepScanResult) callGraphExportV2 {
	ctx := newExportBuildContext(result.CallGraph)

	out := callGraphExportV2{
		SchemaVersion: callGraphSchemaVersion,
		ScanMetadata: callGraphExportScanMeta{
			Ecosystem:     result.Ecosystem,
			RootModule:    result.RootModule,
			ExportedAt:    time.Now().UTC().Format(time.RFC3339),
			FunctionCount: len(result.CallGraph.Functions),
			EdgeCount:     countCallGraphEdges(result.CallGraph),
		},
		FindingGraphs: make([]callGraphExportFinding, 0),
	}

	if result.Report != nil {
		out.ScanMetadata.ToolName = result.Report.Tool.Name
		out.ScanMetadata.ToolVersion = result.Report.Tool.Version
	}

	for _, finding := range result.Report.Findings {
		for _, asset := range finding.CryptographicAssets {
			out.FindingGraphs = append(out.FindingGraphs, buildFindingGraph(ctx, finding, asset))
		}
	}

	sort.SliceStable(out.FindingGraphs, func(i, j int) bool {
		return out.FindingGraphs[i].FindingID < out.FindingGraphs[j].FindingID
	})

	return out
}

func newExportBuildContext(graph *callgraph.CallGraph) *exportBuildContext {
	ctx := &exportBuildContext{
		graph:               graph,
		functionsByAPIShort: make(map[string][]string),
		forwardByStart:      make(map[string]forwardTraceCacheEntry),
	}
	for key, fn := range graph.Functions {
		method := callgraph.BaseFunctionName(fn.ID.Name)
		if method == "" {
			continue
		}
		if fn.ID.Type != "" {
			short := fn.ID.Type + "." + method
			ctx.functionsByAPIShort[short] = append(ctx.functionsByAPIShort[short], key)
			full := fn.ID.Package + "." + short
			ctx.functionsByAPIShort[full] = append(ctx.functionsByAPIShort[full], key)
		}
	}
	for k := range ctx.functionsByAPIShort {
		sort.Strings(ctx.functionsByAPIShort[k])
	}
	return ctx
}

// --- Per-finding graph builder ---

func buildFindingGraph(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) callGraphExportFinding {
	containingFn := findContainingFunctionByFinding(ctx.graph, finding.FilePath, asset.StartLine)

	fg := callGraphExportFinding{
		FindingID: asset.FindingID,
	}

	if containingFn != nil {
		fg.ContainingFunction = &callGraphFunctionLocation{
			callGraphFunctionRef: functionRefFromID(containingFn.ID),
			FilePath:             normalizeFindingRelativePath(containingFn.FilePath, finding.FilePath),
			StartLine:            containingFn.StartLine,
			EndLine:              containingFn.EndLine,
		}
		fg.CryptoCall = findCryptoCall(ctx.graph, containingFn, asset.StartLine, asset.EndLine)
	}

	fg.BackwardPaths = buildBackwardPaths(ctx, containingFn, finding)

	api := asset.Metadata["api"]
	forwardStartNodeID := resolveForwardStartNodeID(ctx, api, containingFn)
	fg.ForwardPaths, fg.Sinks, _ = buildForwardPathsAndSinks(ctx, forwardStartNodeID, api)

	return fg
}

// --- Crypto call identification (find the specific call that triggered the finding) ---

// findCryptoCall identifies the function call within the containing function that
// corresponds to the crypto finding, matched by the finding's line range.
func findCryptoCall(graph *callgraph.CallGraph, containingFn *callgraph.FunctionDecl, startLine, endLine int) *callGraphCalledFunction {
	if containingFn == nil {
		return nil
	}

	// Find the call whose line falls within the finding's line range.
	// When multiple calls share the same line (fluent chains), prefer the one
	// that's resolved (has a class_name in the graph) and has parameters.
	var bestCall *callgraph.FunctionCall
	bestScore := -1
	for i := range containingFn.Calls {
		c := &containingFn.Calls[i]
		if c.Line < startLine || c.Line > endLine {
			continue
		}
		score := 0
		if _, ok := graph.Functions[c.Callee.String()]; ok {
			score += 2 // resolved callee
		}
		if len(c.Arguments) > 0 {
			score += 1 // has arguments (crypto calls usually have params)
		}
		if len(c.ArgumentSources) > 0 {
			score += 1 // has source tracing
		}
		if score > bestScore {
			bestScore = score
			bestCall = c
		}
	}

	if bestCall == nil {
		return nil
	}

	callee, _ := graph.Functions[bestCall.Callee.String()]
	result := &callGraphCalledFunction{
		callGraphFunctionRef: functionRefFromID(bestCall.Callee),
		Line:                bestCall.Line,
		Parameters:          mergeCallParameters(callee, bestCall.Arguments, bestCall.ArgumentSources),
	}

	return result
}

// mergeCallParameters combines declared parameter types, argument expressions,
// and argument source traces into a unified parameters array.
func mergeCallParameters(callee *callgraph.FunctionDecl, args []string, argSources [][]callgraph.SourceNode) []callGraphParameter {
	typeCount := 0
	if callee != nil {
		typeCount = len(callee.Parameters)
	}
	size := typeCount
	if len(args) > size {
		size = len(args)
	}
	if size == 0 {
		return nil
	}

	params := make([]callGraphParameter, 0, size)
	for i := range size {
		p := callGraphParameter{}
		if callee != nil && i < len(callee.Parameters) {
			p.Type = strings.TrimSpace(callee.Parameters[i].Type)
		}
		if i < len(args) {
			p.VariableName = strings.TrimSpace(args[i])
		}
		if i < len(argSources) && len(argSources[i]) > 0 {
			p.SourceNodes = convertSourceNodes(argSources[i])
		}
		if p.Type != "" || p.VariableName != "" {
			params = append(params, p)
		}
	}
	return params
}

// convertSourceNodes converts internal SourceNode to export format.
func convertSourceNodes(nodes []callgraph.SourceNode) []exportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]exportSourceNode, len(nodes))
	for i, n := range nodes {
		result[i] = exportSourceNode{
			Type:           n.Type,
			Name:           n.Name,
			DeclaredType:   n.DeclaredType,
			Value:          n.Value,
			ParameterIndex: n.ParameterIndex,
			SourceNodes:    convertSourceNodes(n.SourceNodes),
		}
		if n.Location != nil && (n.Location.FilePath != "" || n.Location.Line > 0) {
			result[i].Location = &exportSourceLocation{
				FilePath: n.Location.FilePath,
				Line:     n.Location.Line,
			}
		}
	}
	return result
}

// --- Backward paths (traced from graph via BFS) ---

func buildBackwardPaths(
	ctx *exportBuildContext,
	containingFn *callgraph.FunctionDecl,
	finding entities.Finding,
) [][]callGraphPathNode {
	if containingFn == nil {
		return nil
	}

	tracer := callgraph.NewTracer(ctx.graph, ".")
	chains := tracer.TraceBack(containingFn.ID, nil, 0) // nil userPackages = trace to any root

	if len(chains) == 0 {
		// Self-chain fallback: just the containing function
		return [][]callGraphPathNode{{
			{
				callGraphFunctionRef: functionRefFromID(containingFn.ID),
				FilePath:             normalizeFindingRelativePath(containingFn.FilePath, finding.FilePath),
				Line:                 containingFn.StartLine,
			},
		}}
	}

	result := make([][]callGraphPathNode, len(chains))
	for i, chain := range chains {
		path := make([]callGraphPathNode, len(chain.Steps))
		for j, step := range chain.Steps {
			path[j] = callGraphPathNode{
				callGraphFunctionRef: functionRefFromID(step.Function),
				FilePath:             step.FilePath,
				Line:                 step.Line,
			}
		}
		result[i] = path
	}

	return result
}

// --- Forward paths (BFS from finding symbol to crypto sinks) ---

func resolveForwardStartNodeID(ctx *exportBuildContext, api string, containingFn *callgraph.FunctionDecl) string {
	// Try to find a graph node matching the API
	if api != "" {
		if keys := ctx.functionsByAPIShort[api]; len(keys) > 0 {
			return keys[0]
		}
	}
	// Try matching from containing function's calls
	if containingFn != nil && api != "" {
		targetBase := ""
		if idx := strings.LastIndex(api, "."); idx >= 0 && idx < len(api)-1 {
			targetBase = callgraph.BaseFunctionName(api[idx+1:])
		}
		for _, c := range containingFn.Calls {
			if targetBase != "" && callgraph.BaseFunctionName(c.Callee.Name) == targetBase {
				key := c.Callee.String()
				if _, ok := ctx.graph.Functions[key]; ok {
					return key
				}
			}
		}
	}
	return ""
}

func buildForwardPathsAndSinks(
	ctx *exportBuildContext,
	startNodeID string,
	api string,
) ([][]callGraphPathNode, []callGraphFunctionRef, bool) {
	startKeys := collectForwardStartKeys(ctx, startNodeID, api)
	if len(startKeys) == 0 {
		return nil, nil, false
	}
	cacheKey := strings.Join(startKeys, "|")
	if cached, ok := ctx.forwardByStart[cacheKey]; ok {
		return cached.forwardPaths, cached.sinks, cached.truncated
	}

	seenPathKeys := make(map[string]bool)
	seenSinkKeys := make(map[string]bool)
	forwardPaths := make([][]callGraphPathNode, 0)
	sinks := make([]callGraphFunctionRef, 0)
	truncated := false
	totalExpanded := 0
	visited := make(map[string]bool, len(startKeys))
	depth := make(map[string]int, len(startKeys))
	parent := make(map[string]string, len(startKeys))
	rootByNode := make(map[string]string, len(startKeys))
	queue := make([]string, 0, len(startKeys))

	for _, start := range startKeys {
		if _, ok := ctx.graph.Functions[start]; !ok || visited[start] {
			continue
		}
		visited[start] = true
		depth[start] = 0
		rootByNode[start] = namespaceRootFromNodeID(start)
		queue = append(queue, start)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		fn := ctx.graph.Functions[current]
		if fn == nil {
			continue
		}

		if isCryptoSink(fn.ID) {
			if len(sinks) < maxForwardSinkCount {
				sinkKey := fn.ID.String()
				if !seenSinkKeys[sinkKey] {
					seenSinkKeys[sinkKey] = true
					sinks = append(sinks, functionRefFromID(fn.ID))
				}
			} else {
				truncated = true
			}

			pathKeys := reconstructForwardPathKeys(parent, current)
			pathNodes := buildPathNodes(ctx.graph, pathKeys)
			key := pathNodeKey(pathNodes)
			if !seenPathKeys[key] {
				if len(forwardPaths) < maxForwardPathCount {
					seenPathKeys[key] = true
					forwardPaths = append(forwardPaths, pathNodes)
				} else {
					truncated = true
				}
			}
			continue
		}

		d := depth[current]
		if d >= forwardTraceDepthLimit {
			truncated = true
			continue
		}

		next := nextForwardCandidates(ctx.graph, fn)
		if len(next) == 0 {
			continue
		}
		totalExpanded += len(next)
		if totalExpanded > maxForwardExpansions {
			truncated = true
			break
		}
		if len(next) > maxForwardBranchFactor {
			next = next[:maxForwardBranchFactor]
			truncated = true
		}

		startRoot := rootByNode[current]
		for _, calleeKey := range next {
			if !isAllowedForwardTransition(ctx.graph, startRoot, calleeKey) {
				continue
			}
			if visited[calleeKey] {
				continue
			}
			if len(visited) >= maxForwardVisitedNodes {
				truncated = true
				break
			}

			visited[calleeKey] = true
			depth[calleeKey] = d + 1
			parent[calleeKey] = current
			rootByNode[calleeKey] = startRoot
			queue = append(queue, calleeKey)
		}
	}

	sort.SliceStable(sinks, func(i, j int) bool {
		return sinks[i].Namespace+"."+sinks[i].ClassName+"."+sinks[i].FunctionName <
			sinks[j].Namespace+"."+sinks[j].ClassName+"."+sinks[j].FunctionName
	})
	sort.SliceStable(forwardPaths, func(i, j int) bool {
		return pathNodeKey(forwardPaths[i]) < pathNodeKey(forwardPaths[j])
	})

	ctx.forwardByStart[cacheKey] = forwardTraceCacheEntry{
		forwardPaths: forwardPaths,
		sinks:        sinks,
		truncated:    truncated,
	}

	return forwardPaths, sinks, truncated
}

func collectForwardStartKeys(ctx *exportBuildContext, startNodeID, api string) []string {
	keys := make([]string, 0)
	seen := make(map[string]bool)

	add := func(key string) {
		if key == "" || seen[key] {
			return
		}
		if _, ok := ctx.graph.Functions[key]; !ok {
			return
		}
		seen[key] = true
		keys = append(keys, key)
	}

	add(startNodeID)
	if api != "" {
		for _, key := range ctx.functionsByAPIShort[api] {
			add(key)
		}
	}

	sort.Strings(keys)
	return keys
}

func reconstructForwardPathKeys(parent map[string]string, leaf string) []string {
	if leaf == "" {
		return nil
	}
	reversed := make([]string, 0, forwardTraceDepthLimit+1)
	current := leaf
	for current != "" {
		reversed = append(reversed, current)
		current = parent[current]
	}
	path := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		path = append(path, reversed[i])
	}
	return path
}

func isAllowedForwardTransition(graph *callgraph.CallGraph, startRoot, calleeKey string) bool {
	fn := graph.Functions[calleeKey]
	if fn == nil {
		return false
	}
	if isCryptoSink(fn.ID) {
		return true
	}
	if startRoot == "" {
		return true
	}
	return namespaceRootFromPackage(fn.ID.Package) == startRoot
}

func namespaceRootFromNodeID(key string) string {
	id, err := callgraph.ParseFunctionID(key, ".")
	if err != nil {
		return ""
	}
	return namespaceRootFromPackage(id.Package)
}

func namespaceRootFromPackage(pkg string) string {
	parts := strings.Split(pkg, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return pkg
}

func nextForwardCandidates(graph *callgraph.CallGraph, fn *callgraph.FunctionDecl) []string {
	keys := make([]string, 0, len(fn.Calls))
	seen := make(map[string]bool)
	for _, call := range fn.Calls {
		calleeKey := call.Callee.String()
		if _, ok := graph.Functions[calleeKey]; !ok {
			continue
		}
		if seen[calleeKey] {
			continue
		}
		seen[calleeKey] = true
		keys = append(keys, calleeKey)
	}
	sort.Strings(keys)
	return keys
}

func buildPathNodes(graph *callgraph.CallGraph, path []string) []callGraphPathNode {
	nodes := make([]callGraphPathNode, 0, len(path))
	for _, key := range path {
		fn := graph.Functions[key]
		if fn == nil {
			continue
		}
		nodes = append(nodes, callGraphPathNode{
			callGraphFunctionRef: functionRefFromID(fn.ID),
			FilePath:             fn.FilePath,
			Line:                 fn.StartLine,
		})
	}
	return nodes
}

func pathNodeKey(nodes []callGraphPathNode) string {
	var b strings.Builder
	for i := range nodes {
		if i > 0 {
			b.WriteString(" -> ")
		}
		b.WriteString(nodes[i].Namespace + "." + nodes[i].ClassName + "." + nodes[i].FunctionName)
	}
	return b.String()
}

func isCryptoSink(id callgraph.FunctionID) bool {
	pkg := strings.ToLower(id.Package)
	switch {
	case strings.HasPrefix(pkg, "javax.crypto"),
		strings.HasPrefix(pkg, "java.security"),
		strings.HasPrefix(pkg, "org.bouncycastle"),
		strings.HasPrefix(pkg, "io.jsonwebtoken.impl.security"),
		strings.HasPrefix(pkg, "crypto/"):
		return true
	default:
		return false
	}
}

// --- Function ref helpers ---

// functionRefFromID creates a structured function reference from a FunctionID.
// For fluent chain calls where Type contains parentheses (unresolved receiver),
// class_name is omitted.
func functionRefFromID(id callgraph.FunctionID) callGraphFunctionRef {
	className := sanitizeSymbol(id.Type)
	if strings.Contains(className, "(") {
		className = "" // fluent chain receiver — not a real class name
	}
	return callGraphFunctionRef{
		FunctionName: callgraph.BaseFunctionName(id.Name),
		ClassName:    className,
		Namespace:    id.Package,
	}
}

// --- Symbol sanitization ---

// sanitizeSymbol collapses whitespace and newlines in symbol strings.
// Fluent chain calls in Java store the raw multiline expression as the Type,
// e.g. "Jwts.builder()\r\n            .setId(id)". This produces clean
// single-line symbols like "Jwts.builder().setId(id)".
func sanitizeSymbol(s string) string {
	if !strings.ContainsAny(s, "\r\n\t") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- Path normalization ---

func normalizeFindingRelativePath(actualPath, findingPath string) string {
	if findingPath == "" {
		return actualPath
	}
	relativeFindingPath := dependencyRelativePath(findingPath)
	if relativeFindingPath != "" {
		if strings.HasSuffix(filepath.ToSlash(actualPath), filepath.ToSlash(relativeFindingPath)) {
			return findingPath
		}
	}
	return actualPath
}

func findContainingFunctionByFinding(graph *callgraph.CallGraph, findingPath string, line int) *callgraph.FunctionDecl {
	normalizedFindingPath := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalizedFindingPath == "" {
		normalizedFindingPath = filepath.ToSlash(findingPath)
	}

	for _, fn := range graph.Functions {
		fnPath := filepath.ToSlash(fn.FilePath)
		if !strings.HasSuffix(fnPath, normalizedFindingPath) {
			continue
		}
		if line >= fn.StartLine && line <= fn.EndLine {
			return fn
		}
	}
	return nil
}

func dependencyRelativePath(path string) string {
	slash := strings.Index(path, "/")
	if slash <= 0 {
		return path
	}
	prefix := path[:slash]
	if strings.Contains(prefix, "@") {
		return path[slash+1:]
	}
	return path
}

// --- Utility helpers ---

// countCallGraphEdges counts the total number of call edges in a call graph.
func countCallGraphEdges(graph *callgraph.CallGraph) int {
	count := 0
	for _, fn := range graph.Functions {
		count += len(fn.Calls)
	}
	return count
}
