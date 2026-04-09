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
	callGraphSchemaVersion   = "5.0"
	matchedOperationCall     = "call"
	sourceNodeTypeParameter  = "PARAMETER"
	sourceNodeTypeValue      = "VALUE"
	callGraphExportProgress  = 100
	callGraphExportMaxDepth  = 32
	callGraphExportMaxChains = 128
)

// --- v4 JSON schema types (simplified) ---

type exportBuildContext struct {
	graph                   *callgraph.CallGraph
	projectRoot             string
	dependencies            []exportDependencyRoot
	containingFunctionCache map[string]cachedContainingFunction
	callChainCache          map[string][][]callGraphChainNode
	callChainRemainingUses  map[string]int
	userPackages            map[string]bool
	packageSeparator        string
}

type cachedContainingFunction struct {
	fn    *callgraph.FunctionDecl
	found bool
}

type callGraphExportV2 struct {
	SchemaVersion   string                   `json:"schema_version"`
	ScanMetadata    callGraphExportScanMeta  `json:"scan_metadata"`
	FindingGraphs   []callGraphExportFinding `json:"finding_graphs"`
	EntryPointIndex []callGraphEntryPoint    `json:"entry_point_index,omitempty"`
}

type callGraphExportScanMeta struct {
	Ecosystem                              string `json:"ecosystem"`
	RootModule                             string `json:"root_module"`
	ToolName                               string `json:"tool_name,omitempty"`
	ToolVersion                            string `json:"tool_version,omitempty"`
	ExportedAt                             string `json:"exported_at"`
	FunctionCount                          int    `json:"function_count"`
	EdgeCount                              int    `json:"edge_count"`
	JavaRequestedJDKMajor                  string `json:"java_requested_jdk_major,omitempty"`
	JavaRuntimeVersion                     string `json:"java_runtime_version,omitempty"`
	JavaPlatformSignaturesUsed             *bool  `json:"java_platform_signatures_used,omitempty"`
	JavaPlatformSignatureSource            string `json:"java_platform_signature_source,omitempty"`
	JavaPlatformSignatureUnavailableReason string `json:"java_platform_signature_unavailable_reason,omitempty"`
}

type callGraphExportFinding struct {
	FindingID        string                     `json:"finding_id"`
	MatchedOperation *callGraphMatchedOperation `json:"matched_operation,omitempty"`
	FindingLocation  *callGraphFindingLocation  `json:"finding_location,omitempty"`
	UnresolvedReason string                     `json:"unresolved_reason,omitempty"`
	CallChains       [][]callGraphChainNode     `json:"call_chains,omitempty"`
}

type callGraphDependencyContext struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

type callGraphCalledFunction struct {
	FunctionName string               `json:"function_name"`
	Line         int                  `json:"line"`
	Parameters   []callGraphParameter `json:"parameters,omitempty"`
}

type callGraphMatchedOperation struct {
	Kind       string `json:"kind"`
	Symbol     string `json:"symbol,omitempty"`
	Expression string `json:"expression,omitempty"`
	Line       int    `json:"line"`
}

type callGraphEntryCall struct {
	FunctionName string               `json:"function_name,omitempty"`
	FilePath     string               `json:"file_path"`
	Line         int                  `json:"line"`
	Parameters   []callGraphParameter `json:"parameters,omitempty"`
}

type callGraphParameter struct {
	ParameterIndex     int                `json:"parameter_index"`
	Type               string             `json:"type,omitempty"`
	VariableName       string             `json:"variable_name,omitempty"`
	ArgumentExpression string             `json:"argument_expression,omitempty"`
	ResolvedValue      string             `json:"resolved_value,omitempty"`
	SourceNodes        []exportSourceNode `json:"source_nodes,omitempty"`
}

type callGraphFindingLocation struct {
	FilePath       string                      `json:"file_path"`
	StartLine      int                         `json:"start_line"`
	EndLine        int                         `json:"end_line"`
	Language       string                      `json:"language,omitempty"`
	DependencyInfo *callGraphDependencyContext `json:"dependency_info,omitempty"`
}

type exportSourceNode struct {
	Type           string                `json:"type"`
	Name           string                `json:"name,omitempty"`
	DeclaredType   string                `json:"declared_type,omitempty"`
	Value          string                `json:"value,omitempty"`
	ParameterIndex *int                  `json:"parameter_index,omitempty"`
	CallTarget     string                `json:"call_target,omitempty"`
	Location       *exportSourceLocation `json:"location,omitempty"`
	SourceNodes    []exportSourceNode    `json:"source_nodes,omitempty"`
}

type exportSourceLocation struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type callGraphChainNode struct {
	FunctionName   string                      `json:"function_name"`
	FilePath       string                      `json:"file_path"`
	StartLine      int                         `json:"start_line,omitempty"`
	DependencyInfo *callGraphDependencyContext `json:"dependency_info,omitempty"`
	EntryCall      *callGraphEntryCall         `json:"entry_call,omitempty"`
	CryptoCall     *callGraphCalledFunction    `json:"crypto_call,omitempty"`
}

type callGraphEntryPoint struct {
	Function          string                      `json:"function"`
	Class             string                      `json:"class,omitempty"`
	Method            string                      `json:"method"`
	ReturnType        string                      `json:"return_type,omitempty"`
	ParameterTypes    []string                    `json:"parameter_types,omitempty"`
	ReachableFindings []callGraphReachableFinding `json:"reachable_findings"`
}

type callGraphReachableFinding struct {
	FindingID        string                     `json:"finding_id"`
	MatchedOperation *callGraphMatchedOperation `json:"matched_operation"`
	ChainDepth       int                        `json:"chain_depth"`
	FindingGraphRef  string                     `json:"finding_graph_ref"`
}

type exportDependencyRoot struct {
	Module  string
	Version string
	Dir     string
}

// --- Entry point ---

// ExportCallGraph writes a finding-centric call graph export (schema v4.3).
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

	exportStart := time.Now()
	totalAssets := countExportFindingAssets(result.Report)
	log.Info().
		Str("file", path).
		Str("format", format).
		Int("finding_assets", totalAssets).
		Msg("Starting integration call graph export")

	buildStart := time.Now()
	payload := buildCallGraphExportV2(result)
	buildDuration := time.Since(buildStart)

	serializeStart := time.Now()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("failed to serialize call graph export: %w", err)
	}
	serializeDuration := time.Since(serializeStart)

	writeStart := time.Now()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}
	writeDuration := time.Since(writeStart)

	log.Info().
		Str("file", path).
		Str("format", format).
		Int("functions", payload.ScanMetadata.FunctionCount).
		Int("edges", payload.ScanMetadata.EdgeCount).
		Int("findings", len(payload.FindingGraphs)).
		Dur("build_duration", buildDuration).
		Dur("serialize_duration", serializeDuration).
		Dur("write_duration", writeDuration).
		Dur("total_duration", time.Since(exportStart)).
		Msg("Exported integration call graph")

	return nil
}

// --- Build pipeline ---

func buildCallGraphExportV2(result *engine.DepScanResult) callGraphExportV2 {
	ctx := newExportBuildContext(result)
	totalAssets := countExportFindingAssets(result.Report)

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
	if result.Ecosystem == "java" && result.CallGraph != nil && result.CallGraph.JavaPlatformSignatures != nil {
		meta := result.CallGraph.JavaPlatformSignatures
		out.ScanMetadata.JavaRequestedJDKMajor = meta.RequestedMajor
		out.ScanMetadata.JavaRuntimeVersion = meta.RuntimeVersion
		used := meta.SignaturesUsed
		out.ScanMetadata.JavaPlatformSignaturesUsed = &used
		out.ScanMetadata.JavaPlatformSignatureSource = meta.SignatureSource
		out.ScanMetadata.JavaPlatformSignatureUnavailableReason = meta.UnavailableReason
	}

	processedAssets := 0
	buildStart := time.Now()
	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			if log.Debug().Enabled() {
				log.Debug().
					Str("finding_id", asset.FindingID).
					Str("file", finding.FilePath).
					Int("start_line", asset.StartLine).
					Int("processed", processedAssets+1).
					Int("total", totalAssets).
					Msg("Building finding graph")
			}
			out.FindingGraphs = append(out.FindingGraphs, buildFindingGraph(ctx, finding, asset))
			processedAssets++
			if processedAssets%callGraphExportProgress == 0 || processedAssets == totalAssets {
				log.Info().
					Int("processed", processedAssets).
					Int("total", totalAssets).
					Dur("elapsed", time.Since(buildStart)).
					Msg("Building integration call graph export")
			}
		}
	}

	sort.SliceStable(out.FindingGraphs, func(i, j int) bool {
		return out.FindingGraphs[i].FindingID < out.FindingGraphs[j].FindingID
	})

	out.EntryPointIndex = buildEntryPointIndex(out.FindingGraphs)

	return out
}

// buildEntryPointIndex creates an O(1) lookup from function name to reachable
// crypto operations. Every function that appears in any call chain is a
// potential entry point — external code might call any of them.
func buildEntryPointIndex(findingGraphs []callGraphExportFinding) []callGraphEntryPoint {
	type findingRef struct {
		findingID  string
		matchedOp  *callGraphMatchedOperation
		chainDepth int
	}

	type entryPointData struct {
		class    string
		method   string
		findings map[string]findingRef // findingID → ref (keep shallowest depth)
	}

	index := make(map[string]*entryPointData)

	for _, fg := range findingGraphs {
		if fg.MatchedOperation == nil {
			continue
		}
		for _, chain := range fg.CallChains {
			if len(chain) == 0 {
				continue
			}
			for pos, node := range chain {
				fn := node.FunctionName
				if fn == "" {
					continue
				}
				depth := len(chain) - pos

				ep, ok := index[fn]
				if !ok {
					class, method := splitFunctionName(fn)
					ep = &entryPointData{
						class:    class,
						method:   method,
						findings: make(map[string]findingRef),
					}
					index[fn] = ep
				}

				existing, exists := ep.findings[fg.FindingID]
				if !exists || depth < existing.chainDepth {
					ep.findings[fg.FindingID] = findingRef{
						findingID:  fg.FindingID,
						matchedOp:  fg.MatchedOperation,
						chainDepth: depth,
					}
				}
			}
		}
	}

	result := make([]callGraphEntryPoint, 0, len(index))
	for fn, ep := range index {
		findings := make([]callGraphReachableFinding, 0, len(ep.findings))
		for _, ref := range ep.findings {
			findings = append(findings, callGraphReachableFinding{
				FindingID: ref.findingID,
				MatchedOperation: &callGraphMatchedOperation{
					Kind:   ref.matchedOp.Kind,
					Symbol: ref.matchedOp.Symbol,
				},
				ChainDepth:      ref.chainDepth,
				FindingGraphRef: ref.findingID,
			})
		}
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].FindingID < findings[j].FindingID
		})
		result = append(result, callGraphEntryPoint{
			Function:          fn,
			Class:             ep.class,
			Method:            ep.method,
			ReachableFindings: findings,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Function < result[j].Function
	})

	return result
}

// splitFunctionName extracts class and method from a fully qualified function name.
// e.g., "org.apache.http.ssl.SSLContextBuilder.build" → ("org.apache.http.ssl.SSLContextBuilder", "build")
func splitFunctionName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}

func countExportFindingAssets(report *entities.InterimReport) int {
	if report == nil {
		return 0
	}

	total := 0
	for _, finding := range report.Findings {
		total += len(finding.CryptographicAssets)
	}
	return total
}

func newExportBuildContext(result *engine.DepScanResult) *exportBuildContext {
	ctx := &exportBuildContext{
		graph:                   result.CallGraph,
		projectRoot:             filepath.Clean(result.ProjectRoot),
		containingFunctionCache: make(map[string]cachedContainingFunction),
		callChainCache:          make(map[string][][]callGraphChainNode),
		callChainRemainingUses:  make(map[string]int),
		userPackages:            exportUserPackages(result),
		packageSeparator:        exportPackageSeparator(result.Ecosystem),
	}
	for _, dep := range result.Dependencies {
		if dep.Dir == "" {
			continue
		}
		ctx.dependencies = append(ctx.dependencies, exportDependencyRoot{
			Module:  dep.Module,
			Version: dep.Version,
			Dir:     filepath.Clean(dep.Dir),
		})
	}
	sort.SliceStable(ctx.dependencies, func(i, j int) bool {
		return len(ctx.dependencies[i].Dir) > len(ctx.dependencies[j].Dir)
	})
	ctx.populateCallChainUsageCounts(result.Report)
	return ctx
}

// --- Per-finding graph builder ---

func buildFindingGraph(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) callGraphExportFinding {
	start := time.Now()
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	matchedOperation := buildMatchedOperation(asset)

	fg := callGraphExportFinding{
		FindingID:        asset.FindingID,
		MatchedOperation: matchedOperation,
	}
	unresolvedReason := ""
	var cryptoCall *callGraphCalledFunction

	if containingFn == nil {
		unresolvedReason = "no_containing_function"
	} else if matchedOperation != nil && matchedOperation.Kind == matchedOperationCall {
		cryptoCall = findCryptoCall(ctx, ctx.graph, containingFn, asset, asset.StartLine, asset.EndLine)
		if cryptoCall == nil {
			unresolvedReason = "no_crypto_call_match"
		} else {
			fg.MatchedOperation.Symbol = cryptoCall.FunctionName
		}
	}

	fg.CallChains = buildCallChains(ctx, containingFn, cryptoCall)

	if unresolvedReason != "" {
		fg.UnresolvedReason = unresolvedReason
		fg.FindingLocation = buildFindingLocation(ctx, finding, asset)
	}

	if duration := time.Since(start); duration > time.Second {
		functionName := ""
		if containingFn != nil {
			functionName = containingFn.ID.String()
		}
		log.Info().
			Str("finding_id", asset.FindingID).
			Str("function", functionName).
			Int("call_chains", len(fg.CallChains)).
			Dur("duration", duration).
			Msg("Slow finding graph export")
	}

	return fg
}

func buildMatchedOperation(asset entities.CryptographicAsset) *callGraphMatchedOperation {
	line := asset.StartLine
	if line <= 0 {
		line = asset.EndLine
	}

	symbol := strings.TrimSpace(asset.Metadata["api"])
	expression := strings.TrimSpace(asset.Match)

	return &callGraphMatchedOperation{
		Kind:       inferMatchedOperationKind(symbol, expression),
		Symbol:     symbol,
		Expression: expression,
		Line:       line,
	}
}

func inferMatchedOperationKind(symbol, expression string) string {
	symbol = strings.TrimSpace(symbol)
	expression = strings.TrimSpace(expression)

	if symbol != "" {
		switch {
		case looksLikeConstructorOperation(symbol, expression):
			return matchedOperationCall
		case looksLikeMethodOperation(symbol, expression):
			return matchedOperationCall
		case looksLikeTypeUsageOperation(symbol, expression):
			return "type_usage"
		default:
			return "expression"
		}
	}

	if looksLikeInvocationExpression(expression) {
		return matchedOperationCall
	}
	return "expression"
}

func looksLikeConstructorOperation(symbol, expression string) bool {
	if symbol == "" || strings.Contains(symbol, ".") {
		return false
	}

	return strings.Contains(expression, "new "+symbol+"(") || strings.Contains(expression, symbol+"(")
}

func looksLikeMethodOperation(symbol, expression string) bool {
	if symbol == "" || !strings.Contains(symbol, ".") {
		return false
	}

	method := symbol[strings.LastIndex(symbol, ".")+1:]
	return method != "" && strings.Contains(expression, method+"(")
}

func looksLikeTypeUsageOperation(symbol, expression string) bool {
	if symbol == "" || strings.Contains(symbol, ".") {
		return false
	}

	return strings.Contains(expression, symbol) && !looksLikeConstructorOperation(symbol, expression)
}

func looksLikeInvocationExpression(expression string) bool {
	return strings.Contains(expression, "(") && strings.Contains(expression, ")")
}

// --- Crypto call identification (find the specific call that triggered the finding) ---

// findCryptoCall identifies the function call within the containing function that
// corresponds to the crypto finding, matched by the finding's line range.
func findCryptoCall(
	ctx *exportBuildContext,
	graph *callgraph.CallGraph,
	containingFn *callgraph.FunctionDecl,
	asset entities.CryptographicAsset,
	startLine, endLine int,
) *callGraphCalledFunction {
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
			score++ // has arguments (crypto calls usually have params)
		}
		if len(c.ArgumentSources) > 0 {
			score++ // has source tracing
		}
		score += scoreCallCandidate(asset, c)
		if score > bestScore {
			bestScore = score
			bestCall = c
		}
	}

	if bestCall == nil {
		return nil
	}

	callee := graph.Functions[bestCall.Callee.String()]
	sourcePath := normalizeExportPath(ctx, bestCall.FilePath).FilePath
	result := &callGraphCalledFunction{
		FunctionName: fullFunctionName(bestCall.Callee),
		Line:         bestCall.Line,
		Parameters:   mergeCallParameters(ctx, &bestCall.Callee, callee, bestCall.Arguments, bestCall.ArgumentSources, sourcePath, bestCall.Line),
	}

	return result
}

func scoreCallCandidate(asset entities.CryptographicAsset, call *callgraph.FunctionCall) int {
	if call == nil {
		return 0
	}

	api := strings.TrimSpace(asset.Metadata["api"])
	if api == "" {
		return 0
	}

	methodName := baseCallMethodName(call.Callee.Name)
	typeName := simpleTypeName(call.Callee.Type)
	packageBase := simplePackageName(call.Callee.Package)

	if dot := strings.LastIndex(api, "."); dot >= 0 {
		owner := api[:dot]
		method := api[dot+1:]
		if methodName != method {
			return 0
		}
		if owner == "" {
			return 8
		}
		if typeName == owner || packageBase == owner {
			return 10
		}
		if strings.HasSuffix(call.Callee.Type, "."+owner) || strings.HasSuffix(call.Callee.Package, "/"+owner) {
			return 10
		}
		return 6
	}

	if typeName == api && methodName == "<init>" {
		return 10
	}

	return 0
}

func baseCallMethodName(name string) string {
	if name == "" {
		return ""
	}
	if hash := strings.Index(name, "#"); hash >= 0 {
		return name[:hash]
	}
	return name
}

func simpleTypeName(typeName string) string {
	if typeName == "" {
		return ""
	}
	if dot := strings.LastIndex(typeName, "."); dot >= 0 {
		return typeName[dot+1:]
	}
	return typeName
}

func simplePackageName(packageName string) string {
	if packageName == "" {
		return ""
	}
	if slash := strings.LastIndex(packageName, "/"); slash >= 0 {
		packageName = packageName[slash+1:]
	}
	if dot := strings.LastIndex(packageName, "."); dot >= 0 {
		return packageName[dot+1:]
	}
	return packageName
}

// mergeCallParameters combines declared parameter types, argument expressions,
// and argument source traces into a unified parameters array.
func mergeCallParameters(
	ctx *exportBuildContext,
	calleeID *callgraph.FunctionID,
	callee *callgraph.FunctionDecl,
	args []string,
	argSources [][]callgraph.SourceNode,
	sourceFilePath string,
	sourceLine int,
) []callGraphParameter {
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
		p := callGraphParameter{ParameterIndex: i}
		p.Type = resolveExportParameterType(ctx.graph, calleeID, callee, i)
		if i < len(args) {
			expr := strings.TrimSpace(args[i])
			p.ArgumentExpression = expr
			if isSimpleIdentifier(expr) {
				p.VariableName = expr
			}
		}
		if i < len(argSources) && len(argSources[i]) > 0 {
			p.SourceNodes = convertSourceNodes(ctx, argSources[i], filepath.ToSlash(sourceFilePath), sourceLine)
		}
		p.ResolvedValue = resolveSimpleExportParameterValue(p.ArgumentExpression, p.SourceNodes)
		if p.Type != "" || p.VariableName != "" || p.ArgumentExpression != "" {
			params = append(params, p)
		}
	}
	return params
}

// convertSourceNodes converts internal SourceNode to export format.
func convertSourceNodes(ctx *exportBuildContext, nodes []callgraph.SourceNode, defaultFilePath string, defaultLine int) []exportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]exportSourceNode, len(nodes))
	for i, n := range nodes {
		result[i] = exportSourceNode{
			Type:         n.Type,
			Name:         n.Name,
			DeclaredType: n.DeclaredType,
			Value:        n.Value,
			SourceNodes:  convertSourceNodes(ctx, n.SourceNodes, defaultFilePath, defaultLine),
		}
		if n.Type == sourceNodeTypeParameter {
			idx := n.ParameterIndex
			result[i].ParameterIndex = &idx
		}
		if n.CallTarget != nil {
			result[i].CallTarget = fullFunctionName(*n.CallTarget)
		}
		loc := &exportSourceLocation{
			FilePath: defaultFilePath,
			Line:     defaultLine,
		}
		if n.Location != nil {
			if n.Location.FilePath != "" {
				loc.FilePath = normalizeExportPath(ctx, n.Location.FilePath).FilePath
			}
			if n.Location.Line > 0 {
				loc.Line = n.Location.Line
			}
		}
		if loc.FilePath != "" || loc.Line > 0 {
			result[i].Location = loc
		}
	}
	return result
}

func resolveSimpleExportParameterValue(expr string, sourceNodes []exportSourceNode) string {
	if value, ok := resolveSimpleExportSourceValue(sourceNodes); ok {
		return value
	}

	expr = strings.TrimSpace(expr)
	switch {
	case expr == "":
		return ""
	case strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\""):
		return expr
	case expr == "true" || expr == "false":
		return expr
	case looksLikeIntegerLiteralExpr(expr):
		return expr
	case looksLikeEnumConstantExpr(expr):
		return expr
	default:
		return ""
	}
}

func resolveExportParameterType(
	graph *callgraph.CallGraph,
	calleeID *callgraph.FunctionID,
	callee *callgraph.FunctionDecl,
	index int,
) string {
	if callee != nil && index < len(callee.Parameters) {
		if typeName := strings.TrimSpace(callee.Parameters[index].Type); typeName != "" {
			return typeName
		}
	}
	if graph == nil || calleeID == nil || graph.ExternalMethodSignatures == nil {
		return ""
	}

	signatures := graph.ExternalMethodSignatures[callgraph.ExternalMethodSignatureKey(*calleeID)]
	for _, sig := range signatures {
		if index >= len(sig.ParameterTypes) {
			continue
		}
		if typeName := strings.TrimSpace(sig.ParameterTypes[index]); typeName != "" {
			return typeName
		}
	}
	return ""
}

func resolveSimpleExportSourceValue(nodes []exportSourceNode) (string, bool) {
	if len(nodes) == 0 {
		return "", false
	}

	var resolved string
	for _, node := range nodes {
		value, ok := resolveSimpleExportSourceValueNode(node)
		if !ok {
			return "", false
		}
		if resolved == "" {
			resolved = value
			continue
		}
		if resolved != value {
			return "", false
		}
	}

	if resolved == "" {
		return "", false
	}
	return resolved, true
}

func resolveSimpleExportSourceValueNode(node exportSourceNode) (string, bool) {
	switch node.Type {
	case sourceNodeTypeValue:
		value := strings.TrimSpace(node.Value)
		if value == "" {
			value = strings.TrimSpace(node.Name)
		}
		if value == "" {
			return "", false
		}
		return value, true
	case "VARIABLE", "FIELD", sourceNodeTypeParameter:
		return resolveSimpleExportSourceValue(node.SourceNodes)
	default:
		return "", false
	}
}

func looksLikeIntegerLiteralExpr(expr string) bool {
	expr = strings.TrimSpace(strings.TrimSuffix(expr, "L"))
	if expr == "" {
		return false
	}
	for i, r := range expr {
		if i == 0 && (r == '+' || r == '-') {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeEnumConstantExpr(expr string) bool {
	expr = strings.TrimSpace(expr)
	dot := strings.LastIndex(expr, ".")
	if dot <= 0 || dot >= len(expr)-1 {
		return false
	}
	suffix := expr[dot+1:]
	for i, r := range suffix {
		if (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// --- Call chains (traced from graph via BFS) ---

func buildCallChains(
	ctx *exportBuildContext,
	containingFn *callgraph.FunctionDecl,
	cryptoCall *callGraphCalledFunction,
) [][]callGraphChainNode {
	if containingFn == nil {
		return nil
	}

	cacheKey := containingFn.ID.String()
	baseChains, ok := ctx.callChainCache[cacheKey]
	if !ok {
		baseChains = buildBaseCallChains(ctx, containingFn)
		if ctx.callChainRemainingUses[cacheKey] > 1 {
			ctx.callChainCache[cacheKey] = baseChains
			ok = true
		}
	}
	chains := baseChains
	if ok {
		chains = cloneCallGraphChains(baseChains)
	}
	attachCryptoCall(chains, cryptoCall)
	ctx.consumeCallChainUsage(cacheKey)
	return chains
}

func buildBaseCallChains(
	ctx *exportBuildContext,
	containingFn *callgraph.FunctionDecl,
) [][]callGraphChainNode {
	tracer := callgraph.NewTracer(ctx.graph, ctx.packageSeparator)
	chains, truncated := tracer.TraceBackLimited(
		containingFn.ID,
		ctx.userPackages,
		callGraphExportMaxDepth,
		callGraphExportMaxChains,
	)
	if truncated {
		log.Warn().
			Str("function", containingFn.ID.String()).
			Int("max_depth", callGraphExportMaxDepth).
			Int("max_chains", callGraphExportMaxChains).
			Msg("Truncated call chain export for finding function")
	}

	if len(chains) == 0 {
		node := buildChainNode(ctx, containingFn.ID, containingFn.FilePath)
		return [][]callGraphChainNode{{node}}
	}

	result := make([][]callGraphChainNode, len(chains))
	for i, chain := range chains {
		path := make([]callGraphChainNode, len(chain.Steps))
		for j, step := range chain.Steps {
			path[j] = buildChainNode(ctx, step.Function, step.FilePath)
			if j > 0 {
				path[j].EntryCall = buildEntryCall(
					ctx,
					ctx.graph,
					chain.Steps[j-1].Function,
					chain.Steps[j-1].FilePath,
					chain.Steps[j-1].Line,
					step.Function,
				)
			}
		}
		enrichCallChain(path)
		result[i] = path
	}

	return result
}

func exportUserPackages(result *engine.DepScanResult) map[string]bool {
	if result == nil || strings.TrimSpace(result.RootModule) == "" {
		return nil
	}
	// In standalone mode (no dependencies), return nil so the tracer
	// traverses call chains to graph roots instead of stopping at the
	// first root-module function. This produces deeper chains needed
	// for entry_point_index: e.g., HttpClientBuilder.build → ... →
	// SSLContext.getInstance (depth 5) instead of just depth 1.
	if len(result.Dependencies) == 0 {
		return nil
	}
	return map[string]bool{
		strings.TrimSpace(result.RootModule): true,
	}
}


func exportPackageSeparator(ecosystem string) string {
	switch ecosystem {
	case "go":
		return "/"
	case "rust":
		return "::"
	default:
		return "."
	}
}

func (ctx *exportBuildContext) populateCallChainUsageCounts(report *entities.InterimReport) {
	if ctx == nil || ctx.graph == nil || report == nil {
		return
	}

	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[i]
			containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
			if containingFn == nil {
				continue
			}
			ctx.callChainRemainingUses[containingFn.ID.String()]++
		}
	}
}

func (ctx *exportBuildContext) consumeCallChainUsage(cacheKey string) {
	if ctx == nil {
		return
	}
	remaining := ctx.callChainRemainingUses[cacheKey]
	if remaining <= 1 {
		delete(ctx.callChainRemainingUses, cacheKey)
		delete(ctx.callChainCache, cacheKey)
		return
	}
	ctx.callChainRemainingUses[cacheKey] = remaining - 1
}

func attachCryptoCall(chains [][]callGraphChainNode, cryptoCall *callGraphCalledFunction) {
	if cryptoCall == nil {
		return
	}
	for i := range chains {
		if len(chains[i]) == 0 {
			continue
		}
		last := &chains[i][len(chains[i])-1]
		cloned := cloneCalledFunction(cryptoCall)
		last.CryptoCall = cloned
		if last.EntryCall != nil {
			propagateParameterProvenance(
				last.CryptoCall.Parameters,
				last.EntryCall.Parameters,
				last.EntryCall.FilePath,
				last.EntryCall.Line,
			)
		}
	}
}

func cloneCallGraphChains(chains [][]callGraphChainNode) [][]callGraphChainNode {
	if len(chains) == 0 {
		return nil
	}
	cloned := make([][]callGraphChainNode, len(chains))
	for i := range chains {
		cloned[i] = cloneCallGraphChain(chains[i])
	}
	return cloned
}

func cloneCallGraphChain(chain []callGraphChainNode) []callGraphChainNode {
	if len(chain) == 0 {
		return nil
	}
	cloned := make([]callGraphChainNode, len(chain))
	for i := range chain {
		cloned[i] = chain[i]
		cloned[i].DependencyInfo = cloneDependencyContext(chain[i].DependencyInfo)
		cloned[i].EntryCall = cloneEntryCall(chain[i].EntryCall)
		cloned[i].CryptoCall = cloneCalledFunction(chain[i].CryptoCall)
	}
	return cloned
}

func cloneDependencyContext(dep *callGraphDependencyContext) *callGraphDependencyContext {
	if dep == nil {
		return nil
	}
	cloned := *dep
	return &cloned
}

func cloneEntryCall(call *callGraphEntryCall) *callGraphEntryCall {
	if call == nil {
		return nil
	}
	cloned := *call
	cloned.Parameters = cloneCallGraphParameters(call.Parameters)
	return &cloned
}

func cloneCalledFunction(call *callGraphCalledFunction) *callGraphCalledFunction {
	if call == nil {
		return nil
	}
	cloned := *call
	cloned.Parameters = cloneCallGraphParameters(call.Parameters)
	return &cloned
}

func cloneCallGraphParameters(params []callGraphParameter) []callGraphParameter {
	if len(params) == 0 {
		return nil
	}
	cloned := make([]callGraphParameter, len(params))
	for i := range params {
		cloned[i] = params[i]
		cloned[i].SourceNodes = cloneSourceNodes(params[i].SourceNodes)
	}
	return cloned
}

func buildChainNode(
	ctx *exportBuildContext,
	id callgraph.FunctionID,
	actualPath string,
) callGraphChainNode {
	location := normalizeExportPath(ctx, actualPath)
	startLine := 0
	if fn := ctx.graph.Functions[id.String()]; fn != nil {
		startLine = fn.StartLine
	}
	return callGraphChainNode{
		FunctionName:   fullFunctionName(id),
		FilePath:       location.FilePath,
		StartLine:      startLine,
		DependencyInfo: location.DependencyInfo,
	}
}

func buildEntryCall(
	ctx *exportBuildContext,
	graph *callgraph.CallGraph,
	callerID callgraph.FunctionID,
	callSitePath string,
	fallbackLine int,
	calleeID callgraph.FunctionID,
) *callGraphEntryCall {
	location := normalizeExportPath(ctx, callSitePath)
	callerFn := graph.Functions[callerID.String()]
	if callerFn == nil {
		return &callGraphEntryCall{
			FilePath: location.FilePath,
			Line:     fallbackLine,
		}
	}

	call := findMatchingInvocation(callerFn, calleeID.String())
	if call == nil {
		return &callGraphEntryCall{
			FilePath: location.FilePath,
			Line:     fallbackLine,
		}
	}

	location = normalizeExportPath(ctx, call.FilePath)
	calleeFn := graph.Functions[call.Callee.String()]
	entryCall := &callGraphEntryCall{
		FilePath:   location.FilePath,
		Line:       call.Line,
		Parameters: mergeCallParameters(ctx, &call.Callee, calleeFn, call.Arguments, call.ArgumentSources, location.FilePath, call.Line),
	}
	callName := fullFunctionName(call.Callee)
	if callName != fullFunctionName(calleeID) {
		entryCall.FunctionName = callName
	}
	return entryCall
}

func enrichCallChain(chain []callGraphChainNode) {
	if len(chain) == 0 {
		return
	}

	for i := 1; i < len(chain); i++ {
		if chain[i].EntryCall == nil || chain[i-1].EntryCall == nil {
			refreshParameterValues(chain[i].EntryCall)
			continue
		}
		propagateParameterProvenance(
			chain[i].EntryCall.Parameters,
			chain[i-1].EntryCall.Parameters,
			chain[i-1].EntryCall.FilePath,
			chain[i-1].EntryCall.Line,
		)
	}

	last := &chain[len(chain)-1]
	if last.CryptoCall != nil && last.EntryCall != nil {
		propagateParameterProvenance(
			last.CryptoCall.Parameters,
			last.EntryCall.Parameters,
			last.EntryCall.FilePath,
			last.EntryCall.Line,
		)
	}
}

func propagateParameterProvenance(
	params []callGraphParameter,
	upstream []callGraphParameter,
	defaultFilePath string,
	defaultLine int,
) {
	for i := range params {
		if len(params[i].SourceNodes) > 0 && len(upstream) > 0 {
			params[i].SourceNodes = propagateSourceNodes(
				params[i].SourceNodes,
				upstream,
				defaultFilePath,
				defaultLine,
			)
		}
		params[i].ResolvedValue = resolveSimpleExportParameterValue(params[i].ArgumentExpression, params[i].SourceNodes)
	}
}

func refreshParameterValues(call *callGraphEntryCall) {
	if call == nil {
		return
	}
	for i := range call.Parameters {
		call.Parameters[i].ResolvedValue = resolveSimpleExportParameterValue(call.Parameters[i].ArgumentExpression, call.Parameters[i].SourceNodes)
	}
}

func propagateSourceNodes(
	nodes []exportSourceNode,
	upstream []callGraphParameter,
	defaultFilePath string,
	defaultLine int,
) []exportSourceNode {
	result := cloneSourceNodes(nodes)
	propagateSourceNodeChildren(result, upstream, defaultFilePath, defaultLine)
	return result
}

func propagateSourceNodeChildren(
	nodes []exportSourceNode,
	upstream []callGraphParameter,
	defaultFilePath string,
	defaultLine int,
) {
	for i := range nodes {
		originalChildren := len(nodes[i].SourceNodes)
		if nodes[i].Type == "CALL_RESULT" && originalChildren > 0 {
			propagateSourceNodeChildren(nodes[i].SourceNodes[:originalChildren], upstream, defaultFilePath, defaultLine)
		}
		if nodes[i].Type == sourceNodeTypeParameter {
			if nodes[i].ParameterIndex == nil {
				continue
			}
			upstreamIdx := *nodes[i].ParameterIndex
			if upstreamIdx >= 0 && upstreamIdx < len(upstream) && len(upstream[upstreamIdx].SourceNodes) > 0 {
				nodes[i].SourceNodes = append(
					nodes[i].SourceNodes,
					cloneSourceNodesWithFallback(upstream[upstreamIdx].SourceNodes, defaultFilePath, defaultLine)...,
				)
			}
		}
	}
}

func cloneSourceNodes(nodes []exportSourceNode) []exportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]exportSourceNode, len(nodes))
	for i := range nodes {
		result[i] = nodes[i]
		result[i].SourceNodes = cloneSourceNodes(nodes[i].SourceNodes)
		if nodes[i].Location != nil {
			loc := *nodes[i].Location
			result[i].Location = &loc
		}
	}
	return result
}

func cloneSourceNodesWithFallback(nodes []exportSourceNode, defaultFilePath string, defaultLine int) []exportSourceNode {
	cloned := cloneSourceNodes(nodes)
	applyFallbackLocation(cloned, defaultFilePath, defaultLine)
	return cloned
}

func applyFallbackLocation(nodes []exportSourceNode, defaultFilePath string, defaultLine int) {
	for i := range nodes {
		if nodes[i].Location == nil {
			if defaultFilePath != "" || defaultLine > 0 {
				nodes[i].Location = &exportSourceLocation{
					FilePath: defaultFilePath,
					Line:     defaultLine,
				}
			}
		} else {
			if nodes[i].Location.FilePath == "" {
				nodes[i].Location.FilePath = defaultFilePath
			}
			if nodes[i].Location.Line == 0 {
				nodes[i].Location.Line = defaultLine
			}
		}
		applyFallbackLocation(nodes[i].SourceNodes, defaultFilePath, defaultLine)
	}
}

func findMatchingInvocation(callerFn *callgraph.FunctionDecl, calleeKey string) *callgraph.FunctionCall {
	if callerFn == nil {
		return nil
	}

	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	bestIdx := -1
	bestScore := -1
	for i := range callerFn.Calls {
		call := &callerFn.Calls[i]
		if call.Callee.String() == calleeKey {
			return call
		}
		if err != nil {
			continue
		}

		score := 0
		switch {
		case call.Callee.Package == calleeID.Package &&
			call.Callee.Type == calleeID.Type &&
			methodArityKey(call.Callee.Name) == methodArityKey(calleeID.Name):
			score = 80
		case call.Callee.Type == calleeID.Type &&
			methodArityKey(call.Callee.Name) == methodArityKey(calleeID.Name):
			score = 60
		case methodArityKey(call.Callee.Name) == methodArityKey(calleeID.Name):
			score = 40
		case callgraph.BaseFunctionName(call.Callee.Name) == callgraph.BaseFunctionName(calleeID.Name):
			score = 20
		}
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		return &callerFn.Calls[bestIdx]
	}
	return nil
}

func methodArityKey(name string) string {
	idx := strings.Index(name, "#")
	if idx <= 0 || idx >= len(name)-1 {
		return name
	}
	j := idx + 1
	for j < len(name) && name[j] >= '0' && name[j] <= '9' {
		j++
	}
	if j == idx+1 {
		return name
	}
	return name[:j]
}

// --- Function name helpers ---

func fullFunctionName(id callgraph.FunctionID) string {
	base := callgraph.BaseFunctionName(id.Name)
	typeName := sanitizeSymbol(id.Type)
	if typeName == "" || strings.Contains(typeName, "(") {
		if id.Package == "" {
			return base
		}
		return id.Package + "." + base
	}
	if id.Package == "" {
		return typeName + "." + base
	}
	return id.Package + "." + typeName + "." + base
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

type normalizedExportLocation struct {
	FilePath       string
	DependencyInfo *callGraphDependencyContext
}

func buildFindingLocation(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) *callGraphFindingLocation {
	location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
	return &callGraphFindingLocation{
		FilePath:       location.FilePath,
		StartLine:      asset.StartLine,
		EndLine:        asset.EndLine,
		Language:       finding.Language,
		DependencyInfo: location.DependencyInfo,
	}
}

func normalizeFindingPath(ctx *exportBuildContext, findingPath string, depInfo *entities.DependencyInfo) normalizedExportLocation {
	if depInfo != nil && depInfo.Module != "" && depInfo.Version != "" {
		return normalizedExportLocation{
			FilePath:       filepath.ToSlash(findingPath),
			DependencyInfo: dependencyContextFromEntity(depInfo),
		}
	}
	return normalizeExportPath(ctx, findingPath)
}

func normalizeExportPath(ctx *exportBuildContext, actualPath string) normalizedExportLocation {
	if actualPath == "" {
		return normalizedExportLocation{}
	}

	cleanPath := filepath.Clean(actualPath)
	if dep := ctx.dependencyForPath(cleanPath); dep != nil {
		if rel, ok := relativeToRoot(dep.Dir, cleanPath); ok {
			return normalizedExportLocation{
				FilePath: filepath.ToSlash(rel),
				DependencyInfo: &callGraphDependencyContext{
					Module:  dep.Module,
					Version: dep.Version,
				},
			}
		}
		if !filepath.IsAbs(cleanPath) {
			return normalizedExportLocation{
				FilePath: filepath.ToSlash(cleanPath),
				DependencyInfo: &callGraphDependencyContext{
					Module:  dep.Module,
					Version: dep.Version,
				},
			}
		}
	}

	if rel, ok := relativeToRoot(ctx.projectRoot, cleanPath); ok {
		return normalizedExportLocation{FilePath: filepath.ToSlash(rel)}
	}
	if !filepath.IsAbs(cleanPath) {
		return normalizedExportLocation{FilePath: filepath.ToSlash(cleanPath)}
	}
	return normalizedExportLocation{FilePath: filepath.ToSlash(cleanPath)}
}

func (ctx *exportBuildContext) dependencyForPath(path string) *exportDependencyRoot {
	for i := range ctx.dependencies {
		dep := &ctx.dependencies[i]
		if _, ok := relativeToRoot(dep.Dir, path); ok {
			return dep
		}
	}
	return nil
}

func relativeToRoot(root, path string) (string, bool) {
	if root == "" {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return ".", true
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", false
	}
	return rel, true
}

func dependencyContextFromEntity(depInfo *entities.DependencyInfo) *callGraphDependencyContext {
	if depInfo == nil || depInfo.Module == "" || depInfo.Version == "" {
		return nil
	}
	return &callGraphDependencyContext{
		Module:  depInfo.Module,
		Version: depInfo.Version,
	}
}

func (ctx *exportBuildContext) findContainingFunctionByFinding(findingPath string, line int) *callgraph.FunctionDecl {
	normalizedFindingPath := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalizedFindingPath == "" {
		normalizedFindingPath = filepath.ToSlash(findingPath)
	}

	cacheKey := fmt.Sprintf("%s:%d", normalizedFindingPath, line)
	if cached, ok := ctx.containingFunctionCache[cacheKey]; ok {
		if cached.found {
			return cached.fn
		}
		return nil
	}

	for _, fn := range ctx.graph.Functions {
		fnPath := filepath.ToSlash(fn.FilePath)
		if !strings.HasSuffix(fnPath, normalizedFindingPath) {
			continue
		}
		if line >= fn.StartLine && line <= fn.EndLine {
			ctx.containingFunctionCache[cacheKey] = cachedContainingFunction{fn: fn, found: true}
			return fn
		}
	}
	ctx.containingFunctionCache[cacheKey] = cachedContainingFunction{found: false}
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

func isSimpleIdentifier(expr string) bool {
	if expr == "" {
		return false
	}
	for i, r := range expr {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '$' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
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
