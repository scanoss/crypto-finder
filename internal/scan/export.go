package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

const (
	// callGraphSchemaVersion is sourced from pkg/graphfrag so the live
	// --export-callgraph CLI path and the stitch path (ToCallgraphExport) always
	// stamp the same schema_version — single source of truth, no drift.
	callGraphSchemaVersion         = graphfrag.CallgraphSchemaVersion
	matchedOperationCall           = "call"
	sourceNodeTypeParameter        = "PARAMETER"
	sourceNodeTypeValue            = "VALUE"
	sourceNodeTypeCallResult       = "CALL_RESULT"
	sourceNodeTypeField            = "FIELD"
	callGraphExportProgress        = 100
	callGraphExportMaxDepth        = 32
	callGraphExportMaxChains       = 128
	maxExportSourceResolutionDepth = 8
	constructorMethodName          = "<init>"
)

// --- v4 JSON schema types (simplified) ---

type exportBuildContext struct {
	graph                   *callgraph.CallGraph
	projectRoot             string
	dependencies            []exportDependencyRoot
	containingFunctionCache map[string]cachedContainingFunction
	callChainCache          map[string][][]callGraphChainNode
	callChainRemainingUses  map[string]int
	fragmentEdgeResolutions map[string][]fragmentEdgeResolution
	userPackages            map[string]bool
	packageSeparator        string
	// kb holds the ecosystem's callgraph contracts, used to attach contract-role
	// supporting calls (fluent lifecycle methods) to synthesized terminal entry
	// points. nil for ecosystems with no contracts.
	kb            *contracts.KnowledgeBase
	declIndex     map[string][]*callgraph.FunctionDecl      // base FQN → overloads
	declsByMethod map[string][]operationContractDeclaration // method name → definitions
	// callsBySignature caches, per caller FunctionID key, an index of that
	// caller's FunctionCalls grouped by the (Package, Type, BaseFunctionName)
	// tuple callMatchesCallee compares — the same fuzzy key an
	// overload/dispatch-expanded calleeKey still matches against its one
	// underlying source call. Built lazily (one caller's Calls slice is
	// indexed at most once, on first lookup) via callSignatureIndexForCaller,
	// so a caller with heavy dispatch fan-out (many resolved edges, one
	// source call site) pays the O(len(Calls)) index-build cost once instead
	// of once per edge. nil until first use.
	callsBySignature     map[string]map[string][]*callgraph.FunctionCall
	calleeSignatureKeys  map[string]string
	chainIDsByCallerLine map[string]map[int]string
}

type cachedContainingFunction struct {
	fn    *callgraph.FunctionDecl
	found bool
}

type callGraphExportV2 struct {
	SchemaVersion     string                      `json:"schema_version"`
	ScanMetadata      callGraphExportScanMeta     `json:"scan_metadata"`
	FindingGraphs     []callGraphExportFinding    `json:"finding_graphs"`
	SupportingCalls   []callGraphSupportingCall   `json:"supporting_calls,omitempty"`
	CryptoEntryPoints []callGraphCryptoEntryPoint `json:"crypto_entry_points,omitempty"`
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
	FindingID         string                     `json:"finding_id"`
	MatchedOperation  *callGraphMatchedOperation `json:"matched_operation,omitempty"`
	FindingLocation   *callGraphFindingLocation  `json:"finding_location,omitempty"`
	UnresolvedReason  string                     `json:"unresolved_reason,omitempty"`
	SupportingCallIDs []string                   `json:"supporting_call_ids,omitempty"`
	CallChains        [][]callGraphChainNode     `json:"call_chains,omitempty"`
}

type callGraphDependencyContext struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

// callGraphRoleProvenance explains where a method_role/parameter contribution
// came from: a direct contract match, or inherited from same-class sibling
// contract metadata.
type callGraphRoleProvenance struct {
	Kind               string                  `json:"kind,omitempty"`
	ContractMethod     string                  `json:"contract_method,omitempty"`
	InheritedFrom      string                  `json:"inherited_from,omitempty"`
	Inherited          *callGraphInheritedRole `json:"inherited,omitempty"`
	InheritedAmbiguous bool                    `json:"inherited_ambiguous,omitempty"`
}

// callGraphInheritedRole carries the algorithm_family/primitive a synthesized
// operation entry point inherited from a same-class sibling asset.
type callGraphInheritedRole struct {
	AlgorithmFamily string `json:"algorithm_family,omitempty"`
	Primitive       string `json:"primitive,omitempty"`
}

// callGraphParameterRole is one index-aligned parameter role/contribution
// entry (issue-103 WU3), mirrored across crypto_entry_points and the
// supporting-call declaration (callGraphCalledFunction). Never emitted on
// call-site callGraphParameter (literal values stay there).
type callGraphParameterRole struct {
	Index       int                    `json:"index"`
	Name        string                 `json:"name,omitempty"`
	Role        string                 `json:"role"`
	Contributes *callGraphContribution `json:"contributes,omitempty"`
}

// callGraphContribution names the property a parameter contributes to and
// the derivation strategy a downstream consumer applies.
type callGraphContribution struct {
	Property   string `json:"property,omitempty"`
	Derivation string `json:"derivation,omitempty"`
}

type callGraphCalledFunction struct {
	FunctionName       string                `json:"function_name"`
	CanonicalSignature string                `json:"canonical_signature,omitempty"`
	ReturnType         string                `json:"return_type,omitempty"`
	ReturnTypeRef      *exportTypeRef        `json:"return_type_ref,omitempty"`
	ParameterTypes     []string              `json:"parameter_types,omitempty"`
	ParameterTypeRefs  []exportTypeRef       `json:"parameter_type_refs,omitempty"`
	DisplaySymbol      string                `json:"display_symbol,omitempty"`
	Aliases            []string              `json:"aliases,omitempty"`
	Line               int                   `json:"line"`
	Parameters         []callGraphParameter  `json:"parameters,omitempty"`
	InferredReturn     *exportInferredReturn `json:"inferred_return,omitempty"`
	// ParameterRoles is populated from the contracts KB (issue-103 WU3) on the
	// supporting-call declaration; index-aligned with ParameterTypes.
	ParameterRoles []callGraphParameterRole `json:"parameter_roles,omitempty"`
}

// exportTypeRef is the JSON shape for a structured Java type reference,
// optionally carrying nested generic parameters. Surfaced alongside the
// existing flat return_type/parameter_types strings (which keep the erased
// type name for backwards compatibility).
type exportTypeRef struct {
	Name              string          `json:"name"`
	GenericParameters []exportTypeRef `json:"generic_parameters,omitempty"`
}

type callGraphMatchedOperation struct {
	Kind   string `json:"kind"`
	Symbol string `json:"symbol,omitempty"`
	// DisplaySymbol is the customer-facing symbol, with constructor aliases
	// (ClassName.ClassName). Derived from Symbol; empty for non-constructors.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	Expression    string `json:"expression,omitempty"`
	Line          int    `json:"line"`
}

type callGraphEntryCall struct {
	FunctionName       string                `json:"function_name,omitempty"`
	CanonicalSignature string                `json:"canonical_signature,omitempty"`
	ReturnType         string                `json:"return_type,omitempty"`
	ReturnTypeRef      *exportTypeRef        `json:"return_type_ref,omitempty"`
	ParameterTypes     []string              `json:"parameter_types,omitempty"`
	ParameterTypeRefs  []exportTypeRef       `json:"parameter_type_refs,omitempty"`
	DisplaySymbol      string                `json:"display_symbol,omitempty"`
	Aliases            []string              `json:"aliases,omitempty"`
	FilePath           string                `json:"file_path"`
	Line               int                   `json:"line"`
	Parameters         []callGraphParameter  `json:"parameters,omitempty"`
	InferredReturn     *exportInferredReturn `json:"inferred_return,omitempty"`
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
	Type                     string                `json:"type"`
	Name                     string                `json:"name,omitempty"`
	DeclaredType             string                `json:"declared_type,omitempty"`
	Value                    string                `json:"value,omitempty"`
	ParameterIndex           *int                  `json:"parameter_index,omitempty"`
	CallTarget               string                `json:"call_target,omitempty"`
	CallTargetDisplaySymbol  string                `json:"call_target_display_symbol,omitempty"`
	CallTargetInferredReturn *exportInferredReturn `json:"call_target_inferred_return,omitempty"`
	Location                 *exportSourceLocation `json:"location,omitempty"`
	SourceNodes              []exportSourceNode    `json:"source_nodes,omitempty"`
	returnValue              bool
	guard                    *callgraph.SourceGuard
	callArgument             bool
	sourceParameterIndex     int
}

type exportSourceLocation struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type callGraphChainNode struct {
	FunctionKey        string                      `json:"function_key,omitempty"`
	FunctionName       string                      `json:"function_name"`
	CanonicalSignature string                      `json:"canonical_signature,omitempty"`
	ReturnType         string                      `json:"return_type,omitempty"`
	ReturnTypeRef      *exportTypeRef              `json:"return_type_ref,omitempty"`
	ParameterTypes     []string                    `json:"parameter_types,omitempty"`
	ParameterTypeRefs  []exportTypeRef             `json:"parameter_type_refs,omitempty"`
	Visibility         string                      `json:"visibility,omitempty"`
	OwnerVisibility    string                      `json:"owner_visibility,omitempty"`
	DisplaySymbol      string                      `json:"display_symbol,omitempty"`
	Aliases            []string                    `json:"aliases,omitempty"`
	FilePath           string                      `json:"file_path"`
	StartLine          int                         `json:"start_line,omitempty"`
	DependencyInfo     *callGraphDependencyContext `json:"dependency_info,omitempty"`
	EntryCall          *callGraphEntryCall         `json:"entry_call,omitempty"`
	CryptoCall         *callGraphCalledFunction    `json:"crypto_call,omitempty"`
	InferredReturn     *exportInferredReturn       `json:"inferred_return,omitempty"`
}

type callGraphCryptoEntryPoint struct {
	FunctionKey              string                             `json:"function_key"`
	FunctionName             string                             `json:"function_name,omitempty"`
	CanonicalSignature       string                             `json:"canonical_signature,omitempty"`
	Class                    string                             `json:"class,omitempty"`
	Method                   string                             `json:"method"`
	ReturnType               string                             `json:"return_type,omitempty"`
	ReturnTypeRef            *exportTypeRef                     `json:"return_type_ref,omitempty"`
	ParameterTypes           []string                           `json:"parameter_types,omitempty"`
	ParameterTypeRefs        []exportTypeRef                    `json:"parameter_type_refs,omitempty"`
	Visibility               string                             `json:"visibility,omitempty"`
	OwnerVisibility          string                             `json:"owner_visibility,omitempty"`
	DisplaySymbol            string                             `json:"display_symbol,omitempty"`
	Aliases                  []string                           `json:"aliases,omitempty"`
	ReachableFindings        []callGraphReachableFinding        `json:"reachable_findings,omitempty"`
	ReachableSupportingCalls []callGraphReachableSupportingCall `json:"reachable_supporting_calls,omitempty"`
	// MethodRole, RoleProvenance, ParameterRoles are issue-103 (WU2/WU3)
	// additions: the contract-derived role classification of this entry
	// point's method, its provenance, and any per-parameter contributions.
	// All omitempty — absent for entry points with no KB role match.
	MethodRole     string                   `json:"method_role,omitempty"`
	RoleProvenance *callGraphRoleProvenance `json:"role_provenance,omitempty"`
	ParameterRoles []callGraphParameterRole `json:"parameter_roles,omitempty"`
}

type callGraphReachableFinding struct {
	FindingID        string                     `json:"finding_id"`
	MatchedOperation *callGraphMatchedOperation `json:"matched_operation"`
	ChainDepth       int                        `json:"chain_depth"`
	FindingGraphRef  string                     `json:"finding_graph_ref"`
}

type callGraphReachableSupportingCall struct {
	SupportingID      string `json:"supporting_id"`
	ChainDepth        int    `json:"chain_depth"`
	SupportingCallRef string `json:"supporting_call_ref,omitempty"`
}

type callGraphSupportingCall struct {
	SupportingID       string                     `json:"supporting_id"`
	FunctionKey        string                     `json:"function_key,omitempty"`
	FunctionName       string                     `json:"function_name,omitempty"`
	CanonicalSignature string                     `json:"canonical_signature,omitempty"`
	DisplaySymbol      string                     `json:"display_symbol,omitempty"`
	Aliases            []string                   `json:"aliases,omitempty"`
	Category           string                     `json:"category,omitempty"`
	FilePath           string                     `json:"file_path,omitempty"`
	StartLine          int                        `json:"start_line,omitempty"`
	EndLine            int                        `json:"end_line,omitempty"`
	MatchedOperation   *callGraphMatchedOperation `json:"matched_operation,omitempty"`
	SupportingCall     *callGraphCalledFunction   `json:"supporting_call,omitempty"`
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
	payload, err := buildCallGraphExportV2ToFile(path, result)
	buildDuration := time.Since(buildStart)
	if err != nil {
		return err
	}

	log.Info().
		Str("file", path).
		Str("format", format).
		Int("functions", payload.ScanMetadata.FunctionCount).
		Int("edges", payload.ScanMetadata.EdgeCount).
		Int("findings", len(payload.FindingGraphs)).
		Dur("build_duration", buildDuration).
		Dur("total_duration", time.Since(exportStart)).
		Msg("Exported integration call graph")

	return nil
}

func buildCallGraphExportV2ToFile(path string, result *engine.DepScanResult) (callGraphExportV2, error) {
	ctx := newExportBuildContext(result)
	assets := callGraphExportAssets(result.Report)
	meta := buildCallGraphExportScanMeta(result)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return callGraphExportV2{}, fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}
	bw := bufio.NewWriterSize(file, 1<<20)
	writer := graphFragmentJSONWriter{w: bw}

	streamed, writeErr := streamCallGraphExport(&writer, ctx, assets, meta)
	if err := finishBufferedOutput(file, bw, writeErr); err != nil {
		return callGraphExportV2{}, fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}

	return callGraphExportV2{
		SchemaVersion:     callGraphSchemaVersion,
		ScanMetadata:      meta,
		FindingGraphs:     make([]callGraphExportFinding, len(assets)),
		SupportingCalls:   streamed.supportingCalls,
		CryptoEntryPoints: streamed.entryPoints,
	}, nil
}

type streamedCallGraphExport struct {
	supportingCalls []callGraphSupportingCall
	entryPoints     []callGraphCryptoEntryPoint
}

func streamCallGraphExport(
	writer *graphFragmentJSONWriter,
	ctx *exportBuildContext,
	assets []callGraphExportAsset,
	meta callGraphExportScanMeta,
) (streamedCallGraphExport, error) {
	if err := writeCallGraphPrefix(writer, meta); err != nil {
		return streamedCallGraphExport{}, err
	}
	index, supportingByID, referencedSupporting, err := streamFindingGraphs(writer, ctx, assets)
	if err != nil {
		return streamedCallGraphExport{}, err
	}

	supportingCalls := sortedSupportingCalls(supportingByID)
	for i := range supportingCalls {
		if _, ok := referencedSupporting[supportingCalls[i].SupportingID]; ok {
			continue
		}
		addSupportingCallToEntryPointIndex(index, supportingCalls[i])
	}
	if err := writeGraphFragmentArrayField(writer, "supporting_calls", supportingCalls, true); err != nil {
		return streamedCallGraphExport{}, err
	}

	entryPoints := flattenEntryPointIndex(ctx.kb, index)
	if err := writeGraphFragmentArrayField(writer, "crypto_entry_points", entryPoints, true); err != nil {
		return streamedCallGraphExport{}, err
	}
	if _, err := writer.w.WriteString("\n}\n"); err != nil {
		return streamedCallGraphExport{}, err
	}
	return streamedCallGraphExport{supportingCalls: supportingCalls, entryPoints: entryPoints}, nil
}

func writeCallGraphPrefix(writer *graphFragmentJSONWriter, meta callGraphExportScanMeta) error {
	if _, err := writer.w.WriteString("{\n"); err != nil {
		return err
	}
	if err := writer.writeField("schema_version", callGraphSchemaVersion); err != nil {
		return err
	}
	if err := writer.writeField("scan_metadata", meta); err != nil {
		return err
	}
	return writer.startArrayField("finding_graphs")
}

func streamFindingGraphs(
	writer *graphFragmentJSONWriter,
	ctx *exportBuildContext,
	assets []callGraphExportAsset,
) (map[string]*entryPointData, map[string]callGraphSupportingCall, map[string]struct{}, error) {
	index := make(map[string]*entryPointData)
	supportingByID := make(map[string]callGraphSupportingCall)
	referencedSupporting := make(map[string]struct{})
	buildStart := time.Now()

	for i := range assets {
		item := assets[i]
		supporting := deriveSupportingCallsForFinding(ctx, item.finding, item.asset)
		indexSupportingCalls(supportingByID, supporting)

		fg := buildFindingGraph(ctx, item.finding, item.asset)
		fg.SupportingCallIDs = supportingCallIDsOf(supporting)
		addFindingGraphToEntryPointIndex(index, &fg)
		addFindingGraphSupportingToEntryPointIndex(index, &fg, supportingByID, referencedSupporting)
		if err := writer.writeArrayElement(i, fg); err != nil {
			return nil, nil, nil, err
		}
		logCallGraphExportProgress(i+1, len(assets), buildStart)
	}
	if err := writer.endArrayField(len(assets)); err != nil {
		return nil, nil, nil, err
	}
	return index, supportingByID, referencedSupporting, nil
}

func indexSupportingCalls(dst map[string]callGraphSupportingCall, supporting []callGraphSupportingCall) {
	for i := range supporting {
		support := supporting[i]
		if support.SupportingID == "" {
			continue
		}
		if _, exists := dst[support.SupportingID]; !exists {
			dst[support.SupportingID] = support
		}
	}
}

func logCallGraphExportProgress(processed, total int, start time.Time) {
	if processed%callGraphExportProgress != 0 && processed != total {
		return
	}
	log.Info().
		Int("processed", processed).
		Int("total", total).
		Dur("elapsed", time.Since(start)).
		Msg("Building integration call graph export")
}

func finishBufferedOutput(file *os.File, bw *bufio.Writer, writeErr error) error {
	err := writeErr
	if err == nil {
		err = bw.Flush()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

type callGraphExportAsset struct {
	finding entities.Finding
	asset   entities.CryptographicAsset
}

func callGraphExportAssets(report *entities.InterimReport) []callGraphExportAsset {
	if report == nil {
		return nil
	}
	var assets []callGraphExportAsset
	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			assets = append(assets, callGraphExportAsset{finding: finding, asset: finding.CryptographicAssets[i]})
		}
	}
	return assets
}

func sortedSupportingCalls(values map[string]callGraphSupportingCall) []callGraphSupportingCall {
	out := make([]callGraphSupportingCall, 0, len(values))
	for key := range values {
		out = append(out, values[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].SupportingID < out[j].SupportingID
	})
	return out
}

func buildCallGraphExportScanMeta(result *engine.DepScanResult) callGraphExportScanMeta {
	meta := callGraphExportScanMeta{
		Ecosystem:     result.Ecosystem,
		RootModule:    result.RootModule,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		FunctionCount: len(result.CallGraph.Functions),
		EdgeCount:     countCallGraphEdges(result.CallGraph),
	}
	if result.Report != nil {
		meta.ToolName = result.Report.Tool.Name
		meta.ToolVersion = result.Report.Tool.Version
	}
	if result.Ecosystem == ecosystemJava && result.CallGraph != nil && result.CallGraph.JavaPlatformSignatures != nil {
		javaMeta := result.CallGraph.JavaPlatformSignatures
		meta.JavaRequestedJDKMajor = javaMeta.RequestedMajor
		meta.JavaRuntimeVersion = javaMeta.RuntimeVersion
		used := javaMeta.SignaturesUsed
		meta.JavaPlatformSignaturesUsed = &used
		meta.JavaPlatformSignatureSource = javaMeta.SignatureSource
		meta.JavaPlatformSignatureUnavailableReason = javaMeta.UnavailableReason
	}
	return meta
}

func writeIndentedJSONFile(path string, payload any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	err = enc.Encode(payload)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
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
	if result.Ecosystem == ecosystemJava && result.CallGraph != nil && result.CallGraph.JavaPlatformSignatures != nil {
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
			// Derive once: the per-finding supporting calls are the precise
			// finding->supporting link. Capture their ids onto the finding_graph
			// HERE — the top-level slice is deduped across findings (line ~375)
			// and loses which finding each call belongs to.
			supporting := deriveSupportingCallsForFinding(ctx, finding, asset)
			fg := buildFindingGraph(ctx, finding, asset)
			fg.SupportingCallIDs = supportingCallIDsOf(supporting)
			out.FindingGraphs = append(out.FindingGraphs, fg)
			out.SupportingCalls = append(out.SupportingCalls, supporting...)
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

	out.SupportingCalls = dedupSupportingCalls(out.SupportingCalls)
	sort.SliceStable(out.SupportingCalls, func(i, j int) bool {
		return out.SupportingCalls[i].SupportingID < out.SupportingCalls[j].SupportingID
	})
	out.CryptoEntryPoints = buildCryptoEntryPoints(ctx.kb, out.FindingGraphs, out.SupportingCalls)

	return out
}

// buildCryptoEntryPoints creates an O(1) lookup from function name to reachable
// crypto operations. Every function that appears in any call chain is a
// potential entry point — external code might call any of them. kb is
// consulted (issue-103 WU3) to populate parameter_roles on entries whose
// function+arity matches a contract; nil kb simply skips that enrichment.
func buildCryptoEntryPoints(kb *contracts.KnowledgeBase, findingGraphs []callGraphExportFinding, supportingCalls []callGraphSupportingCall) []callGraphCryptoEntryPoint {
	index := make(map[string]*entryPointData)
	supportingByID := make(map[string]callGraphSupportingCall, len(supportingCalls))
	for i := range supportingCalls {
		if supportingCalls[i].SupportingID != "" {
			supportingByID[supportingCalls[i].SupportingID] = supportingCalls[i]
		}
	}
	referencedSupporting := make(map[string]struct{}, len(supportingByID))
	for i := range findingGraphs {
		addFindingGraphToEntryPointIndex(index, &findingGraphs[i])
		addFindingGraphSupportingToEntryPointIndex(index, &findingGraphs[i], supportingByID, referencedSupporting)
	}
	for i := range supportingCalls {
		if _, ok := referencedSupporting[supportingCalls[i].SupportingID]; ok {
			continue
		}
		addSupportingCallToEntryPointIndex(index, supportingCalls[i])
	}
	return flattenEntryPointIndex(kb, index)
}

// splitFunctionName extracts class and method from a fully qualified function name.
// e.g., "org.apache.http.ssl.SSLContextBuilder.build" → ("org.apache.http.ssl.SSLContextBuilder", "build").
func splitFunctionName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}

type entryPointFindingRef struct {
	findingID  string
	matchedOp  *callGraphMatchedOperation
	chainDepth int
}

type entryPointData struct {
	functionKey        string
	function           string
	canonicalSignature string
	class              string
	method             string
	returnType         string
	returnTypeRef      *exportTypeRef
	parameterTypes     []string
	parameterTypeRefs  []exportTypeRef
	visibility         string
	ownerVisibility    string
	displaySymbol      string
	aliases            []string
	findings           map[string]entryPointFindingRef // findingID → ref (keep shallowest depth)
	supporting         map[string]callGraphReachableSupportingCall
}

func addFindingGraphToEntryPointIndex(index map[string]*entryPointData, fg *callGraphExportFinding) {
	if fg == nil || fg.MatchedOperation == nil {
		return
	}
	for _, chain := range fg.CallChains {
		addEntryPointChain(index, fg, chain)
	}
}

func addEntryPointChain(index map[string]*entryPointData, fg *callGraphExportFinding, chain []callGraphChainNode) {
	if len(chain) == 0 {
		return
	}
	for pos := range chain {
		node := &chain[pos]
		if node.FunctionName == "" {
			continue
		}
		recordEntryPointFinding(ensureEntryPointData(index, node), fg, len(chain)-pos)
	}
}

func addFindingGraphSupportingToEntryPointIndex(
	index map[string]*entryPointData,
	fg *callGraphExportFinding,
	supportingByID map[string]callGraphSupportingCall,
	referencedSupporting map[string]struct{},
) {
	if fg == nil || len(fg.SupportingCallIDs) == 0 {
		return
	}
	for _, chain := range fg.CallChains {
		if len(chain) == 0 {
			continue
		}
		for pos := range chain {
			node := &chain[pos]
			if node.FunctionName == "" {
				continue
			}
			ep := ensureEntryPointData(index, node)
			depth := len(chain) - pos
			for _, supportingID := range fg.SupportingCallIDs {
				support, ok := supportingByID[supportingID]
				if !ok {
					continue
				}
				referencedSupporting[supportingID] = struct{}{}
				recordEntryPointSupporting(ep, support, depth)
			}
		}
	}
}

func ensureEntryPointData(index map[string]*entryPointData, node *callGraphChainNode) *entryPointData {
	key := node.FunctionKey
	if key == "" {
		key = node.CanonicalSignature
	}
	if key == "" {
		key = node.FunctionName
	}
	if ep := index[key]; ep != nil {
		mergeEntryPointData(ep, node)
		return ep
	}

	class, method := splitFunctionName(node.FunctionName)
	ep := &entryPointData{
		functionKey:        key,
		function:           node.FunctionName,
		canonicalSignature: node.CanonicalSignature,
		class:              class,
		method:             method,
		returnType:         node.ReturnType,
		returnTypeRef:      cloneExportTypeRef(node.ReturnTypeRef),
		parameterTypes:     cloneStringSlice(node.ParameterTypes),
		parameterTypeRefs:  cloneExportTypeRefs(node.ParameterTypeRefs),
		visibility:         node.Visibility,
		ownerVisibility:    node.OwnerVisibility,
		displaySymbol:      node.DisplaySymbol,
		aliases:            cloneStringSlice(node.Aliases),
		findings:           make(map[string]entryPointFindingRef),
		supporting:         make(map[string]callGraphReachableSupportingCall),
	}
	index[key] = ep
	return ep
}

func mergeEntryPointData(ep *entryPointData, node *callGraphChainNode) {
	if ep == nil || node == nil {
		return
	}
	if ep.canonicalSignature == "" {
		ep.canonicalSignature = node.CanonicalSignature
	}
	if ep.returnType == "" {
		ep.returnType = node.ReturnType
	}
	if ep.returnTypeRef == nil {
		ep.returnTypeRef = cloneExportTypeRef(node.ReturnTypeRef)
	}
	if len(ep.parameterTypes) == 0 {
		ep.parameterTypes = cloneStringSlice(node.ParameterTypes)
	}
	if len(ep.parameterTypeRefs) == 0 {
		ep.parameterTypeRefs = cloneExportTypeRefs(node.ParameterTypeRefs)
	}
	if ep.visibility == "" {
		ep.visibility = node.Visibility
	}
	if ep.ownerVisibility == "" {
		ep.ownerVisibility = node.OwnerVisibility
	}
	if ep.displaySymbol == "" {
		ep.displaySymbol = node.DisplaySymbol
	}
	if len(ep.aliases) == 0 {
		ep.aliases = cloneStringSlice(node.Aliases)
	}
}

func recordEntryPointFinding(ep *entryPointData, fg *callGraphExportFinding, depth int) {
	if ep == nil || fg == nil || fg.MatchedOperation == nil {
		return
	}

	existing, exists := ep.findings[fg.FindingID]
	if exists && depth >= existing.chainDepth {
		return
	}

	ep.findings[fg.FindingID] = entryPointFindingRef{
		findingID:  fg.FindingID,
		matchedOp:  fg.MatchedOperation,
		chainDepth: depth,
	}
}

func recordEntryPointSupporting(ep *entryPointData, support callGraphSupportingCall, depth int) {
	if ep == nil || support.SupportingID == "" {
		return
	}
	existing, exists := ep.supporting[support.SupportingID]
	if exists && depth >= existing.ChainDepth {
		return
	}
	ep.supporting[support.SupportingID] = callGraphReachableSupportingCall{
		SupportingID:      support.SupportingID,
		ChainDepth:        depth,
		SupportingCallRef: support.SupportingID,
	}
}

func addSupportingCallToEntryPointIndex(index map[string]*entryPointData, support callGraphSupportingCall) {
	key := support.FunctionKey
	if key == "" {
		key = support.CanonicalSignature
	}
	if key == "" {
		key = support.FunctionName
	}
	if key == "" || support.SupportingID == "" {
		return
	}
	ep := index[key]
	if ep == nil {
		class, method := splitFunctionName(support.FunctionName)
		ep = &entryPointData{
			functionKey:        key,
			function:           support.FunctionName,
			canonicalSignature: support.CanonicalSignature,
			class:              class,
			method:             method,
			displaySymbol:      support.DisplaySymbol,
			aliases:            cloneStringSlice(support.Aliases),
			findings:           make(map[string]entryPointFindingRef),
			supporting:         make(map[string]callGraphReachableSupportingCall),
		}
		index[key] = ep
	}
	recordEntryPointSupporting(ep, support, 1)
}

func flattenEntryPointIndex(kb *contracts.KnowledgeBase, index map[string]*entryPointData) []callGraphCryptoEntryPoint {
	result := make([]callGraphCryptoEntryPoint, 0, len(index))
	for _, ep := range index {
		result = append(result, callGraphCryptoEntryPoint{
			FunctionKey:              ep.functionKey,
			FunctionName:             ep.function,
			CanonicalSignature:       ep.canonicalSignature,
			Class:                    ep.class,
			Method:                   ep.method,
			ReturnType:               ep.returnType,
			ReturnTypeRef:            cloneExportTypeRef(ep.returnTypeRef),
			ParameterTypes:           cloneStringSlice(ep.parameterTypes),
			ParameterTypeRefs:        cloneExportTypeRefs(ep.parameterTypeRefs),
			Visibility:               ep.visibility,
			OwnerVisibility:          ep.ownerVisibility,
			DisplaySymbol:            ep.displaySymbol,
			Aliases:                  cloneStringSlice(ep.aliases),
			ReachableFindings:        flattenReachableFindings(ep.findings),
			ReachableSupportingCalls: flattenReachableSupportingCalls(ep.supporting),
			ParameterRoles:           parameterRolesFromKB(kb, ep.function, len(ep.parameterTypes)),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].FunctionKey < result[j].FunctionKey
	})
	return result
}

// parameterRolesFromKB returns the exported parameter-role list for a method
// FQN+arity from the contracts KB (issue-103 WU3): the first contract match
// (by ContractsForTolerant) that declares a non-empty Parameters list. Never
// emitted for call-site literals (callGraphParameter carries no such field);
// only for method-static surfaces (crypto_entry_points, supporting-call decl).
func parameterRolesFromKB(kb *contracts.KnowledgeBase, fqn string, arity int) []callGraphParameterRole {
	if kb == nil || fqn == "" {
		return nil
	}
	return parameterRolesFromContracts(kb.ContractsForTolerant(fqn, arity))
}

func parameterRolesFromContracts(matches []contracts.Contract) []callGraphParameterRole {
	for i := range matches {
		contract := &matches[i]
		if len(contract.Parameters) == 0 {
			continue
		}
		out := make([]callGraphParameterRole, 0, len(contract.Parameters))
		for _, p := range contract.Parameters {
			idx := 0
			if p.Index != nil {
				idx = *p.Index
			}
			pr := callGraphParameterRole{Index: idx, Name: p.Name, Role: p.Role}
			if p.Contributes != nil {
				pr.Contributes = &callGraphContribution{
					Property:   p.Contributes.Property,
					Derivation: p.Contributes.Derivation,
				}
			}
			out = append(out, pr)
		}
		return out
	}
	return nil
}

func contractMatchesForCall(ctx *exportBuildContext, call *callgraph.FunctionCall, arity int) []contracts.Contract {
	if ctx.kb == nil || call == nil {
		return nil
	}
	fqn := fullFunctionName(call.Callee)
	if ctx.kb.Ecosystem != "c" {
		matches := ctx.kb.ContractsForTolerant(fqn, arity)
		if len(matches) == 0 && ctx.kb.Ecosystem == "cpp" && call.Callee.Type != "" && call.Callee.Linkage != callgraph.LinkageInternal && !hasCallDeclaration(ctx.graph, call.Callee) {
			matches = ctx.kb.ContractsForTolerant(call.Callee.Type+"."+callgraph.BaseFunctionName(call.Callee.Name), arity)
		}
		return exactConditionalContracts(matches, call)
	}
	if exact := ctx.kb.ContractsFor(fqn, arity); len(exact) > 0 {
		return exactConditionalContracts(exact, call)
	}
	if ctx.graph == nil {
		return nil
	}
	externalGlobal := call.Callee.Linkage == callgraph.LinkageExternal && ctx.graph.Functions[call.Callee.String()] == nil
	return exactConditionalContracts(ctx.kb.ContractsForCFunction(fqn, arity, externalGlobal), call)
}

func exactConditionalContracts(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	exact := matchingConditionalContracts(matches, call)
	if len(exact) > 0 {
		return exact
	}
	return matches
}

func canonicalContractsForCall(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	if exact := matchingConditionalContracts(matches, call); len(exact) > 0 {
		return exact
	}
	unconditional := make([]contracts.Contract, 0, len(matches))
	for i := range matches {
		if matches[i].When == nil {
			unconditional = append(unconditional, matches[i])
		}
	}
	return unconditional
}

func matchingConditionalContracts(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	exact := make([]contracts.Contract, 0, len(matches))
	for i := range matches {
		condition := matches[i].When
		if condition == nil || condition.ArgIndex < 0 || condition.ArgIndex >= len(call.Arguments) {
			continue
		}
		argument := strings.TrimSpace(call.Arguments[condition.ArgIndex])
		if slices.ContainsFunc(condition.ArgValueIn, func(want string) bool {
			return argument == strings.TrimSpace(want)
		}) {
			exact = append(exact, matches[i])
		}
	}
	return exact
}

func hasCallDeclaration(graph *callgraph.CallGraph, id callgraph.FunctionID) bool {
	if graph == nil {
		return false
	}
	if graph.Functions[id.String()] != nil {
		return true
	}
	id.Name = callgraph.BaseFunctionName(id.Name)
	return graph.Functions[id.String()] != nil
}

func flattenReachableSupportingCalls(values map[string]callGraphReachableSupportingCall) []callGraphReachableSupportingCall {
	if len(values) == 0 {
		return nil
	}
	out := make([]callGraphReachableSupportingCall, 0, len(values))
	for key := range values {
		out = append(out, values[key])
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SupportingID < out[j].SupportingID
	})
	return out
}

// operationContractDeclaration links a contract method to a concrete function
// declaration in the scanned dependency graph.
type operationContractDeclaration struct {
	declFQN string
	decl    *callgraph.FunctionDecl
}

func (ctx *exportBuildContext) operationContractDeclarations(c contracts.Contract) []operationContractDeclaration {
	contractClass, contractMethod := splitFunctionName(c.Method)
	candidates := ctx.declsByMethod[contractMethod]
	if candidates == nil {
		candidates = ctx.operationContractDeclarationCandidates(contractMethod)
	}
	out := make([]operationContractDeclaration, 0, len(candidates))
	for _, candidate := range candidates {
		declFQN, decl := candidate.declFQN, candidate.decl
		declClass, declMethod := splitFunctionName(declFQN)
		if declMethod != contractMethod || !functionDeclArityMatches(decl, c.Arity) {
			continue
		}
		if declFQN != c.Method && !ctx.typeOrAncestor(contractClass, declClass) {
			continue
		}
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].declFQN != out[j].declFQN {
			return out[i].declFQN < out[j].declFQN
		}
		return out[i].decl.ID.String() < out[j].decl.ID.String()
	})
	return out
}

func (ctx *exportBuildContext) operationContractDeclarationCandidates(method string) []operationContractDeclaration {
	out := make([]operationContractDeclaration, 0, 1)
	for declFQN, declarations := range ctx.declIndex {
		_, declMethod := splitFunctionName(declFQN)
		if declMethod != method {
			continue
		}
		for _, decl := range declarations {
			out = append(out, operationContractDeclaration{declFQN: declFQN, decl: decl})
		}
	}
	return out
}

func functionDeclArityMatches(decl *callgraph.FunctionDecl, want int) bool {
	if decl == nil || want < 0 {
		return true
	}
	i := strings.LastIndexByte(decl.ID.Name, '#')
	if i < 0 {
		return true
	}
	suffix := decl.ID.Name[i+1:]
	digits := 0
	for digits < len(suffix) && suffix[digits] >= '0' && suffix[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return true
	}
	got, err := strconv.Atoi(suffix[:digits])
	return err != nil || got == want
}

func flattenReachableFindings(findings map[string]entryPointFindingRef) []callGraphReachableFinding {
	flattened := make([]callGraphReachableFinding, 0, len(findings))
	for _, ref := range findings {
		flattened = append(flattened, callGraphReachableFinding{
			FindingID: ref.findingID,
			MatchedOperation: &callGraphMatchedOperation{
				Kind:   ref.matchedOp.Kind,
				Symbol: ref.matchedOp.Symbol,
			},
			ChainDepth:      ref.chainDepth,
			FindingGraphRef: ref.findingID,
		})
	}
	sort.Slice(flattened, func(i, j int) bool {
		return flattened[i].FindingID < flattened[j].FindingID
	})
	return flattened
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
		fragmentEdgeResolutions: indexFragmentEdgeResolutions(result.CallGraph),
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

	// Load contracts + index method definitions so synthesized terminal entry
	// points can attach their fluent lifecycle methods as supporting calls.
	if kb, err := contracts.LoadEmbedded(result.Ecosystem); err == nil {
		ctx.kb = kb
	} else {
		log.Debug().
			Err(err).
			Str("ecosystem", result.Ecosystem).
			Msg("failed to load embedded callgraph contracts")
	}
	if result.CallGraph != nil {
		ctx.declIndex = make(map[string][]*callgraph.FunctionDecl, len(result.CallGraph.Functions))
		ctx.declsByMethod = make(map[string][]operationContractDeclaration)
		for _, fn := range result.CallGraph.Functions {
			if fqn := exportFunctionFQN(fn.ID); fqn != "" {
				_, method := splitFunctionName(fqn)
				ctx.declsByMethod[method] = append(ctx.declsByMethod[method], operationContractDeclaration{
					declFQN: fqn,
					decl:    fn,
				})
				ctx.declIndex[fqn] = append(ctx.declIndex[fqn], fn)
			}
		}
		for fqn := range ctx.declIndex {
			sort.Slice(ctx.declIndex[fqn], func(i, j int) bool {
				return ctx.declIndex[fqn][i].ID.String() < ctx.declIndex[fqn][j].ID.String()
			})
		}
		for method := range ctx.declsByMethod {
			sort.Slice(ctx.declsByMethod[method], func(i, j int) bool {
				left, right := ctx.declsByMethod[method][i], ctx.declsByMethod[method][j]
				if left.declFQN != right.declFQN {
					return left.declFQN < right.declFQN
				}
				return left.decl.ID.String() < right.decl.ID.String()
			})
		}
	}
	return ctx
}

// exportFunctionFQN renders a FunctionID as its undecorated package.Type.method
// symbol (no arity/overload suffix), matching contract method keys.
func exportFunctionFQN(id callgraph.FunctionID) string {
	var fqn string
	switch {
	case id.Type != "" && id.Package != "":
		fqn = id.Package + "." + id.Type + "." + id.Name
	case id.Type != "":
		fqn = id.Type + "." + id.Name
	case id.Package != "":
		fqn = id.Package + "." + id.Name
	default:
		fqn = id.Name
	}
	if i := strings.IndexByte(fqn, '#'); i >= 0 {
		return fqn[:i]
	}
	return fqn
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
			fg.MatchedOperation.DisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(cryptoCall.FunctionName)
		}
	}

	fg.CallChains = buildCallChains(ctx, containingFn, cryptoCall)
	if len(asset.ParameterConditions) > 0 {
		fg.CallChains = filterConditionedCallChains(fg.CallChains, asset.ParameterConditions)
	}

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

func filterConditionedCallChains(chains [][]callGraphChainNode, conditions []paramcondition.Condition) [][]callGraphChainNode {
	filtered := make([][]callGraphChainNode, 0, len(chains))
	for _, chain := range chains {
		if len(chain) == 0 || chain[len(chain)-1].CryptoCall == nil {
			continue
		}
		if _, ok := matchParameterConditions(conditions, chain[len(chain)-1].CryptoCall.Parameters); ok {
			filtered = append(filtered, chain)
		}
	}
	return filtered
}

// deriveSupportingCallsForFinding recovers a finding's supporting calls from the
// call graph rather than from rule metadata. It locates the finding's terminal
// crypto call, enumerates the lifecycle calls of the crypto object it identifies
// (see deriveObjectLifecycleCalls), and renders each as a supporting-call entry.
func deriveSupportingCallsForFinding(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) []callGraphSupportingCall {
	// Synthesized terminal entry points (library API boundary, no in-source call
	// chain) get their fluent lifecycle methods from the contract KB by type
	// lineage, since there are no chain siblings to derive structurally.
	if isSyntheticEntryPoint(asset) {
		return deriveContractSupportingCalls(ctx, asset)
	}
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn == nil {
		return nil
	}
	matchedOperation := buildMatchedOperation(asset)
	if matchedOperation == nil || matchedOperation.Kind != matchedOperationCall {
		return nil
	}
	terminal := findCryptoCallNode(ctx.graph, containingFn, asset, asset.StartLine, asset.EndLine)
	if terminal == nil {
		return nil
	}
	lifecycle := deriveObjectLifecycleCalls(containingFn, terminal)
	contractCalls := deriveContractSupportingCalls(ctx, asset)
	out := make([]callGraphSupportingCall, 0, len(lifecycle)+len(contractCalls))
	out = append(out, contractCalls...)
	for _, c := range lifecycle {
		out = append(out, buildDerivedSupportingCall(ctx, containingFn, c))
	}
	return out
}

// isSyntheticEntryPoint reports whether an asset was produced by the rule-derived
// API-boundary synthesis (engine.SynthesizeRuleCryptoEntryPoints).
func isSyntheticEntryPoint(asset entities.CryptographicAsset) bool {
	for _, r := range asset.Rules {
		if r.ID == engine.SyntheticEntryPointRuleID {
			return true
		}
	}
	return false
}

// receiverType returns the owning type FQN of a fully-qualified method symbol,
// e.g. "com.password4j.HashBuilder.withBcrypt" → "com.password4j.HashBuilder".
func receiverType(method string) string {
	if i := strings.LastIndex(method, "."); i >= 0 {
		return method[:i]
	}
	return ""
}

// contractReturnType returns the contract-declared return type of a method FQN
// (any arity), or "" when unknown.
func (ctx *exportBuildContext) contractReturnType(method string) string {
	if ctx.kb == nil {
		return ""
	}
	for _, group := range ctx.kb.Contracts {
		for i := range group {
			if group[i].Method == method {
				return group[i].Return.Type
			}
		}
	}
	return ""
}

// typeOrAncestor reports whether candidate is typ itself or a transitive
// supertype of typ in the contract hierarchy. It lets a role-tagged method
// declared on a base class attach to a terminal of a subtype that inherits it
// (e.g. GeneralDigest.update -> a SHA256Digest constructor terminal).
func (ctx *exportBuildContext) typeOrAncestor(candidate, typ string) bool {
	if candidate == "" || typ == "" {
		return false
	}
	if candidate == typ {
		return true
	}
	if ctx.kb == nil {
		return false
	}
	seen := map[string]bool{typ: true}
	queue := append([]string(nil), ctx.kb.Hierarchy[typ]...)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if p == candidate {
			return true
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		queue = append(queue, ctx.kb.Hierarchy[p]...)
	}
	return false
}

// deriveContractSupportingCalls returns contract-role lifecycle methods as
// supporting calls by terminal API type lineage. For HashBuilder.withBcrypt
// (builder=HashBuilder, return=Hash): factory methods that return the builder
// (Password.hash), config/operation methods on the builder or a supertype, and
// output methods on the return type (Hash.getResult). Gated on the method
// definition being present in the scanned source; Category carries the role.
func deriveContractSupportingCalls(ctx *exportBuildContext, asset entities.CryptographicAsset) []callGraphSupportingCall {
	if ctx.kb == nil || len(ctx.kb.Contracts) == 0 || ctx.declIndex == nil {
		return nil
	}
	terminalAPI := strings.TrimSpace(asset.Metadata["api"])
	builderType := receiverType(terminalAPI)
	if builderType == "" {
		return nil
	}
	returnType := ctx.contractReturnType(terminalAPI)

	var out []callGraphSupportingCall
	seen := make(map[string]struct{})
	for _, group := range ctx.kb.Contracts {
		for i := range group {
			out = ctx.appendContractSupportingCall(out, seen, group[i], builderType, returnType)
		}
	}
	return out
}

func (ctx *exportBuildContext) appendContractSupportingCall(
	out []callGraphSupportingCall,
	seen map[string]struct{},
	c contracts.Contract,
	builderType string,
	returnType string,
) []callGraphSupportingCall {
	if c.Role == "" {
		return out
	}
	recv := receiverType(c.Method)
	isFactory := c.Return.Type == builderType
	isConfig := ctx.typeOrAncestor(recv, builderType)
	isOutput := returnType != "" && ctx.typeOrAncestor(recv, returnType)
	if !isFactory && !isConfig && !isOutput {
		return out
	}
	if c.Role == string(contracts.RoleOperation) {
		return ctx.appendOperationSupportingCalls(out, seen, c, builderType, returnType)
	}
	for _, decl := range ctx.declIndex[c.Method] {
		if !functionDeclArityMatches(decl, c.Arity) {
			continue
		}
		call := buildContractSupportingCall(ctx, c, decl)
		key := "signature:" + call.CanonicalSignature
		if call.CanonicalSignature == "" {
			key = "function:" + call.FunctionKey
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, call)
	}
	return out
}

func (ctx *exportBuildContext) appendOperationSupportingCalls(
	out []callGraphSupportingCall,
	seen map[string]struct{},
	c contracts.Contract,
	builderType string,
	returnType string,
) []callGraphSupportingCall {
	for _, match := range ctx.operationSupportingDeclarations(c, builderType, returnType) {
		key := "function:" + match.decl.ID.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, buildContractSupportingCall(ctx, c, match.decl))
	}
	return out
}

func (ctx *exportBuildContext) operationSupportingDeclarations(c contracts.Contract, builderType, returnType string) []operationContractDeclaration {
	matches := ctx.operationContractDeclarations(c)
	out := make([]operationContractDeclaration, 0, len(matches))
	for _, match := range matches {
		declClass, _ := splitFunctionName(match.declFQN)
		if ctx.typeOrAncestor(declClass, builderType) || ctx.typeOrAncestor(declClass, returnType) {
			out = append(out, match)
		}
	}
	return out
}

// buildContractSupportingCall renders a contract-role method definition as a
// supporting-call entry.
func buildContractSupportingCall(ctx *exportBuildContext, c contracts.Contract, decl *callgraph.FunctionDecl) callGraphSupportingCall {
	sourcePath := normalizeExportPath(ctx, decl.FilePath).FilePath
	meta := buildExportFunctionMetadata(ctx.graph, decl.ID, decl)
	functionName := fullFunctionName(decl.ID)
	if functionName == "" {
		functionName = c.Method
	}
	return callGraphSupportingCall{
		SupportingID:       supportingIDFromParts(sourcePath, decl.StartLine, decl.ID.String()),
		FunctionKey:        decl.ID.String(),
		FunctionName:       meta.FunctionName,
		CanonicalSignature: meta.CanonicalSignature,
		DisplaySymbol:      meta.DisplaySymbol,
		Aliases:            cloneStringSlice(meta.Aliases),
		Category:           c.Role,
		FilePath:           sourcePath,
		StartLine:          decl.StartLine,
		EndLine:            decl.StartLine,
		MatchedOperation: &callGraphMatchedOperation{
			Kind:   "type_usage",
			Symbol: functionName,
			Line:   decl.StartLine,
		},
		SupportingCall: &callGraphCalledFunction{FunctionName: functionName},
	}
}

// supportingCallIDsOf returns the sorted, de-duplicated supporting-call ids of a
// single finding's derived supporting calls — the per-finding breadcrumb stored
// on finding_graph.supporting_call_ids. It is computed at the point the
// per-finding association still exists; the top-level supporting_calls array is
// deduped across all findings (dedupSupportingCalls) and carries no finding_id,
// so this foreign key cannot be reconstructed from the serialized array alone.
func supportingCallIDsOf(calls []callGraphSupportingCall) []string {
	if len(calls) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(calls))
	ids := make([]string, 0, len(calls))
	for i := range calls {
		supportingID := calls[i].SupportingID
		if _, ok := seen[supportingID]; ok {
			continue
		}
		seen[supportingID] = struct{}{}
		ids = append(ids, supportingID)
	}
	sort.Strings(ids)
	return ids
}

// buildDerivedSupportingCall renders a single call-graph FunctionCall as a
// supporting-call entry, carrying the call's resolved (or raw) symbol, line,
// and argument data-flow. Category and parameter_roles are populated from the
// contracts KB when the callee+arity matches a contract (issue-103 WU1/WU3);
// they stay empty for callees the KB has no opinion on — no structural
// guessing.
func buildDerivedSupportingCall(ctx *exportBuildContext, containingFn *callgraph.FunctionDecl, call *callgraph.FunctionCall) callGraphSupportingCall {
	sourcePath := normalizeExportPath(ctx, call.FilePath).FilePath
	meta := buildExportFunctionMetadata(ctx.graph, containingFn.ID, containingFn)
	support := callGraphSupportingCall{
		SupportingID:       supportingCallIDFromCall(sourcePath, call),
		FunctionKey:        containingFn.ID.String(),
		FunctionName:       meta.FunctionName,
		CanonicalSignature: meta.CanonicalSignature,
		DisplaySymbol:      meta.DisplaySymbol,
		Aliases:            cloneStringSlice(meta.Aliases),
		FilePath:           sourcePath,
		StartLine:          call.Line,
		EndLine:            call.Line,
		MatchedOperation:   matchedOperationFromCall(call),
	}

	callee := ctx.graph.Functions[call.Callee.String()]
	sc := &callGraphCalledFunction{
		FunctionName: fullFunctionName(call.Callee),
		Line:         call.Line,
		Parameters:   mergeCallParameters(ctx, &containingFn.ID, &call.Callee, callee, call.Arguments, call.ArgumentSources, sourcePath, call.Line),
	}
	callMeta, matches := buildCallExportFunctionMetadata(ctx, call, callee)
	applyExportFunctionMetadataToCalledFunction(sc, callMeta)
	support.SupportingCall = sc
	if support.MatchedOperation != nil && sc.FunctionName != "" {
		support.MatchedOperation.Symbol = sc.FunctionName
		support.MatchedOperation.DisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(sc.FunctionName)
	}
	// WU1 (issue-103): consult the contracts KB for a role-tagged contract
	// matching this call edge's callee+arity, so structural (call-edge-based)
	// supporting calls carry a category too — not just the definition-based
	// ones deriveContractSupportingCalls already tags. No double-categorization:
	// the two derivation paths key on distinct SupportingIDs (call-site line
	// vs. definition line), already separated by dedupSupportingCalls.
	if ctx.kb != nil {
		arity := len(sc.ParameterTypes)
		if ctx.kb.Ecosystem == "cpp" {
			arity = len(call.Arguments)
		}
		if len(matches) == 0 || arity != len(call.Arguments) {
			matches = contractMatchesForCall(ctx, call, arity)
		}
		for i := range matches {
			contract := &matches[i]
			if contract.Role != "" {
				support.Category = contract.Role
				break
			}
		}
		// WU3 (issue-103): parameter_roles on the supporting-call declaration,
		// method-static (independent of which contract entry won the category
		// match above). Flows to the served surface natively, since
		// fragment_export.go reuses this same builder via
		// deriveSupportingCallsForFinding.
		sc.ParameterRoles = parameterRolesFromContracts(matches)
	}
	return support
}

// matchedOperationFromCall builds a matched-operation descriptor for a derived
// supporting call. Library-only calls that the graph could not resolve to a
// fully-qualified target still surface via their source-level expression (Raw),
// preserving completeness of the reported call list.
func matchedOperationFromCall(call *callgraph.FunctionCall) *callGraphMatchedOperation {
	symbol := fullFunctionName(call.Callee)
	return &callGraphMatchedOperation{
		Kind:          matchedOperationCall,
		Symbol:        symbol,
		DisplaySymbol: graphfrag.ConstructorDisplayFromSymbol(symbol),
		Expression:    call.Raw,
		Line:          call.Line,
	}
}

// supportingCallIDFromCall produces a stable short id for a derived supporting
// call, mirroring the finding_id scheme (SHA-256(path:line:callee)[:8]).
func supportingCallIDFromCall(sourcePath string, call *callgraph.FunctionCall) string {
	return supportingIDFromParts(sourcePath, call.Line, call.Callee.String())
}

// supportingIDFromParts computes the stable supporting-call id from its raw
// parts. Shared by the live exporter (supportingCallIDFromCall) and the
// annotate-from-fragment path so an id derived from a cached edge matches the id
// a live scan derived from the corresponding call: sha256(path:line:calleeKey).
//
// The id is intentionally truncated to 8 hex chars (32 bits) to mirror the
// finding_id scheme — the input (path:line:calleeKey) is unique per call site,
// so collisions are bounded by the number of distinct call sites in a single
// scan, well within the 32-bit space for realistic projects. dedupSupportingCalls
// keys on this id; a collision would silently coalesce two entries, so widen the
// prefix here if call-site volume ever approaches the birthday bound (~2^16).
func supportingIDFromParts(sourcePath string, line int, calleeKey string) string {
	input := sourcePath + ":" + strconv.Itoa(line) + ":" + calleeKey
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:8]
}

// dedupSupportingCalls removes duplicate supporting-call entries by SupportingID.
// The same lifecycle call can be derived from multiple findings that share a
// crypto object; we keep the first occurrence.
func dedupSupportingCalls(calls []callGraphSupportingCall) []callGraphSupportingCall {
	if len(calls) <= 1 {
		return calls
	}
	seen := make(map[string]bool, len(calls))
	out := make([]callGraphSupportingCall, 0, len(calls))
	for i := range calls {
		c := &calls[i]
		if seen[c.SupportingID] {
			continue
		}
		seen[c.SupportingID] = true
		out = append(out, *c)
	}
	return out
}

func buildMatchedOperation(asset entities.CryptographicAsset) *callGraphMatchedOperation {
	line := asset.StartLine
	if line <= 0 {
		line = asset.EndLine
	}

	// symbol (metadata.api) is kept as informational CBOM output only — it is
	// NOT used for kind classification. Kind is derived from source text alone.
	symbol := strings.TrimSpace(asset.Metadata["api"])
	expression := strings.TrimSpace(asset.Match)

	return &callGraphMatchedOperation{
		Kind:          inferMatchedOperationKind(expression),
		Symbol:        symbol,
		DisplaySymbol: graphfrag.ConstructorDisplayFromSymbol(symbol),
		Expression:    expression,
		Line:          line,
	}
}

// inferMatchedOperationKind classifies a matched operation from the source text
// of the match expression alone. metadata.api / rule symbol is NOT consulted —
// it is informational CBOM metadata and must not gate kind classification.
//
// Precedence (purely from source text):
//  1. looksLikeInvocationExpression → "call"  (parentheses present)
//  2. looksLikeTypeUsageExpression  → "type_usage" (bare identifier/dotted type)
//  3. default                       → "expression"
func inferMatchedOperationKind(expression string) string {
	expression = strings.TrimSpace(expression)

	if looksLikeInvocationExpression(expression) {
		return matchedOperationCall
	}
	if looksLikeTypeUsageExpression(expression) {
		return "type_usage"
	}
	return "expression"
}

// looksLikeTypeUsageExpression reports whether expression is a bare type
// reference: non-empty, contains no '(' (no invocation), and consists only of
// identifier and dot characters (e.g. "MessageDigest", "javax.crypto.Cipher").
func looksLikeTypeUsageExpression(expression string) bool {
	if expression == "" || strings.Contains(expression, "(") {
		return false
	}
	for _, r := range expression {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' &&
			r != '$' &&
			r != '.' {
			return false
		}
	}
	return true
}

func looksLikeInvocationExpression(expression string) bool {
	return strings.Contains(expression, "(") && strings.Contains(expression, ")")
}

// --- Crypto call identification (find the specific call that triggered the finding) ---

// findCryptoCall identifies the function call within the containing function that
// corresponds to the crypto finding, matched by the finding's line range.
// findCryptoCallNode selects the FunctionCall within the containing function
// that corresponds to the crypto finding, matched by the finding's line range.
// When multiple calls share a line (fluent chains), it uses position and chain
// structure only. It is the structural anchor both for building the finding's
// crypto-call display and for deriving the crypto object's lifecycle/supporting
// calls.
//
// Selection algorithm (position + structure, no api):
//
//  1. Candidate set: all calls in containingFn.Calls whose Line falls within
//     [startLine, endLine].
//
//  2. Column filter (when both asset and call have non-zero columns):
//     keep candidates whose [StartCol, EndCol) intersects [asset.StartCol,
//     asset.EndCol), then prefer the tightest call span containing the match.
//     If the filter yields 0 matches, use the full line-only set (never worse).
//
//  3. Tie-break to chain ROOT among survivors.
//     - Prefer a chain candidate whose AssignedVar != "" (chain root).
//     - If no chain candidate carries AssignedVar, prefer the longest Raw
//     expression (outermost expression).
//     - Among non-chain candidates, prefer resolved callee, then arguments, then
//     ArgumentSources.
//     - Deterministic final tiebreak: lowest StartCol, then slice order.
//
//  4. Column-absent fallback (any side has zero columns): skip step 2, run 1+3.
//
// CRITICAL: the returned call MUST be the chain root when a ChainID is present,
// because deriveObjectLifecycleCalls keys off the root's AssignedVar/ChainID.
func findCryptoCallNode(
	graph *callgraph.CallGraph,
	containingFn *callgraph.FunctionDecl,
	asset entities.CryptographicAsset,
	startLine, endLine int,
) *callgraph.FunctionCall {
	if containingFn == nil {
		return nil
	}

	// Step 1: line-range candidate set.
	lineCandidates := cryptoCallLineCandidates(containingFn, startLine, endLine)
	if len(lineCandidates) == 0 {
		return nil
	}

	// Step 2: column intersection filter (when both sides carry column info).
	if asset.TerminalStartCol > 0 && asset.TerminalEndCol > 0 {
		asset.StartCol = asset.TerminalStartCol
		asset.EndCol = asset.TerminalEndCol
	}
	candidates := cryptoCallColumnCandidates(lineCandidates, asset)

	// Step 3: tie-break.
	return pickBestCandidate(graph, candidates)
}

func cryptoCallLineCandidates(containingFn *callgraph.FunctionDecl, startLine, endLine int) []*callgraph.FunctionCall {
	var candidates []*callgraph.FunctionCall
	for i := range containingFn.Calls {
		c := &containingFn.Calls[i]
		if c.Line < startLine || c.Line > endLine {
			continue
		}
		candidates = append(candidates, c)
	}
	return candidates
}

// callCandidateViews projects call graph FunctionCalls onto the shared
// candidateView so the live path runs the same position/chain selection policy
// (terminal_selection.go) as the annotate-from-cache path.
func callCandidateViews(calls []*callgraph.FunctionCall) []candidateView {
	views := make([]candidateView, len(calls))
	for i, c := range calls {
		views[i] = candidateView{
			StartCol:    c.StartCol,
			EndCol:      c.EndCol,
			ChainID:     c.ChainID,
			AssignedVar: c.AssignedVar,
			RawLen:      len(c.Raw),
			Constructor: callgraph.BaseFunctionName(c.Callee.Name) == constructorMethodName,
		}
	}
	return views
}

func cryptoCallColumnCandidates(
	lineCandidates []*callgraph.FunctionCall,
	asset entities.CryptographicAsset,
) []*callgraph.FunctionCall {
	views := callCandidateViews(lineCandidates)
	keep := columnFilterIndices(views, identityIndices(len(lineCandidates)), asset.StartCol, asset.EndCol)
	if len(keep) == len(lineCandidates) {
		return lineCandidates
	}
	out := make([]*callgraph.FunctionCall, len(keep))
	for k, i := range keep {
		out[k] = lineCandidates[i]
	}
	return out
}

// pickBestCandidate selects the best call from a candidate set using the
// chain-root / best-resolved heuristic with a deterministic final tiebreak.
func pickBestCandidate(graph *callgraph.CallGraph, candidates []*callgraph.FunctionCall) *callgraph.FunctionCall {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}

	// Step 3a: prefer chain root (AssignedVar set) within a shared ChainID.
	// If multiple ChainIDs are present (unlikely), pick root of the first chain.
	// Among non-chain candidates (ChainID == ""), fall through to step 3b.
	if chainRoot := bestChainRootCandidate(candidates); chainRoot != nil {
		return chainRoot
	}

	// Step 3a (fallback): no AssignedVar on any chain candidate — prefer longest Raw
	// (outermost expression text in a fluent chain).
	if chainCandidate := longestChainCandidate(candidates); chainCandidate != nil {
		return chainCandidate
	}

	// Step 3b: non-chain candidates — score by resolved / args / sources.
	return bestScoredCandidate(graph, candidates)
}

func bestChainRootCandidate(candidates []*callgraph.FunctionCall) *callgraph.FunctionCall {
	views := callCandidateViews(candidates)
	if i := chainRootIndexAmong(views, identityIndices(len(candidates))); i >= 0 {
		return candidates[i]
	}
	return nil
}

func longestChainCandidate(candidates []*callgraph.FunctionCall) *callgraph.FunctionCall {
	views := callCandidateViews(candidates)
	if i := longestChainIndexAmong(views, identityIndices(len(candidates))); i >= 0 {
		return candidates[i]
	}
	return nil
}

func bestScoredCandidate(graph *callgraph.CallGraph, candidates []*callgraph.FunctionCall) *callgraph.FunctionCall {
	type scored struct {
		call  *callgraph.FunctionCall
		score int
	}
	scored0 := make([]scored, len(candidates))
	for i, c := range candidates {
		s := 0
		if graph != nil {
			if _, ok := graph.Functions[c.Callee.String()]; ok {
				s += 4 // resolved callee is the strongest signal
			}
		}
		if len(c.Arguments) > 0 {
			s += 2
		}
		if len(c.ArgumentSources) > 0 {
			s++
		}
		scored0[i] = scored{c, s}
	}

	// Step 3c: deterministic final tiebreak — lowest StartCol, then slice order.
	best := scored0[0]
	for _, sc := range scored0[1:] {
		if sc.score > best.score {
			best = sc
			continue
		}
		if sc.score == best.score && sc.call.StartCol > 0 && (best.call.StartCol == 0 || sc.call.StartCol < best.call.StartCol) {
			best = sc
		}
	}
	return best.call
}

func findCryptoCall(
	ctx *exportBuildContext,
	graph *callgraph.CallGraph,
	containingFn *callgraph.FunctionDecl,
	asset entities.CryptographicAsset,
	startLine, endLine int,
) *callGraphCalledFunction {
	bestCall := findCryptoCallNode(graph, containingFn, asset, startLine, endLine)
	if bestCall == nil {
		return nil
	}
	return buildCryptoCall(ctx, graph, containingFn, bestCall)
}

func buildCryptoCall(
	ctx *exportBuildContext,
	graph *callgraph.CallGraph,
	containingFn *callgraph.FunctionDecl,
	bestCall *callgraph.FunctionCall,
) *callGraphCalledFunction {
	callee := graph.Functions[bestCall.Callee.String()]
	sourcePath := normalizeExportPath(ctx, bestCall.FilePath).FilePath
	result := &callGraphCalledFunction{
		FunctionName: fullFunctionName(bestCall.Callee),
		Line:         bestCall.Line,
		Parameters:   mergeCallParameters(ctx, &containingFn.ID, &bestCall.Callee, callee, bestCall.Arguments, bestCall.ArgumentSources, sourcePath, bestCall.Line),
	}
	meta, _ := buildCallExportFunctionMetadata(ctx, bestCall, callee)
	applyExportFunctionMetadataToCalledFunction(result, meta)

	return result
}

// mergeCallParameters combines declared parameter types, argument expressions,
// and argument source traces into a unified parameters array.
func mergeCallParameters(
	ctx *exportBuildContext,
	callerID *callgraph.FunctionID,
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
			p.SourceNodes = convertSourceNodes(ctx, resolveExportSourceNodes(ctx, callerID, argSources[i], 0), filepath.ToSlash(sourceFilePath), sourceLine)
		}
		if p.Type == "" {
			p.Type = uniqueSourceDeclaredType(p.SourceNodes)
		}
		p.ResolvedValue = resolveSimpleExportParameterValue(p.ArgumentExpression, p.SourceNodes)
		if p.Type != "" || p.VariableName != "" || p.ArgumentExpression != "" {
			params = append(params, p)
		}
	}
	return params
}

// resolveExportSourceNodes follows simple Java parameter pass-through and return
// paths before serializing provenance. It keeps every candidate so a dynamic
// selector remains unresolved instead of choosing an arbitrary caller value.
//
//nolint:gocognit // Recursive provenance dispatch intentionally keeps every source-node kind fail-closed.
func resolveExportSourceNodes(ctx *exportBuildContext, ownerID *callgraph.FunctionID, nodes []callgraph.SourceNode, depth int) []callgraph.SourceNode {
	if ctx == nil || ctx.graph == nil || depth >= maxExportSourceResolutionDepth || len(nodes) == 0 {
		return cloneCallgraphSourceNodes(nodes)
	}

	resolved := cloneCallgraphSourceNodes(nodes)
	for i := range resolved {
		node := &resolved[i]
		switch node.Type {
		case sourceNodeTypeParameter:
			node.SourceNodes = append(node.SourceNodes, resolveIncomingParameterSources(ctx, ownerID, node.Name, node.ParameterIndex, depth+1)...)
		case sourceNodeTypeCallResult:
			node.SourceNodes = resolveExportSourceNodes(ctx, ownerID, node.SourceNodes, depth+1)
			if node.CallTarget != nil {
				if callee := ctx.graph.Functions[node.CallTarget.String()]; callee != nil {
					returns := selectGuardedReturnSources(callee.ReturnSources, node.SourceNodes)
					for i := range returns {
						if returns[i].Flow == nil {
							returns[i].Flow = &callgraph.SourceFlow{}
						}
						returns[i].Flow.ReturnValue = true
					}
					node.SourceNodes = append(node.SourceNodes, resolveExportSourceNodes(ctx, node.CallTarget, returns, depth+1)...)
				}
			}
		case sourceNodeTypeField:
			// A field's nested PARAMETER provenance may describe constructor
			// initialization, not the current method's argument list.
			node.SourceNodes = resolveExportSourceNodes(ctx, nil, node.SourceNodes, depth+1)
		default:
			node.SourceNodes = resolveExportSourceNodes(ctx, ownerID, node.SourceNodes, depth+1)
		}
	}
	return resolved
}

func resolveIncomingParameterSources(ctx *exportBuildContext, calleeID *callgraph.FunctionID, parameterName string, parameterIndex, depth int) []callgraph.SourceNode {
	if calleeID == nil || parameterIndex < 0 || depth >= maxExportSourceResolutionDepth {
		return nil
	}
	if callee := ctx.graph.Functions[calleeID.String()]; callee != nil && parameterIndex < len(callee.Parameters) &&
		callee.Parameters[parameterIndex].Name != "" && callee.Parameters[parameterIndex].Name != parameterName {
		return nil
	}

	callers := make([]*callgraph.FunctionDecl, 0, len(ctx.graph.Functions))
	for _, caller := range ctx.graph.Functions {
		callers = append(callers, caller)
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ID.String() < callers[j].ID.String() })

	var matches [][]callgraph.SourceNode
	for _, caller := range callers {
		for i := range caller.Calls {
			call := &caller.Calls[i]
			if call.Callee.String() != calleeID.String() || parameterIndex >= len(call.ArgumentSources) {
				continue
			}
			matches = append(matches, resolveExportSourceNodes(ctx, &caller.ID, call.ArgumentSources[parameterIndex], depth+1))
		}
	}
	if len(matches) != 1 {
		return nil
	}
	return matches[0]
}

//nolint:gocognit // Guard matching must distinguish exact, default, and unresolved branches without guessing.
func selectGuardedReturnSources(returns, arguments []callgraph.SourceNode) []callgraph.SourceNode {
	if len(returns) == 0 {
		return nil
	}
	values := make(map[int]string)
	for i := range arguments {
		if value, ok := resolveSimpleCallgraphSourceValue([]callgraph.SourceNode{arguments[i]}); ok {
			values[arguments[i].ParameterIndex] = normalizeSelectorValue(value)
		}
	}

	matched := make(map[int]bool)
	for i := range returns {
		guard := sourceNodeGuard(&returns[i])
		if guard == nil || guard.Default {
			continue
		}
		if value, ok := values[guard.ParameterIndex]; ok && value == normalizeSelectorValue(guard.Value) {
			matched[guard.ParameterIndex] = true
		}
	}

	selected := make([]callgraph.SourceNode, 0, len(returns))
	for i := range returns {
		source := &returns[i]
		guard := sourceNodeGuard(source)
		if guard == nil {
			selected = append(selected, *source)
			continue
		}
		value, known := values[guard.ParameterIndex]
		if !known {
			selected = append(selected, *source)
			continue
		}
		if guard.Default {
			if !matched[guard.ParameterIndex] {
				selected = append(selected, *source)
			}
			continue
		}
		if value == normalizeSelectorValue(guard.Value) {
			selected = append(selected, *source)
		}
	}
	return selected
}

func sourceNodeGuard(node *callgraph.SourceNode) *callgraph.SourceGuard {
	if node == nil || node.Flow == nil {
		return nil
	}
	return node.Flow.Guard
}

func resolveSimpleCallgraphSourceValue(nodes []callgraph.SourceNode) (string, bool) {
	if len(nodes) == 0 {
		return "", false
	}
	var resolved string
	for _, node := range nodes {
		value := strings.TrimSpace(node.Value)
		ok := node.Type == sourceNodeTypeValue && value != ""
		if !ok && len(node.SourceNodes) > 0 {
			value, ok = resolveSimpleCallgraphSourceValue(node.SourceNodes)
		}
		if !ok {
			return "", false
		}
		if resolved == "" {
			resolved = value
		} else if resolved != value {
			return "", false
		}
	}
	return resolved, resolved != ""
}

func normalizeSelectorValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func cloneCallgraphSourceNodes(nodes []callgraph.SourceNode) []callgraph.SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	cloned := make([]callgraph.SourceNode, len(nodes))
	for i := range nodes {
		cloned[i] = nodes[i]
		cloned[i].SourceNodes = cloneCallgraphSourceNodes(nodes[i].SourceNodes)
		if nodes[i].CallTarget != nil {
			target := *nodes[i].CallTarget
			cloned[i].CallTarget = &target
		}
		if nodes[i].Location != nil {
			location := *nodes[i].Location
			cloned[i].Location = &location
		}
		if nodes[i].Flow != nil {
			flow := *nodes[i].Flow
			cloned[i].Flow = &flow
			if nodes[i].Flow.Guard != nil {
				guard := *nodes[i].Flow.Guard
				cloned[i].Flow.Guard = &guard
			}
		}
	}
	return cloned
}

// convertSourceNodes converts internal SourceNode to export format.
func convertSourceNodes(ctx *exportBuildContext, nodes []callgraph.SourceNode, defaultFilePath string, defaultLine int) []exportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]exportSourceNode, len(nodes))
	for i, n := range nodes {
		result[i] = exportSourceNode{
			Type:                 n.Type,
			Name:                 n.Name,
			DeclaredType:         n.DeclaredType,
			Value:                n.Value,
			SourceNodes:          convertSourceNodes(ctx, n.SourceNodes, defaultFilePath, defaultLine),
			returnValue:          n.Flow != nil && n.Flow.ReturnValue,
			guard:                sourceNodeGuard(&n),
			callArgument:         n.Flow != nil && n.Flow.CallArgument,
			sourceParameterIndex: n.ParameterIndex,
		}
		if n.Type == sourceNodeTypeParameter {
			idx := n.ParameterIndex
			result[i].ParameterIndex = &idx
		}
		if n.CallTarget != nil {
			result[i].CallTarget = fullFunctionName(*n.CallTarget)
			result[i].CallTargetDisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(result[i].CallTarget)
			// Option 1e: decorate CALL_RESULT nodes with the call target's
			// inferred return type when it differs from the target's declared
			// return type. This surfaces inferred types on argument provenance
			// nodes even when the target function is not itself a finding caller.
			// resolveCallTargetInferredReturn checks the node type internally.
			result[i].CallTargetInferredReturn = resolveCallTargetInferredReturn(ctx, n.CallTarget, n.Type)
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

// resolveCallTargetInferredReturn looks up the target function's InferredReturn
// in the call graph and returns an exportInferredReturn for it, or nil when:
//   - the nodeType is not "CALL_RESULT",
//   - the target function is not in the graph,
//   - no inference result exists,
//   - the origin is join-failed, or
//   - the inferred type equals the function's declared return type (Issue 2 rule).
func resolveCallTargetInferredReturn(ctx *exportBuildContext, target *callgraph.FunctionID, nodeType string) *exportInferredReturn {
	if nodeType != sourceNodeTypeCallResult {
		return nil
	}
	if ctx == nil || ctx.graph == nil || target == nil {
		return nil
	}
	fn := ctx.graph.Functions[target.String()]
	if fn == nil || fn.InferredReturn == nil {
		return nil
	}
	ir := fn.InferredReturn
	if ir.Origin == "join-failed" {
		return nil
	}
	// Suppress when inferred type == declared return type (de-noising rule, Issue 2).
	if strings.TrimSpace(ir.Type) == strings.TrimSpace(fn.ReturnType) {
		return nil
	}
	return &exportInferredReturn{
		Type:       ir.Type,
		TypeRef:    exportTypeRefFromCallgraph(ir.TypeRef),
		Confidence: ir.Confidence,
		Origin:     ir.Origin,
		Provenance: convertInferredReturnProvenance(ir.Provenance),
	}
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
	for i := range nodes {
		value, ok := resolveSimpleExportSourceValueNode(nodes[i])
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
	case "VARIABLE", sourceNodeTypeField, sourceNodeTypeParameter:
		return resolveSimpleExportSourceValue(node.SourceNodes)
	case sourceNodeTypeCallResult:
		return resolveDirectExportReturnValue(node.SourceNodes)
	default:
		return "", false
	}
}

func resolveDirectExportReturnValue(nodes []exportSourceNode) (string, bool) {
	if value, handled := resolveGuardedDirectReturnValue(nodes); handled {
		return value, value != ""
	}
	hasMarkedReturn := false
	for i := range nodes {
		if nodes[i].returnValue {
			hasMarkedReturn = true
			break
		}
	}
	var value string
	for i := range nodes {
		if hasMarkedReturn && !nodes[i].returnValue {
			continue
		}
		if nodes[i].Type != sourceNodeTypeValue {
			continue
		}
		candidate := strings.TrimSpace(nodes[i].Value)
		if candidate == "" || (value != "" && value != candidate) {
			return "", false
		}
		value = candidate
	}
	return value, value != ""
}

//nolint:gocognit,gocyclo // Mirrors guarded-source selection after path enrichment, retaining all ambiguous candidates.
func resolveGuardedDirectReturnValue(nodes []exportSourceNode) (string, bool) {
	hasGuard := false
	arguments := make(map[int]string)
	for i := range nodes {
		if nodes[i].guard != nil {
			hasGuard = true
		}
		if nodes[i].callArgument {
			if value, ok := resolveSimpleExportSourceValueNode(nodes[i]); ok {
				arguments[nodes[i].sourceParameterIndex] = normalizeSelectorValue(value)
			}
		}
	}
	if !hasGuard {
		return "", false
	}

	matched := make(map[int]bool)
	for i := range nodes {
		guard := nodes[i].guard
		if guard == nil || guard.Default {
			continue
		}
		if value, ok := arguments[guard.ParameterIndex]; ok && value == normalizeSelectorValue(guard.Value) {
			matched[guard.ParameterIndex] = true
		}
	}
	var selected []exportSourceNode
	for i := range nodes {
		guard := nodes[i].guard
		if guard == nil {
			continue
		}
		value, known := arguments[guard.ParameterIndex]
		if !known {
			selected = append(selected, nodes[i])
			continue
		}
		if guard.Default {
			if !matched[guard.ParameterIndex] {
				selected = append(selected, nodes[i])
			}
			continue
		}
		if value == normalizeSelectorValue(guard.Value) {
			selected = append(selected, nodes[i])
		}
	}
	returnValue := ""
	for i := range selected {
		value, ok := resolveSimpleExportSourceValueNode(selected[i])
		if !ok || (returnValue != "" && returnValue != value) {
			return "", true
		}
		returnValue = value
	}
	return returnValue, true
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
	chains = expandCallChainCallSites(ctx.graph, chains, callGraphExportMaxChains)

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
					chain.Steps[j-1].StartCol,
					chain.Steps[j-1].EndCol,
					step.Function,
				)
			}
		}
		enrichCallChain(path)
		result[i] = path
	}

	return result
}

// expandCallChainCallSites preserves distinct invocations when one caller
// function calls the same wrapper more than once with different selector
// values. The tracer intentionally deduplicates functions for O(V+E)
// reachability; export expands only the bounded completed chains so per-call
// applicability is not lost.
func expandCallChainCallSites(graph *callgraph.CallGraph, chains []callgraph.CallChain, maxChains int) []callgraph.CallChain {
	var expanded []callgraph.CallChain
	for _, chain := range chains {
		variants := expandOneCallChain(graph, chain, maxChains-len(expanded))
		expanded = append(expanded, variants...)
		if maxChains > 0 && len(expanded) >= maxChains {
			return expanded[:maxChains]
		}
	}
	return expanded
}

//nolint:gocognit // Bounded call-site cross-product is kept together so every cap check remains auditable.
func expandOneCallChain(graph *callgraph.CallGraph, chain callgraph.CallChain, remaining int) []callgraph.CallChain {
	variants := []callgraph.CallChain{{Steps: append([]callgraph.CallChainStep(nil), chain.Steps...)}}
	for stepIndex := 1; stepIndex < len(chain.Steps); stepIndex++ {
		caller := graph.Functions[chain.Steps[stepIndex-1].Function.String()]
		matches := matchingInvocations(caller, chain.Steps[stepIndex].Function.String())
		if len(matches) == 0 {
			continue
		}
		var next []callgraph.CallChain
		for _, variant := range variants {
			for _, call := range matches {
				cloned := callgraph.CallChain{Steps: append([]callgraph.CallChainStep(nil), variant.Steps...)}
				cloned.Steps[stepIndex-1].Line = call.Line
				cloned.Steps[stepIndex-1].StartCol = call.StartCol
				cloned.Steps[stepIndex-1].EndCol = call.EndCol
				if call.FilePath != "" {
					cloned.Steps[stepIndex-1].FilePath = call.FilePath
				}
				next = append(next, cloned)
				if remaining > 0 && len(next) >= remaining {
					break
				}
			}
			if remaining > 0 && len(next) >= remaining {
				break
			}
		}
		variants = next
	}
	return variants
}

func exportUserPackages(result *engine.DepScanResult) map[string]bool {
	if result == nil || strings.TrimSpace(result.RootModule) == "" {
		return nil
	}
	// In standalone mode (no dependencies), return nil so the tracer
	// traverses call chains to graph roots instead of stopping at the
	// first root-module function. This produces deeper chains needed
	// for crypto_entry_points: e.g., HttpClientBuilder.build → ... →
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
	case ecosystemRust:
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
		cloned[i].ReturnTypeRef = cloneExportTypeRef(chain[i].ReturnTypeRef)
		cloned[i].ParameterTypeRefs = cloneExportTypeRefs(chain[i].ParameterTypeRefs)
		cloned[i].ParameterTypes = cloneStringSlice(chain[i].ParameterTypes)
		cloned[i].Aliases = cloneStringSlice(chain[i].Aliases)
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
	cloned.ParameterTypes = cloneStringSlice(call.ParameterTypes)
	cloned.Aliases = cloneStringSlice(call.Aliases)
	cloned.Parameters = cloneCallGraphParameters(call.Parameters)
	cloned.ReturnTypeRef = cloneExportTypeRef(call.ReturnTypeRef)
	cloned.ParameterTypeRefs = cloneExportTypeRefs(call.ParameterTypeRefs)
	return &cloned
}

func cloneCalledFunction(call *callGraphCalledFunction) *callGraphCalledFunction {
	if call == nil {
		return nil
	}
	cloned := *call
	cloned.ParameterTypes = cloneStringSlice(call.ParameterTypes)
	cloned.Aliases = cloneStringSlice(call.Aliases)
	cloned.Parameters = cloneCallGraphParameters(call.Parameters)
	cloned.ReturnTypeRef = cloneExportTypeRef(call.ReturnTypeRef)
	cloned.ParameterTypeRefs = cloneExportTypeRefs(call.ParameterTypeRefs)
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
	var fn *callgraph.FunctionDecl
	if decl := ctx.graph.Functions[id.String()]; decl != nil {
		fn = decl
		startLine = fn.StartLine
	}
	meta := buildExportFunctionMetadata(ctx.graph, id, fn)
	return callGraphChainNode{
		FunctionKey:        id.String(),
		FunctionName:       meta.FunctionName,
		CanonicalSignature: meta.CanonicalSignature,
		ReturnType:         meta.ReturnType,
		ReturnTypeRef:      cloneExportTypeRef(meta.ReturnTypeRef),
		ParameterTypes:     cloneStringSlice(meta.ParameterTypes),
		ParameterTypeRefs:  cloneExportTypeRefs(meta.ParameterTypeRefs),
		Visibility:         meta.Visibility,
		OwnerVisibility:    meta.OwnerVisibility,
		DisplaySymbol:      meta.DisplaySymbol,
		Aliases:            cloneStringSlice(meta.Aliases),
		FilePath:           location.FilePath,
		StartLine:          startLine,
		DependencyInfo:     location.DependencyInfo,
		InferredReturn:     cloneExportInferredReturn(meta.InferredReturn),
	}
}

func buildEntryCall(
	ctx *exportBuildContext,
	graph *callgraph.CallGraph,
	callerID callgraph.FunctionID,
	callSitePath string,
	fallbackLine int,
	startCol int,
	endCol int,
	calleeID callgraph.FunctionID,
) *callGraphEntryCall {
	location := normalizeExportPath(ctx, callSitePath)
	callerFn := graph.Functions[callerID.String()]
	if callerFn == nil {
		entryCall := &callGraphEntryCall{
			FilePath: location.FilePath,
			Line:     fallbackLine,
		}
		applyExportFunctionMetadataToEntryCall(entryCall, buildExportFunctionMetadata(graph, calleeID, graph.Functions[calleeID.String()]))
		return entryCall
	}

	call := findMatchingInvocationAtSpan(callerFn, calleeID.String(), fallbackLine, startCol, endCol)
	if call == nil {
		entryCall := &callGraphEntryCall{
			FilePath: location.FilePath,
			Line:     fallbackLine,
		}
		applyExportFunctionMetadataToEntryCall(entryCall, buildExportFunctionMetadata(graph, calleeID, graph.Functions[calleeID.String()]))
		return entryCall
	}

	location = normalizeExportPath(ctx, call.FilePath)
	calleeFn := graph.Functions[call.Callee.String()]
	entryCall := &callGraphEntryCall{
		FilePath:   location.FilePath,
		Line:       call.Line,
		Parameters: mergeCallParameters(ctx, &callerID, &call.Callee, calleeFn, call.Arguments, call.ArgumentSources, location.FilePath, call.Line),
	}
	meta, _ := buildCallExportFunctionMetadata(ctx, call, calleeFn)
	applyExportFunctionMetadataToEntryCall(entryCall, meta)
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
		if nodes[i].Type == sourceNodeTypeCallResult && originalChildren > 0 {
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
		result[i].CallTargetInferredReturn = cloneExportInferredReturn(nodes[i].CallTargetInferredReturn)
	}
	return result
}

// exportInferredReturn is the JSON shape for the inferred_return field on call
// graph entries. The field is omitted (omitempty pointer) when no inference
// fires or when the internal origin is "join-failed".
//
// "join-failed" exists in the internal origin enum for logging/telemetry but
// MUST NOT appear in exported output. When a join fails, InferredReturn is nil
// or its Origin is "join-failed"; the export layer treats both as absent.
type exportInferredReturn struct {
	Type       string             `json:"type"`
	TypeRef    *exportTypeRef     `json:"type_ref,omitempty"`
	Confidence string             `json:"confidence"`
	Origin     string             `json:"origin"`
	Provenance []exportSourceNode `json:"provenance,omitempty"`
}

type exportFunctionMetadata struct {
	FunctionName       string
	CanonicalSignature string
	ReturnType         string
	ReturnTypeRef      *exportTypeRef
	ParameterTypes     []string
	ParameterTypeRefs  []exportTypeRef
	Visibility         string
	OwnerVisibility    string
	DisplaySymbol      string
	Aliases            []string
	InferredReturn     *exportInferredReturn
}

func buildExportFunctionMetadata(
	graph *callgraph.CallGraph,
	id callgraph.FunctionID,
	decl *callgraph.FunctionDecl,
) exportFunctionMetadata {
	meta := exportFunctionMetadata{
		FunctionName: fullFunctionName(id),
	}

	if decl != nil {
		meta.ParameterTypes = exportParameterTypesFromDecl(decl.Parameters)
		meta.ParameterTypeRefs = exportParameterTypeRefsFromDecl(decl.Parameters)
		meta.ReturnType = strings.TrimSpace(decl.ReturnType)
		meta.ReturnTypeRef = exportTypeRefFromCallgraph(decl.ReturnTypeRef)
		meta.Visibility = strings.TrimSpace(decl.Visibility)
		meta.OwnerVisibility = strings.TrimSpace(decl.OwnerVisibility)
	}

	if sig, ok := exportExternalSignature(graph, id, len(meta.ParameterTypes)); ok {
		meta.ParameterTypes = mergeExportParameterTypes(meta.ParameterTypes, sig.ParameterTypes)
		meta.ParameterTypeRefs = mergeExportParameterTypeRefs(meta.ParameterTypeRefs, sig.ParameterTypeRefs)
		if meta.ReturnType == "" {
			meta.ReturnType = strings.TrimSpace(sig.ReturnType)
		}
		if meta.ReturnTypeRef == nil {
			meta.ReturnTypeRef = exportTypeRefFromCallgraph(sig.ReturnTypeRef)
		}
	}

	meta.ReturnType = normalizeExportReturnType(id, meta.ReturnType)
	meta.CanonicalSignature = canonicalSignature(meta.FunctionName, meta.ParameterTypes, meta.ReturnType)
	meta.DisplaySymbol, meta.Aliases = exportDisplaySymbolAndAliases(id, meta.FunctionName)

	// Populate inferred_return when the inference pass produced a result.
	// Two suppression rules apply:
	//   1. join-failed origin is suppressed (logged internally for telemetry only).
	//   2. When inferred type == declared type the field carries zero information
	//      and is omitted to reduce noise (Issue 2).
	if decl != nil && decl.InferredReturn != nil &&
		decl.InferredReturn.Origin != "join-failed" &&
		strings.TrimSpace(decl.InferredReturn.Type) != strings.TrimSpace(meta.ReturnType) {
		ir := decl.InferredReturn
		meta.InferredReturn = &exportInferredReturn{
			Type:       ir.Type,
			TypeRef:    exportTypeRefFromCallgraph(ir.TypeRef),
			Confidence: ir.Confidence,
			Origin:     ir.Origin,
			Provenance: convertInferredReturnProvenance(ir.Provenance),
		}
	}

	return meta
}

// buildCallExportFunctionMetadata enriches an external call with canonical
// signature details that the contract KB can state unambiguously. Source or
// scanned declarations remain authoritative; contracts only fill gaps.
func buildCallExportFunctionMetadata(
	ctx *exportBuildContext,
	call *callgraph.FunctionCall,
	decl *callgraph.FunctionDecl,
) (exportFunctionMetadata, []contracts.Contract) {
	if call == nil {
		return exportFunctionMetadata{}, nil
	}
	meta := buildExportFunctionMetadata(ctx.graph, call.Callee, decl)
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	if len(matches) == 0 {
		return meta, nil
	}
	canonicalMatches := canonicalContractsForCall(matches, call)
	if len(canonicalMatches) == 0 {
		return meta, matches
	}

	parameterTypes := canonicalMatches[0].ParameterTypes
	returnType := canonicalMatches[0].CanonicalReturnType
	for i := 1; i < len(canonicalMatches); i++ {
		if !slices.Equal(parameterTypes, canonicalMatches[i].ParameterTypes) {
			parameterTypes = nil
		}
		if returnType != canonicalMatches[i].CanonicalReturnType {
			returnType = ""
		}
	}
	meta.ParameterTypes = mergeExportParameterTypes(meta.ParameterTypes, parameterTypes)
	if meta.ReturnType == "" {
		meta.ReturnType = returnType
	}
	meta.CanonicalSignature = canonicalSignature(meta.FunctionName, meta.ParameterTypes, meta.ReturnType)
	return meta, matches
}

// convertInferredReturnProvenance converts a []callgraph.SourceNode (inference
// provenance) into the export shape without path normalization. This is used
// only for the inferred_return.provenance field — the paths are not available
// at metadata-build time since we don't have an exportBuildContext here.
func convertInferredReturnProvenance(nodes []callgraph.SourceNode) []exportSourceNode {
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
			SourceNodes:  convertInferredReturnProvenance(n.SourceNodes),
		}
		if n.Type == sourceNodeTypeParameter {
			idx := n.ParameterIndex
			result[i].ParameterIndex = &idx
		}
		if n.CallTarget != nil {
			result[i].CallTarget = fullFunctionName(*n.CallTarget)
			result[i].CallTargetDisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(result[i].CallTarget)
		}
	}
	return result
}

// exportTypeRefFromCallgraph converts a callgraph.TypeRef into the exported
// shape, returning nil when the source carries no useful structured data.
// The flat name alone is not surfaced through *_ref fields; consumers can
// read it from the existing return_type / parameter_types strings.
func exportTypeRefFromCallgraph(ref callgraph.TypeRef) *exportTypeRef {
	if ref.Name == "" && len(ref.GenericParameters) == 0 {
		return nil
	}
	if !ref.HasGenerics() {
		return nil
	}
	out := convertCallgraphTypeRef(ref)
	return &out
}

func convertCallgraphTypeRef(ref callgraph.TypeRef) exportTypeRef {
	out := exportTypeRef{Name: ref.Name}
	if len(ref.GenericParameters) > 0 {
		out.GenericParameters = make([]exportTypeRef, len(ref.GenericParameters))
		for i, child := range ref.GenericParameters {
			out.GenericParameters[i] = convertCallgraphTypeRef(child)
		}
	}
	return out
}

func exportParameterTypeRefsFromDecl(params []callgraph.FunctionParameter) []exportTypeRef {
	if len(params) == 0 {
		return nil
	}
	hasGenerics := false
	refs := make([]exportTypeRef, len(params))
	for i, param := range params {
		refs[i] = convertCallgraphTypeRef(param.TypeRef)
		if refs[i].Name == "" {
			refs[i].Name = strings.TrimSpace(param.Type)
		}
		if param.TypeRef.HasGenerics() {
			hasGenerics = true
		}
	}
	if !hasGenerics {
		return nil
	}
	return refs
}

func mergeExportParameterTypeRefs(existing []exportTypeRef, fallback []callgraph.TypeRef) []exportTypeRef {
	if len(fallback) == 0 {
		return existing
	}
	merged := append([]exportTypeRef(nil), existing...)
	hasGenerics := false
	for _, r := range merged {
		if len(r.GenericParameters) > 0 {
			hasGenerics = true
			break
		}
	}
	if len(merged) == 0 {
		merged = make([]exportTypeRef, len(fallback))
	}
	limit := len(merged)
	if len(fallback) < limit {
		limit = len(fallback)
	}
	for i := 0; i < limit; i++ {
		converted := convertCallgraphTypeRef(fallback[i])
		if merged[i].Name == "" {
			merged[i].Name = converted.Name
		}
		if len(merged[i].GenericParameters) == 0 {
			merged[i].GenericParameters = converted.GenericParameters
		}
		if len(converted.GenericParameters) > 0 {
			hasGenerics = true
		}
	}
	if !hasGenerics {
		return existing
	}
	return merged
}

func normalizeExportReturnType(id callgraph.FunctionID, returnType string) string {
	trimmed := strings.TrimSpace(returnType)
	if callgraph.BaseFunctionName(id.Name) != constructorMethodName {
		return trimmed
	}
	if trimmed != "" && trimmed != "void" {
		return trimmed
	}
	return strings.TrimSpace(id.Type)
}

func exportParameterTypesFromDecl(params []callgraph.FunctionParameter) []string {
	if len(params) == 0 {
		return nil
	}
	types := make([]string, len(params))
	for i := range params {
		types[i] = strings.TrimSpace(params[i].Type)
	}
	if allEmptyStrings(types) {
		return nil
	}
	return types
}

func mergeExportParameterTypes(existing, fallback []string) []string {
	if len(existing) == 0 {
		if len(fallback) == 0 {
			return nil
		}
		return append([]string(nil), fallback...)
	}
	if len(fallback) == 0 {
		return existing
	}

	merged := append([]string(nil), existing...)
	limit := len(merged)
	if len(fallback) < limit {
		limit = len(fallback)
	}
	for i := 0; i < limit; i++ {
		if strings.TrimSpace(merged[i]) == "" {
			merged[i] = strings.TrimSpace(fallback[i])
		}
	}
	return merged
}

func parameterTypesFromCallParameters(parameters []callGraphParameter) []string {
	if len(parameters) == 0 {
		return nil
	}
	types := make([]string, len(parameters))
	for i := range parameters {
		types[i] = parameters[i].Type
	}
	return types
}

func uniqueSourceDeclaredType(nodes []exportSourceNode) string {
	current := nodes
	for len(current) > 0 {
		types := make(map[string]struct{})
		nextCapacity := 0
		for i := range current {
			nextCapacity += len(current[i].SourceNodes)
		}
		next := make([]exportSourceNode, 0, nextCapacity)
		for i := range current {
			if declared := strings.TrimSpace(current[i].DeclaredType); declared != "" {
				types[declared] = struct{}{}
			}
			next = append(next, current[i].SourceNodes...)
		}
		if len(types) == 1 {
			for declared := range types {
				return declared
			}
		}
		if len(types) > 1 {
			return ""
		}
		current = next
	}
	return ""
}

func exportExternalSignature(
	graph *callgraph.CallGraph,
	id callgraph.FunctionID,
	paramCount int,
) (callgraph.ExternalMethodSignature, bool) {
	if graph == nil || graph.ExternalMethodSignatures == nil {
		return callgraph.ExternalMethodSignature{}, false
	}

	signatures := graph.ExternalMethodSignatures[callgraph.ExternalMethodSignatureKey(id)]
	if len(signatures) == 0 {
		return callgraph.ExternalMethodSignature{}, false
	}
	for _, sig := range signatures {
		if paramCount == 0 || len(sig.ParameterTypes) == paramCount {
			return sig, true
		}
	}
	return signatures[0], true
}

func canonicalSignature(functionName string, parameterTypes []string, returnType string) string {
	if functionName == "" {
		return ""
	}

	params := make([]string, len(parameterTypes))
	for i := range parameterTypes {
		paramType := strings.TrimSpace(parameterTypes[i])
		if paramType == "" {
			paramType = "?"
		}
		params[i] = paramType
	}

	signature := functionName + "(" + strings.Join(params, ", ") + ")"
	if trimmedReturnType := strings.TrimSpace(returnType); trimmedReturnType != "" {
		signature += ": " + trimmedReturnType
	}
	return signature
}

func applyExportFunctionMetadataToEntryCall(call *callGraphEntryCall, meta exportFunctionMetadata) {
	if call == nil {
		return
	}
	call.FunctionName = meta.FunctionName
	call.ReturnType = meta.ReturnType
	call.ReturnTypeRef = cloneExportTypeRef(meta.ReturnTypeRef)
	call.ParameterTypes = mergeExportParameterTypes(meta.ParameterTypes, parameterTypesFromCallParameters(call.Parameters))
	call.CanonicalSignature = canonicalSignature(call.FunctionName, call.ParameterTypes, call.ReturnType)
	call.ParameterTypeRefs = cloneExportTypeRefs(meta.ParameterTypeRefs)
	call.DisplaySymbol = meta.DisplaySymbol
	call.Aliases = cloneStringSlice(meta.Aliases)
	call.InferredReturn = cloneExportInferredReturn(meta.InferredReturn)
}

func applyExportFunctionMetadataToCalledFunction(call *callGraphCalledFunction, meta exportFunctionMetadata) {
	if call == nil {
		return
	}
	call.FunctionName = meta.FunctionName
	call.ReturnType = meta.ReturnType
	call.ReturnTypeRef = cloneExportTypeRef(meta.ReturnTypeRef)
	call.ParameterTypes = mergeExportParameterTypes(meta.ParameterTypes, parameterTypesFromCallParameters(call.Parameters))
	call.CanonicalSignature = canonicalSignature(call.FunctionName, call.ParameterTypes, call.ReturnType)
	call.ParameterTypeRefs = cloneExportTypeRefs(meta.ParameterTypeRefs)
	call.DisplaySymbol = meta.DisplaySymbol
	call.Aliases = cloneStringSlice(meta.Aliases)
	call.InferredReturn = cloneExportInferredReturn(meta.InferredReturn)
}

func exportDisplaySymbolAndAliases(id callgraph.FunctionID, functionName string) (string, []string) {
	display := constructorDisplaySymbol(id, functionName)
	if display == "" || display == functionName {
		return display, nil
	}
	return display, []string{display}
}

func constructorDisplaySymbol(id callgraph.FunctionID, fallback string) string {
	if callgraph.BaseFunctionName(id.Name) != constructorMethodName {
		return fallback
	}
	typeName := sanitizeSymbol(id.Type)
	if typeName == "" || strings.Contains(typeName, "(") {
		return fallback
	}
	simpleName := typeName
	if dot := strings.LastIndex(simpleName, "."); dot >= 0 {
		simpleName = simpleName[dot+1:]
	}
	if id.Package == "" {
		return typeName + "." + simpleName
	}
	return id.Package + "." + typeName + "." + simpleName
}

// cloneExportInferredReturn returns a deep copy of an exportInferredReturn,
// or nil if the source is nil.
func cloneExportInferredReturn(ir *exportInferredReturn) *exportInferredReturn {
	if ir == nil {
		return nil
	}
	clone := *ir
	clone.TypeRef = cloneExportTypeRef(ir.TypeRef)
	clone.Provenance = cloneSourceNodes(ir.Provenance)
	return &clone
}

func cloneExportTypeRef(ref *exportTypeRef) *exportTypeRef {
	if ref == nil {
		return nil
	}
	out := *ref
	out.GenericParameters = cloneExportTypeRefs(ref.GenericParameters)
	return &out
}

func cloneExportTypeRefs(refs []exportTypeRef) []exportTypeRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]exportTypeRef, len(refs))
	for i, r := range refs {
		out[i] = *cloneExportTypeRef(&r)
	}
	return out
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func allEmptyStrings(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
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

func findMatchingInvocationAtSpan(callerFn *callgraph.FunctionDecl, calleeKey string, line, startCol, endCol int) *callgraph.FunctionCall {
	matches := matchingInvocations(callerFn, calleeKey)
	if startCol > 0 && endCol > 0 {
		for _, call := range matches {
			if call.Line == line && call.StartCol == startCol && call.EndCol == endCol {
				return call
			}
		}
	}
	for _, call := range matches {
		if line > 0 && call.Line == line {
			return call
		}
	}
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

func matchingInvocations(callerFn *callgraph.FunctionDecl, calleeKey string) []*callgraph.FunctionCall {
	if callerFn == nil {
		return nil
	}

	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	bestScore := -1
	var best []*callgraph.FunctionCall
	for i := range callerFn.Calls {
		call := &callerFn.Calls[i]
		score := invocationMatchScore(call, calleeKey, calleeID, err == nil)
		if score == 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = []*callgraph.FunctionCall{call}
		} else if score > 0 && score == bestScore {
			best = append(best, call)
		}
	}
	return best
}

func invocationMatchScore(call *callgraph.FunctionCall, calleeKey string, calleeID callgraph.FunctionID, parsed bool) int {
	if call.Callee.String() == calleeKey {
		return 100
	}
	if !parsed {
		return 0
	}
	callMethod := methodArityKey(call.Callee.Name)
	wantMethod := methodArityKey(calleeID.Name)
	switch {
	case call.Callee.Package == calleeID.Package && call.Callee.Type == calleeID.Type && callMethod == wantMethod:
		return 80
	case call.Callee.Type == calleeID.Type && callMethod == wantMethod:
		return 60
	case callMethod == wantMethod:
		return 40
	case callgraph.BaseFunctionName(call.Callee.Name) == callgraph.BaseFunctionName(calleeID.Name):
		return 20
	default:
		return 0
	}
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

	// graph.Functions is an unordered map and spans can nest (a synthetic
	// <clinit> may cover the whole class around the real method), so pick the
	// tightest enclosing span instead of the first match; tie-break on the
	// function key for full determinism.
	var best *callgraph.FunctionDecl
	for _, fn := range ctx.graph.Functions {
		fnPath := filepath.ToSlash(fn.FilePath)
		if !strings.HasSuffix(fnPath, normalizedFindingPath) {
			continue
		}
		if line < fn.StartLine || line > fn.EndLine {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	if best != nil {
		ctx.containingFunctionCache[cacheKey] = cachedContainingFunction{fn: best, found: true}
		return best
	}
	ctx.containingFunctionCache[cacheKey] = cachedContainingFunction{found: false}
	return nil
}

// tighterSpan reports whether a encloses fewer lines than b (or, on equal
// spans, sorts first by function key) so the containing-function choice is
// stable across map iteration orders.
func tighterSpan(a, b *callgraph.FunctionDecl) bool {
	spanA := a.EndLine - a.StartLine
	spanB := b.EndLine - b.StartLine
	if spanA != spanB {
		return spanA < spanB
	}
	return a.ID.String() < b.ID.String()
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
