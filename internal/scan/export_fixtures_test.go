// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

// Fixture plumbing only tests use: exports built straight from a
// DepScanResult, without the OID-prepared report the commands pass to
// ExportResolvedCallGraph and ExportResolvedGraphFragment.

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/utils"
)

func appendConditionedAsset(
	finding *entities.Finding,
	anchor entities.CryptographicAsset,
	rule engine.RuleCryptoMetadata,
	params []callGraphParameter,
	seen, existing map[string]struct{},
) bool {
	_, appended := specializeAnchor(finding, anchor, rule, params, seen, existing)
	return appended
}

// exportCallGraph is the raw fixture helper; production must use ExportResolvedCallGraph.
func exportCallGraph(path, format string, result *engine.DepScanResult) error {
	return exportCallGraphWithOptions(path, format, result, CallGraphExportOptions{})
}

func exportCallGraphWithOptions(path, format string, result *engine.DepScanResult, options CallGraphExportOptions) error {
	AssignOccurrenceKeys(result)
	return exportCallGraphProjectionWithOptions(path, format, result, options)
}

// exportCallGraphProjectionWithOptions reads a finalized report without modifying it.
func exportCallGraphProjectionWithOptions(path, format string, result *engine.DepScanResult, options CallGraphExportOptions) error {
	if result == nil {
		return fmt.Errorf("cannot export call graph: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("cannot export call graph: result.CallGraph is nil")
	}
	if result.Report == nil {
		return fmt.Errorf("cannot export call graph: result.Report is nil")
	}
	if format != callGraphJSONFormat {
		return fmt.Errorf("unsupported call graph format %q (supported: "+callGraphJSONFormat+")", format)
	}

	exportStart := time.Now()
	totalAssets := countExportFindingAssets(result.Report)
	log.Info().
		Str("file", path).
		Str("format", format).
		Int("finding_assets", totalAssets).
		Int("max_chains", graphfrag.ResolveMaxChains(options.MaxChains)).
		Bool("omit_crypto_entry_points", options.OmitCryptoEntryPoints).
		Bool("interned_frames", options.InternedFrames).
		Bool("project_reachability", options.ProjectReachability).
		Msg("Starting integration call graph export")

	buildStart := time.Now()
	payload, err := buildCallGraphExportV2ToFile(path, result, options)
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

func buildCallGraphExportV2ToFile(path string, result *engine.DepScanResult, options CallGraphExportOptions) (callGraphExportV2, error) {
	ctxs := newCallGraphExportContextSet(result, result.Report.Findings, options)
	assets := callGraphExportAssets(result.Report)
	meta := buildCallGraphExportScanMeta(result)
	applyExportEcosystemsMeta(&meta, result, options)

	var streamed streamedCallGraphExport
	if err := utils.WriteFileAtomic(path, 0o600, func(file *os.File) error {
		bw := bufio.NewWriterSize(file, 1<<20)
		writer := graphFragmentJSONWriter{w: bw}
		var writeErr error
		streamed, writeErr = streamCallGraphExport(&writer, ctxs, assets, meta, options)
		return finishBufferedOutput(bw, writeErr)
	}); err != nil {
		return callGraphExportV2{}, fmt.Errorf("failed to write call graph to %s: %w", path, err)
	}

	return callGraphExportV2{
		SchemaVersion:     graphfrag.CallgraphExportSchemaVersion(options.InternedFrames),
		ScanMetadata:      meta,
		FindingGraphs:     make([]callGraphExportFinding, len(assets)),
		Functions:         streamed.functions,
		SupportingCalls:   streamed.supportingCalls,
		CryptoEntryPoints: streamed.entryPoints,
	}, nil
}

func callGraphExportAssets(report *entities.InterimReport) []callGraphExportAsset {
	if report == nil {
		return nil
	}
	return callGraphExportAssetsFromFindings(report.Findings)
}

func buildCallGraphExportV2(result *engine.DepScanResult) callGraphExportV2 {
	return buildCallGraphExportV2WithMaxChains(result, 0)
}

func buildCallGraphExportV2WithMaxChains(result *engine.DepScanResult, maxChains int) callGraphExportV2 {
	AssignOccurrenceKeys(result)
	ctx := newExportBuildContextWithMaxChains(result, maxChains)
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

	// containingByFinding remembers where each finding sits so the entry-point
	// pass below can resolve its containing function after supporting calls
	// have been deduped.
	type findingSite struct {
		findingID  string
		filePath   string
		dependency *entities.DependencyInfo
		startLine  int
		startCol   int
	}
	var sites []findingSite

	processedAssets := 0
	buildStart := time.Now()
	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			sites = append(sites, findingSite{
				findingID:  asset.FindingID,
				filePath:   finding.FilePath,
				dependency: asset.DependencyInfo,
				startLine:  asset.StartLine,
				startCol:   asset.StartCol,
			})
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
	out.CryptoEntryPoints = buildCryptoEntryPoints(ctx, out.FindingGraphs, out.SupportingCalls, func(findingID string) *callgraph.FunctionDecl {
		for i := range sites {
			if sites[i].findingID == findingID {
				return ctx.findContainingFunctionByFinding(sites[i].filePath, sites[i].dependency, sites[i].startLine, sites[i].startCol)
			}
		}
		return nil
	})
	for i := range out.CryptoEntryPoints {
		out.CryptoEntryPoints[i].ErasedSignature = erasedSignatureForFunctionKey(ctx, out.CryptoEntryPoints[i].FunctionKey)
	}
	for i := range out.SupportingCalls {
		out.SupportingCalls[i].ErasedSignature = erasedSignatureForFunctionKey(ctx, out.SupportingCalls[i].FunctionKey)
	}

	out.Functions = internLiveCatalog(out.FindingGraphs)
	return out
}

func internLiveCatalog(graphs []callGraphExportFinding) []graphfrag.ExportInternedFunction {
	intern := graphfrag.FunctionInterner{}
	for i := range graphs {
		internLiveFindingGraph(&intern, &graphs[i])
	}
	return intern.Functions()
}

// buildCryptoEntryPoints creates an O(1) lookup from function name to reachable
// crypto operations, derived from reverse reachability over the call graph
// (issue #249). kb is consulted (issue-103 WU3) to populate parameter_roles on
// entries whose function+arity matches a contract; nil kb skips that enrichment.
//
// containingFor resolves a finding's containing function; the two live builders
// reach it differently, so they supply it rather than duplicating the lookup.
func buildCryptoEntryPoints(
	ctx *exportBuildContext,
	findingGraphs []callGraphExportFinding,
	supportingCalls []callGraphSupportingCall,
	containingFor func(findingID string) *callgraph.FunctionDecl,
) []callGraphCryptoEntryPoint {
	index := make(map[string]*entryPointData)
	roots := make(map[string]bool)
	supportingByID := make(map[string]callGraphSupportingCall, len(supportingCalls))
	for i := range supportingCalls {
		if supportingCalls[i].SupportingID != "" {
			supportingByID[supportingCalls[i].SupportingID] = supportingCalls[i]
		}
	}
	referencedSupporting := make(map[string]struct{}, len(supportingByID))
	for i := range findingGraphs {
		// An entry point is something user code reaches. A finding the tracer
		// proved unreachable contributes none: publishing its containing function
		// here would list a function nothing calls beside the ones that really run,
		// with nothing to tell them apart. Reachable is nil on the mine path, where
		// a chainless finding means "graph root" — a library's public API, and its
		// most important entry point — so that case is deliberately not filtered.
		if findingGraphs[i].Reachable != nil && !*findingGraphs[i].Reachable {
			claimSupportingCalls(referencedSupporting, &findingGraphs[i])
			continue
		}
		containingFn := containingFor(findingGraphs[i].FindingID)
		addFindingGraphReachSetToEntryPointIndex(
			ctx, index, &findingGraphs[i], containingFn, supportingByID, referencedSupporting)
		markReachSetRoots(ctx, roots, containingFn)
	}
	for i := range supportingCalls {
		if _, ok := referencedSupporting[supportingCalls[i].SupportingID]; ok {
			continue
		}
		addSupportingCallToEntryPointIndex(index, supportingCalls[i])
	}
	out := flattenEntryPointIndex(ctx.kb, index)
	for i := range out {
		if roots[out[i].FunctionKey] {
			out[i].Root = true
		}
	}
	return out
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

// dedupSupportingCalls removes duplicate supporting-call entries by SupportingID.
// The same lifecycle call can be derived from multiple findings that share a
// crypto object; we keep the first occurrence, folding each later claimant's
// rule-declared key-length conflict into it so no conflict is lost.
func dedupSupportingCalls(calls []callGraphSupportingCall) []callGraphSupportingCall {
	if len(calls) <= 1 {
		return calls
	}
	seen := make(map[string]int, len(calls))
	out := make([]callGraphSupportingCall, 0, len(calls))
	for i := range calls {
		c := &calls[i]
		if kept, exists := seen[c.SupportingID]; exists {
			mergeRuleKeyLengthConflict(supportingCallKeyLength(&out[kept]), supportingCallKeyLength(c))
			continue
		}
		seen[c.SupportingID] = len(out)
		out = append(out, *c)
	}
	return out
}

// exportGraphFragment is the raw fixture helper; production must use ExportResolvedGraphFragment.
func exportGraphFragment(path string, result *engine.DepScanResult) error {
	if result == nil {
		return fmt.Errorf("scan: cannot export graph fragment: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("scan: cannot export graph fragment: result.CallGraph is nil")
	}

	AssignOccurrenceKeys(result)
	if err := writeGraphFragmentJSONFile(path, result); err != nil {
		return fmt.Errorf("scan: failed to write graph fragment to %s: %w", path, err)
	}
	return nil
}

func writeGraphFragmentJSONFile(path string, result *engine.DepScanResult) error {
	return utils.WriteFileAtomic(path, 0o600, func(file *os.File) error {
		bw := bufio.NewWriterSize(file, 1<<20)
		writer := graphFragmentJSONWriter{w: bw}
		if err := writer.writeResult(result); err != nil {
			return err
		}
		return bw.Flush()
	})
}

func (w *graphFragmentJSONWriter) writeResult(result *engine.DepScanResult) error {
	if _, err := w.w.WriteString("{\n"); err != nil {
		return err
	}
	if err := w.writeField("schema_version", graphfrag.SchemaVersion); err != nil {
		return err
	}

	ctx := newExportBuildContext(result)
	meta := buildGraphFragmentScanMetadata(result)
	var err error
	var functionIndex map[string]int
	functionIndex, meta.FunctionCount, err = w.writeFunctions(ctx)
	if err != nil {
		return err
	}
	sourceLines := newFragmentSourceLines(ctx)
	sourceLines.addIncludes()
	meta.InternalEdges, meta.ExternalCalls, err = w.writeEdges(ctx, functionIndex, sourceLines)
	if err != nil {
		return err
	}
	if err := w.writeConstantRefs(ctx, functionIndex, sourceLines); err != nil {
		return err
	}

	cryptoAnnotations, supportingCalls, entryPoints := materializeGraphFragmentCrypto(ctx, result, functionIndex)
	meta.CryptoOps = len(cryptoAnnotations)
	if err := writeGraphFragmentArrayField(w, "crypto_annotations", cryptoAnnotations, true); err != nil {
		return err
	}
	meta.SupportingCalls = len(supportingCalls)
	if err := writeGraphFragmentArrayField(w, "supporting_calls", supportingCalls, true); err != nil {
		return err
	}
	meta.CryptoEntryPoints = len(entryPoints)
	if err := writeGraphFragmentArrayField(w, "crypto_entry_points", entryPoints, true); err != nil {
		return err
	}
	if supertypes := result.CallGraph.ExportSupertypes(); len(supertypes) > 0 {
		// Lets a server stitching components follow a call on a supertype to
		// its implementation in another component.
		if err := w.writeField("supertypes", supertypes); err != nil {
			return err
		}
	}
	if providers := result.CallGraph.ServiceProviders; len(providers) > 0 {
		// Lets a server stitching components dispatch a call on a service
		// type to the implementations a component registers for it.
		if err := w.writeField("service_providers", providers); err != nil {
			return err
		}
	}
	if text := sourceLines.text(); len(text) > 0 {
		if err := w.writeField("source_lines", text); err != nil {
			return err
		}
	}
	if signatures := buildGraphFragmentExternalSignatures(ctx); len(signatures) > 0 {
		if err := w.writeField("external_signatures", signatures); err != nil {
			return err
		}
	}
	if err := w.writeRebindLines(ctx, functionIndex, &meta); err != nil {
		return err
	}
	if imports := buildGraphFragmentImports(ctx); len(imports) > 0 {
		if err := w.writeField("imports", imports); err != nil {
			return err
		}
	}
	if objects := buildGraphFragmentObjectLiterals(ctx); len(objects) > 0 {
		if err := w.writeField("object_literals", objects); err != nil {
			return err
		}
	}
	if reads := buildGraphFragmentPropertyReads(ctx); len(reads) > 0 {
		if err := w.writeField("property_reads", reads); err != nil {
			return err
		}
	}
	if items := buildGraphFragmentItems(ctx); len(items) > 0 {
		if err := w.writeField("items", items); err != nil {
			return err
		}
	}
	if exprs := buildGraphFragmentBinaryExprs(ctx); len(exprs) > 0 {
		if err := w.writeField("binary_exprs", exprs); err != nil {
			return err
		}
	}
	if literals := buildGraphFragmentStrings(ctx); len(literals) > 0 {
		if err := w.writeField("strings", literals); err != nil {
			return err
		}
	}
	if exports := fragmentExports(ctx.graph); len(exports) > 0 {
		if err := w.writeField("exports", exports); err != nil {
			return err
		}
	}
	if paths := ctx.graph.PythonPublicPaths; len(paths) > 0 {
		if err := w.writeField("public_paths", paths); err != nil {
			return err
		}
	}
	w.setElided(&meta)
	if err := w.writeField("scan_metadata", meta); err != nil {
		return err
	}
	_, err = w.w.WriteString("\n}\n")
	return err
}

// buildGraphFragmentExport is the raw fixture helper; production must use BuildGraphFragmentExport.
func buildGraphFragmentExport(result *engine.DepScanResult) graphfrag.GraphFragmentExport {
	AssignOccurrenceKeys(result)
	return buildGraphFragmentProjection(result)
}

// buildGraphFragmentProjection reads finalized report data without mutating it.
func buildGraphFragmentProjection(result *engine.DepScanResult) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		ScanMetadata:  buildGraphFragmentScanMetadata(result),
	}
	if result.CallGraph == nil {
		return out
	}

	ctx := newExportBuildContext(result)

	functionKeys := make([]string, 0, len(result.CallGraph.Functions))
	for key := range result.CallGraph.Functions {
		functionKeys = append(functionKeys, key)
	}
	sort.Strings(functionKeys)

	// Same numbering the streaming writer assigns, and built here rather than
	// re-derived later: a route resolved against a different order would name
	// the wrong functions and still look well-formed.
	functionIndex := make(map[string]int, len(functionKeys))
	for _, key := range functionKeys {
		decl := result.CallGraph.Functions[key]
		functionIndex[key] = len(out.Functions)
		out.Functions = append(out.Functions, buildGraphFragmentFunction(ctx, decl.ID, decl))
	}
	out.InternalEdges, out.ExternalCalls = buildGraphFragmentResolvedEdges(ctx)
	out.Supertypes = result.CallGraph.ExportSupertypes()
	out.ServiceProviders = result.CallGraph.ServiceProviders
	out.ConstantRefs = buildGraphFragmentConstantRefs(ctx, functionIndex)
	out.AttributeStores = buildGraphFragmentAttributeStores(ctx, functionIndex)
	out.LocalBindings = buildGraphFragmentLocalBindings(ctx, functionIndex)
	out.Declarations, out.Casts = buildGraphFragmentDeclarations(ctx, functionIndex)
	out.CallAnchors = buildGraphFragmentCallAnchors(ctx, functionIndex)
	out.ExternalSignatures = buildGraphFragmentExternalSignatures(ctx)
	out.SourceLines = graphFragmentSourceLines(ctx, &out)
	out.RebindLines = buildGraphFragmentRebinds(ctx, functionIndex)
	out.Imports = buildGraphFragmentImports(ctx)
	out.ObjectLiterals = buildGraphFragmentObjectLiterals(ctx)
	out.PropertyReads = buildGraphFragmentPropertyReads(ctx)
	out.Items = buildGraphFragmentItems(ctx)
	out.BinaryExprs = buildGraphFragmentBinaryExprs(ctx)
	if literals := buildGraphFragmentStrings(ctx); len(literals) > 0 {
		out.Strings = literals
	}
	out.Exports = fragmentExports(result.CallGraph)
	out.PublicPaths = result.CallGraph.PythonPublicPaths
	out.ScanMetadata.RebindLines = writesRebindLines(ctx)

	out.CryptoAnnotations, out.SupportingCalls, out.CryptoEntryPoints = materializeGraphFragmentCrypto(ctx, result, functionIndex)
	out.ScanMetadata.FunctionCount = len(out.Functions)
	out.ScanMetadata.InternalEdges = len(out.InternalEdges)
	out.ScanMetadata.ExternalCalls = len(out.ExternalCalls)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	out.ScanMetadata.SupportingCalls = len(out.SupportingCalls)
	out.ScanMetadata.CryptoEntryPoints = len(out.CryptoEntryPoints)
	return out
}

// materializeGraphFragmentCrypto builds crypto_annotations, supporting_calls, and
// crypto_entry_points in one pass over findings. Supporting-call derivation and
// structural reachability chains are computed once per asset (not three times).
func materializeGraphFragmentCrypto(
	ctx *exportBuildContext,
	result *engine.DepScanResult,
	functionIndex map[string]int,
) (
	[]graphfrag.GraphFragmentCryptoOp,
	[]graphfrag.GraphFragmentSupporting,
	[]graphfrag.GraphFragmentCryptoEntryPoint,
) {
	if result == nil || result.Report == nil {
		return nil, nil, nil
	}
	return materializeGraphFragmentCryptoFromFindings(ctx, result, result.Report.Findings, functionIndex)
}
