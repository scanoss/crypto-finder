// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

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

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// BuildAnnotateExport produces a graph-fragment export carrying ONLY
// scan_metadata + crypto_annotations, mapping each crypto finding in report to
// its containing function using the imported (cached) structural fragment.
//
// This is the annotate-only path: it runs after a detection-only scan (no
// callgraph build, the expensive ~95% of a scan) so a rules refresh can
// re-annotate a component against its already-cached structure.
//
// Invariant: for the SAME source + rules, the crypto_annotations here are
// byte-identical to what a full `scan --export-graph-fragment` emits. This holds
// because:
//   - the detection-derived fields (finding_id, rule_id, expression, file_path,
//     line range, oid, source, metadata, matched_operation) come from the
//     SAME builder the full exporter uses (buildBaseGraphFragmentCryptoAnnotation);
//   - function_key is recovered from the imported fragment's function line
//     ranges, which were produced by the same scan that the full export read its
//     containing function from;
//   - crypto_call and the call-resolved Symbol override are carried verbatim
//     from the imported fragment's matching CryptoOperation (joined by
//     finding_id) — the full export already computed those from the live graph,
//     so reusing them avoids both rebuilding the callgraph and any drift.
//
// Functions, internal_edges, and external_calls are intentionally left empty:
// the structure lives in the imported fragment and is not rebuilt here.
func BuildAnnotateExport(report *entities.InterimReport, fragment graphfrag.Fragment) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{
			RootModule:       fragment.Module,
			GraphAlgoVersion: fragment.GraphAlgoVersion,
			ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		},
	}
	if report == nil {
		return out
	}
	if report.Tool.Name != "" {
		out.ScanMetadata.ToolName = report.Tool.Name
		out.ScanMetadata.ToolVersion = report.Tool.Version
	}
	out.ScanMetadata.RulesVersion = report.Rules.Version

	opsByFindingID := indexFragmentOpsByFindingID(fragment)

	for _, finding := range report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			out.CryptoAnnotations = append(out.CryptoAnnotations, buildAnnotateCryptoOp(finding, asset, fragment, opsByFindingID))
		}
	}

	sortGraphFragmentCryptoOps(out.CryptoAnnotations)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	return out
}

// buildAnnotateCryptoOp builds one crypto annotation from a detection finding +
// the imported fragment, without a live callgraph.
func buildAnnotateCryptoOp(
	finding entities.Finding,
	asset entities.CryptographicAsset,
	fragment graphfrag.Fragment,
	opsByFindingID map[string]graphfrag.CryptoOperation,
) graphfrag.GraphFragmentCryptoOp {
	matched := buildMatchedOperation(asset)
	op := buildBaseGraphFragmentCryptoAnnotation(finding, asset, matched)

	if fn, ok := annotateContainingFunction(fragment, finding.FilePath, asset.StartLine); ok {
		op.FunctionKey = fn.Signature
	}

	// Carry the callgraph-derived enrichment (resolved Symbol + crypto_call)
	// from the imported fragment's matching operation, joined by finding_id. The
	// full scan computed these from the live graph; reusing them keeps the
	// annotation byte-identical without rebuilding the callgraph. Genuinely new
	// findings (rules added since the fragment was built) have no match and
	// degrade gracefully to the detection-only fields.
	if prior, ok := opsByFindingID[asset.FindingID]; ok {
		applyPriorCryptoEnrichment(&op, prior)
	}
	return op
}

// applyPriorCryptoEnrichment copies the callgraph-derived fields (resolved
// Symbol and crypto_call) from a previously-exported CryptoOperation onto op.
func applyPriorCryptoEnrichment(op *graphfrag.GraphFragmentCryptoOp, prior graphfrag.CryptoOperation) {
	if prior.Symbol != "" {
		op.Symbol = prior.Symbol
		if op.MatchedOperation != nil {
			op.MatchedOperation.Symbol = prior.Symbol
		}
	}
	op.CryptoCall = fragmentCryptoCallFromModel(prior.CryptoCall)
}

// fragmentCryptoCallFromModel projects a graphfrag.CryptoCall (the decoded model
// shape) back onto the wire GraphFragmentCryptoCall, the inverse of toCryptoCall
// in pkg/graphfrag. Returns nil when there is no crypto call (legacy fragments).
func fragmentCryptoCallFromModel(cc *graphfrag.CryptoCall) *graphfrag.GraphFragmentCryptoCall {
	if cc == nil {
		return nil
	}
	out := &graphfrag.GraphFragmentCryptoCall{
		FunctionName:       cc.FunctionName,
		CanonicalSignature: cc.CanonicalSignature,
		ReturnType:         cc.ReturnType,
		ParameterTypes:     cc.ParameterTypes,
		Line:               cc.Line,
	}
	for i := range cc.Parameters {
		out.Parameters = append(out.Parameters, fragmentParameterFromModel(cc.Parameters[i]))
	}
	return out
}

func fragmentParameterFromModel(p graphfrag.Parameter) graphfrag.GraphFragmentParameter {
	out := graphfrag.GraphFragmentParameter{
		ParameterIndex:     p.ParameterIndex,
		Type:               p.Type,
		VariableName:       p.VariableName,
		ArgumentExpression: p.ArgumentExpression,
		ResolvedValue:      p.ResolvedValue,
	}
	for i := range p.SourceNodes {
		out.SourceNodes = append(out.SourceNodes, fragmentSourceNodeFromModel(p.SourceNodes[i]))
	}
	return out
}

func fragmentSourceNodeFromModel(n graphfrag.SourceNode) graphfrag.GraphFragmentSourceNode {
	out := graphfrag.GraphFragmentSourceNode{
		Type:           n.Type,
		Name:           n.Name,
		DeclaredType:   n.DeclaredType,
		Value:          n.Value,
		ParameterIndex: n.ParameterIndex,
		CallTarget:     n.CallTarget,
	}
	if n.Location != nil {
		out.Location = &graphfrag.GraphFragmentSourceLoc{
			FilePath: n.Location.FilePath,
			Line:     n.Location.Line,
		}
	}
	for i := range n.SourceNodes {
		out.SourceNodes = append(out.SourceNodes, fragmentSourceNodeFromModel(n.SourceNodes[i]))
	}
	return out
}

// annotateContainingFunction maps a finding (file, line) to its owning function
// in the imported fragment. It mirrors the full exporter's
// findContainingFunctionByFinding path normalization (dependency-relative path,
// then suffix match) so the recovered function_key is identical, falling back to
// the exact-match Fragment.ContainingFunction helper.
func annotateContainingFunction(fragment graphfrag.Fragment, findingPath string, line int) (graphfrag.Function, bool) {
	if fn, ok := fragment.ContainingFunction(findingPath, line); ok {
		return fn, true
	}

	normalized := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalized == "" {
		normalized = filepath.ToSlash(findingPath)
	}

	best := -1
	bestSpan := 0
	for i := range fragment.Functions {
		fn := &fragment.Functions[i]
		fnPath := filepath.ToSlash(fn.FilePath)
		if !strings.HasSuffix(fnPath, normalized) {
			continue
		}
		if line < fn.StartLine || line > fn.EndLine {
			continue
		}
		span := fn.EndLine - fn.StartLine
		if best == -1 || span < bestSpan {
			best = i
			bestSpan = span
		}
	}
	if best == -1 {
		return graphfrag.Function{}, false
	}
	return fragment.Functions[best], true
}

func indexFragmentOpsByFindingID(fragment graphfrag.Fragment) map[string]graphfrag.CryptoOperation {
	out := make(map[string]graphfrag.CryptoOperation, len(fragment.CryptoOperations))
	for i := range fragment.CryptoOperations {
		op := fragment.CryptoOperations[i]
		if op.FindingID == "" {
			continue
		}
		out[op.FindingID] = op
	}
	return out
}

// sortGraphFragmentCryptoOps orders annotations identically to the full export
// (buildGraphFragmentCryptoAnnotations) so the two outputs are byte-identical.
func sortGraphFragmentCryptoOps(ops []graphfrag.GraphFragmentCryptoOp) {
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].FunctionKey != ops[j].FunctionKey {
			return ops[i].FunctionKey < ops[j].FunctionKey
		}
		if ops[i].StartLine != ops[j].StartLine {
			return ops[i].StartLine < ops[j].StartLine
		}
		return ops[i].FindingID < ops[j].FindingID
	})
}

// MarshalAnnotateExport serializes an annotate-only graph-fragment export as
// indented JSON, matching the formatting of ExportGraphFragment.
func MarshalAnnotateExport(payload *graphfrag.GraphFragmentExport) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, fmt.Errorf("scan: failed to serialize annotation export: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteAnnotateExport writes an annotate-only graph-fragment export to path as
// indented JSON, matching the formatting of ExportGraphFragment.
func WriteAnnotateExport(path string, payload *graphfrag.GraphFragmentExport) error {
	data, err := MarshalAnnotateExport(payload)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("scan: failed to write annotation to %s: %w", path, err)
	}
	return nil
}
