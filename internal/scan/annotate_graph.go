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
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// BuildGraphAnnotateExport writes the annotation of a stored graph: the
// crypto sections and scan metadata a scan's graph-fragment export writes,
// built by the same code from result, the call graph FragmentScanResult
// rebuilt from doc, and report, the findings detected on it. Routes index
// doc's functions, which the annotation does not repeat; the graph counts
// are doc's, so the metadata describes the graph the annotation belongs to.
func BuildGraphAnnotateExport(result *engine.DepScanResult, report *oid.ResolvedReport, doc *graphfrag.GraphFragmentExport) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion}
	if result == nil || result.CallGraph == nil || report == nil || doc == nil {
		return out
	}
	out.ScanMetadata = buildResolvedGraphFragmentScanMetadata(result, report)
	out.ScanMetadata.GraphAlgoVersion = doc.ScanMetadata.GraphAlgoVersion
	out.ScanMetadata.AbstractMethods = doc.ScanMetadata.AbstractMethods
	out.ScanMetadata.FunctionCount = len(doc.Functions)
	out.ScanMetadata.InternalEdges = doc.ScanMetadata.InternalEdges
	out.ScanMetadata.ExternalCalls = doc.ScanMetadata.ExternalCalls

	functionIndex := make(map[string]int, len(doc.Functions))
	for i := range doc.Functions {
		functionIndex[doc.Functions[i].Key] = i
	}
	ctx := newExportBuildContextWithFindings(result, report.Findings, 0)
	out.CryptoAnnotations, out.SupportingCalls, out.CryptoEntryPoints = materializeGraphFragmentCryptoFromFindings(ctx, result, report.Findings, functionIndex)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	out.ScanMetadata.SupportingCalls = len(out.SupportingCalls)
	out.ScanMetadata.CryptoEntryPoints = len(out.CryptoEntryPoints)
	return out
}
