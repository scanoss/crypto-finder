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
	"path/filepath"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// buildCallSiteParameters constructs the unified parameters slice for a call
// site by delegating to mergeCallParameters — the same path that the schema-5.x
// call-graph builder uses for entry_call and crypto_call. This function is the
// shared helper called by both ExportCallGraph (via buildEntryCall) and
// ExportGraphFragment (via buildGraphFragmentResolvedEdges) to guarantee
// identical output from both code paths.
func buildCallSiteParameters(ctx *exportBuildContext, call *callgraph.FunctionCall) []callGraphParameter {
	if call == nil {
		return nil
	}
	callee := ctx.graph.Functions[call.Callee.String()]
	sourcePath := filepath.ToSlash(call.FilePath)
	if ctx.graph != nil {
		sourcePath = normalizeExportPath(ctx, call.FilePath).FilePath
	}
	return mergeCallParameters(
		ctx,
		&call.Callee,
		callee,
		call.Arguments,
		call.ArgumentSources,
		sourcePath,
		call.Line,
	)
}
