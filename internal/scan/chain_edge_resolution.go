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
	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// applyChainEdgeResolution stamps how the call from caller to the frame's
// function was resolved, from the builder's edge classification. The
// classification recorded at the call site the chain step names wins, taking
// the most certain derivation of that one call. Without a site match the least
// certain classification of the caller-callee pair is reported, so a frame
// never reads more certain than some edge that could have produced it.
func applyChainEdgeResolution(ctx *exportBuildContext, node *callGraphChainNode, caller, callee callgraph.CallChainStep) {
	if ctx == nil || node == nil {
		return
	}
	variants := resolveFragmentEdges(ctx, caller.Function.String(), callee.Function.String())
	if len(variants) == 0 {
		return
	}
	chosen, matched := variants[0], false
	for i := range variants {
		variant := &variants[i]
		if !chainStepMatchesCallSite(caller, variant.EdgeResolution) {
			continue
		}
		if !matched || edgeResolutionLessCertain(chosen.Kind, variant.Kind) {
			chosen, matched = *variant, true
		}
	}
	if !matched {
		for i := 1; i < len(variants); i++ {
			if edgeResolutionLessCertain(variants[i].Kind, chosen.Kind) {
				chosen = variants[i]
			}
		}
	}
	node.EntryResolution = chosen.Resolution
	if chosen.Kind != callgraph.EdgeKindExact {
		node.EntryDeclaredType = chosen.DeclaredType
	}
}

func chainStepMatchesCallSite(caller callgraph.CallChainStep, res callgraph.EdgeResolution) bool {
	if res.CallSite == 0 || caller.Line == 0 || res.CallSite != caller.Line {
		return false
	}
	if caller.StartCol > 0 && res.StartCol > 0 {
		return caller.StartCol == res.StartCol && caller.EndCol == res.EndCol
	}
	return true
}

// edgeResolutionLessCertain orders edge kinds from the least to the most
// certain: a name-only guess, then a dispatch expansion, then an exact edge.
func edgeResolutionLessCertain(a, b callgraph.EdgeKind) bool {
	return edgeKindCertainty(a) < edgeKindCertainty(b)
}

func edgeKindCertainty(kind callgraph.EdgeKind) int {
	switch kind {
	case callgraph.EdgeKindExact:
		return 3
	case callgraph.EdgeKindInterfaceDispatch, callgraph.EdgeKindPythonSubclassDispatch:
		return 2
	case callgraph.EdgeKindNameOnly:
		return 1
	default:
		return 0
	}
}
