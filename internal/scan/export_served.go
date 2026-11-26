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
	"encoding/json"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// servedFindingGraph is the finding graph of a dependency asset whose verdict
// a server decided (asset.Served): the verdict, its reason, and the server's
// call chains and analysis, under the same identity, matched operation and
// dependency route a locally traced finding carries. An unknown verdict's
// reason goes in unresolved_reason.
func servedFindingGraph(ctx *exportBuildContext, asset entities.CryptographicAsset) callGraphExportFinding {
	served := asset.Served
	fg := callGraphExportFinding{
		FindingID:        asset.FindingID,
		PURL:             asset.PURL,
		OccurrenceKey:    asset.OccurrenceKey,
		MatchedOperation: buildMatchedOperation(asset),
		Reachability:     served.Reachability,
	}
	switch served.Reachability {
	case graphfrag.ReachabilityReachable, graphfrag.ReachabilityUnreachable:
		reachable := served.Reachability == graphfrag.ReachabilityReachable
		fg.Reachable = &reachable
	case graphfrag.ReachabilityUnknown:
		fg.UnresolvedReason = served.Reason
	}
	if len(served.CallChains) > 0 {
		if err := json.Unmarshal(served.CallChains, &fg.CallChains); err != nil {
			log.Debug().Err(err).Str("finding_id", asset.FindingID).Msg("Served call chains are not chain frames; left out")
			fg.CallChains = nil
		}
	}
	if len(served.Analysis) > 0 {
		var analysis graphfrag.ExportFindingAnalysis
		if err := json.Unmarshal(served.Analysis, &analysis); err == nil {
			fg.Analysis = &analysis
		}
	}
	fg.Dependency, _ = ctx.findingDependency(asset.DependencyInfo)
	return fg
}
