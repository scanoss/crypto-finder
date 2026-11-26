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
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// A scan exports the call graph from the OID-prepared report, not the raw
// one. A value enumeration cut at the depth cap must still read partial
// there: the preparation keeps the in-process state the export reads.
func TestConditionedValueEnumeration_CutReadsPartialThroughOIDPreparation(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	g := newSelectorGraph()
	top := g.addForwarderChain(maxConditionedWalkDepth + 2)
	g.addLiteralCaller("top000", top, 1)
	report := g.report()
	result := &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}
	MaterializeConditionedFindings(report, result, []string{rules})
	if !report.Findings[0].CryptographicAssets[0].ConditionedValuesIncomplete {
		t.Fatal("fixture: the enumeration was not cut")
	}

	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "callgraph.json")
	if err := ExportResolvedCallGraph(path, "json", result, prepared.ReportClone(), CallGraphExportOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var export struct {
		FindingGraphs []struct {
			FindingID string `json:"finding_id"`
			Analysis  *struct {
				CallChains string `json:"call_chains"`
			} `json:"analysis"`
		} `json:"finding_graphs"`
	}
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	if len(export.FindingGraphs) == 0 {
		t.Fatal("export holds no finding graph")
	}
	for _, fg := range export.FindingGraphs {
		if fg.Analysis == nil || fg.Analysis.CallChains != string(graphfrag.AnalysisPartial) {
			t.Errorf("%s: analysis = %+v, want call_chains %q", fg.FindingID, fg.Analysis, graphfrag.AnalysisPartial)
		}
	}
}
