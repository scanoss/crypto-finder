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

// Package exports checks the embedded contracts KB end to end through the
// static-engine scan exports: a library's calls, built into a call graph and
// exported as a graph fragment, must carry the lifecycle roles and parameter
// roles its contracts declare.
package exports

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/static-engine/callgraph"
	"github.com/scanoss/static-engine/domains/crypto/oid"
	"github.com/scanoss/static-engine/engine"
	"github.com/scanoss/static-engine/entities"
	"github.com/scanoss/static-engine/graphfrag"
	"github.com/scanoss/static-engine/scan"

	cfcontracts "github.com/scanoss/crypto-finder/internal/contracts"
)

func TestMain(m *testing.M) {
	cfcontracts.RegisterAll()
	os.Exit(m.Run())
}

// buildGraphFragmentExport builds the graph fragment of result the way a scan
// exports it: occurrence keys assigned, findings prepared by the OID resolver,
// then the engine's BuildGraphFragmentExport.
func buildGraphFragmentExport(result *engine.DepScanResult) graphfrag.GraphFragmentExport {
	scan.AssignOccurrenceKeys(result)
	prepared, err := oid.NewDefaultResolver().PrepareReport(result.Report)
	if err != nil {
		panic(err)
	}
	return scan.BuildGraphFragmentExport(result, prepared.ReportClone())
}

// fullFunctionName is the exported symbol of a call identity, as the engine's
// exports spell it: package, type and base method name, with a receiver
// expression that is not a type left out.
func fullFunctionName(id callgraph.FunctionID) string {
	base := callgraph.BaseFunctionName(id.Name)
	typeName, pkg := sanitizeSymbol(id.Type), sanitizeSymbol(id.Package)
	if typeName == "" || strings.Contains(typeName, "(") {
		if pkg == "" {
			return base
		}
		return pkg + "." + base
	}
	if pkg == "" {
		return typeName + "." + base
	}
	return pkg + "." + typeName + "." + base
}

// sanitizeSymbol drops the line breaks and indentation a multi-line receiver
// expression carries.
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

func cAsset(startLine, endLine, startCol, endCol int, match, rule string, metadata map[string]string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		StartLine: startLine,
		EndLine:   endLine,
		StartCol:  startCol,
		EndCol:    endCol,
		Match:     match,
		Rules:     []entities.RuleInfo{{ID: rule}},
		Metadata:  metadata,
	}
}

// assertNodeSupportingRoles scans src as file with one finding and checks that
// the graph fragment's supporting calls carry the wanted contract roles. (The
// engine's own tests check that the call graph export and the annotate path
// agree with the fragment.)
func assertNodeSupportingRoles(t *testing.T, file, src string, asset entities.CryptographicAsset, want map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath:            file,
			Language:            "javascript",
			CryptographicAssets: []entities.CryptographicAsset{asset},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	fragment := buildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "node"})
	got := map[string]string{}
	for i := range fragment.SupportingCalls {
		s := &fragment.SupportingCalls[i]
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("graph fragment supporting calls = %v, want %v", got, want)
	}
}
