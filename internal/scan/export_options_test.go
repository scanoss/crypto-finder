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

	"github.com/scanoss/crypto-finder/internal/engine"
)

func TestExportCallGraphWithOptions_CryptoEntryPoints(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                string
		options             CallGraphExportOptions
		wantCryptoEntryKeys bool
	}{
		{
			name:                "zero value preserves the reverse reachability index",
			wantCryptoEntryKeys: true,
		},
		{
			name: "explicit omission removes the reverse reachability index",
			options: CallGraphExportOptions{
				OmitCryptoEntryPoints: true,
			},
			wantCryptoEntryKeys: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph, projectRoot := buildSupportingGraph(t)
			report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
			outputPath := filepath.Join(t.TempDir(), "callgraph.json")
			if err := ExportCallGraphWithOptions(outputPath, "json", &engine.DepScanResult{
				Report:      report,
				CallGraph:   graph,
				Ecosystem:   "java",
				ProjectRoot: projectRoot,
				RootModule:  "com.app:app",
			}, tc.options); err != nil {
				t.Fatalf("ExportCallGraphWithOptions: %v", err)
			}

			assertJSONMatchesSchema(t, filepath.Join("..", "..", "schemas", "callgraph-schema.json"), outputPath)

			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("read callgraph export: %v", err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("decode callgraph export: %v", err)
			}
			_, hasCryptoEntryPoints := document["crypto_entry_points"]
			if hasCryptoEntryPoints != tc.wantCryptoEntryKeys {
				t.Fatalf("crypto_entry_points present = %v, want %v", hasCryptoEntryPoints, tc.wantCryptoEntryKeys)
			}
			for _, key := range []string{"schema_version", "scan_metadata", "finding_graphs", "functions", "supporting_calls"} {
				if _, ok := document[key]; !ok {
					t.Errorf("callgraph export missing %q when crypto_entry_points presence is %v", key, hasCryptoEntryPoints)
				}
			}
		})
	}
}
