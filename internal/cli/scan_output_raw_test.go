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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/static-engine/entities"
	"github.com/scanoss/static-engine/output"
)

func TestWriteScanOutputRAW(t *testing.T) {
	previousFormat, previousOutput := scanFormat, scanOutput
	t.Cleanup(func() { scanFormat, scanOutput = previousFormat, previousOutput })

	report := &entities.InterimReport{
		Version: entities.InterimFormatVersion,
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "main.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 3, EndLine: 3, Match: "sha256.Sum256(data)",
				Rules:    []entities.RuleInfo{{ID: "go.crypto.sha256"}},
				Metadata: map[string]string{"assetType": "algorithm", "algorithmName": "SHA-256"},
			}},
		}},
	}
	scanFormat = "raw"
	scanOutput = filepath.Join(t.TempDir(), "raw.json")
	if err := writeScanOutput(report, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(scanOutput)
	if err != nil {
		t.Fatal(err)
	}
	var raw output.RAWReport
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Version != "raw-1.0" || raw.Domain != "crypto" || len(raw.Findings) != 1 {
		t.Fatalf("RAW report = %s", data)
	}
	finding := raw.Findings[0]
	if finding.RuleID != "go.crypto.sha256" || finding.Metadata["algorithmName"] != "SHA-256" || finding.Reachability.String() != "unknown" {
		t.Fatalf("RAW finding = %+v", finding)
	}

	// The crypto formats need the OID-resolved report.
	scanFormat = formatJSON
	if err := writeScanOutput(report, nil); err == nil {
		t.Fatal("json output without a resolved report succeeded")
	}
}
