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
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

func TestScanProgressSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "schemas", "scan-progress-schema.json")
	tests := []struct {
		name      string
		document  string
		wantValid bool
	}{
		{
			name: "scan-started",
			document: `{
				"event": "scan_progress",
				"schema_version": "1",
				"phase": "scan",
				"status": "started"
			}`,
			wantValid: true,
		},
		{
			name: "skipped-with-reason",
			document: `{
				"event": "scan_progress",
				"schema_version": "1",
				"phase": "dependencies",
				"status": "skipped",
				"parent_phase": "scan",
				"details": {"reason": "not_requested"}
			}`,
			wantValid: true,
		},
		{
			name: "completed-dependencies",
			document: `{
				"event": "scan_progress",
				"schema_version": "1",
				"phase": "dependencies",
				"status": "completed",
				"parent_phase": "scan",
				"duration_ms": 1,
				"details": {
					"deps_scanned": 2,
					"deps_skipped": 0,
					"deps_failed": 0,
					"deps_with_findings": 1,
					"total_dep_findings": 3
				}
			}`,
			wantValid: true,
		},
		{
			name: "reason-on-non-skipped-event",
			document: `{
				"event": "scan_progress",
				"schema_version": "1",
				"phase": "scan",
				"status": "completed",
				"duration_ms": 1,
				"details": {"reason": "not_requested"}
			}`,
			wantValid: false,
		},
		{
			name: "dependency-counters-on-non-dependency-event",
			document: `{
				"event": "scan_progress",
				"schema_version": "1",
				"phase": "scan",
				"status": "completed",
				"duration_ms": 1,
				"details": {
					"deps_scanned": 0,
					"deps_skipped": 0,
					"deps_failed": 0,
					"deps_with_findings": 0,
					"total_dep_findings": 0
				}
			}`,
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := gojsonschema.Validate(
				gojsonschema.NewReferenceLoader("file://"+schemaPath),
				gojsonschema.NewBytesLoader([]byte(tc.document)),
			)
			if err != nil {
				t.Fatalf("validate JSON against schema: %v", err)
			}
			if got := result.Valid(); got != tc.wantValid {
				t.Fatalf("schema validity = %v, want %v: %v", got, tc.wantValid, result.Errors())
			}
		})
	}
}
