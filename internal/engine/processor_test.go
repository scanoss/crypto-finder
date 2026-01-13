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

package engine

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/version"
)

func TestProcessor_Process(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		inputReport    *entities.InterimReport
		languages      []string
		expectedReport *entities.InterimReport
		expectError    bool
	}{
		{
			name:        "nil report returns empty report with defaults",
			inputReport: nil,
			languages:   []string{"go"},
			expectedReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    version.ToolName,
					Version: version.Version,
				},
				Findings: []entities.Finding{},
			},
			expectError: false,
		},
		{
			name: "valid report is returned unchanged",
			inputReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: []entities.Finding{
					{
						FilePath: "test.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								MatchType: "semgrep",
								StartLine: 10,
								EndLine:   10,
								Match:     "AES.encrypt",
								Rule: entities.RuleInfo{
									ID:       "go.crypto.aes",
									Message:  "AES detected",
									Severity: "INFO",
								},
								Status:   "pending",
								Metadata: map[string]string{"algorithm": "AES"},
							},
						},
					},
				},
			},
			languages: []string{"go"},
			expectedReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: []entities.Finding{
					{
						FilePath: "test.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								MatchType: "semgrep",
								StartLine: 10,
								EndLine:   10,
								Match:     "AES.encrypt",
								Rule: entities.RuleInfo{
									ID:       "go.crypto.aes",
									Message:  "AES detected",
									Severity: "INFO",
								},
								Status:   "pending",
								Metadata: map[string]string{"algorithm": "AES"},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "report with empty version gets default version",
			inputReport: &entities.InterimReport{
				Version: "",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: []entities.Finding{},
			},
			languages: []string{"python"},
			expectedReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: []entities.Finding{},
			},
			expectError: false,
		},
		{
			name: "report with nil findings gets initialized slice",
			inputReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: nil,
			},
			languages: []string{"java"},
			expectedReport: &entities.InterimReport{
				Version: "1.0",
				Tool: entities.ToolInfo{
					Name:    "test-tool",
					Version: "1.0.0",
				},
				Findings: []entities.Finding{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			processor := NewProcessor()
			result, err := processor.Process(tt.inputReport, tt.languages)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			// Validate version
			if result.Version != tt.expectedReport.Version {
				t.Errorf("expected version %q, got %q", tt.expectedReport.Version, result.Version)
			}

			// Validate tool info
			if result.Tool.Name != tt.expectedReport.Tool.Name {
				t.Errorf("expected tool name %q, got %q", tt.expectedReport.Tool.Name, result.Tool.Name)
			}
			if result.Tool.Version != tt.expectedReport.Tool.Version {
				t.Errorf("expected tool version %q, got %q", tt.expectedReport.Tool.Version, result.Tool.Version)
			}

			// Validate findings
			if result.Findings == nil {
				t.Error("expected non-nil findings slice")
			}
			if len(result.Findings) != len(tt.expectedReport.Findings) {
				t.Errorf("expected %d findings, got %d", len(tt.expectedReport.Findings), len(result.Findings))
			}
		})
	}
}

func TestNewProcessor(t *testing.T) {
	t.Parallel()

	processor := NewProcessor()
	if processor == nil {
		t.Fatal("NewProcessor() returned nil")
	}
}
