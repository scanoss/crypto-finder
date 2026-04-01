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

package deadcode

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestFilterReport(t *testing.T) {
	t.Parallel()

	testdataDir := "../../testdata/code/c"

	tests := []struct {
		name           string
		report         *entities.InterimReport
		expectedAssets int // total assets across all findings
		expectedFiles  int // total findings (files) remaining
	}{
		{
			name:           "nil report returns nil",
			report:         nil,
			expectedAssets: 0,
			expectedFiles:  0,
		},
		{
			name: "non-C file is not filtered",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "main.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 10, EndLine: 10, Match: "sha256.New()"},
						},
					},
				},
			},
			expectedAssets: 1,
			expectedFiles:  1,
		},
		{
			name: "C file with asset inside #if 0 is filtered",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "dead_code.c",
						Language: "c",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 6, EndLine: 6, Match: "EVP_md5()"},      // live
							{StartLine: 12, EndLine: 12, Match: "EVP_sha256()"}, // dead (#if 0 at line 9-14)
							{StartLine: 18, EndLine: 18, Match: "EVP_sha1()"},   // live
						},
					},
				},
			},
			expectedAssets: 2,
			expectedFiles:  1,
		},
		{
			name: "all assets filtered removes the entire finding",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "dead_code.c",
						Language: "c",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 12, EndLine: 12, Match: "EVP_sha256()"}, // dead
							{StartLine: 24, EndLine: 24, Match: "EVP_aes()"},    // dead
						},
					},
				},
			},
			expectedAssets: 0,
			expectedFiles:  0,
		},
		{
			name: "file not readable keeps all assets",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "nonexistent.c",
						Language: "c",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 5, EndLine: 5, Match: "EVP_md5()"},
						},
					},
				},
			},
			expectedAssets: 1,
			expectedFiles:  1,
		},
		{
			name: "#if 0 / #else — only filters the #if 0 branch",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "if0_else.c",
						Language: "c",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 7, EndLine: 7, Match: "EVP_md5()"},      // dead (#if 0 branch, lines 4-9)
							{StartLine: 12, EndLine: 12, Match: "EVP_sha256()"}, // live (#else branch)
							{StartLine: 18, EndLine: 18, Match: "EVP_sha1()"},   // live
						},
					},
				},
			},
			expectedAssets: 2,
			expectedFiles:  1,
		},
		{
			name: "no dead code in file keeps all assets",
			report: &entities.InterimReport{
				Findings: []entities.Finding{
					{
						FilePath: "no_dead_code.c",
						Language: "c",
						CryptographicAssets: []entities.CryptographicAsset{
							{StartLine: 6, EndLine: 6, Match: "EVP_md5()"},
							{StartLine: 13, EndLine: 13, Match: "EVP_sha256()"},
							{StartLine: 18, EndLine: 18, Match: "EVP_sha1()"},
						},
					},
				},
			},
			expectedAssets: 3,
			expectedFiles:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := FilterReport(tt.report, testdataDir)

			if tt.report == nil {
				if result != nil {
					t.Fatal("expected nil result for nil input")
				}
				return
			}

			if len(result.Findings) != tt.expectedFiles {
				t.Errorf("expected %d findings, got %d", tt.expectedFiles, len(result.Findings))
			}

			totalAssets := 0
			for _, f := range result.Findings {
				totalAssets += len(f.CryptographicAssets)
			}
			if totalAssets != tt.expectedAssets {
				t.Errorf("expected %d total assets, got %d", tt.expectedAssets, totalAssets)
			}
		})
	}
}

func TestIsCFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{"main.c", true},
		{"header.h", true},
		{"code.cpp", true},
		{"code.cc", true},
		{"code.cxx", true},
		{"header.hpp", true},
		{"header.hh", true},
		{"header.hxx", true},
		{"UPPER.C", true},
		{"main.go", false},
		{"script.py", false},
		{"App.java", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			if got := isCFile(tt.path); got != tt.expected {
				t.Errorf("isCFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}
