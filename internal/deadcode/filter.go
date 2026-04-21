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
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// cLanguageExtensions lists file extensions for C/C++ source and header files.
var cLanguageExtensions = map[string]bool{
	".c": true, ".h": true,
	".cpp": true, ".cc": true, ".cxx": true,
	".hpp": true, ".hh": true, ".hxx": true,
}

// maxWorkers caps the number of concurrent file reads for dead code detection.
// Bounded to avoid exhausting file descriptors on large scans.
var maxWorkers = min(runtime.NumCPU(), 8)

// filterResult holds the outcome of processing a single finding.
type filterResult struct {
	index   int               // original position in the findings slice
	finding *entities.Finding // nil if the finding was fully filtered out
}

// FilterReport removes cryptographic assets that fall entirely within
// preprocessor dead code regions (#if 0 blocks) in C/C++ files.
// Non-C/C++ files are passed through unchanged.
// If a source file cannot be read, its findings are kept (best-effort filtering).
// C/C++ files are processed concurrently using a bounded worker pool.
func FilterReport(report *entities.InterimReport, targetDir string) *entities.InterimReport {
	if report == nil || len(report.Findings) == 0 {
		return report
	}

	// Separate C/C++ findings (need processing) from non-C findings (pass through).
	type indexedFinding struct {
		index   int
		finding entities.Finding
	}

	results := make([]filterResult, len(report.Findings))
	var cFindings []indexedFinding

	for i, finding := range report.Findings {
		if !isCFile(finding.FilePath) {
			f := finding
			results[i] = filterResult{index: i, finding: &f}
		} else {
			cFindings = append(cFindings, indexedFinding{index: i, finding: finding})
		}
	}

	// Process C/C++ files concurrently using a bounded worker pool.
	if len(cFindings) > 0 {
		resultsCh := make(chan filterResult, len(cFindings))
		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for _, cf := range cFindings {
			wg.Add(1)
			go func(idx int, finding entities.Finding) {
				defer wg.Done()
				sem <- struct{}{}        // acquire
				defer func() { <-sem }() // release

				result := filterFinding(finding, targetDir)
				resultsCh <- filterResult{index: idx, finding: result}
			}(cf.index, cf.finding)
		}

		wg.Wait()
		close(resultsCh)

		for r := range resultsCh {
			results[r.index] = r
		}
	}

	// Rebuild findings slice preserving original order.
	filtered := make([]entities.Finding, 0, len(report.Findings))
	for _, r := range results {
		if r.finding != nil {
			filtered = append(filtered, *r.finding)
		}
	}

	report.Findings = filtered
	return report
}

// filterFinding processes a single C/C++ finding, removing assets inside dead code regions.
// Returns nil if all assets were filtered out.
func filterFinding(finding entities.Finding, targetDir string) *entities.Finding {
	if filepath.IsAbs(finding.FilePath) {
		log.Debug().Str("file", finding.FilePath).Msg("Skipping finding with absolute file path")
		return &finding
	}

	fullPath := filepath.Clean(filepath.Join(targetDir, finding.FilePath))

	relPath, err := filepath.Rel(targetDir, fullPath)
	if err != nil || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		log.Debug().Str("file", finding.FilePath).Msg("Skipping finding with file path escaping target directory")
		return &finding
	}

	regions, err := FindDeadRegions(fullPath)
	if err != nil {
		log.Debug().Err(err).Str("file", finding.FilePath).Msg("Could not read file for dead code filtering, keeping all findings")
		return &finding
	}

	if len(regions) == 0 {
		return &finding
	}

	var liveAssets []entities.CryptographicAsset
	for i := range finding.CryptographicAssets {
		asset := &finding.CryptographicAssets[i]
		if IsInsideDeadRegion(regions, asset.StartLine, asset.EndLine) {
			log.Debug().
				Str("file", finding.FilePath).
				Int("startLine", asset.StartLine).
				Int("endLine", asset.EndLine).
				Msg("Filtered finding inside preprocessor dead code block")
			continue
		}
		liveAssets = append(liveAssets, *asset)
	}

	if len(liveAssets) == 0 {
		return nil
	}

	finding.CryptographicAssets = liveAssets
	return &finding
}

// isCFile checks if a file path has a C/C++ extension.
func isCFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return cLanguageExtensions[ext]
}
