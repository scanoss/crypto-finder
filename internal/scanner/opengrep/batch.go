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

package opengrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

// ScanRoots runs one OpenGrep process over every root and reports each root
// as a scan of that root alone would: its results and errors are the ones
// in files below it, with paths relative to it. Roots must not nest or
// repeat: an exclusion of the outer root could hide the inner one, and
// OpenGrep scans a repeated root once.
func (s *Scanner) ScanRoots(ctx context.Context, roots, rulePaths []string, toolInfo entities.ToolInfo) ([]*entities.InterimReport, error) {
	if len(rulePaths) == 0 {
		return nil, failure.New(
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"no rule paths provided",
			failure.WithDetail("scanner", ScannerName),
		)
	}
	cleaned := make([]string, len(roots))
	for i, root := range roots {
		cleaned[i] = filepath.Clean(root)
	}
	for i, inner := range cleaned {
		for j, outer := range cleaned {
			if i != j && holds(outer, inner) {
				return nil, failure.New(
					failure.CodeInvalidArguments,
					failure.StageInput,
					fmt.Sprintf("roots %s and %s cannot share one opengrep process: they nest or repeat", roots[j], roots[i]),
					failure.WithDetail("scanner", ScannerName),
				)
			}
		}
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	parsed, _, _, err := s.run(ctx, s.buildCommand(ctx, roots, rulePaths, false), rulePaths, nil)
	if err != nil {
		return nil, err
	}
	semgrep.LogSemgrepCompatibleErrors(parsed.Errors)

	parts, err := partitionByRoot(parsed, cleaned)
	if err != nil {
		return nil, err
	}
	reports := make([]*entities.InterimReport, len(roots))
	for i, part := range parts {
		reports[i] = semgrep.TransformSemgrepCompatibleOutputToInterimFormat(part, toolInfo, roots[i], rulePaths, s.disableDedup)
	}
	return reports, nil
}

// partitionByRoot splits results and errors by the root holding their file.
// A result outside every root (a symlinked root reported by its real path,
// say) cannot be attributed, so the whole scan fails rather than lose it.
// An error without a file, or with one outside every root, goes to every
// root: a limit it reports may have cut any of them short.
func partitionByRoot(output *entities.SemgrepOutput, roots []string) ([]*entities.SemgrepOutput, error) {
	parts := make([]*entities.SemgrepOutput, len(roots))
	for i := range parts {
		parts[i] = &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}
	}
	for r := range output.Results {
		i := rootOf(output.Results[r].Path, roots)
		if i < 0 {
			return nil, failure.New(
				failure.CodeScannerOutputParseFailed,
				failure.StageScan,
				fmt.Sprintf("opengrep reported %s, which lies under none of the scanned roots", output.Results[r].Path),
				failure.WithDetail("scanner", ScannerName),
			)
		}
		parts[i].Results = append(parts[i].Results, output.Results[r])
	}
	for _, e := range output.Errors {
		if i := rootOf(e.Path, roots); i >= 0 {
			parts[i].Errors = append(parts[i].Errors, e)
			continue
		}
		for _, part := range parts {
			part.Errors = append(part.Errors, e)
		}
	}
	return parts, nil
}

// rootOf returns the index of the root holding path, the longest one when
// roots nest, or -1.
func rootOf(path string, roots []string) int {
	best, bestLen := -1, -1
	for i, root := range roots {
		if len(root) > bestLen && holds(root, path) {
			best, bestLen = i, len(root)
		}
	}
	return best
}

// holds reports whether path is root or lies below it at a separator.
func holds(root, path string) bool {
	return strings.HasPrefix(path, root) && (len(path) == len(root) || os.IsPathSeparator(path[len(root)]))
}

var _ scanner.BatchScanner = (*Scanner)(nil)
