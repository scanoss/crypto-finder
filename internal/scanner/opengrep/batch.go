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

// ScanRoots runs one OpenGrep process over every root, or one per share of
// the command-line budget when scoped roots name many files, and reports
// each root as a scan of that root alone would: its results and errors are
// the ones in its files, with paths relative to it. Roots must not nest or
// repeat unless they are disjoint (scanner.Disjoint): a walk of the outer
// root covers the inner one's files and its exclusions could hide them, and
// OpenGrep scans a repeated target once.
func (s *Scanner) ScanRoots(ctx context.Context, roots []scanner.Root, rulePaths []string, toolInfo entities.ToolInfo) ([]*entities.InterimReport, error) {
	if len(rulePaths) == 0 {
		return nil, failure.New(
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"no rule paths provided",
			failure.WithDetail("scanner", ScannerName),
		)
	}
	if err := refuseNestedRoots(roots); err != nil {
		return nil, err
	}
	scoped := false
	for _, root := range roots {
		scoped = scoped || root.Scope != nil
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	if scoped {
		if err := s.requireForceExclude(ctx); err != nil {
			return nil, err
		}
	}
	parsed := &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}
	for _, targets := range scanner.RootTargetBatches(roots) {
		batch, _, _, err := s.run(ctx, s.buildCommand(ctx, targets, rulePaths, scoped), rulePaths, nil)
		if err != nil {
			return nil, err
		}
		parsed.Results = append(parsed.Results, batch.Results...)
		parsed.Errors = append(parsed.Errors, batch.Errors...)
	}
	semgrep.LogSemgrepCompatibleErrors(parsed.Errors)

	parts, err := partitionByRoot(parsed, roots)
	if err != nil {
		return nil, err
	}
	reports := make([]*entities.InterimReport, len(roots))
	for i, part := range parts {
		reports[i] = semgrep.TransformSemgrepCompatibleOutputToInterimFormat(part, toolInfo, roots[i].Dir, rulePaths, s.disableDedup)
	}
	return reports, nil
}

// refuseNestedRoots fails when two roots nest or repeat and are not
// disjoint.
func refuseNestedRoots(roots []scanner.Root) error {
	for i := range roots {
		for j := range roots {
			if i != j && holds(filepath.Clean(roots[j].Dir), filepath.Clean(roots[i].Dir)) && !scanner.Disjoint(roots[i], roots[j]) {
				return failure.New(
					failure.CodeInvalidArguments,
					failure.StageInput,
					fmt.Sprintf("roots %s and %s cannot share one opengrep process: they nest or repeat", roots[j].Dir, roots[i].Dir),
					failure.WithDetail("scanner", ScannerName),
				)
			}
		}
	}
	return nil
}

// partitionByRoot splits results and errors by the root holding their file:
// the root whose scope names it, else the innermost root below which it
// lies. A result outside every root (a symlinked root reported by its real
// path, say) cannot be attributed, so the whole scan fails rather than lose
// it. An error without a file, or with one outside every root, goes to every
// root: a limit it reports may have cut any of them short.
func partitionByRoot(output *entities.SemgrepOutput, scanRoots []scanner.Root) ([]*entities.SemgrepOutput, error) {
	parts := make([]*entities.SemgrepOutput, len(scanRoots))
	roots := make([]string, len(scanRoots))
	named := make(map[string]int)
	for i := range scanRoots {
		parts[i] = &entities.SemgrepOutput{Results: []entities.SemgrepResult{}, Errors: []entities.SemgrepError{}}
		roots[i] = filepath.Clean(scanRoots[i].Dir)
		if scope := scanRoots[i].Scope; scope != nil {
			for _, rel := range scope.Paths {
				named[filepath.Join(roots[i], rel)] = i
			}
		}
	}
	rootOf := func(path string) int {
		if i, ok := named[filepath.Clean(path)]; ok {
			return i
		}
		return innermostRoot(path, roots)
	}
	for r := range output.Results {
		i := rootOf(output.Results[r].Path)
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
		if i := rootOf(e.Path); i >= 0 {
			parts[i].Errors = append(parts[i].Errors, e)
			continue
		}
		for _, part := range parts {
			part.Errors = append(part.Errors, e)
		}
	}
	return parts, nil
}

// innermostRoot returns the index of the root holding path, the longest one
// when roots nest, or -1.
func innermostRoot(path string, roots []string) int {
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
