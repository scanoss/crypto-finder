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
	"os"
	"strings"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

// ScanRoots reports each root as a scan of that root alone does, in the
// order of roots: its results and errors, with paths relative to it. Each
// root runs in its own OpenGrep process (one per share of the command-line
// budget when scoped) in the root's directory (site). One process over
// several roots would hand the engine paths that name a common ancestor of
// the batch, and OpenGrep's results depend on those path strings, so a
// dependency's findings would change with the dependencies scanned beside
// it and with where they lie. The rules are read once per run.
func (s *Scanner) ScanRoots(ctx context.Context, roots []scanner.Root, rulePaths []string, toolInfo entities.ToolInfo) ([]*entities.InterimReport, error) {
	if len(rulePaths) == 0 {
		return nil, failure.New(
			failure.CodeRulesLoadFailed,
			failure.StageRules,
			"no rule paths provided",
			failure.WithDetail("scanner", ScannerName),
		)
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
	reports := make([]*entities.InterimReport, len(roots))
	for i, root := range roots {
		parsed, err := s.collect(ctx, root, rulePaths)
		if err != nil {
			return nil, err
		}
		semgrep.LogSemgrepCompatibleErrors(parsed.Errors)
		reports[i] = semgrep.TransformSemgrepCompatibleOutputToInterimFormat(parsed, toolInfo, root.Dir, rulePaths, s.disableDedup)
	}
	return reports, nil
}

// holds reports whether path is root or lies below it at a separator.
func holds(root, path string) bool {
	return strings.HasPrefix(path, root) && (len(path) == len(root) || os.IsPathSeparator(path[len(root)]))
}

// ScansRootRelative reports whether scans run in the root over relative
// paths (site): unless extra scanner arguments, which may name paths
// relative to crypto-finder's working directory, are set.
func (s *Scanner) ScansRootRelative() bool {
	return len(s.extraArgs) == 0
}

var (
	_ scanner.BatchScanner        = (*Scanner)(nil)
	_ scanner.RootRelativeScanner = (*Scanner)(nil)
)
