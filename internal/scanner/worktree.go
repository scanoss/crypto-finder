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

package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WorkTree makes git treat a scan target as the root of a work tree of its
// own, backed by an empty temporary repository: the .gitignore files inside
// the target apply and those above it do not.
type WorkTree struct {
	gitDir string
	dir    string
}

// IgnoredTargetWorkTree returns a WorkTree for target when the Git work tree
// that contains target ignores target itself. Scanned through that work tree,
// target would have no files at all. It returns nil when target is not inside
// a work tree, is its root, is not ignored, or git is unavailable: git then
// sees target as it always has. Close the result when the scan ends.
func IgnoredTargetWorkTree(ctx context.Context, target string) (*WorkTree, error) {
	dir, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("scanner: resolve scan target %s: %w", target, err)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	if !ignoredByEnclosingWorkTree(ctx, dir) {
		return nil, nil
	}
	gitDir, err := os.MkdirTemp("", "crypto-finder-worktree-")
	if err != nil {
		return nil, fmt.Errorf("scanner: create a work tree for %s: %w", dir, err)
	}
	if _, err := gitOutput(ctx, gitDir, "init", "--quiet", "--bare", gitDir); err != nil {
		_ = os.RemoveAll(gitDir) //nolint:errcheck // Best-effort cleanup of the failed temporary repository.
		return nil, fmt.Errorf("scanner: create a work tree for %s: %w", dir, err)
	}
	return &WorkTree{gitDir: gitDir, dir: dir}, nil
}

// ignoredByEnclosingWorkTree reports whether dir is a directory below the
// root of a Git work tree that ignores it. Any git failure reads as false.
func ignoredByEnclosingWorkTree(ctx context.Context, dir string) bool {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false
	}
	top, err := gitOutput(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return false // not a work tree, or no git
	}
	top = strings.TrimSpace(top)
	if resolved, err := filepath.EvalSymlinks(top); err == nil {
		top = resolved
	}
	rel, err := filepath.Rel(top, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	// check-ignore exits 0 when the path is ignored and 1 when it is not.
	_, err = gitOutput(ctx, top, "check-ignore", "-q", "--", filepath.ToSlash(rel)+"/")
	return err == nil
}

// Env returns the variables that point git at the work tree; nil for a nil
// WorkTree.
func (w *WorkTree) Env() map[string]string {
	if w == nil {
		return nil
	}
	return map[string]string{"GIT_DIR": w.gitDir, "GIT_WORK_TREE": w.dir}
}

// WithEnv returns env with the work tree's variables added, or env itself
// for a nil WorkTree.
func (w *WorkTree) WithEnv(env map[string]string) map[string]string {
	if w == nil {
		return env
	}
	merged := make(map[string]string, len(env)+2)
	for name, value := range env {
		merged[name] = value
	}
	for name, value := range w.Env() {
		merged[name] = value
	}
	return merged
}

// Close removes the temporary repository.
func (w *WorkTree) Close() error {
	if w == nil {
		return nil
	}
	if err := os.RemoveAll(w.gitDir); err != nil {
		return fmt.Errorf("scanner: remove the work tree of %s: %w", w.dir, err)
	}
	return nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- fixed git subcommands.
	cmd.Dir = dir
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	return string(out), err
}
