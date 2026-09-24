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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// detectionScopeStats counts list entries that did not become scoped files.
type detectionScopeStats struct {
	missing    int // absent from disk, e.g. deleted in the change being scanned
	gitIgnored int // untracked and ignored by git, so a whole-target walk never reads them
	special    int // not a regular file (symlink, device, ...)
}

// loadDetectionScope builds the scope named by --detect-paths-from.
func loadDetectionScope(ctx context.Context, stdin io.Reader, target string) (*scanner.DetectionScope, error) {
	entries, err := readDetectionPathList(scanDetectPathsFrom, stdin)
	if err != nil {
		return nil, failure.Wrap(err, failure.CodeInvalidArguments, failure.StageInput,
			fmt.Sprintf("failed to read --detect-paths-from %s", scanDetectPathsFrom))
	}
	scope, stats, err := buildDetectionScope(ctx, target, entries)
	if err != nil {
		return nil, failure.Wrap(err, failure.CodeInvalidArguments, failure.StageInput, "invalid --detect-paths-from list")
	}
	log.Info().
		Int("listed", len(entries)).
		Int("scoped", len(scope.Paths)).
		Int("missing", stats.missing).
		Int("git_ignored", stats.gitIgnored).
		Int("not_regular", stats.special).
		Msg("Detection limited to listed files; call graph and reachability use the whole target")
	return scope, nil
}

// readDetectionPathList reads one path per line from listPath, or from stdin
// when listPath is "-". Blank lines are ignored.
func readDetectionPathList(listPath string, stdin io.Reader) (entries []string, err error) {
	r := stdin
	if listPath != "-" {
		f, openErr := os.Open(listPath)
		if openErr != nil {
			return nil, openErr
		}
		defer func() {
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}()
		r = f
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			entries = append(entries, line)
		}
	}
	return entries, sc.Err()
}

// buildDetectionScope resolves list entries against the directory target into
// a scope of target-relative regular files. An entry outside the target or
// naming a directory is an error. Missing entries are dropped, because a
// changed-file list names deleted files too.
//
// The scope must never reach a file a whole-target scan would skip. OpenGrep
// applies --exclude to named files under --force-exclude, but its git-aware
// directory walk also drops untracked files git ignores, which naming a file
// bypasses, so those are filtered here with git's own answer.
func buildDetectionScope(ctx context.Context, target string, entries []string) (*scanner.DetectionScope, detectionScopeStats, error) {
	var stats detectionScopeStats
	info, err := os.Stat(target)
	if err != nil {
		return nil, stats, err
	}
	if !info.IsDir() {
		return nil, stats, fmt.Errorf("--detect-paths-from requires a directory scan target, got file %s", target)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return nil, stats, err
	}

	seen := make(map[string]struct{}, len(entries))
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		rel, kind, err := resolveDetectionEntry(target, targetAbs, entry)
		if err != nil {
			return nil, stats, err
		}
		switch kind {
		case entryMissing:
			stats.missing++
		case entrySpecial:
			stats.special++
		case entryFile:
			if _, dup := seen[rel]; !dup {
				seen[rel] = struct{}{}
				paths = append(paths, rel)
			}
		}
	}

	ignored, err := gitIgnoredPaths(ctx, targetAbs, paths)
	if err != nil {
		return nil, stats, err
	}
	if len(ignored) > 0 {
		kept := paths[:0]
		for _, rel := range paths {
			if _, drop := ignored[rel]; !drop {
				kept = append(kept, rel)
			}
		}
		stats.gitIgnored = len(paths) - len(kept)
		paths = kept
	}
	slices.Sort(paths)
	return &scanner.DetectionScope{Paths: paths}, stats, nil
}

type entryKind int

const (
	entryFile entryKind = iota
	entryMissing
	entrySpecial
)

// resolveDetectionEntry maps one list entry to its path relative to targetAbs.
func resolveDetectionEntry(target, targetAbs, entry string) (string, entryKind, error) {
	abs := filepath.FromSlash(entry)
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(targetAbs, abs)
	}
	rel, err := filepath.Rel(targetAbs, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", 0, fmt.Errorf("detection path %q is not a file under the scan target %s", entry, target)
	}
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", entryMissing, nil
	case err != nil:
		return "", 0, err
	case fi.IsDir():
		return "", 0, fmt.Errorf("detection path %q is a directory; list files only", entry)
	case !fi.Mode().IsRegular():
		return "", entrySpecial, nil
	}
	return rel, entryFile, nil
}

// gitIgnoredPaths returns the subset of rels, relative to dir, that git
// ignores. Tracked files are never reported, matching the files a git-aware
// walk lists. Outside a work tree, or without git, nothing is ignored: the
// scanner then walks without consulting .gitignore either.
func gitIgnoredPaths(ctx context.Context, dir string, rels []string) (map[string]struct{}, error) {
	if len(rels) == 0 {
		return nil, nil
	}
	var input bytes.Buffer
	for _, rel := range rels {
		input.WriteString(filepath.ToSlash(rel))
		input.WriteByte(0)
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "check-ignore", "--stdin", "-z")
	cmd.Stdin = &input
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, exec.ErrNotFound):
		return nil, nil // no git, so the scanner's walk cannot consult .gitignore either
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		return nil, nil // no path is ignored
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 128:
		return nil, nil // not a git work tree
	default:
		return nil, fmt.Errorf("git check-ignore in %s: %w", dir, err)
	}
	ignored := make(map[string]struct{})
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) > 0 {
			ignored[filepath.FromSlash(string(p))] = struct{}{}
		}
	}
	return ignored, nil
}
