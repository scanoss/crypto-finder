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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

// defaultMaxTargetBytes is the opengrep CLI's --max-target-bytes default.
const defaultMaxTargetBytes = 1_000_000

// maxShebangBytes is how much of a file the CLI decodes before it reads the
// first line for a shebang: a text stream decodes a whole 8 KiB chunk.
const maxShebangBytes = 8192

// maxShebangChars caps the shebang line the CLI reads.
const maxShebangChars = 255

// alwaysSkipped are the CLI's PATHS_ALWAYS_SKIPPED.
var alwaysSkipped = []string{".git"}

// errTargetsUnsupported marks a target set the CLI would reject or treat in
// a way core mode does not reproduce; the caller runs the CLI instead.
var errTargetsUnsupported = errors.New("opengrep: target set needs the opengrep CLI")

// coreTarget is one (file, analyzer) pair the CLI hands opengrep-core.
type coreTarget struct {
	path     string
	analyzer string
}

// targetPlan is the outcome of enumerating targets like the CLI.
type targetPlan struct {
	targets []coreTarget
	// analyzers lists, per selected file, the analyzers it is scanned with.
	analyzers map[string][]string
	// dir is the directory relative target paths lie in: the working
	// directory of the engine process.
	dir string
}

// file is the path of target as crypto-finder opens it.
func (p *targetPlan) file(target string) string {
	return fsPath(p.dir, target)
}

// targetOptions are the CLI options that select targets.
type targetOptions struct {
	targets           []string
	skipPatterns      []string
	includeGitIgnored bool
	forceExclude      bool
	maxTargetBytes    int64
	env               []string
	// dir is the working directory of the engine process, which relative
	// targets lie in; empty is crypto-finder's own.
	dir string
}

// fsPath is path, as an engine running in dir names it, for crypto-finder
// to open.
func fsPath(dir, path string) string {
	if dir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// enumerateTargets selects the files the opengrep CLI would hand
// opengrep-core for rules of the given languages: the files below each
// directory target (tracked or untracked-but-not-ignored ones in a Git work
// tree unless includeGitIgnored), selected by name suffix or shebang and not
// matched by an exclude pattern, readable and no larger than maxTargetBytes,
// plus explicitly named files of those languages unless forceExclude.
func enumerateTargets(ctx context.Context, opts targetOptions, langs []*language) (*targetPlan, error) {
	files, explicit, err := collectFiles(ctx, opts)
	if err != nil {
		return nil, err
	}
	sel := &selector{
		excludes:  newExcludeMatcher(opts.skipPatterns),
		always:    newExcludeMatcher(alwaysSkipped),
		maxBytes:  opts.maxTargetBytes,
		dir:       opts.dir,
		shebangs:  make(map[string]string),
		filtered:  make(map[string]bool),
		forceExcl: opts.forceExclude,
	}
	plan := &targetPlan{analyzers: make(map[string][]string), dir: opts.dir}
	for _, lang := range langs {
		kept := sel.keep(lang, files, explicit)
		for _, path := range files {
			if kept[path] {
				plan.targets = append(plan.targets, coreTarget{path: path, analyzer: lang.id})
				plan.analyzers[path] = append(plan.analyzers[path], lang.id)
			}
		}
	}
	return plan, nil
}

// collectFiles returns the sorted files below or named by the targets, and
// the explicitly named ones.
func collectFiles(ctx context.Context, opts targetOptions) (files, explicit []string, err error) {
	prune := newExcludeMatcher(append(append([]string(nil), opts.skipPatterns...), alwaysSkipped...))
	all := make(map[string]bool)
	for _, target := range opts.targets {
		path := pyPath(target)
		info, err := os.Lstat(fsPath(opts.dir, path))
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !readable(fsPath(opts.dir, path)) {
			// The CLI refuses a missing, unreadable or symlinked target.
			return nil, nil, fmt.Errorf("%w: target %s", errTargetsUnsupported, target)
		}
		if !info.IsDir() {
			if info.Mode().IsRegular() {
				all[path] = true
				explicit = append(explicit, path)
			}
			continue
		}
		for _, file := range directoryFiles(ctx, path, prune, opts) {
			all[file] = true
		}
	}
	files = make([]string, 0, len(all))
	for path := range all {
		files = append(files, path)
	}
	sort.Strings(files)
	return files, explicit, nil
}

// selector applies the CLI's per-language target filters, remembering the
// language-independent ones per file.
type selector struct {
	excludes, always *excludeMatcher
	maxBytes         int64
	shebangs         map[string]string
	// filtered caches whether a file survives the exclude, permission and
	// size filters.
	filtered  map[string]bool
	forceExcl bool
	// dir is the directory relative paths lie in.
	dir string
}

// keep returns the files the CLI scans with lang.
func (sel *selector) keep(lang *language, files, explicit []string) map[string]bool {
	kept := make(map[string]bool)
	for _, path := range files {
		if selectsLanguage(path, fsPath(sel.dir, path), lang, sel.shebangs) && sel.passes(path) {
			kept[path] = true
		}
	}
	if !sel.forceExcl {
		// Explicitly named files bypass the exclude, permission and size
		// filters; only their language must fit.
		for _, path := range explicit {
			if selectsLanguage(path, fsPath(sel.dir, path), lang, sel.shebangs) {
				kept[path] = true
			}
		}
	}
	return kept
}

func (sel *selector) passes(path string) bool {
	ok, seen := sel.filtered[path]
	if !seen {
		file := fsPath(sel.dir, path)
		ok = !sel.excludes.matches(path) && !sel.always.matches(path) && readable(file) && withinSize(file, sel.maxBytes)
		sel.filtered[path] = ok
	}
	return ok
}

// directoryFiles lists the regular files below dir as the CLI's Target.files
// does, pruning excluded directories during the walk.
func directoryFiles(ctx context.Context, dir string, prune *excludeMatcher, opts targetOptions) []string {
	walked := walkFiles(opts.dir, dir, prune)
	if opts.includeGitIgnored {
		return walked
	}
	tracked, ok := gitFiles(ctx, opts.dir, dir, opts.env)
	if !ok {
		// Not a Git work tree, or no git: the CLI scans all files.
		return walked
	}
	kept := walked[:0]
	for _, file := range walked {
		if tracked[file] {
			kept = append(kept, file)
		}
	}
	return kept
}

// walkFiles mirrors os.walk(followlinks=False) with directory pruning: a
// subdirectory whose path relative to root matches a prune pattern is not
// entered, symlinks are never followed and only regular files that are not
// symlinks are kept. Unreadable directories are skipped silently. Paths
// are named as root is, and relative ones lie in base.
func walkFiles(base, root string, prune *excludeMatcher) []string {
	var files []string
	var walk func(dir, rel string)
	walk = func(dir, rel string) {
		entries, err := os.ReadDir(fsPath(base, dir))
		if err != nil {
			return
		}
		for _, entry := range entries {
			name := entry.Name()
			path := pyJoin(dir, name)
			relPath := name
			if rel != "" {
				relPath = rel + "/" + name
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if entry.IsDir() {
				if prune.matches(relPath) {
					continue
				}
				walk(path, relPath)
				continue
			}
			if entry.Type().IsRegular() {
				files = append(files, path)
			}
		}
	}
	walk(root, "")
	return files
}

// gitFiles returns the files `git ls-files` lists below dir, tracked or
// untracked but not ignored, joined onto dir as the CLI joins them, and false
// when git cannot list them. A relative dir lies in base.
func gitFiles(ctx context.Context, base, dir string, env []string) (map[string]bool, bool) {
	resolved, err := filepath.EvalSymlinks(fsPath(base, dir))
	if err != nil {
		return nil, false
	}
	if resolved, err = filepath.Abs(resolved); err != nil {
		return nil, false
	}
	files := make(map[string]bool)
	for _, args := range [][]string{{"ls-files", "-z"}, {"ls-files", "-z", "--others", "--exclude-standard"}} {
		cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- fixed git subcommands.
		cmd.Dir = resolved
		cmd.Env = env
		cmd.Stderr = io.Discard
		out, err := cmd.Output()
		if err != nil {
			return nil, false
		}
		for _, elem := range bytes.Split(out, []byte{0}) {
			if len(elem) == 0 {
				continue
			}
			path := pyJoin(dir, string(elem))
			info, err := os.Lstat(fsPath(base, path))
			if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
				continue
			}
			files[path] = true
		}
	}
	return files, true
}

// selectsLanguage reports whether the CLI assigns path to lang: by name
// suffix, or by a shebang line of an executable file ending in one of the
// language's interpreters. file is path as crypto-finder opens it.
func selectsLanguage(path, file string, lang *language, shebangs map[string]string) bool {
	for _, ext := range lang.exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	if len(lang.shebangs) == 0 {
		return false
	}
	line, ok := shebangs[path]
	if !ok {
		line = shebangLine(file)
		shebangs[path] = line
	}
	if line == "" {
		return false
	}
	for _, interpreter := range lang.shebangs {
		if strings.HasSuffix(line, interpreter) {
			return true
		}
	}
	return false
}

// shebangLine reads the first line of an owner-readable, owner-executable
// file the way the CLI does, or "" when it is not one or does not decode as
// UTF-8.
func shebangLine(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o500 != 0o500 {
		return ""
	}
	file, err := os.Open(path) // #nosec G304 -- path is a scan target the caller enumerated.
	if err != nil {
		return ""
	}
	defer file.Close() //nolint:errcheck // Read-only close.
	buf := make([]byte, maxShebangBytes)
	n, _ := io.ReadFull(file, buf) //nolint:errcheck // A short read is the whole file.
	buf = buf[:n]
	if !utf8.Valid(trimPartialRune(buf)) {
		return ""
	}
	text := string(buf)
	if end := strings.IndexAny(text, "\r\n"); end >= 0 {
		text = text[:end]
	}
	if runes := []rune(text); len(runes) > maxShebangChars {
		text = string(runes[:maxShebangChars])
	}
	return strings.TrimRight(text, " \t\f\v\r\n")
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of a chunk,
// which the decoder would complete from the next chunk.
func trimPartialRune(buf []byte) []byte {
	for i := 1; i <= utf8.UTFMax && i <= len(buf); i++ {
		if utf8.RuneStart(buf[len(buf)-i]) {
			if !utf8.FullRune(buf[len(buf)-i:]) {
				return buf[:len(buf)-i]
			}
			break
		}
	}
	return buf
}

func readable(path string) bool {
	file, err := os.Open(path) // #nosec G304 -- path is a scan target the caller enumerated.
	if err != nil {
		return false
	}
	_ = file.Close() //nolint:errcheck // Read-only close.
	return true
}

func withinSize(path string, maxBytes int64) bool {
	if maxBytes <= 0 {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() <= maxBytes
}

// pyPath normalizes a path the way Python's pathlib does on POSIX: repeated
// slashes and "." components go, ".." stays, and an empty path is ".".
func pyPath(path string) string {
	path = filepath.ToSlash(path)
	absolute := strings.HasPrefix(path, "/")
	parts := strings.Split(path, "/")
	kept := parts[:0]
	for _, part := range parts {
		if part != "" && part != "." {
			kept = append(kept, part)
		}
	}
	joined := strings.Join(kept, "/")
	switch {
	case absolute:
		return "/" + joined
	case joined == "":
		return "."
	default:
		return joined
	}
}

// pyJoin is pathlib's Path(base) / rel.
func pyJoin(base, rel string) string {
	if base == "." {
		return pyPath(rel)
	}
	return pyPath(base + "/" + rel)
}

// targetStrings lists the positional targets the CLI receives for roots.
func targetStrings(roots []scanner.Root) []string {
	batches := scanner.RootTargetBatches(roots)
	targets := make([]string, 0, len(roots))
	for _, batch := range batches {
		targets = append(targets, batch...)
	}
	return targets
}
