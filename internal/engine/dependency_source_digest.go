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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// sourceDigest is the SHA-256 digest of the source a dependency scan reads
// under dir: files, when non-nil (dependency.Dependency.Files), else every
// regular file below dir, as its slash-separated path relative to dir and
// the SHA-256 of its content, sorted by path. Two directories holding the
// same files at the same relative paths digest the same, wherever they
// lie. Files outside dir, which the scan never reads, add nothing; neither
// does anything under an excluded directory (rootAnchoredDirs), nor a
// symlink, which the scan does not follow out of the dependency either.
// Dir's own symlink is resolved, as the scan reads through it. An error
// means the content is unknown, not partly known.
func sourceDigest(dir string, files, excluded []string) (string, error) {
	sources, err := sourceFiles(dir, files)
	if err != nil {
		return "", fmt.Errorf("engine: dependency source %s: %w", dir, err)
	}
	entries := make([]string, 0, len(sources))
	for _, source := range sources {
		if bytecode(source.rel) || slices.ContainsFunc(excluded, func(dir string) bool { return source.rel == dir || strings.HasPrefix(source.rel, dir+"/") }) {
			continue
		}
		sum, err := fileDigest(source.path)
		if err != nil {
			return "", fmt.Errorf("engine: dependency source %s: %w", dir, err)
		}
		entries = append(entries, source.rel+"\x00"+sum+"\n")
	}
	slices.Sort(entries)
	digest := sha256.New()
	for _, e := range slices.Compact(entries) {
		if _, err := io.WriteString(digest, e); err != nil {
			return "", fmt.Errorf("engine: dependency source %s: %w", dir, err)
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// sourceFile is a file of a dependency: its slash-separated path relative
// to the dependency's directory, and its path.
type sourceFile struct {
	rel, path string
}

// sourceFiles lists the files of the dependency at dir: files, when
// non-nil, as far as they lie below dir, else the regular files below dir.
func sourceFiles(dir string, files []string) ([]sourceFile, error) {
	if files != nil {
		sources := make([]sourceFile, 0, len(files))
		for _, file := range files {
			if rel, ok := pathRelativeToRoot(dir, file); ok {
				sources = append(sources, sourceFile{rel: filepath.ToSlash(rel), path: file})
			}
		}
		return sources, nil
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	var sources []sourceFile
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := pathRelativeToRoot(root, path)
			sources = append(sources, sourceFile{rel: filepath.ToSlash(rel), path: path})
		}
		return nil
	})
	return sources, err
}

// fileDigest is the hex SHA-256 of the regular file at path; a symlink or
// any other file is an error, as is one the scan could not read.
func fileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, f)
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// rootAnchoredDirs returns the directories the patterns anchored at dir
// exclude, as slash-separated paths relative to dir: the patterns that
// name an absolute directory below dir, ending in "/", as the dependency
// scan's own node_modules exclusion does.
func rootAnchoredDirs(patterns []string, dir string) []string {
	base := filepath.ToSlash(filepath.Clean(dir)) + "/"
	var dirs []string
	for _, pattern := range patterns {
		if rest, ok := strings.CutPrefix(pattern, base); ok && strings.HasSuffix(rest, "/") {
			dirs = append(dirs, strings.TrimSuffix(rest, "/"))
		}
	}
	return dirs
}

// bytecode reports whether rel, slash-separated, lies in a Python
// __pycache__ directory. No scanner reads compiled bytecode, and each .pyc
// embeds the mtime of the source it was compiled from, so the same wheel
// installed on two hosts would otherwise digest differently and never
// share an entry.
func bytecode(rel string) bool {
	return rel == "__pycache__" || strings.HasPrefix(rel, "__pycache__/") || strings.Contains(rel, "/__pycache__/")
}
