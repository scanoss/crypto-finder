// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package offline

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

// The miner stores a component's findings report and graph with every
// "file_path" relative to the directory it scanned (crypto-finder writes
// them as found, absolute); the API serves those paths. A dependency mined
// offline is stored the same way, so its paths, and the finding ids hashed
// from them, are the ones the API serves. This is the miner's own rewrite,
// applied the same way: the document is re-encoded through generic JSON,
// numbers kept exact.

// relativePaths rewrites every "file_path" string in the JSON document raw
// relative to dir. raw is returned unchanged when it is not JSON or no path
// changes.
func relativePaths(raw []byte, dir string) []byte {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return raw
	}
	if !rewriteFilePaths(doc, func(p string) string { return workspaceRelative(dir, p) }) {
		return raw
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

func rewriteFilePaths(v any, transform func(string) string) bool { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	changed := false
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			if k == "file_path" {
				if s, ok := child.(string); ok {
					if rewritten := transform(s); rewritten != s {
						node[k] = rewritten
						changed = true
					}
					continue
				}
			}
			if rewriteFilePaths(child, transform) {
				changed = true
			}
		}
	case []any:
		for _, child := range node {
			if rewriteFilePaths(child, transform) {
				changed = true
			}
		}
	}
	return changed
}

// workspaceRelative is filePath relative to dir when it is an absolute path
// inside dir; a relative path is returned slash-separated and any other
// unchanged.
func workspaceRelative(dir, filePath string) string {
	if !filepath.IsAbs(filePath) {
		return filepath.ToSlash(filePath)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return filePath
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return filePath
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filePath
	}
	return filepath.ToSlash(rel)
}
