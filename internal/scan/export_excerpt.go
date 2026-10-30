// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// excerptCacheBytes bounds the source an export keeps in memory. Chains of
// one finding, and findings of one file, read the same files, so a file is
// read once while the files in use fit under the bound.
const excerptCacheBytes = 64 << 20

// sourceExcerpts cuts chain-frame excerpts out of the files a scan analyzed.
// It reads only files under the project root or a dependency source directory
// the scan resolved, after resolving symlinks, so a path in the graph cannot
// make an export quote a file outside them.
type sourceExcerpts struct {
	roots    []string
	readFile func(string) ([]byte, error)
	files    map[string]*sourceFile
	// order lists files in the order they were cached, oldest first.
	order []string
	bytes int
}

// sourceFile is one file's text, split into lines, or why it has none.
type sourceFile struct {
	content     []byte
	lineStarts  []int
	unavailable string
}

func newSourceExcerpts(artifacts *exportArtifacts, readFile func(string) ([]byte, error)) *sourceExcerpts {
	x := &sourceExcerpts{readFile: readFile, files: make(map[string]*sourceFile)}
	add := func(dir string) {
		if dir == "" {
			return
		}
		root := artifacts.absPath(dir)
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			root = resolved
		}
		x.roots = append(x.roots, root)
	}
	add(artifacts.projectRoot)
	for i := range artifacts.dependencies {
		add(artifacts.dependencies[i].Dir)
	}
	return x
}

// excerpt returns the window around focus in the file at path, or the reason
// there is none.
func (x *sourceExcerpts) excerpt(path string, focus int) (*graphfrag.ExportExcerpt, string) {
	if path == "" {
		return nil, graphfrag.ExcerptNoSource
	}
	file := x.file(path)
	if file.unavailable != "" {
		return nil, file.unavailable
	}
	if focus < 1 || focus > len(file.lineStarts) {
		return nil, graphfrag.ExcerptOutOfRange
	}
	first := max(1, focus-graphfrag.ExcerptContextLines)
	last := min(len(file.lineStarts), focus+graphfrag.ExcerptContextLines)
	out := &graphfrag.ExportExcerpt{StartLine: first, FocusLine: focus, Lines: make([]string, 0, last-first+1)}
	for line := first; line <= last; line++ {
		text, cut := capLine(file.line(line))
		out.Lines = append(out.Lines, text)
		out.Truncated = out.Truncated || cut
	}
	return out, ""
}

func (x *sourceExcerpts) file(path string) *sourceFile {
	if file, ok := x.files[path]; ok {
		return file
	}
	file := x.load(path)
	x.files[path] = file
	x.order = append(x.order, path)
	x.bytes += len(file.content)
	for x.bytes > excerptCacheBytes && len(x.order) > 1 {
		oldest := x.order[0]
		x.order = x.order[1:]
		x.bytes -= len(x.files[oldest].content)
		delete(x.files, oldest)
	}
	return file
}

func (x *sourceExcerpts) load(path string) *sourceFile {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !x.allowed(resolved) {
		return &sourceFile{unavailable: graphfrag.ExcerptNoSource}
	}
	content, err := x.readFile(resolved)
	if err != nil {
		return &sourceFile{unavailable: graphfrag.ExcerptUnreadable}
	}
	return &sourceFile{content: content, lineStarts: lineStarts(content)}
}

func (x *sourceExcerpts) allowed(path string) bool {
	for _, root := range x.roots {
		if _, ok := relativeToRoot(root, path); ok {
			return true
		}
	}
	return false
}

// lineStarts returns the offset of each line. A final newline ends the last
// line rather than starting an empty one.
func lineStarts(content []byte) []int {
	if len(content) == 0 {
		return nil
	}
	starts := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// line returns the 1-based line n without its line ending.
func (f *sourceFile) line(n int) []byte {
	end := len(f.content)
	if n < len(f.lineStarts) {
		end = f.lineStarts[n]
	}
	text := f.content[f.lineStarts[n-1]:end]
	text = bytes.TrimSuffix(text, []byte("\n"))
	return bytes.TrimSuffix(text, []byte("\r"))
}

// capLine keeps the first ExcerptLineMaxRunes runes of a line and reports
// whether it cut any.
func capLine(text []byte) (string, bool) {
	offset := 0
	for runes := 0; offset < len(text); runes++ {
		if runes == graphfrag.ExcerptLineMaxRunes {
			return string(text[:offset]), true
		}
		_, size := utf8.DecodeRune(text[offset:])
		offset += size
	}
	return string(text), false
}

// attachChainExcerpts gives each frame of chains the excerpt around its focus
// line: the call into the next frame, the crypto call on the last frame, or
// the function's first line when neither is known.
func attachChainExcerpts(ctx *exportBuildContext, chains [][]callGraphChainNode) {
	for _, chain := range chains {
		for i := range chain {
			frame := &chain[i]
			focus := frame.StartLine
			switch {
			case i+1 < len(chain) && chain[i+1].EntryCall != nil && chain[i+1].EntryCall.Line > 0:
				focus = chain[i+1].EntryCall.Line
			case i+1 == len(chain) && frame.CryptoCall != nil && frame.CryptoCall.Line > 0:
				focus = frame.CryptoCall.Line
			}
			path := ""
			if frame.sourcePath != "" {
				path = ctx.absPath(frame.sourcePath)
			}
			frame.Excerpt, frame.ExcerptUnavailable = ctx.excerpts().excerpt(path, focus)
		}
	}
}

func (ctx *exportBuildContext) excerpts() *sourceExcerpts {
	if ctx.excerptSource == nil {
		ctx.excerptSource = newSourceExcerpts(&ctx.exportArtifacts, os.ReadFile)
	}
	return ctx.excerptSource
}
