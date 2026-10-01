// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"path/filepath"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// functionFileIndex groups a call graph's functions by the base name of the
// file that declares them.
//
// Finding the function that contains a finding used to walk every function in
// the graph once per asset. A dependency scan holds hundreds of thousands of
// functions and thousands of assets, so that walk dominated a warm scan:
// occurrence keys and the callgraph export together spent about 3 of a warm
// run's 7 minutes in it. Every match the walk can accept is declared in a file
// whose base name the finding path determines, so only that file's functions
// need checking. The match predicates stay exactly as they were; the index
// only narrows which functions reach them.
type functionFileIndex struct {
	byBaseName map[string][]*callgraph.FunctionDecl
	all        []*callgraph.FunctionDecl
}

func newFunctionFileIndex(functions map[string]*callgraph.FunctionDecl) *functionFileIndex {
	idx := &functionFileIndex{
		byBaseName: make(map[string][]*callgraph.FunctionDecl),
		all:        make([]*callgraph.FunctionDecl, 0, len(functions)),
	}
	for _, fn := range functions {
		if fn == nil {
			continue
		}
		idx.all = append(idx.all, fn)
		base := pathBaseName(strings.TrimRight(filepath.ToSlash(fn.FilePath), "/"))
		idx.byBaseName[base] = append(idx.byBaseName[base], fn)
	}
	return idx
}

// suffixCandidates returns the functions whose slash path can end with
// suffix. When suffix names a directory as well as a file, a match must be
// declared in a file with exactly suffix's base name. A bare file name can
// also be the tail of a longer base name ("Foo.java" ends "BarFoo.java"), so
// it gets every function.
func (idx *functionFileIndex) suffixCandidates(suffix string) []*callgraph.FunctionDecl {
	slash := strings.LastIndex(suffix, "/")
	if slash < 0 || slash == len(suffix)-1 {
		return idx.all
	}
	return idx.byBaseName[suffix[slash+1:]]
}

// segmentSuffixCandidates returns the functions whose path can end with the
// whole path segments of suffix, as hasPathSegmentSuffix compares them. Such
// a match always shares suffix's base name.
func (idx *functionFileIndex) segmentSuffixCandidates(suffix string) []*callgraph.FunctionDecl {
	trimmed := strings.Trim(filepath.ToSlash(suffix), "/")
	if trimmed == "" {
		return idx.all
	}
	return idx.byBaseName[pathBaseName(trimmed)]
}

func pathBaseName(slashPath string) string {
	return slashPath[strings.LastIndex(slashPath, "/")+1:]
}
