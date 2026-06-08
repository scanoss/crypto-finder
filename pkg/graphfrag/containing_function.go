// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

// ContainingFunction returns the function in this fragment whose source file is
// filePath and whose [StartLine, EndLine] range (inclusive) encloses line.
//
// This is how annotate-only maps a crypto finding (file, line) back to its
// owning function WITHOUT re-parsing source into an AST: the cached structural
// fragment already carries every function's file and line range, so a finding's
// location is enough to recover its function key.
//
// When several functions in the same file enclose the line (nested ranges, e.g.
// a lambda or local class inside a method), the tightest — innermost — range
// wins, since that is the most specific function that owns the finding. Returns
// (zero Function, false) when no function in filePath encloses line.
func (f Fragment) ContainingFunction(filePath string, line int) (Function, bool) {
	best := -1
	bestSpan := 0
	for i := range f.Functions {
		fn := &f.Functions[i]
		if fn.FilePath != filePath {
			continue
		}
		if line < fn.StartLine || line > fn.EndLine {
			continue
		}
		span := fn.EndLine - fn.StartLine
		if best == -1 || span < bestSpan {
			best = i
			bestSpan = span
		}
	}
	if best == -1 {
		return Function{}, false
	}
	return f.Functions[best], true
}
