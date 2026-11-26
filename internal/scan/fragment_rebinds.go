// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// writesRebindLines reports whether a fragment of the scanned ecosystem
// carries rebind_lines: one whose calls a re-annotation rebuilds with the
// arguments the scan saw (call_anchors, graph-fragment-1.21), Java or Python.
func writesRebindLines(ctx *exportBuildContext) bool {
	return fragmentCarriesCalls(ctx)
}

// buildGraphFragmentRebinds records, for each function in functionIndex, the
// lines the related-material pass would read to tell whether a variable is
// rebound between a draw and its use (materialTracer.rebound): for each
// variable a call of the function passes, the lines from after the first line
// that can start the check (the function's, or its first call's) to before
// its last call that may rebind it. A function whose source cannot be read is
// recorded unread, as the pass then treats every variable as rebound.
func buildGraphFragmentRebinds(ctx *exportBuildContext, functionIndex map[string]int) []graphfrag.GraphFragmentRebind { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if !writesRebindLines(ctx) {
		return nil
	}
	keys := make([]string, len(functionIndex))
	for key, index := range functionIndex {
		keys[index] = key
	}
	patterns := rebindPatternCache{}
	var out []graphfrag.GraphFragmentRebind
	for index, key := range keys {
		decl := ctx.graph.Functions[key]
		if decl == nil {
			continue
		}
		names, first, last := rebindCandidates(decl, ctx.ecosystem)
		if len(names) == 0 || last <= first+1 {
			continue
		}
		file := ctx.excerpts().file(ctx.absPath(decl.FilePath))
		if file.unavailable != "" || last-1 > len(file.lineStarts) {
			out = append(out, graphfrag.GraphFragmentRebind{Function: index})
			continue
		}
		lines := make(map[string][]int)
		for line := first + 1; line < last; line++ {
			text := string(file.line(line))
			for _, name := range names {
				if strings.Contains(text, name) && lineMayRebind(text, patterns.patterns(name)) {
					lines[name] = append(lines[name], line)
				}
			}
		}
		for _, name := range names {
			if len(lines[name]) > 0 {
				out = append(out, graphfrag.GraphFragmentRebind{Function: index, Name: name, Lines: lines[name]})
			}
		}
	}
	return out
}

// rebindCandidates are, sorted, the variables decl's calls pass as bare
// arguments (the only names the pass follows in it), and the first and last
// line a rebind check in decl can span: from the function's first line or
// its first call, to its last call.
func rebindCandidates(decl *callgraph.FunctionDecl, ecosystem string) (names []string, first, last int) {
	first = decl.StartLine
	for i := range decl.Calls {
		call := &decl.Calls[i]
		if call.Line > 0 && (first <= 0 || call.Line < first) {
			first = call.Line
		}
		last = max(last, call.Line)
		for _, arg := range call.Arguments {
			if _, name := passedVariable(arg, ecosystem); isSimpleIdentifier(name) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names, first, last
}

// fragmentRebindLines is the RebindLines of a call graph rebuilt from doc:
// every function doc lists, but those recorded unread, with the lines
// recorded for it. Nil when doc records none, or its calls are not rebuilt
// with the scan's arguments (no call anchors with calls, 1.21).
func fragmentRebindLines(doc *graphfrag.GraphFragmentExport) map[string]map[string][]int {
	if !doc.ScanMetadata.RebindLines || !hasAnchoredCalls(doc) {
		return nil
	}
	out := make(map[string]map[string][]int, len(doc.Functions))
	for i := range doc.Functions {
		out[doc.Functions[i].Key] = nil
	}
	for _, r := range doc.RebindLines {
		if r.Function < 0 || r.Function >= len(doc.Functions) {
			continue
		}
		key := doc.Functions[r.Function].Key
		if r.Unread() {
			delete(out, key)
			continue
		}
		byName, ok := out[key]
		if !ok {
			continue
		}
		if byName == nil {
			byName = make(map[string][]int)
			out[key] = byName
		}
		byName[r.Name] = r.Lines
	}
	return out
}
