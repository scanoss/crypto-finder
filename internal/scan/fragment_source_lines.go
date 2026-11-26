// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"maps"
	"os"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/deadcode"
)

// fragmentCallEndLine is the end line a fragment edge carries for call: the
// line its expression ends on when that is after line, else 0.
func fragmentCallEndLine(call *callgraph.FunctionCall, line int) int {
	if call == nil || call.EndLine <= line {
		return 0
	}
	return call.EndLine
}

// fragmentSourceLines collects the lines the exported call sites of the
// scanned source cover and reads their text for the fragment's
// source_lines. A call in a dependency's source is left out: its file path is
// relative to that dependency, not to the scanned tree.
type fragmentSourceLines struct {
	ctx   *exportBuildContext
	lines map[string]map[int]bool // actual path -> lines
	paths map[string]string       // actual path -> exported path
}

func newFragmentSourceLines(ctx *exportBuildContext) *fragmentSourceLines {
	return &fragmentSourceLines{ctx: ctx, lines: make(map[string]map[int]bool), paths: make(map[string]string)}
}

// add records the lines line..endLine of a call site in callerKey's file.
func (s *fragmentSourceLines) add(callerKey string, line, endLine int) {
	if line <= 0 || s.ctx == nil || s.ctx.graph == nil {
		return
	}
	decl := s.ctx.graph.Functions[callerKey]
	if decl == nil || decl.FilePath == "" {
		return
	}
	s.addFile(decl.FilePath, line, endLine)
}

// addFile records the lines line..endLine of the source file at path.
func (s *fragmentSourceLines) addFile(path string, line, endLine int) {
	lines := s.lines[path]
	if lines == nil {
		location := normalizeExportPath(s.ctx, path)
		if location.DependencyInfo != nil || location.FilePath == "" {
			return
		}
		s.paths[path] = location.FilePath
		lines = make(map[int]bool)
		s.lines[path] = lines
	}
	for n := line; n <= max(line, endLine); n++ {
		lines[n] = true
	}
}

// addIncludes records the line of each #include directive and the lines of
// each string literal of a C or C++ graph, which a finding on a directive or
// a literal reports.
func (s *fragmentSourceLines) addIncludes() {
	if s.ctx == nil || s.ctx.graph == nil {
		return
	}
	for path, includes := range s.ctx.graph.CIncludes {
		for _, inc := range includes {
			if inc.Line > 0 {
				s.addFile(path, inc.Line, inc.Line)
			}
		}
	}
	for path, literals := range s.ctx.graph.CStrings {
		for _, l := range literals {
			if l.Line > 0 {
				s.addFile(path, l.Line, l.EndLine)
			}
		}
	}
}

func (s *fragmentSourceLines) addInternal(edge graphfrag.GraphFragmentEdge) {
	s.add(edge.CallerKey, edge.Line, edge.EndLine)
}

func (s *fragmentSourceLines) addExternal(call *graphfrag.GraphFragmentExternal) {
	s.add(call.CallerKey, call.Line, call.EndLine)
}

// text reads the recorded lines from the source files, keyed by exported
// path. A file that cannot be read contributes nothing.
func (s *fragmentSourceLines) text() map[string]map[int]string {
	if len(s.lines) == 0 {
		return nil
	}
	out := make(map[string]map[int]string, len(s.lines))
	for actual, wanted := range s.lines {
		data, err := os.ReadFile(actual) // #nosec G304 -- a source file the call graph parsed.
		if err != nil {
			continue
		}
		fileLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		text := make(map[int]string, len(wanted))
		for n := range wanted {
			if n >= 1 && n <= len(fileLines) {
				text[n] = fileLines[n-1]
			}
		}
		if deadcode.IsCFile(actual) {
			// The conditionals of the file's #if 0 blocks, from which
			// annotate finds the blocks whose findings a scan drops.
			maps.Copy(text, deadcode.RegionDirectives(fileLines))
		}
		if len(text) > 0 {
			out[s.paths[actual]] = text
		}
	}
	return out
}

// graphFragmentSourceLines is the source_lines of a fragment built in memory:
// the lines of its call sites, constant references, declarations, casts,
// attribute stores and #include directives, as the streamed export writes.
func graphFragmentSourceLines(ctx *exportBuildContext, out *graphfrag.GraphFragmentExport) map[string]map[int]string {
	lines := newFragmentSourceLines(ctx)
	lines.addIncludes()
	for i := range out.InternalEdges {
		lines.addInternal(out.InternalEdges[i])
	}
	for i := range out.ExternalCalls {
		lines.addExternal(&out.ExternalCalls[i])
	}
	add := func(function, line, endLine int) { lines.add(out.Functions[function].Key, line, endLine) }
	for _, r := range out.ConstantRefs {
		add(r.Function, r.Line, r.EndLine)
	}
	for _, d := range out.Declarations {
		add(d.Function, d.Line, d.EndLine)
	}
	for _, c := range out.Casts {
		add(c.Function, c.Line, c.EndLine)
	}
	for _, st := range out.AttributeStores {
		add(st.Function, st.Line, st.EndLine)
	}
	return lines.text()
}
