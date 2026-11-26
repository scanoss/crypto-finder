// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"cmp"
	"slices"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// buildGraphFragmentImports is the graph's import bindings by file path
// relative to the component root, as functions name their files: Python's,
// Node's with the form of each, Rust's with the declaration's span and use
// tree (graph-fragment-1.26), Go's import specs with their alias and span
// (graph-fragment-1.32), or C's and C++'s #include directives, the header as
// module, with the directive's text and span (graph-algo-c-1,
// graph-algo-cpp-1). A graph holds one ecosystem, so at most one of the maps
// is set.
func buildGraphFragmentImports(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentImport {
	out := make(map[string][]graphfrag.GraphFragmentImport,
		len(ctx.graph.PythonImports)+len(ctx.graph.NodeImports)+len(ctx.graph.RustImports)+len(ctx.graph.GoImports)+len(ctx.graph.CIncludes)+len(ctx.graph.CSharpUsings))
	addGraphFragmentImports(ctx, out, ctx.graph.PythonImports, func(imp callgraph.PythonImport) graphfrag.GraphFragmentImport {
		return graphfrag.GraphFragmentImport{Line: imp.Line, Module: imp.Module, Name: imp.Name, Alias: imp.Alias, Local: imp.Local}
	})
	addGraphFragmentImports(ctx, out, ctx.graph.NodeImports, func(imp callgraph.NodeImport) graphfrag.GraphFragmentImport {
		return graphfrag.GraphFragmentImport{Line: imp.Line, Module: imp.Module, Name: imp.Name, Alias: imp.Alias, Kind: imp.Kind, Local: imp.Local}
	})
	addGraphFragmentImports(ctx, out, ctx.graph.GoImports, func(imp callgraph.GoImport) graphfrag.GraphFragmentImport {
		return graphfrag.GraphFragmentImport{
			Line: imp.Line, Module: imp.Path, Alias: imp.Alias,
			StartCol: imp.StartCol, EndCol: imp.EndCol, EndLine: imp.EndLine,
		}
	})
	addGraphFragmentImports(ctx, out, ctx.graph.RustImports, func(imp callgraph.RustImport) graphfrag.GraphFragmentImport {
		return graphfrag.GraphFragmentImport{
			Line: imp.Line, Module: imp.Module, Name: imp.Name, Alias: imp.Alias, Local: imp.Local,
			StartCol: imp.StartCol, EndCol: imp.EndCol, EndLine: imp.EndLine, Text: imp.Text,
		}
	})
	addGraphFragmentImports(ctx, out, ctx.graph.CSharpUsings, func(using callgraph.CSharpUsing) graphfrag.GraphFragmentImport {
		kind := using.Kind
		if using.Global {
			kind = "global-" + kind
		}
		return graphfrag.GraphFragmentImport{
			Line: using.Line, Module: using.Namespace, Alias: using.Alias, Kind: kind,
			StartCol: using.StartCol, EndCol: using.EndCol, EndLine: using.EndLine, Text: using.Text,
		}
	})
	addGraphFragmentImports(ctx, out, ctx.graph.CIncludes, func(inc callgraph.CInclude) graphfrag.GraphFragmentImport {
		return graphfrag.GraphFragmentImport{
			Line: inc.Line, Module: inc.Header, StartCol: inc.StartCol, EndCol: inc.EndCol, EndLine: inc.Line, Text: inc.Text,
			Local: inc.InFunction,
		}
	})
	return out
}

// addGraphFragmentImports converts one ecosystem's imports by file into out,
// keyed by file path relative to the component root.
func addGraphFragmentImports[T any](ctx *exportBuildContext, out map[string][]graphfrag.GraphFragmentImport, byFile map[string][]T, convert func(T) graphfrag.GraphFragmentImport) {
	for path, imports := range byFile {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentImport, len(imports))
		for i, imp := range imports {
			entries[i] = convert(imp)
		}
		out[file] = entries
	}
}

// buildGraphFragmentItems is the items each Rust file declares by file path
// relative to the component root (graph-fragment-1.26), a type alias with its
// aliased type and the column of its `type` keyword (graph-fragment-1.27), a
// fn with its parameters as written (graph-fragment-1.30).
func buildGraphFragmentItems(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentItem {
	out := make(map[string][]graphfrag.GraphFragmentItem, len(ctx.graph.RustItems))
	for path, items := range ctx.graph.RustItems {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentItem, len(items))
		for i, it := range items {
			entries[i] = graphfrag.GraphFragmentItem{
				Line: it.Line, StartCol: it.StartCol, EndCol: it.EndCol, EndLine: it.EndLine, Kind: it.Kind, Name: it.Name,
				Type: it.Type, KeywordCol: it.KeywordCol, Params: buildGraphFragmentParams(it.Params),
			}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentParams is a Rust fn item's parameters as written, nil
// for a fn without any.
func buildGraphFragmentParams(params []callgraph.RustParam) []graphfrag.GraphFragmentParam {
	if len(params) == 0 {
		return nil
	}
	out := make([]graphfrag.GraphFragmentParam, len(params))
	for i, p := range params {
		out[i] = graphfrag.GraphFragmentParam{
			Line: p.Line, StartCol: p.StartCol, EndCol: p.EndCol, EndLine: p.EndLine,
			Pattern: p.Pattern, Type: p.Type, Self: p.Self,
		}
	}
	return out
}

// buildGraphFragmentBinaryExprs is the binary expressions of each Rust
// file's function bodies by file path relative to the component root, with
// the key of the function that holds each (graph-fragment-1.30).
func buildGraphFragmentBinaryExprs(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentBinaryExpr {
	out := make(map[string][]graphfrag.GraphFragmentBinaryExpr, len(ctx.graph.RustBinaryExprs))
	for path, exprs := range ctx.graph.RustBinaryExprs {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentBinaryExpr, len(exprs))
		for i, e := range exprs {
			entries[i] = graphfrag.GraphFragmentBinaryExpr{
				Line: e.Line, StartCol: e.StartCol, EndCol: e.EndCol, EndLine: e.EndLine,
				Op: e.Op, Left: e.Left, Right: e.Right,
				LeftEndCol: e.LeftEndCol, LeftEndLine: e.LeftEndLine, RightStartCol: e.RightStartCol, RightLine: e.RightLine,
				Function: e.Function,
			}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentObjectLiterals is the graph's Node object literals by
// file path relative to the component root, as functions name their files.
// EndLine is left out (0) when the literal ends on its first line.
func buildGraphFragmentObjectLiterals(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentObjectLiteral {
	out := make(map[string][]graphfrag.GraphFragmentObjectLiteral, len(ctx.graph.NodeObjectLiterals))
	for path, objects := range ctx.graph.NodeObjectLiterals {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentObjectLiteral, len(objects))
		for i, o := range objects {
			endLine := o.EndLine
			if endLine == o.Line {
				endLine = 0
			}
			entries[i] = graphfrag.GraphFragmentObjectLiteral{
				Line: o.Line, StartCol: o.StartCol, EndLine: endLine, EndCol: o.EndCol, Text: o.Text, CallerKey: o.CallerKey,
				AssignedVar: o.AssignedVar, AssignStartCol: o.AssignStartCol, AssignLine: o.AssignLine,
			}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentPropertyReads is the graph's Node property reads by file
// path relative to the component root, as functions name their files.
func buildGraphFragmentPropertyReads(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentPropertyRead {
	out := make(map[string][]graphfrag.GraphFragmentPropertyRead, len(ctx.graph.NodePropertyReads))
	for path, reads := range ctx.graph.NodePropertyReads {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentPropertyRead, len(reads))
		for i, r := range reads {
			entries[i] = graphfrag.GraphFragmentPropertyRead{
				CallerKey: r.CallerKey, TargetKey: r.TargetKey, MethodName: r.MethodName, Raw: r.Raw,
				Line: r.Line, StartCol: r.StartCol, EndLine: r.EndLine, EndCol: r.EndCol,
				ReceiverVar: r.ReceiverVar, AssignedVar: r.AssignedVar, CandidateModules: r.CandidateModules,
			}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentStrings is a C or C++ graph's string literals by file
// path relative to the component root, as functions name their files
// (graph-algo-c-1, graph-algo-cpp-1).
func buildGraphFragmentStrings(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentString {
	out := make(map[string][]graphfrag.GraphFragmentString, len(ctx.graph.CStrings))
	for path, literals := range ctx.graph.CStrings {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentString, len(literals))
		for i, l := range literals {
			entries[i] = graphfrag.GraphFragmentString{Line: l.Line, StartCol: l.StartCol, EndCol: l.EndCol, EndLine: l.EndLine, Text: l.Text}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentAttributeStores lists the attribute stores of every
// exported function, in function index order, then line and column.
func buildGraphFragmentAttributeStores(ctx *exportBuildContext, functionIndex map[string]int) []graphfrag.GraphFragmentAttributeStore {
	if ctx == nil || ctx.graph == nil {
		return nil
	}
	var out []graphfrag.GraphFragmentAttributeStore
	for _, key := range sortedKeys(ctx.graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		fn := ctx.graph.Functions[key]
		for _, store := range fn.AttributeStores {
			out = append(out, graphfrag.GraphFragmentAttributeStore{
				Function: index, Line: store.Line, StartCol: store.StartCol, EndCol: store.EndCol, EndLine: store.EndLine,
				Receiver: store.Receiver, Attribute: store.Attribute, Operator: store.Operator,
				Value: exportTracedValue(ctx, fn, store.Value, store.Line),
			})
		}
	}
	slices.SortStableFunc(out, func(a, b graphfrag.GraphFragmentAttributeStore) int {
		return cmp.Or(cmp.Compare(a.Function, b.Function), cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return out
}

// buildGraphFragmentLocalBindings lists the local bindings of every exported
// function, in function index order, then line and column.
func buildGraphFragmentLocalBindings(ctx *exportBuildContext, functionIndex map[string]int) []graphfrag.GraphFragmentLocalBinding {
	if ctx == nil || ctx.graph == nil {
		return nil
	}
	var out []graphfrag.GraphFragmentLocalBinding
	for _, key := range sortedKeys(ctx.graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		for _, b := range ctx.graph.Functions[key].LocalBindings {
			out = append(out, graphfrag.GraphFragmentLocalBinding{
				Function: index, Name: b.Name, Line: b.Line, Col: b.Col, EffectLine: b.EffectLine, EffectCol: b.EffectCol,
				BlockEndLine: b.BlockEndLine, BlockEndCol: b.BlockEndCol, LoopLine: b.LoopLine, LoopCol: b.LoopCol,
				Unpacked: b.Unpacked, Element: b.Element, ValueLine: b.ValueLine, ValueCol: b.ValueCol,
			})
		}
	}
	return out
}

// buildGraphFragmentGoValues is the composite literals, new(T) expressions
// and field stores of each Go file by file path relative to the component
// root (graph-fragment-1.34), and its assignments (kind assign, 1.36).
func buildGraphFragmentGoValues(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentGoValue {
	out := make(map[string][]graphfrag.GraphFragmentGoValue, len(ctx.graph.GoValues))
	for path, values := range ctx.graph.GoValues {
		file := normalizeExportPath(ctx, path).FilePath
		entries := make([]graphfrag.GraphFragmentGoValue, len(values))
		for i, v := range values {
			fields := make([]graphfrag.GraphFragmentGoValueField, len(v.Fields))
			for j, f := range v.Fields {
				fields[j] = graphfrag.GraphFragmentGoValueField{
					Name: f.Name, Value: f.Value, Line: f.Line, StartCol: f.StartCol, EndCol: f.EndCol, EndLine: f.EndLine,
				}
			}
			if len(fields) == 0 {
				fields = nil
			}
			entries[i] = graphfrag.GraphFragmentGoValue{
				Kind: v.Kind, Line: v.Line, StartCol: v.StartCol, EndCol: v.EndCol, EndLine: v.EndLine, AddrCol: v.AddrCol,
				TypeText: v.TypeText, Package: v.Package, Type: v.Type, Receiver: v.Receiver, Fields: fields,
				Names: v.Names, Op: v.Op, Value: v.Value, Function: v.Function,
			}
		}
		out[file] = entries
	}
	return out
}

// buildGraphFragmentGoBlocks is the blocks of each Go file's function
// bodies, case clauses included, by file path relative to the component
// root (graph-fragment-1.36).
func buildGraphFragmentGoBlocks(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentGoBlock {
	out := make(map[string][]graphfrag.GraphFragmentGoBlock, len(ctx.graph.GoBlocks))
	for path, blocks := range ctx.graph.GoBlocks {
		entries := make([]graphfrag.GraphFragmentGoBlock, len(blocks))
		for i, b := range blocks {
			entries[i] = graphfrag.GraphFragmentGoBlock{
				StartLine: b.StartLine, StartCol: b.StartCol, EndLine: b.EndLine, EndCol: b.EndCol, Function: b.Function,
			}
		}
		out[normalizeExportPath(ctx, path).FilePath] = entries
	}
	return out
}
