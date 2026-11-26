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

package scan

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// The graph-fragment 1.21 sections that hold what a scan's crypto export
// reads from its call graph beyond the edges: the parser's calls, return
// provenance and external signatures. FragmentScanResult reads them back.

// fragmentCarriesCalls reports a fragment that holds them: a Java, Python,
// Go, Node, C, C++, Rust, Ruby or C# one, the languages the cards scanner
// re-annotates. Another language's fragment leaves them out
// (graph-fragment-1.22) and annotate rebuilds its calls from the edges, which
// hold no call the graph records no edge for (a Node chain's `.digest()` that
// resolves to the module's own digest function) and not the call's text (a C
// supporting call's callee as written, and the linkage restoreCCallLinkage
// reads from it; a C++ call the graph resolved to a project function, whose
// internal edge holds no text, and the callee the parser gave a call that is
// also a construction).
func fragmentCarriesCalls(ctx *exportBuildContext) bool {
	return ctx != nil && (ctx.ecosystem == ecosystemJava || ctx.ecosystem == ecosystemPython || ctx.ecosystem == ecosystemGo || ctx.ecosystem == ecosystemNode || ctx.ecosystem == ecosystemC ||
		ctx.ecosystem == ecosystemCPP || ctx.ecosystem == ecosystemRust || ctx.ecosystem == ecosystemRuby || ctx.ecosystem == ecosystemCSharp)
}

// fragmentRawSources projects provenance as the parser traced it, with file
// paths relative to the component root.
func fragmentRawSources(ctx *exportBuildContext, nodes []callgraph.SourceNode) []graphfrag.GraphFragmentRawSource {
	if nodes == nil {
		return nil
	}
	out := make([]graphfrag.GraphFragmentRawSource, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		raw := graphfrag.GraphFragmentRawSource{
			Type: node.Type, Name: node.Name, DeclaredType: node.DeclaredType, Value: node.Value,
			ParameterIndex: node.ParameterIndex, SourceNodes: fragmentRawSources(ctx, node.SourceNodes),
			MayValues: node.MayValues, MayValuesExhaustive: node.MayValuesExhaustive,
		}
		if node.CallTarget != nil {
			raw.CallTarget = node.CallTarget.String()
		}
		if node.Location != nil {
			raw.Location = &graphfrag.GraphFragmentSourceLoc{Line: node.Location.Line}
			if node.Location.FilePath != "" {
				raw.Location.FilePath = normalizeExportPath(ctx, node.Location.FilePath).FilePath
			}
		}
		if flow := node.Flow; flow != nil {
			raw.ReturnValue, raw.CallArgument = flow.ReturnValue, flow.CallArgument
			if flow.Guard != nil {
				raw.Guard = &graphfrag.GraphFragmentRawGuard{ParameterIndex: flow.Guard.ParameterIndex, Value: flow.Guard.Value, Default: flow.Guard.Default}
			}
		}
		out[i] = raw
	}
	return out
}

// callgraphRawSources restores provenance fragmentRawSources projected, with
// file paths rooted at root.
func callgraphRawSources(root string, nodes []graphfrag.GraphFragmentRawSource) []callgraph.SourceNode {
	if nodes == nil {
		return nil
	}
	out := make([]callgraph.SourceNode, len(nodes))
	for i := range nodes {
		raw := &nodes[i]
		node := callgraph.SourceNode{
			Type: raw.Type, Name: raw.Name, DeclaredType: raw.DeclaredType, Value: raw.Value,
			ParameterIndex: raw.ParameterIndex, SourceNodes: callgraphRawSources(root, raw.SourceNodes),
			MayValues: raw.MayValues, MayValuesExhaustive: raw.MayValuesExhaustive,
		}
		if raw.CallTarget != "" {
			if target, err := callgraph.ParseFunctionID(raw.CallTarget); err == nil {
				node.CallTarget = &target
			}
		}
		if raw.Location != nil {
			node.Location = &callgraph.SourceLocation{Line: raw.Location.Line}
			if raw.Location.FilePath != "" {
				node.Location.FilePath = filepath.Join(root, filepath.FromSlash(raw.Location.FilePath))
			}
		}
		if raw.ReturnValue || raw.CallArgument || raw.Guard != nil {
			node.Flow = &callgraph.SourceFlow{ReturnValue: raw.ReturnValue, CallArgument: raw.CallArgument}
			if g := raw.Guard; g != nil {
				node.Flow.Guard = &callgraph.SourceGuard{ParameterIndex: g.ParameterIndex, Value: g.Value, Default: g.Default}
			}
		}
		out[i] = node
	}
	return out
}

// fragmentArgumentSources projects a call's argument provenance, one slot
// per argument.
func fragmentArgumentSources(ctx *exportBuildContext, sources [][]callgraph.SourceNode) [][]graphfrag.GraphFragmentRawSource {
	if sources == nil {
		return nil
	}
	out := make([][]graphfrag.GraphFragmentRawSource, len(sources))
	for i := range sources {
		out[i] = fragmentRawSources(ctx, sources[i])
	}
	return out
}

func callgraphArgumentSources(root string, sources [][]graphfrag.GraphFragmentRawSource) [][]callgraph.SourceNode {
	if sources == nil {
		return nil
	}
	out := make([][]callgraph.SourceNode, len(sources))
	for i := range sources {
		out[i] = callgraphRawSources(root, sources[i])
	}
	return out
}

// buildGraphFragmentExternalSignatures lists the external signatures the
// graph holds for the targets of its calls and for its own functions, the
// ones an export of the graph reads.
func buildGraphFragmentExternalSignatures(ctx *exportBuildContext) map[string][]graphfrag.GraphFragmentExternalSignature {
	if !fragmentCarriesCalls(ctx) || ctx.graph == nil || len(ctx.graph.ExternalMethodSignatures) == 0 {
		return nil
	}
	out := make(map[string][]graphfrag.GraphFragmentExternalSignature)
	add := func(id callgraph.FunctionID) {
		key := callgraph.ExternalMethodSignatureKey(id)
		if _, done := out[key]; done {
			return
		}
		signatures := ctx.graph.ExternalMethodSignatures[key]
		if len(signatures) == 0 {
			return
		}
		list := make([]graphfrag.GraphFragmentExternalSignature, len(signatures))
		for i := range signatures {
			list[i] = graphfrag.GraphFragmentExternalSignature{
				ParameterTypes: append([]string{}, signatures[i].ParameterTypes...),
				ReturnType:     signatures[i].ReturnType,
			}
		}
		out[key] = list
	}
	for _, decl := range ctx.graph.Functions {
		add(decl.ID)
		for i := range decl.Calls {
			add(decl.Calls[i].Callee)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// callgraphExternalSignatures restores the signatures
// buildGraphFragmentExternalSignatures listed.
func callgraphExternalSignatures(signatures map[string][]graphfrag.GraphFragmentExternalSignature) map[string][]callgraph.ExternalMethodSignature {
	if len(signatures) == 0 {
		return nil
	}
	out := make(map[string][]callgraph.ExternalMethodSignature, len(signatures))
	for key, list := range signatures {
		restored := make([]callgraph.ExternalMethodSignature, len(list))
		for i := range list {
			restored[i] = callgraph.ExternalMethodSignature{ParameterTypes: list[i].ParameterTypes, ReturnType: list[i].ReturnType}
		}
		out[key] = restored
	}
	return out
}

// fragmentParameterNames lists a function's parameter names, none when it
// has no named parameter.
func fragmentParameterNames(parameters []callgraph.FunctionParameter) []string {
	names := make([]string, len(parameters))
	named := false
	for i := range parameters {
		names[i] = parameters[i].Name
		named = named || names[i] != ""
	}
	if !named {
		return nil
	}
	return names
}

// restoreCCallLinkage gives each call of a C graph rebuilt from its fragment
// the linkage the C parser gave its callee, which the callee key does not
// spell: the contracts match a call of an externally linked function by its
// bare name (contracts.ContractsForCFunction), so a call that lost it loses
// the category and parameter roles its supporting call carries. The parser
// names a direct call's callee by the identifier written (the call's text):
// a function of the caller's own file when the file declares it static, its
// key's package then ending in the file's name, and an externally linked one
// otherwise. A call through a struct field (`hash->init(ctx)`) has none.
func restoreCCallLinkage(graph *callgraph.CallGraph) {
	for _, decl := range graph.Functions {
		file := filepath.Base(decl.FilePath)
		for i := range decl.Calls {
			call := &decl.Calls[i]
			if !cIdentifier(call.Raw) {
				continue
			}
			call.Callee.Linkage = callgraph.LinkageExternal
			if call.Callee.Package == file || strings.HasSuffix(call.Callee.Package, "/"+file) {
				call.Callee.Linkage = callgraph.LinkageInternal
			}
		}
	}
}

// cIdentifier reports text that is a C identifier.
func cIdentifier(text string) bool {
	for i, r := range text {
		if r != '_' && !unicode.IsLetter(r) && (i == 0 || !unicode.IsDigit(r)) {
			return false
		}
	}
	return text != ""
}

// restoreCPPCallLinkage marks internal, as the C++ graph builder does
// (callgraph's markCPPProjectLocalCalls), each call and return source of a C++
// graph rebuilt from its fragment whose callee is a member of a type the
// project declares, or a method the project defines. The contracts then leave
// such a call to the project's own definition: a type the KB describes and
// the scanned project declares (Qt's QCryptographicHash in qtbase) is the
// project's type, so its supporting call takes no KB category or parameter
// roles (contractMatchesForCall). The callee key does not spell the linkage
// and the fragment does not list the declared types, so a type is read as
// declared when a function of the fragment is one of its members, the types
// a crypto KB describes and a project declares define their methods.
func restoreCPPCallLinkage(graph *callgraph.CallGraph) {
	types := make(map[string]bool)
	methods := make(map[string]bool)
	for _, decl := range graph.Functions {
		if decl.ID.Type == "" {
			continue
		}
		types[decl.ID.Type] = true
		methods[decl.ID.Type+"."+callgraph.BaseFunctionName(decl.ID.Name)] = true
	}
	mark := func(target *callgraph.FunctionID) {
		if target == nil || target.Type == "" {
			return
		}
		name := callgraph.BaseFunctionName(target.Name)
		if types[target.Type] || types[target.Type+"::"+name] || methods[target.Type+"."+name] {
			target.Linkage = callgraph.LinkageInternal
		}
	}
	for _, decl := range graph.Functions {
		for i := range decl.Calls {
			mark(&decl.Calls[i].Callee)
		}
		for i := range decl.ReturnSources {
			mark(decl.ReturnSources[i].CallTarget)
		}
	}
}
