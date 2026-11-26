// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// A call that dispatches to several implementations is one edge per target
// in a fragment. The rebuilt graph holds the call once, with its exact
// target, as the parser recorded it; the caller index keeps every target.
func TestFragmentScanResultHoldsEachCallOnce(t *testing.T) {
	root := t.TempDir()
	doc := &graphfrag.GraphFragmentExport{
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{Ecosystem: "java", RootModule: "app"},
		Functions: []graphfrag.GraphFragmentFunction{
			{Key: "app.(A).run#0", FilePath: "app/A.java", StartLine: 3, EndLine: 9},
			{Key: "app.(Codec).encode#1", FilePath: "app/Codec.java", StartLine: 2, EndLine: 2},
			{Key: "app.(Hex).encode#1", FilePath: "app/Hex.java", StartLine: 5, EndLine: 7},
		},
		InternalEdges: []graphfrag.GraphFragmentEdge{
			{CallerKey: "app.(A).run#0", CalleeKey: "app.(Hex).encode#1", Line: 5, StartCol: 9, EndCol: 25, Resolution: "interface_dispatch", MethodName: "encode", Arity: 1},
			{CallerKey: "app.(A).run#0", CalleeKey: "app.(Codec).encode#1", Line: 5, StartCol: 9, EndCol: 25, Resolution: "exact", MethodName: "encode", Arity: 1},
		},
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			{CallerKey: "app.(A).run#0", TargetKey: "javax.crypto.(Cipher).getInstance#1", Raw: "Cipher.getInstance", Line: 4, StartCol: 20, EndCol: 52, Resolution: "exact", MethodName: "getInstance", Arity: 1},
		},
	}
	result := FragmentScanResult(doc, root, nil)
	if result.Ecosystem != "java" || result.RootModule != "app" || result.ProjectRoot != root {
		t.Errorf("result = %q %q %q, want the fragment's ecosystem and module under the root", result.Ecosystem, result.RootModule, result.ProjectRoot)
	}
	run := result.CallGraph.Functions["app.(A).run#0"]
	if run == nil || run.FilePath != filepath.Join(root, "app", "A.java") || run.StartLine != 3 || run.EndLine != 9 {
		t.Fatalf("run = %+v, want its file under the root and its lines", run)
	}
	callees := make([]string, 0, len(run.Calls))
	for _, call := range run.Calls {
		callees = append(callees, call.Callee.String())
		if call.FilePath != run.FilePath || len(call.Arguments) != 1 {
			t.Errorf("call %s: file %q, %d arguments; want the caller's file and one argument", call.Callee, call.FilePath, len(call.Arguments))
		}
	}
	if want := []string{"javax.crypto.(Cipher).getInstance#1", "app.(Codec).encode#1"}; !reflect.DeepEqual(callees, want) {
		t.Errorf("calls = %v, want %v: each call once, by line, with its exact target", callees, want)
	}
	for _, callee := range []string{"app.(Codec).encode#1", "app.(Hex).encode#1", "javax.crypto.(Cipher).getInstance#1"} {
		if got := result.CallGraph.Callers[callee]; !reflect.DeepEqual(got, []string{"app.(A).run#0"}) {
			t.Errorf("callers of %s = %v, want run", callee, got)
		}
	}
}

// A call's arguments and their provenance come from its call-site record.
// A parameter the function's own calls pass names that parameter, which a
// fragment lists by type only; the callers' values the export nested under
// a parameter are dropped, since the passes resolve a parameter themselves.
func TestFragmentScanResultRestoresArgumentsAndParameterNames(t *testing.T) {
	root := t.TempDir()
	parameter := graphfrag.GraphFragmentSourceNode{
		Type: "PARAMETER", Name: "algorithm", DeclaredType: "String", ParameterIndex: intPointer(0),
		Location:    &graphfrag.GraphFragmentSourceLoc{FilePath: "app/A.java", Line: 4},
		SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "LITERAL", Value: `"SHA-256"`}},
	}
	call := graphfrag.GraphFragmentSourceNode{
		Type: "CALL_RESULT", CallTarget: "app.(A).name#0",
		SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "LITERAL", Value: `"AES"`}},
	}
	doc := &graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{
			{Key: "app.(A).digest#2", FilePath: "app/A.java", StartLine: 4, EndLine: 8, ParameterTypes: []string{"String", "byte[]"}},
		},
		ExternalCalls: []graphfrag.GraphFragmentExternal{{
			CallerKey: "app.(A).digest#2", TargetKey: "java.security.(MessageDigest).getInstance#2", Line: 5, StartCol: 28, EndCol: 70,
			Resolution: "exact", MethodName: "getInstance", Arity: 2,
			EntryCall: &graphfrag.GraphFragmentCallSite{Line: 5, Parameters: []graphfrag.GraphFragmentParameter{
				{ParameterIndex: 0, ArgumentExpression: "algorithm", SourceNodes: []graphfrag.GraphFragmentSourceNode{parameter}},
				{ParameterIndex: 1, ArgumentExpression: "name()", SourceNodes: []graphfrag.GraphFragmentSourceNode{call}},
			}},
		}},
	}
	digest := FragmentScanResult(doc, root, nil).CallGraph.Functions["app.(A).digest#2"]
	if got := []string{digest.Parameters[0].Name, digest.Parameters[1].Name}; !reflect.DeepEqual(got, []string{"algorithm", ""}) {
		t.Errorf("parameter names = %q, want the passed parameter named and the other unnamed", got)
	}
	if got := []string{digest.Parameters[0].Type, digest.Parameters[1].Type}; !reflect.DeepEqual(got, []string{"String", "byte[]"}) {
		t.Errorf("parameter types = %q", got)
	}
	got := digest.Calls[0]
	if !reflect.DeepEqual(got.Arguments, []string{"algorithm", "name()"}) {
		t.Errorf("arguments = %q", got.Arguments)
	}
	nameID := callgraph.FunctionID{Package: "app", Type: "A", Name: "name#0"}
	want := [][]callgraph.SourceNode{
		{{Type: "PARAMETER", Name: "algorithm", DeclaredType: "String", ParameterIndex: 0, Location: &callgraph.SourceLocation{FilePath: filepath.Join(root, "app", "A.java"), Line: 4}}},
		{{Type: "CALL_RESULT", CallTarget: &nameID, SourceNodes: []callgraph.SourceNode{{Type: "LITERAL", Value: `"AES"`}}}},
	}
	if !reflect.DeepEqual(got.ArgumentSources, want) {
		t.Errorf("argument sources = %+v, want %+v", got.ArgumentSources, want)
	}
}

// Two calls that trace one parameter index to different names leave it
// unnamed rather than pick one.
func TestFragmentScanResultLeavesAConflictingParameterUnnamed(t *testing.T) {
	site := func(line int, name string) graphfrag.GraphFragmentExternal {
		return graphfrag.GraphFragmentExternal{
			CallerKey: "app.(A).f#1", TargetKey: "app.(Log).write#1", Line: line, StartCol: 9, EndCol: 20, Resolution: "exact", MethodName: "write", Arity: 1,
			EntryCall: &graphfrag.GraphFragmentCallSite{Parameters: []graphfrag.GraphFragmentParameter{{
				ParameterIndex: 0, ArgumentExpression: name,
				SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "PARAMETER", Name: name, ParameterIndex: intPointer(0)}},
			}}},
		}
	}
	doc := &graphfrag.GraphFragmentExport{
		Functions:     []graphfrag.GraphFragmentFunction{{Key: "app.(A).f#1", FilePath: "app/A.java", StartLine: 1, EndLine: 5, ParameterTypes: []string{"String"}}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{site(2, "a"), site(3, "b")},
	}
	if got := FragmentScanResult(doc, t.TempDir(), nil).CallGraph.Functions["app.(A).f#1"].Parameters[0].Name; got != "" {
		t.Errorf("parameter name = %q, want none", got)
	}
}

// Each edge of a fragment is one resolution of the rebuilt graph, of its
// kind and at its site, as the parsed graph recorded it: tracing a finding
// back to its entry points reads them.
func TestFragmentScanResultRecordsEachEdgesResolution(t *testing.T) {
	doc := &graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{
			{Key: "app.(A).f#0", FilePath: "app/A.java", StartLine: 1, EndLine: 4},
			{Key: "app.(Impl).run#0", FilePath: "app/Impl.java", StartLine: 1, EndLine: 3},
		},
		InternalEdges: []graphfrag.GraphFragmentEdge{{
			CallerKey: "app.(A).f#0", CalleeKey: "app.(Impl).run#0", Line: 2, StartCol: 5, EndCol: 12,
			Resolution: "interface_dispatch", DeclaredType: "app.Runner", MethodName: "run",
		}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{{
			CallerKey: "app.(A).f#0", TargetKey: "java.lang.(Math).max#2", Line: 3, StartCol: 9, EndCol: 20,
			Resolution: "exact", MethodName: "max", Arity: 2, ResolvedReceiverType: "java.lang.Math",
		}},
	}
	graph := FragmentScanResult(doc, t.TempDir(), nil).CallGraph
	got := make([]string, 0, len(graph.EdgeResolutions))
	for key, res := range graph.EdgeResolutions {
		caller, callee, _ := callgraph.EdgeResolutionEndpoints(key, res)
		got = append(got, fmt.Sprintf("%s->%s %s %s %s/%d %d:%d-%d %s", caller, callee, res.Kind, res.DeclaredType, res.MethodName, res.Arity,
			res.CallSite, res.StartCol, res.EndCol, res.ResolvedReceiverType))
	}
	sort.Strings(got)
	want := []string{
		"app.(A).f#0->app.(Impl).run#0 interface_dispatch app.Runner run/0 2:5-12 ",
		"app.(A).f#0->java.lang.(Math).max#2 exact  max/2 3:9-20 java.lang.Math",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolutions = %q, want %q", got, want)
	}
}

// A 1.21 fragment names every parameter, also one no call of the function
// passes on: the export reads the name to tell a caller's argument from
// another parameter's.
func TestFragmentScanResultNamesParametersAsTheFragmentDoes(t *testing.T) {
	doc := &graphfrag.GraphFragmentExport{Functions: []graphfrag.GraphFragmentFunction{
		{Key: "app.(A).f#2", FilePath: "app/A.java", StartLine: 1, EndLine: 3, ParameterTypes: []string{"String", "int"}, ParameterNames: []string{"name", "size"}},
	}}
	decl := FragmentScanResult(doc, t.TempDir(), nil).CallGraph.Functions["app.(A).f#2"]
	if got := []string{decl.Parameters[0].Name, decl.Parameters[1].Name}; !reflect.DeepEqual(got, []string{"name", "size"}) {
		t.Errorf("parameter names = %q, want the fragment's", got)
	}
}

// The public paths of a Python graph (the names a package's __init__.py
// imports) go into the fragment and come back in the rebuilt graph, where
// entry-point synthesis keys a rule's api on them.
func TestFragmentScanResultRestoresPythonPublicPaths(t *testing.T) {
	paths := map[string]string{"sealer.Box": "sealer.box.Box", "sealer.new_nonce": "sealer.box.new_nonce"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			"sealer.box.new_nonce#0": {ID: callgraph.FunctionID{Package: "sealer.box", Name: "new_nonce"}, FilePath: "sealer/box.py", StartLine: 1, EndLine: 2},
		},
		Callers:           map[string][]string{},
		PythonPublicPaths: paths,
	}
	doc := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "python"}, &oid.ResolvedReport{})
	if !reflect.DeepEqual(doc.PublicPaths, paths) {
		t.Fatalf("export public_paths = %v, want %v", doc.PublicPaths, paths)
	}
	if got := FragmentScanResult(&doc, t.TempDir(), nil).CallGraph.PythonPublicPaths; !reflect.DeepEqual(got, paths) {
		t.Errorf("rebuilt PythonPublicPaths = %v, want %v", got, paths)
	}
}
