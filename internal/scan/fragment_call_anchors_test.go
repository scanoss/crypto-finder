// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

const callAnchorsSource = `package app;
import javax.crypto.Cipher;
public class Box {
    byte[] seal(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        return c.doFinal(data);
    }

    int size(byte[] data) throws Exception {
        return Cipher.getInstance("AES").getBlockSize() + Integer.bitCount(data.length);
    }
}
`

// A fragment records, for every call, the syntax node the scan keys an
// asset's occurrence by and the chain the call is a link of, in the order
// the parser recorded the calls, in memory and written out alike.
func TestGraphFragmentCarriesCallAnchors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Box.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(callAnchorsSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}

	inMemory := buildGraphFragmentExport(result)
	prepared, err := oid.NewDefaultResolver().PrepareReport(&entities.InterimReport{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := BuildGraphFragmentExport(result, prepared.ReportClone())
	file := filepath.Join(t.TempDir(), "fragment.json")
	if err := writeGraphFragmentJSONFile(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var streamed graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &streamed); err != nil {
		t.Fatal(err)
	}
	streamed.RestoreElided()
	// In the parser's order, the outer link of a chain first; the call that
	// only sits on the chain's line is no link of it.
	want := []string{
		"app.Box.seal 5:20-45 method_invocation block[4]/local_variable_declaration[0]/variable_declarator[1]/method_invocation[1] chain=false",
		"app.Box.seal 6:16-31 method_invocation block[4]/return_statement[1]/method_invocation[0] chain=false",
		"app.Box.size 10:16-56 method_invocation block[4]/return_statement[0]/binary_expression[0]/method_invocation[0] chain=true",
		"app.Box.size 10:16-41 method_invocation block[4]/return_statement[0]/binary_expression[0]/method_invocation[0]/method_invocation[0] chain=true",
		"app.Box.size 10:59-88 method_invocation block[4]/return_statement[0]/binary_expression[0]/method_invocation[1] chain=false",
	}
	for name, fragment := range map[string]graphfrag.GraphFragmentExport{"in memory": inMemory, "resolved": resolved, "streamed": streamed} {
		var got []string
		for _, a := range fragment.CallAnchors {
			got = append(got, fmt.Sprintf("%s %d:%d-%d %s %s chain=%t", fragment.Functions[a.Function].FunctionName, a.Line, a.StartCol, a.EndCol, a.Kind, a.Path, a.ChainID != ""))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: call anchors = %q, want %q", name, got, want)
		}
		// The edge of that call carries the chain of its line.
		for _, call := range fragment.ExternalCalls {
			if call.Line == 10 && call.StartCol == 59 && call.ChainID == "" {
				t.Errorf("%s: the edge of bitCount has no chain; the anchor's own chain is then not needed", name)
			}
		}
	}
}

// The rebuilt graph gives each call the syntax node and the chain its
// anchor records, by function and span, and keeps the calls in the anchors'
// order, which is the parser's; a call without an anchor keeps its edge's
// chain and follows by position.
func TestFragmentScanResultAnchorsCalls(t *testing.T) {
	site := func(target string, line, start, end int) graphfrag.GraphFragmentExternal {
		return graphfrag.GraphFragmentExternal{
			CallerKey: "app.(Box).size#1", TargetKey: target, Line: line, StartCol: start, EndCol: end,
			Resolution: "exact", MethodName: "m", ChainID: "7",
		}
	}
	doc := &graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{{Key: "app.(Box).size#1", FilePath: "app/Box.java", StartLine: 9, EndLine: 12}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			site("javax.crypto.(Cipher).getInstance#1", 10, 16, 41),
			site("javax.crypto.(Cipher).getBlockSize#0", 10, 16, 56),
			site("java.lang.(Integer).bitCount#1", 10, 59, 88),
			site("java.lang.(Math).max#2", 11, 9, 30),
		},
		CallAnchors: []graphfrag.GraphFragmentCallAnchor{
			{Function: 0, Line: 10, StartCol: 16, EndCol: 56, Kind: "method_invocation", Path: "p/outer", ChainID: "7"},
			{Function: 0, Line: 10, StartCol: 16, EndCol: 41, Kind: "method_invocation", Path: "p/inner", ChainID: "7"},
			{Function: 0, Line: 10, StartCol: 59, EndCol: 88, Kind: "method_invocation", Path: "p/other"},
		},
	}
	calls := FragmentScanResult(doc, t.TempDir(), nil).CallGraph.Functions["app.(Box).size#1"].Calls
	got := make([]string, 0, len(calls))
	for _, call := range calls {
		got = append(got, fmt.Sprintf("%s %q %q", call.Callee.Name, call.NamedASTPath, call.ChainID))
	}
	want := []string{`getBlockSize#0 "p/outer" "7"`, `getInstance#1 "p/inner" "7"`, `bitCount#1 "p/other" ""`, `max#2 "" "7"`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// As the Java parser records them, a call with arguments has one provenance
// slot per argument, empty when nothing was traced; one without has none.
func TestFragmentScanResultGivesEveryArgumentAProvenanceSlot(t *testing.T) {
	doc := &graphfrag.GraphFragmentExport{
		Functions: []graphfrag.GraphFragmentFunction{{Key: "app.(A).f#0", FilePath: "app/A.java", StartLine: 1, EndLine: 4}},
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			{
				CallerKey: "app.(A).f#0", TargetKey: "app.(Log).write#2", Line: 2, StartCol: 9, EndCol: 30, Resolution: "exact", MethodName: "write", Arity: 2,
				EntryCall: &graphfrag.GraphFragmentCallSite{Parameters: []graphfrag.GraphFragmentParameter{{ParameterIndex: 0, ArgumentExpression: "a"}, {ParameterIndex: 1, ArgumentExpression: "b"}}},
			},
			{CallerKey: "app.(A).f#0", TargetKey: "app.(Log).flush#0", Line: 3, StartCol: 9, EndCol: 20, Resolution: "exact", MethodName: "flush"},
		},
	}
	calls := FragmentScanResult(doc, t.TempDir(), nil).CallGraph.Functions["app.(A).f#0"].Calls
	if len(calls[0].ArgumentSources) != 2 || calls[0].ArgumentSources[0] != nil || calls[1].ArgumentSources != nil {
		t.Errorf("provenance = %v and %v, want two empty slots and none", calls[0].ArgumentSources, calls[1].ArgumentSources)
	}
}
