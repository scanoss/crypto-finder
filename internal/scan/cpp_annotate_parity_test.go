// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// std::make_unique<T>(...) is a call of make_unique and a construction of T
// at one span. Neither resolved, they score the same: the construction is
// the crypto call whichever the function lists first.
func TestPickBestCandidatePrefersTheConstructionOfMakeUnique(t *testing.T) {
	makeUnique := callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "app", Type: "std", Name: "make_unique"}, Line: 7, StartCol: 19, EndCol: 69, Arguments: []string{"port", `"AES"`}}
	construct := callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "app", Type: "acme::Server", Name: "Server"}, Line: 7, StartCol: 19, EndCol: 69, Arguments: []string{"port", `"AES"`}}
	for _, calls := range [][]callgraph.FunctionCall{{makeUnique, construct}, {construct, makeUnique}} {
		got := pickBestCandidate(&callgraph.CallGraph{}, []*callgraph.FunctionCall{&calls[0], &calls[1]})
		if got.Callee != construct.Callee {
			t.Errorf("order %s, %s: picked %s, want the construction", calls[0].Callee, calls[1].Callee, got.Callee)
		}
	}
}

func TestIsCPPConstruction(t *testing.T) {
	for callee, want := range map[callgraph.FunctionID]bool{
		{Package: "app", Type: "Botan::TLS::Server", Name: "Server"}:    true,
		{Package: "app", Type: "std::vector<Botan::X>", Name: "vector"}: true,
		{Type: "Hash", Name: "Hash"}:                                    true,
		{Package: "app", Type: "std", Name: "make_unique"}:              false,
		{Package: "app", Type: "Botan::TLS::Server", Name: "send"}:      false,
		{Package: "app", Name: "Server"}:                                false,
		{Package: "app", Type: "Hash", Name: "<init>"}:                  false,
	} {
		if got := isCPPConstruction(callee); got != want {
			t.Errorf("isCPPConstruction(%s) = %v, want %v", callee, got, want)
		}
	}
}

// A call of a type a C++ project declares is internally linked in the scan's
// graph (reach's markCPPProjectLocalCalls), so the contracts leave it to the
// project's definition. A graph rebuilt from the fragment reads the declared
// types off the fragment's functions and links the calls the same way.
func TestFragmentScanResultRestoresCPPProjectLinkage(t *testing.T) {
	doc := &graphfrag.GraphFragmentExport{
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{Ecosystem: ecosystemCPP, RootModule: "app"},
		Functions: []graphfrag.GraphFragmentFunction{
			{Key: "app.digest", FilePath: "app/digest.cpp", StartLine: 1, EndLine: 9},
			{Key: "lib.(QCryptographicHash).QCryptographicHash", FilePath: "lib/qhash.cpp", StartLine: 2, EndLine: 2},
			{Key: "lib.(Outer::Inner).run", FilePath: "lib/qhash.cpp", StartLine: 3, EndLine: 3},
		},
		CallAnchors: []graphfrag.GraphFragmentCallAnchor{
			{Function: 0, Line: 3, StartCol: 5, EndCol: 22, Callee: "app.(QCryptographicHash).addData", Raw: "hash.addData", Arguments: []string{"data"}},
			{Function: 0, Line: 4, StartCol: 5, EndCol: 20, Callee: "app.(Outer).Inner", Raw: "Outer::Inner"},
			{Function: 0, Line: 5, StartCol: 5, EndCol: 25, Callee: "app.(Botan::HashFunction).update", Raw: "h->update", Arguments: []string{"x"}},
			{Function: 0, Line: 6, StartCol: 5, EndCol: 15, Callee: "app.helper", Raw: "helper"},
		},
	}
	graph := FragmentScanResult(doc, t.TempDir(), nil).CallGraph
	want := map[string]callgraph.Linkage{
		"app.(QCryptographicHash).addData": callgraph.LinkageInternal,
		"app.(Outer).Inner":                callgraph.LinkageInternal,
		"app.(Botan::HashFunction).update": "",
		"app.helper":                       "",
	}
	calls := graph.Functions["app.digest"].Calls
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v, want %d", calls, len(want))
	}
	for _, call := range calls {
		if got := call.Callee.Linkage; got != want[call.Callee.String()] {
			t.Errorf("linkage of %s = %q, want %q", call.Callee, got, want[call.Callee.String()])
		}
	}
}

// A call that dispatches is an edge per target at its site. When a dispatch
// edge lists another call's variables (an override the caller also calls
// directly) before the call's own exact edge, the rebuilt call takes the
// exact edge's.
func TestFragmentScanResultTakesTheVariablesOfTheExactEdge(t *testing.T) {
	doc := &graphfrag.GraphFragmentExport{
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{Ecosystem: ecosystemCPP, RootModule: "app"},
		Functions: []graphfrag.GraphFragmentFunction{
			{Key: "app.main", FilePath: "app/main.cpp", StartLine: 1, EndLine: 9},
			{Key: "app.(PrivKey).write", FilePath: "app/keys.cpp", StartLine: 2, EndLine: 2},
			{Key: "app.(PubKey).write", FilePath: "app/keys.cpp", StartLine: 3, EndLine: 3},
		},
		InternalEdges: []graphfrag.GraphFragmentEdge{
			{CallerKey: "app.main", CalleeKey: "app.(PrivKey).write", Line: 6, StartCol: 18, EndCol: 28, Resolution: "exact", MethodName: "write", ReceiverVar: "sk", ChainID: "1"},
			{CallerKey: "app.main", CalleeKey: "app.(PrivKey).write", Line: 8, StartCol: 18, EndCol: 28, Resolution: "interface_dispatch", MethodName: "write", ReceiverVar: "sk", ChainID: "1"},
			{CallerKey: "app.main", CalleeKey: "app.(PubKey).write", Line: 8, StartCol: 18, EndCol: 28, Resolution: "exact", MethodName: "write", ReceiverVar: "pk", ChainID: "2"},
		},
		CallAnchors: []graphfrag.GraphFragmentCallAnchor{
			{Function: 0, Line: 6, StartCol: 18, EndCol: 28, ChainID: "1", Callee: "app.(PrivKey).write", Raw: "sk.write"},
			{Function: 0, Line: 8, StartCol: 18, EndCol: 28, ChainID: "2", Callee: "app.(PubKey).write", Raw: "pk.write"},
		},
	}
	calls := FragmentScanResult(doc, t.TempDir(), nil).CallGraph.Functions["app.main"].Calls
	if len(calls) != 2 || calls[0].ReceiverVar != "sk" || calls[1].ReceiverVar != "pk" {
		t.Errorf("calls = %+v, want sk.write on sk and pk.write on pk", calls)
	}
}
