// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
)

const goRoundTripSource = `package app

import (
	"crypto/sha256"
	"crypto/tls"

	"example.com/dep"
)

var suites = []uint16{tls.TLS_AES_128_GCM_SHA256}

type Local struct{ n int }

func (l *Local) Sum(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

func run(s *dep.Signer, min uint16) *tls.Config {
	var cfg tls.Config
	if min == tls.VersionTLS10 {
		min = tls.VersionTLS12
	}
	key := dep.Open("k", 2)
	key.Use(min)
	s.Sign(Local{}.Sum([]byte("x")))
	cfg.MinVersion = min
	return &cfg
}
`

// A Go fragment carries what a source-free annotate reads: the graph
// FragmentScanResult rebuilds from it has the calls and arguments of the graph
// built from source, and the fragment itself holds the constant references
// and declarations the cards matcher reads from it.
func TestFragmentScanResult_GoRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for name, content := range map[string]string{"go.mod": "module example.com/app\n", "app.go": goRoundTripSource} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	builder := callgraph.NewBuilderForEcosystem("go", callgraph.NewParserForEcosystem("go"))
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{CallGraph: graph, Ecosystem: "go", ProjectRoot: root, RootModule: "example.com/app"}
	path := filepath.Join(t.TempDir(), "fragment.json")
	if err := ExportResolvedGraphFragment(path, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	doc := decodeFragmentFile(t, path)
	doc.RestoreElided()
	doc.ExpandInternalEdges()
	rebuilt := FragmentScanResult(&doc, result.ProjectRoot, &entities.InterimReport{})

	calls := func(fn *callgraph.FunctionDecl) []pythonRoundTripCall {
		out := make([]pythonRoundTripCall, len(fn.Calls))
		for i := range fn.Calls {
			c := &fn.Calls[i]
			out[i] = pythonRoundTripCall{
				Callee: c.Callee.String(), Raw: c.Raw, ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID,
				Line: c.Line, StartCol: c.StartCol, EndCol: c.EndCol, EndLine: max(c.EndLine, c.Line), Arguments: c.Arguments,
			}
		}
		return out
	}
	var compared int
	for key, want := range result.CallGraph.Functions {
		got := rebuilt.CallGraph.Functions[key]
		if got == nil {
			t.Errorf("%s: not rebuilt", key)
			continue
		}
		if !reflect.DeepEqual(calls(got), calls(want)) {
			t.Errorf("%s: calls\n got %+v\nwant %+v", key, calls(got), calls(want))
		}
		compared += min(len(want.Calls), 1)
	}
	if compared < 2 {
		t.Fatalf("only %d functions with calls compared", compared)
	}
	var refs, decls int
	for _, fn := range result.CallGraph.Functions {
		refs += len(fn.ConstantRefs)
		decls += len(fn.Declarations)
	}
	if len(doc.ConstantRefs) != refs || len(doc.Declarations) != decls || refs == 0 || decls == 0 {
		t.Errorf("fragment holds %d constant refs and %d declarations, want %d and %d", len(doc.ConstantRefs), len(doc.Declarations), refs, decls)
	}
}
