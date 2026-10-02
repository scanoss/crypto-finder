// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// anchorScopeFunction declares one Go function spanning lines 1 to endLine of
// file, with a call at line 10 that a finding there anchors to.
func anchorScopeFunction(pkg, file string, endLine int) *callgraph.FunctionDecl {
	return &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: pkg, Name: "Seal"},
		FilePath:  file,
		StartLine: 1,
		EndLine:   endLine,
		Calls: []callgraph.FunctionCall{{
			Callee:   callgraph.FunctionID{Package: "crypto/aes", Name: "NewCipher"},
			FilePath: file, Line: 10, StartCol: 5, EndCol: 25,
			ASTKind: "call_expression", NamedASTPath: "block[0]/call_expression[0]",
		}},
	}
}

// anchorScopeResult scans a project at /work with dependencies a and b. The
// finding sits at line 10 of findingPath, inside depModule when it is set.
func anchorScopeResult(findingPath, depModule string, functions ...*callgraph.FunctionDecl) *engine.DepScanResult {
	asset := entities.CryptographicAsset{
		FindingID: "f1", StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25,
		Match: "aes.NewCipher(key)",
	}
	if depModule != "" {
		asset.Source = "dependency"
		asset.DependencyInfo = &entities.DependencyInfo{Module: depModule, Version: "v1.0.0"}
	}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}
	for _, fn := range functions {
		graph.Functions[fn.ID.String()] = fn
	}
	return &engine.DepScanResult{
		RootModule:  "example.com/app",
		ProjectRoot: "/work",
		Ecosystem:   "go",
		Dependencies: []dependency.Dependency{
			{Module: "example.com/a", Version: "v1.0.0", Dir: "/mod/example.com/a@v1.0.0"},
			{Module: "example.com/b", Version: "v1.0.0", Dir: "/mod/example.com/b@v1.0.0"},
		},
		CallGraph: graph,
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: findingPath, Language: "go", CryptographicAssets: []entities.CryptographicAsset{asset},
		}}},
	}
}

// anchorScopeCases each pair a finding with its own file's function and a
// tighter-spanned function in a different file that only shares the
// finding's relative path as a suffix. Lookups prefer the tighter span, so a
// suffix match binds the finding to the impostor.
var anchorScopeCases = []struct {
	name        string
	findingPath string
	depModule   string
	own         *callgraph.FunctionDecl
	impostor    *callgraph.FunctionDecl
}{
	{
		name:        "same relative path in another dependency",
		findingPath: "util/seal.go",
		depModule:   "example.com/b",
		own:         anchorScopeFunction("example.com/b/util", "/mod/example.com/b@v1.0.0/util/seal.go", 100),
		impostor:    anchorScopeFunction("example.com/a/util", "/mod/example.com/a@v1.0.0/util/seal.go", 20),
	},
	{
		name:        "dependency path inside a longer project path",
		findingPath: "util/seal.go",
		depModule:   "example.com/b",
		own:         anchorScopeFunction("example.com/b/util", "/mod/example.com/b@v1.0.0/util/seal.go", 100),
		impostor:    anchorScopeFunction("example.com/app/vendored/util", "/work/vendored/util/seal.go", 20),
	},
	{
		name:        "project path inside a longer project path",
		findingPath: "a/seal.go",
		own:         anchorScopeFunction("example.com/app/a", "/work/a/seal.go", 100),
		impostor:    anchorScopeFunction("example.com/app/b/a", "/work/b/a/seal.go", 20),
	},
	{
		name:        "project path as a dependency path",
		findingPath: "util/seal.go",
		own:         anchorScopeFunction("example.com/app/util", "/work/util/seal.go", 100),
		impostor:    anchorScopeFunction("example.com/a/util", "/mod/example.com/a@v1.0.0/util/seal.go", 20),
	},
	{
		name:        "file name that ends another file name",
		findingPath: "a/seal.go",
		own:         anchorScopeFunction("example.com/app/a", "/work/a/seal.go", 100),
		impostor:    anchorScopeFunction("example.com/app/ba", "/work/ba/seal.go", 20),
	},
}

func TestAssignOccurrenceKeys_BindsFindingToItsOwnArtifactFile(t *testing.T) {
	for _, tc := range anchorScopeCases {
		t.Run(tc.name, func(t *testing.T) {
			want := anchorScopeResult(tc.findingPath, tc.depModule, tc.own)
			AssignOccurrenceKeys(want)
			wantKey := want.Report.Findings[0].CryptographicAssets[0].OccurrenceKey

			got := anchorScopeResult(tc.findingPath, tc.depModule, tc.own, tc.impostor)
			AssignOccurrenceKeys(got)
			if key := got.Report.Findings[0].CryptographicAssets[0].OccurrenceKey; key != wantKey {
				t.Fatalf("occurrence_key = %q, want %q (the key of %s alone)", key, wantKey, tc.own.FilePath)
			}
		})
	}
}

func TestCallGraphExport_FindingNeverBindsAnotherArtifactsFile(t *testing.T) {
	for _, tc := range anchorScopeCases {
		t.Run(tc.name, func(t *testing.T) {
			export := buildCallGraphExportV2(anchorScopeResult(tc.findingPath, tc.depModule, tc.impostor))
			if got := export.FindingGraphs[0].UnresolvedReason; got != unresolvedNoContainingFunction {
				t.Fatalf("unresolved_reason = %q, want %q: only %s, which is not the finding's file, declares a function",
					got, unresolvedNoContainingFunction, tc.impostor.FilePath)
			}
		})
	}
}

func TestCallGraphExport_FindingBindsItsOwnArtifactFile(t *testing.T) {
	for _, tc := range anchorScopeCases {
		t.Run(tc.name, func(t *testing.T) {
			export := buildCallGraphExportV2(anchorScopeResult(tc.findingPath, tc.depModule, tc.own, tc.impostor))
			fg := export.FindingGraphs[0]
			if fg.UnresolvedReason != "" {
				t.Fatalf("unresolved_reason = %q, want the finding bound to %s", fg.UnresolvedReason, tc.own.FilePath)
			}
			if len(fg.CallChains) == 0 || len(fg.CallChains[0]) == 0 {
				t.Fatal("finding exported no call chain")
			}
			chain := fg.CallChains[0]
			if got, want := chain[len(chain)-1].FunctionName, tc.own.ID.Package+".Seal"; got != want {
				t.Fatalf("containing function = %q, want %q", got, want)
			}
		})
	}
}

func TestAnnotateContainingFunction_MatchesWholePathSegments(t *testing.T) {
	fragment := graphfrag.Fragment{Functions: []graphfrag.Function{{
		Signature: "example.com/app/ba.Seal", FilePath: "ba/seal.go", StartLine: 1, EndLine: 20,
	}}}
	if fn, ok := annotateContainingFunction(fragment, "a/seal.go", 10); ok {
		t.Fatalf("a/seal.go bound to %s in ba/seal.go", fn.Signature)
	}
}
