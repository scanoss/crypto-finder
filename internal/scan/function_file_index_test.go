// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// linearContainingFunctionByFinding is findContainingFunctionByFinding's walk
// before the index: every function in the graph, raw path suffix.
func linearContainingFunctionByFinding(functions map[string]*callgraph.FunctionDecl, findingPath string, line int) *callgraph.FunctionDecl {
	normalized := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalized == "" {
		normalized = filepath.ToSlash(findingPath)
	}
	var best *callgraph.FunctionDecl
	for _, fn := range functions {
		if !strings.HasSuffix(filepath.ToSlash(fn.FilePath), normalized) || line < fn.StartLine || line > fn.EndLine {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	return best
}

// linearOccurrenceContainingFunction is findOccurrenceContainingFunction's
// walk before the index: every function, whole path segments.
func linearOccurrenceContainingFunction(functions map[string]*callgraph.FunctionDecl, findingPath string, line int) *callgraph.FunctionDecl {
	normalized := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalized == "" {
		normalized = filepath.ToSlash(findingPath)
	}
	var best *callgraph.FunctionDecl
	for _, fn := range functions {
		if !hasPathSegmentSuffix(fn.FilePath, normalized) || line < fn.StartLine || line > fn.EndLine {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	return best
}

// The paths a dependency scan mixes: the project tree, dependency trees under
// module@version, nested classes, a base name that is the tail of another,
// a root-level file, and two files of the same name in different packages.
func functionFileIndexFixture() map[string]*callgraph.FunctionDecl {
	files := []string{
		"/work/src/main/java/com/acme/Crypto.java",
		"/work/src/main/java/com/acme/NotCrypto.java",
		"/work/src/main/java/com/other/Crypto.java",
		"/deps/org.bouncycastle:bcprov@1.70/org/bouncycastle/x509/PKIXCertPathReviewer.java",
		"/deps/org.bouncycastle:bcprov@1.70/org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi.java",
		"/deps/com.example:lib@2.0/com/example/Crypto.java",
		"/work/main.go",
		"/work/cmd/tool/main.go",
		`C:\work\src\Win.java`,
	}
	functions := make(map[string]*callgraph.FunctionDecl)
	for i, file := range files {
		// Nested spans: a whole-file <clinit>, a method, and a lambda inside
		// it, plus a second method with the same span as the first so the
		// tie-break on the function key decides.
		for j, span := range [][2]int{{1, 400}, {10, 60}, {20, 30}, {10, 60}, {100, 200}} {
			id := callgraph.FunctionID{Package: fmt.Sprintf("p%d", i), Name: fmt.Sprintf("f%d", j)}
			functions[id.String()] = &callgraph.FunctionDecl{ID: id, FilePath: file, StartLine: span[0], EndLine: span[1]}
		}
	}
	return functions
}

func functionFileIndexQueries() []string {
	return []string{
		"Crypto.java",
		"acme/Crypto.java",
		"com/acme/Crypto.java",
		"src/main/java/com/acme/Crypto.java",
		"rypto.java",
		"NotCrypto.java",
		"org.bouncycastle:bcprov@1.70/org/bouncycastle/x509/PKIXCertPathReviewer.java",
		"org/bouncycastle/x509/PKIXCertPathReviewer.java",
		"com.example:lib@2.0/com/example/Crypto.java",
		"main.go",
		"tool/main.go",
		"/main.go",
		"src/",
		"Win.java",
		"Missing.java",
		"",
	}
}

// The index only narrows which functions are checked; the answer must be the
// one the full walk gave, for every path shape and line.
func TestFunctionFileIndex_AgreesWithTheFullWalk(t *testing.T) {
	functions := functionFileIndexFixture()
	idx := newFunctionFileIndex(functions)
	ctx := &exportBuildContext{
		graph:                   &callgraph.CallGraph{Functions: functions},
		containingFunctionCache: make(map[string]cachedContainingFunction),
	}
	for _, query := range functionFileIndexQueries() {
		for _, line := range []int{0, 1, 15, 25, 60, 61, 150, 400, 401} {
			want := linearContainingFunctionByFinding(functions, query, line)
			if got := ctx.findContainingFunctionByFinding(query, line); got != want {
				t.Errorf("findContainingFunctionByFinding(%q, %d) = %v, want %v", query, line, got, want)
			}
			want = linearOccurrenceContainingFunction(functions, query, line)
			if got := findOccurrenceContainingFunction(idx, query, line); got != want {
				t.Errorf("findOccurrenceContainingFunction(%q, %d) = %v, want %v", query, line, got, want)
			}
		}
	}
}

// What makes it fast: a path with a directory reaches only that file name's
// functions, not the graph.
func TestFunctionFileIndex_NarrowsToOneFileName(t *testing.T) {
	idx := newFunctionFileIndex(functionFileIndexFixture())
	for _, fn := range idx.suffixCandidates("org/bouncycastle/x509/PKIXCertPathReviewer.java") {
		if !strings.HasSuffix(fn.FilePath, "/PKIXCertPathReviewer.java") {
			t.Fatalf("candidate %s is declared in another file", fn.FilePath)
		}
	}
	if got := len(idx.suffixCandidates("com/acme/Crypto.java")); got != 15 {
		t.Fatalf("Crypto.java candidates = %d, want the 15 functions of its three files", got)
	}
	if got, all := len(idx.suffixCandidates("Crypto.java")), len(idx.all); got != all {
		t.Fatalf("a bare file name can be the tail of a longer one, so it must check all %d functions, got %d", all, got)
	}
}

// BenchmarkContainingFunction_DependencyScale compares the walk with the
// index at a dependency scan's size: about 400k functions across 40k files,
// one lookup per asset.
func BenchmarkContainingFunction_DependencyScale(b *testing.B) {
	functions := make(map[string]*callgraph.FunctionDecl)
	for f := 0; f < 40000; f++ {
		file := fmt.Sprintf("/deps/m%d@1.0/org/pkg%d/File%d.java", f%100, f%997, f)
		for m := 0; m < 10; m++ {
			id := callgraph.FunctionID{Package: fmt.Sprintf("org.pkg%d", f), Name: fmt.Sprintf("m%d", m)}
			functions[id.String()] = &callgraph.FunctionDecl{ID: id, FilePath: file, StartLine: m*20 + 1, EndLine: m*20 + 15}
		}
	}
	query := "m7@1.0/org/pkg31/File20007.java"
	b.Run("walk", func(b *testing.B) {
		for range b.N {
			_ = linearContainingFunctionByFinding(functions, query, 45)
		}
	})
	b.Run("index", func(b *testing.B) {
		idx := newFunctionFileIndex(functions)
		b.ResetTimer()
		for range b.N {
			ctx := &exportBuildContext{
				graph:                   &callgraph.CallGraph{Functions: functions},
				containingFunctionCache: make(map[string]cachedContainingFunction),
				functionsByFile:         idx,
			}
			_ = ctx.findContainingFunctionByFinding(query, 45)
		}
	})
}
