// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// recursiveReturnSource renders a class whose peel method returns a call to
// itself from recursiveReturns branches, the shape that made exported
// provenance grow as recursiveReturns^depth.
func recursiveReturnSource(recursiveReturns int) string {
	var b strings.Builder
	b.WriteString("package com.example;\n\nimport java.security.MessageDigest;\n\npublic class Peel {\n")
	b.WriteString("    static String peel(String name, int k) {\n")
	for i := range recursiveReturns {
		fmt.Fprintf(&b, "        if (k == %d) {\n            return peel(name, %d);\n        }\n", i, i+1)
	}
	b.WriteString("        return name;\n    }\n\n")
	b.WriteString("    static String helper() {\n        return \"SHA-256\";\n    }\n\n")
	b.WriteString("    static String algorithm() {\n        return helper();\n    }\n\n")
	b.WriteString("    static String choose(boolean strong) {\n        if (strong) {\n            return helper();\n        }\n        return helper();\n    }\n\n")
	b.WriteString("    void run(String name) throws Exception {\n")
	b.WriteString("        MessageDigest.getInstance(peel(name, 0));\n")
	b.WriteString("        MessageDigest.getInstance(algorithm());\n")
	b.WriteString("        MessageDigest.getInstance(choose(true));\n")
	b.WriteString("    }\n}\n")
	return b.String()
}

func exportRecursiveReturnFixture(t *testing.T, recursiveReturns int) map[string]graphfrag.GraphFragmentParameter {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Peel.java"), []byte(recursiveReturnSource(recursiveReturns)), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.example"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	payload := buildGraphFragmentExport(&engine.DepScanResult{
		Report:    &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}},
		CallGraph: graph,
		Ecosystem: "java",
	})

	byArgument := make(map[string]graphfrag.GraphFragmentParameter)
	for i := range payload.ExternalCalls {
		ext := &payload.ExternalCalls[i]
		if ext.MethodName != "getInstance" || ext.EntryCall == nil || len(ext.EntryCall.Parameters) != 1 {
			continue
		}
		param := ext.EntryCall.Parameters[0]
		byArgument[param.ArgumentExpression] = param
	}
	for _, want := range []string{"peel(name, 0)", "algorithm()", "choose(true)"} {
		if _, ok := byArgument[want]; !ok {
			t.Fatalf("recursiveReturns=%d: no exported getInstance(%s) argument; got %v", recursiveReturns, want, byArgument)
		}
	}
	return byArgument
}

func countSourceNodes(nodes []graphfrag.GraphFragmentSourceNode) int {
	total := len(nodes)
	for i := range nodes {
		total += countSourceNodes(nodes[i].SourceNodes)
	}
	return total
}

// renderSourceNodes flattens provenance to type, target or value, and
// children, leaving out locations that vary with the fixture directory.
func renderSourceNodes(nodes []graphfrag.GraphFragmentSourceNode) string {
	parts := make([]string, 0, len(nodes))
	for i := range nodes {
		node := nodes[i]
		label := node.Type + " " + node.Value
		if node.CallTarget != "" {
			label = node.Type + " " + node.CallTarget
		}
		if node.Type == "PARAMETER" {
			label = node.Type + " " + node.Name
		}
		if len(node.SourceNodes) > 0 {
			label += "(" + renderSourceNodes(node.SourceNodes) + ")"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func TestGraphFragmentExport_RecursiveReturnProvenanceStaysLinear(t *testing.T) {
	t.Parallel()

	counts := make(map[int]int)
	for _, returns := range []int{2, 4, 6} {
		peel := exportRecursiveReturnFixture(t, returns)["peel(name, 0)"]
		counts[returns] = countSourceNodes(peel.SourceNodes)
		if len(peel.SourceNodes) != 1 {
			t.Fatalf("recursiveReturns=%d: peel provenance roots = %d, want 1", returns, len(peel.SourceNodes))
		}
		inlined := make(map[string]bool)
		for _, child := range peel.SourceNodes[0].SourceNodes {
			inlined[child.Value] = true
		}
		for i := 1; i <= returns; i++ {
			if want := fmt.Sprintf("peel(name, %d)", i); !inlined[want] {
				t.Fatalf("recursiveReturns=%d: recursive return %q missing from provenance %s", returns, want, renderSourceNodes(peel.SourceNodes))
			}
		}
	}
	if first, second := counts[4]-counts[2], counts[6]-counts[4]; first != second {
		t.Fatalf("provenance nodes by recursive return count = %v, want linear growth (deltas %d and %d)", counts, first, second)
	}
}

func TestGraphFragmentExport_NonRecursiveReturnProvenanceIsInlined(t *testing.T) {
	t.Parallel()

	byArgument := exportRecursiveReturnFixture(t, 2)
	want := map[string]string{
		"algorithm()":  `CALL_RESULT com.example.Peel.algorithm(CALL_RESULT com.example.Peel.helper(VALUE "SHA-256"))`,
		"choose(true)": `CALL_RESULT com.example.Peel.choose(VALUE true, CALL_RESULT com.example.Peel.helper(VALUE "SHA-256"), CALL_RESULT com.example.Peel.helper(VALUE "SHA-256"))`,
	}
	for argument, wantProvenance := range want {
		if got := renderSourceNodes(byArgument[argument].SourceNodes); got != wantProvenance {
			t.Errorf("getInstance(%s) provenance =\n  %s\nwant\n  %s", argument, got, wantProvenance)
		}
	}
}
