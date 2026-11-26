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
)

const constantRefsSource = `package app;
public class Algs {
    Object pick(Object alg) {
        if (Alg.HS256.equals(alg)) {
            return Alg.HS384;
        }
        return null;
    }
}
`

// A fragment lists the constant references of each function with their
// position kind, and carries the lines they stand on; both export paths
// agree, and the streamed form decodes back to the same references.
func TestGraphFragmentCarriesConstantRefs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "app", "Algs.java")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(constantRefsSource), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := &engine.DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java"}

	inMemory := buildGraphFragmentExport(result)
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
	for name, fragment := range map[string]graphfrag.GraphFragmentExport{"in memory": inMemory, "streamed": streamed} {
		var got []string
		for _, r := range fragment.ConstantRefs {
			entry := fmt.Sprintf("%s %s %s %d:%d-%d", fragment.Functions[r.Function].FunctionName, r.Context, r.Text, r.Line, r.StartCol, r.EndCol)
			if op := r.Operand; op != nil {
				entry += " operand " + op.ArgumentExpression
				for _, n := range op.SourceNodes {
					entry += " " + n.Type
					if n.ParameterIndex != nil {
						entry += fmt.Sprintf("#%d", *n.ParameterIndex)
					}
				}
			}
			got = append(got, entry)
		}
		want := []string{"app.Algs.pick equals Alg.HS256 4:13-22 operand alg PARAMETER#0", "app.Algs.pick return Alg.HS384 5:20-29"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: constant_refs = %v, want %v", name, got, want)
		}
		lines := fragment.SourceLines["app/Algs.java"]
		if lines[4] != "        if (Alg.HS256.equals(alg)) {" || lines[5] != "            return Alg.HS384;" {
			t.Errorf("%s: source_lines = %#v, want lines 4 and 5", name, lines)
		}
	}
}
